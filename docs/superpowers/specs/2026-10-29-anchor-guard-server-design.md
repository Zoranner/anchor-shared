# Anchor Guard 服务端管理模式设计

## 目标

在现有终端本地管控能力之上，增加一套自建 B/S 管理服务：

- 服务端以 Docker 镜像部署，使用 Rust/Axum + SeaORM 访问 PostgreSQL，保存设备、硬件清单和策略数据。
- 管理员通过浏览器登录管理台，管理设备、策略、签名和分发。
- 客户端使用一个通用 Windows 安装包，安装时填写服务端地址和端口。
- 客户端注册后进入待审批列表，管理员批准后开始拉取策略。
- 服务端保存策略并负责签名；客户端本地验证签名后执行。
- 客户端可以离线运行并缓存最后可用策略；策略过期时优先在线获取，服务端不可用时保留离线导入兜底。
- 本期服务端不保存审计数据，也不提供审计页；审计日志仍在客户端本地查看。
- 策略编辑器必须提供可视化编辑，覆盖 USB、网络、刻录、扫描、例外设备和有效期。
- 客户端上报全量硬件清单，服务端据此展示设备信息并辅助策略配置。

## 组件

```text
crates/
  anchor-core             服务端与客户端共享的策略模型和签名
  anchor-protocol         服务端与客户端共享的 DTO、错误码和版本

client/
  crates/
    anchor-ipc            客户端本地 Named Pipe 协议
    anchor-scan           客户端文件扫描
    anchor-store          客户端 SQLite
    anchor-system         客户端 Windows 系统适配
  service                 注册、心跳、清单上报、策略同步、本地验签
  desktop                 展示待审批、服务端连接和策略状态
  credential              登录组件，继续只读查询本地服务
  session                 交互会话授权协作和锁定
  installer               Windows 安装包和安装动作

server/                   anchor-server crate 根目录
  web/                    B/S 管理台

```

PostgreSQL 和 Docker 镜像属于部署形态，放在“部署”一节，不作为 `server/` 目录下的文件或组件。

根 `crates/` 只放服务端和客户端共享的 crate；客户端专用 crate 放在 `client/crates/`，服务端专用 crate 如需拆分则放在 `server/crates/`。`client/`、`server/`、`crates/` 各自使用独立 Cargo workspace，仓库根不定义 workspace；`client/Cargo.toml` 和 `client/src/` 是客户端构建与打包入口。客户端访问服务端的 HTTP 代码直接放在 `client/service/src/server_sync.rs`，不单独建 crate；只有出现第二个直接调用服务端的消费者时才重新评估。

管理端不再做成独立桌面软件；管理员使用浏览器访问服务端管理台。

## 命名与术语

- `device` 指 Windows 终端；`client` 指终端代码，不作为服务端表名或 API 资源名。
- `installation_id` 是客户端首次安装生成的本地标识，只用于注册幂等；`device_id` 是服务端设备记录 ID；`device_token` 是设备凭证；`token_hash` 是服务端保存的哈希。
- `approved` 是管理员动作，`active` 是设备状态；不要用 `enabled` 表示设备审批状态。
- `policy_json`、`signature_hex`、`server_key_id` 与 `PolicyEnvelope` 保持一致；`inventory_json`、`inventory_hash` 表示全量硬件快照。
- 表名使用复数 snake_case，字段和 JSON 使用 snake_case；Rust 类型使用 PascalCase。

## 信任与密钥

- 服务端持有策略签名私钥。`ANCHOR_MASTER_KEY_FILE` 指向只读挂载的 32 字节主密钥（64 位 hex）；主密钥只作为密钥加密密钥，不进入数据库、镜像和日志。
- 签名私钥使用 HKDF-SHA256 派生的 AES-256-GCM 密钥加密后保存到 `ANCHOR_DATA_DIR/signing-keys/<key_id>.key`，文件权限为 0600。数据库 `signing_keys` 只保存 `key_id`、公钥、状态和时间，不保存私钥明文。
- `server_key_id` 是公钥 32 字节的 SHA-256 十六进制摘要。`signing_keys.status` 只允许 `active`、`retired`、`revoked`：同一时刻最多一个 `active`；轮换后旧密钥转为 `retired`，只用于验证旧策略；撤销后转为 `revoked`，不再被信任。
- 管理员登录后才能触发策略签发；管理台只有管理员角色。
- 客户端安装包不包含任何部署实例的验证公钥。
- 客户端通过 HTTPS 连接服务端，校验证书后完成注册。
- 客户端注册时由服务端生成 256 位随机设备令牌，只返回一次；服务端保存 SHA-256 令牌哈希，客户端保存在受 ACL 保护的本地文件中，后续心跳和策略拉取使用 Bearer 令牌认证。DPAPI 仅作为可选的离线保护，不作为同用户隔离手段。
- Windows 客户端的 `installation_id` 保存在数据目录的 `installation-id`；设备令牌保存在 `secrets\device-token`。`secrets` 目录和令牌文件只授予 SYSTEM 与 Administrators，写入通过临时文件替换完成。
- 服务端向已批准设备下发当前验证公钥；客户端保存后用于本地验签。
- 服务端只分发已签名策略，不能下发无签名的“无条件解锁”命令。
- 首次初始化必须配置 `ANCHOR_SETUP_TOKEN`。初始化成功后由 `admin_users` 是否存在判定入口关闭，再次调用返回 `409 setup_complete`；部署环境可以在完成后移除该变量。
- 管理员密码使用 Argon2id 保存。管理会话令牌为 256 位随机值，数据库只保存 SHA-256 哈希；会话绝对有效期为 12 小时。
- 管理员会话 Cookie 名为 `anchor_admin_session`，使用 HttpOnly、Secure、SameSite=Strict。CSRF Cookie 名为 `anchor_admin_csrf`，前端读取后通过 `X-CSRF-Token` 请求头回传；所有改变状态的已认证管理请求同时校验 Cookie、请求头和会话中的 CSRF 哈希。

## 安装与注册

通用 Windows 安装包提供两个输入项：

- 服务端地址
- 服务端端口

安装程序将地址和端口写入本地服务配置。安装完成后：

1. Windows 服务启动并生成设备 ID 和全量硬件快照；注册成功后保存服务端下发的设备令牌。
2. 客户端调用注册接口，服务端创建设备记录，状态为 `pending`。
3. 管理员在 B/S 管理台查看待审批设备、硬件摘要和注册时间。
4. 管理员批准后，设备状态变为 `active`。
5. 客户端轮询注册状态，获得验证公钥和初始策略，开始正常同步。

服务端模式的 `service.toml` 使用 `server_url` 指向完整服务地址，客户端从安装标识文件读取 `installation_id`。旧离线配置中的 `verifying_key_hex` 和 `device_id` 仍可读取；没有 `server_url` 时保持原有离线模式。服务端模式启动后由独立同步线程执行注册、审批轮询、心跳和策略拉取，避免阻塞本地策略执行循环。

设备注册后由管理员审批；审批通过是设备获取策略的唯一准入条件，本期不增加机器指纹硬绑定。硬件清单只用于展示和策略配置，不作为每次请求的认证条件。

## 全量硬件清单

客户端在注册时和硬件变化时上报完整快照，至少包含：

- 计算机厂商、型号、序列号、BIOS 信息。
- 操作系统版本、安装语言、系统架构、主机名。
- CPU 型号、核心数、线程数。
- 内存条数量、容量、频率、厂商、序列号。
- 物理磁盘、分区、卷标、容量、序列号。
- 网卡实例 ID、适配器名称、MAC 地址、链路状态、驱动版本。
- USB 控制器、USB 设备、存储设备实例 ID。
- 光驱设备实例 ID、介质状态。
- GPU 型号、显存、驱动版本。

服务端保存完整快照，并在设备详情中展示结构化的硬件分组。策略编辑器可以从硬件清单选择网卡、USB 存储、光驱等对象作为例外或拒绝目标。

`inventory_hash` 是服务端解析请求后重新序列化 `HardwareInventory` 得到的字节的 SHA-256；客户端使用同一个共享类型和 serde 序列化计算，避免依赖原始 JSON 空白或对象字段顺序。

Windows 客户端使用 WMI 读取系统、BIOS、CPU、内存、磁盘、卷、网卡、USB、光驱和显卡信息。策略执行的每周期设备观测仍使用 CfgMgr32 轻量库存，全量 WMI 快照只在注册、硬件变化和人工刷新时采集。

## 策略与可视化编辑器

策略编辑在 B/S 管理台完成，至少包含：

- USB 读取和写入策略。
- USB 允许列表，支持从硬件清单选择设备。
- 网卡策略和允许列表，支持按适配器实例 ID、厂商、型号选择。
- 刻录策略和允许列表。
- 文件扫描目录、文件类型、关键词和正则规则。
- 策略有效期。
- 当前设备与策略差异预览。

保存策略时先生成草稿；管理员确认后触发签名。签名结果保存为不可变的策略版本，版本号在部署实例内单调递增。

策略可以分配给单台设备，也可以作为默认策略分配给尚未单独配置的设备。客户端只接受签名有效、版本不回退且未过期的策略。

## 策略获取与过期

客户端按固定周期和网络变化事件拉取策略：

- 服务端在线且有新版本：下载策略包，本地验签后原子替换。
- 服务端在线但没有新版本：保留本地缓存。
- 服务端不可用：继续使用最后可用策略，直到过期。
- 策略过期且服务端可达：请求新策略；管理员批准后返回签名策略。
- 策略过期且服务端不可达：保持锁定，允许通过本地文件导入新策略。

服务端不是授权状态的最终判断者。客户端本地服务仍负责验签、版本、有效期、时间回拨和审计链判断。

Windows 登录界面可能没有可用网络，在线解锁不能作为唯一路径；本地缓存和离线导入必须始终保留。

## 数据模型

服务端使用 SeaORM 实体，初始表如下。所有时间字段使用 UTC `timestamptz`。

| 表 | 关键字段 | 约束和索引 |
| --- | --- | --- |
| `admin_users` | `id`、`username`、`password_hash`、`role`、`created_at`、`updated_at`、`disabled_at` | `username` 唯一；`role` 当前只允许 `admin` |
| `admin_sessions` | `id`、`admin_user_id`、`session_hash`、`csrf_hash`、`created_at`、`expires_at`、`last_seen_at`、`revoked_at` | `session_hash` 唯一；`admin_user_id` 外键；`expires_at` 索引 |
| `server_settings` | `key`、`value_json`、`updated_at` | `key` 主键 |
| `signing_keys` | `key_id`、`public_key_hex`、`status`、`created_by_admin_id`、`created_at`、`activated_at`、`retired_at`、`revoked_at` | `key_id` 和 `public_key_hex` 唯一；状态只允许 `active/retired/revoked`；最多一个 `active` |
| `devices` | `id`、`installation_id`、`hostname`、`status`、`token_hash`、`token_issued_at`、`approved_at`、`approved_by_admin_id`、`last_seen_at`、`client_version`、`created_at`、`updated_at`、`disabled_at` | `installation_id` 唯一；`token_hash` 唯一；`status` 只允许 `pending/active/rejected/disabled`；`status`、`last_seen_at` 建索引 |
| `device_inventory_snapshots` | `id`、`device_id`、`captured_at`、`inventory_json`、`inventory_hash`、`created_at` | `device_id` 外键；`(device_id, created_at desc)` 索引；`captured_at` 是客户端采集时间，最新快照按服务端 `created_at` 选取 |
| `policies` | `id`、`version`、`status`、`policy_json`、`signature_hex`、`server_key_id`、`expires_at`、`created_by_admin_id`、`created_at`、`signed_at`、`updated_at` | `version` 在签名后唯一且为正数，草稿为 `NULL`；`status` 只允许 `draft/signed`；`status`、`expires_at` 建索引；已签名的包不可修改 |
| `policy_assignments` | `id`、`policy_id`、`device_id`、`is_default`、`assigned_by_admin_id`、`created_at` | `device_id` 和 `is_default` 二选一；每台设备最多一条显式分配，默认策略最多一条 |
| `anchor_schema_migrations` | `version`、`applied_at` | `version` 主键；schema 初始化按版本顺序执行 |

策略版本由 PostgreSQL sequence 在签名事务内分配，客户端不能提交版本号。显式设备分配优先于默认策略；删除显式分配后回退默认策略。删除设备时级联删除其硬件快照，策略分配按业务规则先清理。

签名流程在单个数据库事务内完成：先锁定活动签名密钥和策略行，校验策略仍未签名、到期时间晚于当前时间且版本不倒退，再从 `policy_version_seq` 取 `nextval`，用 `anchor-core` 的 `PolicyPackage::sign` 生成签名，最后写入 `version`、`signature_hex`、`server_key_id`、`signed_at` 和 `status = signed`。已签名策略的内容、版本和签名不可修改；重新编辑必须创建新的草稿。签名成功后通过 `/api/admin/policies/{policy_id}/export` 导出的包必须能被当前活动公钥直接验证。

本期不建 `audit_logs`，服务端不接收客户端审计事件。

## API 契约

### 通用约定

- 所有请求和响应使用 `application/json`，协议版本通过 `X-Anchor-Protocol: 1` 传递；缺失或不支持时返回 `400 protocol_version_unsupported`。
- 错误统一为 `{"error":{"code":"...","message":"...","details":{}}}`；错误码使用 snake_case，例如 `invalid_request`、`unauthorized`、`invalid_credentials`、`csrf_invalid`、`setup_unavailable`、`setup_complete`、`setup_token_invalid`、`device_pending`、`device_rejected`、`device_disabled`、`token_invalid`、`policy_not_found`、`policy_not_signed`、`version_conflict`、`rate_limited`。
- 列表统一使用游标分页：请求 `cursor`、`limit`（默认 50，最大 100），响应 `{"items":[],"next_cursor":null}`。
- 硬件快照上限 1 MiB，策略包上限 256 KiB，普通请求上限 2 MiB；超限返回 `413`。
- 请求中的未知字段忽略，协议版本负责处理不兼容变更。

### 设备接口

| 方法 | 路径 | 认证 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/api/device/register` | 无，按 IP 和 `installation_id` 限流 | 提交 `installation_id`、`hostname`、`client_version` 和完整 `inventory`；新设备返回 `pending` 和一次性 `device_token` |
| `GET` | `/api/device/status` | Bearer `device_token` | 返回 `pending/active/rejected/disabled` 和审批时间 |
| `POST` | `/api/device/heartbeat` | Bearer `device_token` | 更新 `last_seen_at`、`client_version` 和 `inventory_hash`；硬件变化时可携带完整 `inventory`，返回 `204` |
| `GET` | `/api/device/policy` | Bearer `device_token` | `active` 返回 `PolicyEnvelope`；无策略返回 `204`；未批准返回 `403 device_pending` |
| `GET` | `/api/device/keyring` | Bearer `device_token` | 返回服务端活动验证公钥和 `server_key_id` |

注册幂等：`installation_id` 唯一。新设备或 `pending` 重试返回新令牌并替换旧哈希；`active` 返回 `409 already_active`；`rejected/disabled` 返回 `403`。设备令牌丢失由管理员重置令牌后重新注册。

注册限流按来源 IP 和 `installation_id` 分别计数：单 IP 每 10 分钟最多 30 次，单 `installation_id` 每 10 分钟最多 5 次；超限返回 `429 rate_limited`。来源 IP 默认取 TCP 对端地址；只有显式设置 `ANCHOR_TRUST_PROXY_HEADERS=true` 且服务端只接受可信反向代理访问时，才读取 `X-Forwarded-For` 的第一个地址。管理员重置令牌后设备回到 `pending`，旧令牌立即失效。

心跳携带的 `inventory_hash` 必须与最新硬件快照的 SHA-256 一致。`inventory` 为空且哈希不一致时返回 `409 inventory_changed`；客户端重新采集清单后，在心跳中同时提交新的 `inventory_hash` 和完整 `inventory`，服务端校验两者一致后保存新快照。

### 管理接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/admin/setup` | 首次初始化管理员和签名密钥，只允许执行一次 |
| `POST` | `/api/admin/login` | 管理员登录，返回 HttpOnly 会话 Cookie |
| `POST` | `/api/admin/logout` | 撤销当前会话 |
| `GET` | `/api/admin/me` | 当前管理员和密钥状态 |
| `POST` | `/api/admin/signing-keys/rotate` | 生成新活动密钥并退休旧密钥 |
| `GET` | `/api/admin/devices` | 按状态分页查看设备 |
| `GET` | `/api/admin/devices/{device_id}` | 查看设备元数据和最新完整硬件清单 |
| `POST` | `/api/admin/devices/{device_id}/approve` | 批准设备 |
| `POST` | `/api/admin/devices/{device_id}/reject` | 拒绝设备 |
| `POST` | `/api/admin/devices/{device_id}/disable` | 禁用设备并使令牌失效 |
| `POST` | `/api/admin/devices/{device_id}/reset-token` | 重置令牌，设备回到 `pending` |
| `GET` | `/api/admin/policies` | 分页查看策略 |
| `POST` | `/api/admin/policies` | 保存草稿 |
| `GET` | `/api/admin/policies/{policy_id}` | 查看策略草稿或已签名版本 |
| `POST` | `/api/admin/policies/{policy_id}/sign` | 校验后签名，版本由服务端分配 |
| `POST` | `/api/admin/policies/{policy_id}/assign` | 分配给设备或设为默认策略 |
| `GET` | `/api/admin/policies/{policy_id}/export` | 导出已签名策略包，供离线导入 |

首次初始化和登录请求体：

```json
{
  "setup_token": "<ANCHOR_SETUP_TOKEN>",
  "username": "admin",
  "password": "<至少 12 字节>",
  "signing_key_hex": null
}
```

```json
{
  "username": "admin",
  "password": "<管理员密码>"
}
```

`signing_key_hex` 为空时生成新的 Ed25519 密钥对，提供时导入 32 字节 hex 私钥并校验推导出的公钥。初始化成功返回 `201`，登录成功返回 `200`，两者都设置会话和 CSRF Cookie；响应只返回管理员信息、公钥和会话到期时间，不返回任何私钥、会话令牌或 CSRF 令牌。

设备列表返回 `{"items": [...], "next_cursor": null}`，列表项包含设备标识、主机名、状态、客户端版本、最后在线时间、批准时间和硬件摘要；设备详情额外返回最新完整硬件清单、客户端采集时间 `inventory_captured_at`、服务端接收时间 `inventory_received_at`、当前生效策略摘要 `effective_policy`、客户端最后拉取版本 `last_policy_version` 和拉取时间 `last_policy_fetched_at`。批准、拒绝、禁用和重置令牌成功时返回 `{"id": "<device_id>", "status": "<new_status>"}`。

`/api/device/keyring` 返回 `{"keys":[...]}`，包含 `active` 和保留用于旧策略验签的 `retired` 公钥，不返回 `revoked` 密钥。`/api/device/policy` 只返回已签名且未过期的显式设备策略或默认策略；没有可用策略时返回 `204`。

创建策略草稿时不提交 `version`，只提交 `expires_at`、`usb`、`network`、`burning` 和 `scan`。分配请求提交 `device_id` 或 `is_default = true` 二者之一；显式设备分配要求设备处于 `active` 状态。

## 管理台

B/S 管理台至少包含：

- 管理员登录、退出和会话管理。
- 待审批设备列表、批准和拒绝。
- 设备列表、设备详情、完整硬件清单、最后在线时间、禁用和重置令牌。
- 策略编辑器、草稿、签名、版本历史和分配。
- 策略下发状态和客户端最后拉取时间。
- 密钥状态、初始化和导入入口。

首次初始化必须使用一次性初始化令牌或仅允许本机回环地址访问，初始化完成后关闭该入口，防止未授权人员抢先设置管理员和密钥。

## 部署

服务端使用 Docker Compose 部署：

```text
anchor-server
postgres
caddy 或现有反向代理
```

- Compose 文件固定为 `server/deploy/docker-compose.yml`，参考 `quizbank`、`provider-relay` 的写法：镜像从 GHCR 拉取，`env_file` 读取 `.env`，PostgreSQL 16，带健康检查，使用外部网络 `anchor`。
- PostgreSQL 数据和密钥文件使用宿主机 bind mount，不使用 Docker named volume。
- 应用启动时通过 SeaORM 执行 schema 初始化；schema 代码放 `server/src/schema/`，不使用独立 SQL 迁移目录。
- TLS 由反向代理或应用终止，管理台和客户端 API 必须使用 HTTPS。
- 服务端镜像按版本构建，不按部署实例构建。
- 备份范围包括 PostgreSQL、密钥目录和 TLS 证书。
- 仓库只保留 `.github/workflows/release.yml` 一个发布工作流；服务端和 web 的校验、镜像构建都并入该工作流，不新增其他 workflow。

## 密钥轮换

- 管理员在服务端生成新密钥对，旧密钥状态转为 `retired`，继续保留用于验证已经签发的旧策略。
- 客户端下次同步密钥环时获取新的 `active` 公钥；已经安装的客户端不需要重新安装。
- 新策略使用新密钥签名；旧策略在旧公钥保留期间仍可验证。
- 旧密钥在迁移窗口结束后可以撤销；撤销后依赖该公钥的旧策略不再被信任。

## 验收

- 通用安装包连接服务端完成安装和注册，不要求输入公钥。
- 管理员批准设备后，客户端获得验证公钥和初始策略。
- 服务端展示完整硬件清单，策略编辑器可以选择硬件对象。
- 策略可视化编辑、签名、分配后，客户端拉取并本地验签。
- 断网重启后客户端继续使用缓存策略，策略过期后锁定。
- 服务端恢复后客户端能拉取新策略并解锁。
- 服务端不可达时可以通过本地文件导入策略。
- 服务端镜像不包含私钥，密钥只存在于宿主机 bind mount 目录或 Docker secret。
- 密钥轮换后客户端同步密钥环并使用新公钥，旧策略在旧密钥退休期间仍可验证。
