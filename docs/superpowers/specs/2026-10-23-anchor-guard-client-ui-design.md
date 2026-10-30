# Anchor Guard 桌面端设计

## 背景

当前终端只有登录页策略导入和无界面的 `anchor-session` 授权轮询。管理员签发策略后，用户无法在已登录状态查看当前策略规则、到期时间，也不能在策略到期前主动导入更新。策略更新只能等到当前策略失效，或由管理员把文件放到本地卷后从登录页导入。

本设计增加一个常驻托盘的桌面端，用于查看当前授权和策略开关、在授权有效期内导入管理员签名的策略，并在同一个窗口内查看在线审计日志。

## 目标

- 每个交互会话有一个托盘桌面端，关闭窗口后继续后台常驻。
- 展示当前授权结论、拒绝原因、策略版本、到期时间、最后导入时间和四个控制域的规则摘要。
- 允许已登录用户选择管理员签名的策略文件，在服务校验通过后提前替换当前策略。
- 导入失败时保持当前策略不变，并保留具体拒绝原因。
- 桌面端结构完全参考 `prelay-client`：`app/` 前端、`src-tauri/` 后端、Nuxt 4、Vue、Bun、`@stellar/ui`、Tauri 2、自绘标题栏、托盘和 Tauri 命令层。
- 继续使用一个 WiX MSI 安装服务、登录组件、会话协作程序和桌面端。

## 非目标

- 不在桌面端编辑或签发策略。策略内容仍由管理电脑上的 `anchor-policy` 生成和签名。
- 本轮只实现在线审计日志查看，不做审计导出、不打开离线复制的审计库，也不保留 `anchor-viewer` 独立工具。
- 不展示设备实际接入状态。本轮展示的是策略预期，不是 USB、网卡、光驱的实时库存。
- 不实现远程策略下发、自动更新、服务端上报或自动升级。
- 不改变登录页导入、Credential Provider、动态 Filter 和会话锁屏流程。
- 不把界面当作安全边界。拥有本机管理员权限的人仍然可以结束进程、修改文件或绕过正常路径；本设计的目标是让正常使用路径可用、可观察、可审计。

## 已确认的约束

- 目标系统为 Windows 10 x64。
- 目标机的普通用户同时具有管理员权限，不设计单独的 UAC 提权导入路径。
- 任意已登录用户都可以发起策略导入；信任来自管理员签名、版本递增和有效期，不来自 Windows 用户身份。
- 目标机预装 WebView2 Runtime，安装包不携带 WebView2 运行时，也不在首次启动时联网下载。
- 前端使用 Bun，禁止使用 `npm`、`npx` 或生成 `package-lock.json`。
- 组件库使用 `@stellar/ui` 0.3.4，参考 `prelay-client` 的 Nuxt 模块、组件和 Tailwind 配置。
- 服务、系统适配和 CLI 继续保持 Rust 实现；桌面端采用 Tauri 2 + Nuxt/Vue，这是对原设计“所有组件使用 Rust 实现”的明确收窄，实施时同步更新 `docs/design.md`。

## 总体架构

### 进程与职责

```text
anchor-service.exe (SYSTEM)
  授权判断、策略验签与替换、审计、设备执行
    |
    | AnchorGuard.SessionStatus（只读）
    | AnchorGuard.Desktop（状态查询、策略导入与审计查询）
    | AnchorGuard.Control（仅 SYSTEM，登录页）
    v
anchor-session.exe (每个交互会话)
  只读授权轮询、拒绝时锁屏，保持现职责

anchor-guard.exe (每个交互会话)
  Tauri 托盘、状态展示、文件选择、导入确认
  不判断授权，不直接读写 SQLite

anchor-credential.dll (LogonUI)
  登录页导入项和动态 Filter，保持现职责
```

`anchor-service` 是策略、授权、审计和设备执行的唯一组织者。`anchor-guard` 只展示服务返回的事实，并把用户选择的策略包交给服务。`anchor-session` 不承载界面，避免桌面端崩溃或消息循环异常影响锁屏协作。

### 目录与依赖

```text
runtime/                          安装到终端的 Anchor Guard 程序
  desktop/                        Tauri 桌面端（package/binary = anchor-guard）
    app/                          Nuxt 4 前端
    src-tauri/                    Tauri Rust 后端（独立 Cargo workspace）
    scripts/
    tests/
    package.json
    bun.lock
    nuxt.config.ts
    tsconfig.json
    eslint.config.mjs
    prettier.config.mjs
    .editorconfig
    .gitattributes
    .gitignore
    .npmrc
    README.md
  service/                        Windows Service（anchor-service）
  session/                        会话协作程序（anchor-session）
  credential/                     COM DLL（anchor-credential）

installer/                        WiX 安装定义和安装期组件
  AnchorGuard.wxs
  setup/                          anchor-setup 库 + CLI
  action/                         anchor-installer-action

admin/                            管理侧工具
  anchor-policy                   策略生成/签名

crates/                           共享库
  anchor-core
  anchor-ipc
  anchor-store
  anchor-scan
  anchor-system
```

- `runtime/desktop` 的前端、Tauri 后端、脚本、测试和配置文件结构完全参考 `prelay-client`：`app/` 放 Nuxt 页面与组件，`src-tauri/` 放 Tauri 后端，`scripts/` 和 `tests/` 保留同名位置。
- `runtime/desktop/app` 使用与 prelay 相同的 `app.vue`、`pages/`、`components/`、`composables/`、`stores/`、`utils/` 和 `assets/css/` 目录；`runtime/desktop/src-tauri/src` 使用 `app/mod.rs`、`app/state.rs`、`commands/` 和 `preferences/tray.rs` 分层，并保留 `capabilities/default.json`、`tauri.conf.json`、`build.rs`、`icons/` 和 `tests/`。
- 页面入口为 `app/pages/index.vue`（策略状态）和 `app/pages/audit.vue`（审计日志）；侧栏对应两个真实入口。
- 根 workspace members 包含 `crates/*`、`runtime/service`、`runtime/session`、`runtime/credential`、`installer/setup`、`installer/action` 和 `admin/*`；`runtime/desktop/src-tauri` 不加入根 workspace，避免 `cargo test --workspace` 被 Tauri 构建和前端产物拖入。
- `runtime/` 是安装到终端的完整程序，`service`、`session`、`desktop`、`credential` 都是它的组件；不再把 service 或 desktop 拆成独立主程序。
- `anchor-session` 不是 Windows Service，但它属于终端运行程序，放 `runtime/session`；`anchor-setup` 和 `anchor-installer-action` 是安装期组件，放 `installer/`。
- `crates/` 只保留共享库；`anchor-policy` 是管理侧工具，放 `admin/`；`anchor-viewer` 删除，审计查看改由桌面端在线完成。
- `policy-example.toml` 随 `anchor-policy` 放在 `admin/anchor-policy/`，发布组装路径同步调整。
- `anchor-ipc` 只依赖 `serde`、`serde_json`、`chrono`、`thiserror` 和 `anchor-core` 的策略类型，不依赖服务、SQLite 或 Windows API。
- `anchor-service`、`anchor-session`、`anchor-credential` 和 `anchor-guard` 共用 `anchor-ipc` 的协议类型。`anchor-session` 和 `anchor-credential` 不再为了协议类型依赖整个 `anchor-service`。
- `runtime/desktop/src-tauri` 通过 `anchor-ipc` 和 `anchor-system::pipe` 与服务通信；不复制策略模型或授权判断。

## 服务端协议

### 共享协议 crate

现有 `anchor-service/src/protocol.rs` 中的 `ServiceRequest`、`ServiceResponse`、`AuthorizationResponse` 和 `ImportResponse` 迁入 `anchor-ipc`。新增：

```text
DesktopRequest
  GetStatus
  InspectPolicy { package_json: String }
  ImportPolicy { package_json: String }
  QueryAudit { filter: AuditFilter, after_sequence: Option<i64>, limit: u32 }

DesktopResponse
  Status(DesktopStatus)
  Inspection(PolicyInspection)
  Import(ImportResponse)
  Audit(AuditPage)
  Error(DesktopProtocolError)

DesktopStatus
  authorization: AuthorizationResponse
  policy: Option<PolicySummary>
  last_trusted_at: Option<DateTime<Utc>>

PolicySummary
  imported_at: Option<DateTime<Utc>>
  payload: PolicyPayload

PolicyInspection
  accepted: bool
  reason: String
  current: Option<PolicySummary>
  candidate: Option<PolicySummary>

DesktopProtocolError
  code: String
  message: String

AuditFilter
  since: Option<DateTime<Utc>>
  until: Option<DateTime<Utc>>
  event_type: Option<String>
  user: Option<String>
  policy_version: Option<u64>
  resource_prefix: Option<String>

AuditPage
  events: Vec<AuditViewEvent>
  next_after_sequence: Option<i64>
  chain_healthy: bool

AuditViewEvent
  sequence: i64
  event: AuditEvent
```

`PolicySummary` 直接复用 `anchor-core::PolicyPayload`，保证桌面端看到的字段与策略模型只有一个事实来源。桌面端只读取摘要和规则，不参与签名验证。

### 管道

- 新管道：`\\.\pipe\AnchorGuard.Desktop`。
- ACL：`D:P(A;;GA;;;SY)(A;;GRGW;;;AU)`，与现有调用方可访问的会话状态管道一致。
- `anchor-system::pipe` 增加 `DESKTOP_PIPE` 常量和 `serve_desktop_once`，沿用现有长度前缀、JSON 和“桌面端验证服务端为 SYSTEM”的传输约束。
- 会话桌面端管道消息上限为 1 MiB，`AnchorGuard.Control` 和 `AnchorGuard.SessionStatus` 保持现有 64 KiB 上限；策略包上限为 256 KiB。超过策略包上限时返回 `policy_too_large`，不截断内容。
- `DesktopRequest` 只接受 JSON 文本形式的策略包，不接受文件路径。桌面端在用户上下文读取文件，服务不在 SYSTEM 权限下按调用方提供的任意路径读盘。

### 服务处理

`anchor-service` 增加以下方法：

- `desktop_status(now)`：调用现有授权判断，读取活动策略和最后可信时间，返回 `DesktopStatus`。授权判断仍是唯一结论来源，桌面端不重新计算。
- `inspect_policy(package_json, now)`：解析、验签、比较版本、检查有效期，返回 `PolicyInspection`。该方法不写策略库、不写审计、不更新最后可信时间。
- `import_policy_json(package_json, user, now)`：复用媒体导入的校验和 `Store::import_policy`，原子替换策略并写审计。解析失败、签名错误、版本回退、已过期、超限都写入 `PolicyImportRejected`，当前策略保持不变。
- `record_desktop_launch_failure(reason, now)`：写入 `desktop_launch_failed` 审计事件，只记录桌面端启动失败，不设置 enforcement failure，不改变授权结论。
- `query_audit(filter, after_sequence, limit, now)`：只读查询审计事件，返回一页事件、下一页游标和整库 hash chain 状态。`limit` 由服务限制在 200 条以内。

`Store` 增加 `active_policy_record()`，一次读取活动策略和 `policies.imported_at`，不改表结构。另增加 `query_audit_page(filter, after_sequence, limit)`，返回带 `sequence` 的事件、下一页游标和整库校验结论；审计页只读，不提供导出或离线库打开。

`anchor-service/src/main.rs` 增加第三个管道监听线程。桌面端导入的操作者由服务按当前活动交互会话读取，不使用调用方自报的用户名；活动会话取不到时记录 `unknown`。

### 审计

- 导入成功：沿用 `PolicyImported`，动作 `import_policy`，结果 `accepted`，带策略版本。
- 导入拒绝：沿用 `PolicyImportRejected`，结果使用 `policy_parse_failed`、`invalid_signature`、`version_not_newer`、`expired`、`policy_too_large` 或 `store_unavailable`。
- 新增 `DesktopLaunchFailed` 事件类型，字符串为 `desktop_launch_failed`，只在连续失败段记录一次；桌面端恢复运行后清除失败状态。
- 桌面端预览不产生审计事件，避免每次选择文件都污染审计链。
- 审计查询只读，不产生审计事件，也不修改审计库。

## 桌面端生命周期

### 服务拉起

- 服务枚举交互会话，按会话检查 `anchor-guard.exe` 是否已在运行；不存在时以该会话用户身份启动，存在时跳过。
- 检查依据是进程名和会话 ID。它只用于避免重复启动，不作为安全判断。
- 桌面端启动失败只写 `DesktopLaunchFailed`，不影响授权、设备执行或 `anchor-session`。
- 服务重启后按进程发现结果跳过仍在运行的桌面端；桌面端被用户结束或崩溃后，下一轮检查重新拉起，不会因为互斥体形成重启循环。

### 桌面端实例

- `anchor-guard` 启动时用当前进程会话 ID 创建 `Local\AnchorGuard.Desktop.<session_id>` 命名互斥体；已存在时退出，防止同一会话出现两个托盘。
- 不同交互会话各自允许一个桌面端，快速用户切换时不会互相阻塞。
- 不使用 `prelay-client` 的全局 `single-instance` 插件；它会让第二个会话的桌面端持续启动失败；桌面端目录、命令层和托盘结构仍按 prelay 组织。

### 窗口与托盘

- 服务启动桌面端时不带参数，窗口保持隐藏，只显示托盘图标。
- 开始菜单快捷方式以 `--show` 启动，用于桌面端崩溃或被结束后手动恢复；程序启动时解析该参数决定是否显示窗口。
- 关闭窗口只隐藏到托盘，不退出进程。
- 托盘菜单：版本项（禁用）、显示窗口、导入策略…、隐藏窗口。不提供退出项。
- 托盘双击显示窗口；“导入策略…”先显示窗口，再通过 Tauri 事件通知前端打开导入弹窗。
- 托盘提示文字随状态更新：正常、剩余天数、需要导入、服务不可用。

## 界面结构

### 外壳

- 无边框窗口，自绘标题栏，沿用 `prelay-client` 的拖拽区和窗口按钮模式。
- 标题栏：Anchor Guard 图标、名称、最小化、最大化、关闭。关闭按钮的提示是“隐藏到托盘”。
- 左侧 `Sidebar` rail 当前有“策略状态”和“审计日志”两个真实入口；设备状态、设置等功能实现后再加入口，不放禁用占位。
- 主内容区独立滚动，顶部操作区固定；窗口最小尺寸下不把导入按钮挤出视口。
- 使用 `@stellar/ui` 的深色/浅色主题令牌，品牌图标沿用现有琥珀色盾牌；业务布局不硬编码状态颜色。

### 策略状态页

页面按“当前结论 → 策略有效期 → 各控制域 → 操作”组织，同一事实只出现一次。

**顶部操作区**

- 标题“策略状态”。
- 手动刷新按钮，刷新时保留旧内容并显示进行中状态。
- 主按钮“导入策略”。

**授权摘要**

- 使用 `Card` 承载，`Badge` 显示“正常”“需要导入”或“服务不可用”。
- 正常时文案为“策略有效，设备正常使用”。
- 拒绝时按原因显示具体事实，例如“策略已到期”“尚未导入策略”“审计链校验失败”“策略执行异常”“检测到系统时间回拨”“运行状态不可用”。
- 摘要内显示策略版本、到期时间、最后导入时间和剩余天数。
- 使用 `ProgressBar` 表示有效期剩余比例；过期或没有策略时不显示虚假进度。

**策略开关**

四个 `Card` 组成自适应网格，宽窗口两列，窄窗口一列：

| 卡片 | 展示内容 | 例外入口 |
| --- | --- | --- |
| USB 存储 | 读取允许/禁止、写入允许/禁止、允许设备数 | 有例外时打开 `Drawer` 列出设备标识 |
| 网络 | 允许/禁止、允许网卡数 | 有例外时列出适配器标识 |
| 刻录 | 允许/禁止、允许光驱数 | 有例外时列出光驱标识 |
| 文件扫描 | 已启用/未配置、受控目录数、文件类型数、规则数 | 列出受控目录和文件类型，不展示敏感词或正则内容 |

允许使用 `Badge` 的 success 语义，禁止使用 neutral 语义，不用 error 表达“策略主动禁止”；error 只用于真正的失败和过期。每张卡的允许/禁止同时有文字和图标，不只靠颜色。

**无策略与异常状态**

- 无活动策略：用 `EmptyState` 说明“尚未导入策略”，解释导入签名策略后才能正常登录，主按钮直接打开导入弹窗。
- 策略过期或授权拒绝：保留已导入策略的只读摘要，但在摘要上方用 `Alert` 说明当前授权已拒绝，规则仅供查看，不能暗示设备仍按该策略执行。
- 服务不可用：有旧数据时保留旧数据并标记“上次更新于 …”，禁止导入；首次加载就不可用时用 `Result` 提供重试。
- 首次加载：用 `Skeleton` 保留摘要和卡片结构，不用整页转圈。

### 导入策略

导入使用一个 `Modal`，内部按三步组织，不嵌套第二个弹窗：

1. **选择文件**：说明策略由管理员签发；按钮打开原生文件选择器，过滤 `.policy` 和 `.json`。
2. **预览**：显示文件名、当前版本和新版本、新策略到期时间、有效期，以及 USB、网络、刻录、扫描四个域的变化和例外数量变化。服务预览返回 `accepted=false` 时，用 `Alert` 显示具体原因并禁用“导入并应用”。
3. **结果**：成功时显示“策略已导入，设备将在下一轮核对后应用”，刷新状态；失败时显示服务返回的原因，保留当前策略。

交互约束：

- 预览期间禁止重复选择或提交；导入期间禁用确认按钮并显示“正在导入…”。
- 关闭弹窗、按 Esc 或取消时丢弃 Rust 侧缓存的候选策略；导入进行中不允许关闭。
- 确认按钮使用“导入并应用”，取消使用“取消”，选择文件使用“选择策略文件”。
- 导入结果只在弹窗内就地展示，不再额外弹全局通知，避免同一结果重复反馈。
- 预览只做服务端校验结果展示，前端不自行判断签名或有效期。

### 审计日志页

审计页只做在线查看，不提供导出、离线库打开、删除或修改。

- 页面顶部显示整库 hash chain 状态：正常、异常或不可用；异常时用 `Alert` 说明影响。
- 筛选区：时间范围、事件类型、用户、策略版本、资源前缀；筛选变化后回到第一页。
- 事件表使用 `Table`，列为时间、事件类型、用户、动作、结果、资源、策略版本和短哈希；长资源允许换行，不截断关键标识。
- 使用服务返回的游标分页，每页最多 100 条；`Pagination` 只负责页间移动，不把整库一次性加载到前端。
- 首次加载用 `Skeleton` 保留表格结构；无匹配事件用 `EmptyState` 说明筛选条件；查询失败保留旧数据和筛选条件，显示可重试的 `Alert`。
- 审计页不显示导出按钮，不打开文件选择器，不直接读写 SQLite。

## Tauri 命令

| 命令 | 行为 |
| --- | --- |
| `get_policy_status` | 调用 `DesktopRequest::GetStatus`，返回授权、策略摘要和最后可信时间；同时更新托盘提示 |
| `inspect_policy_file(path)` | 校验路径、文件大小和 UTF-8，调用 `InspectPolicy`，把候选包和 `pending_id` 存入 Rust 状态，返回预览 |
| `import_pending_policy(pending_id)` | 只导入预览时缓存的包，调用 `ImportPolicy`，返回导入结果 |
| `discard_pending_policy(pending_id)` | 取消时清空缓存 |
| `get_audit_page(query)` | 调用 `DesktopRequest::QueryAudit`，返回一页审计事件、下一页游标和整库校验状态 |

命令返回 `Result<T, DesktopCommandError>`，`DesktopCommandError` 包含稳定的 `code` 和用户可读的 `message`。前端按 `code` 映射中文文案，未知错误保留 `message`。前端不接触策略文件内容，也不直接读写 SQLite。

状态每 10 秒刷新一次，并提供手动刷新和窗口重新获得焦点时的刷新。刷新失败不清空已有内容，标记数据过期。

## 组件使用

- 外壳：`Sidebar`、`SidebarItem`、`Button`、`Tooltip`。
- 摘要与开关：`Card`、`Badge`、`Tag`、`ProgressBar`、`Alert`。
- 例外明细：`Drawer`、`List` 或 `Table`；长设备标识使用等宽字体，允许换行。
- 导入：`Modal`、`Steps`、`Alert`、`Button`、`Skeleton`。
- 审计：`Table`、`Pagination`、`Select`、`Input`、`DatePicker`、`Badge`、`Alert`、`EmptyState`。
- 空态与错误：`EmptyState`、`Result`、`Spinner`。
- 通知只在确有全局结果时使用 `NotificationContainer`；导入结果不重复通知。

业务侧只写布局、品牌图标和标题栏拖拽区域。若 `@stellar/ui` 缺少必要能力，先判断能否通过现有 API 组合；确实需要新变体时先扩展 `@stellar/ui`，不在业务侧复制按钮、标签或弹窗样式。

## 安装与发布

### 安装包

- 继续使用现有 WiX MSI，不新增第二个安装器。
- Tauri 的 `productName` 为 Anchor Guard，crate 和二进制名为 `anchor-guard`；以 `--no-bundle` 构建 `runtime/desktop/src-tauri/target/release/anchor-guard.exe`，WiX 将 `anchor-guard.exe` 加入 `Program Files\Anchor Guard`。
- `ServiceExecutableComponent` 增加 `DesktopExecutable` 文件引用；卸载时随组件移除。
- 增加开始菜单快捷方式，显示名称为 Anchor Guard，目标为 `anchor-guard.exe --show`，用于托盘进程被结束后手动恢复；不创建登录自启动项。
- 目标机预装 WebView2。安装包不携带 Evergreen 安装器，不在首次启动联网下载；安装文档明确这一前置条件。

### 版本

- 根 `Cargo.toml` 的 `workspace.package.version` 仍是唯一版本事实。
- `runtime/desktop/package.json`、`runtime/desktop/src-tauri/tauri.conf.json` 和 `runtime/desktop/src-tauri/Cargo.toml` 的版本必须与 workspace 版本一致。
- 发布工作流的 prepare 阶段同时校验四处版本；不一致时不构建、不发布。

### 发布工作流

- 新增 `verify-desktop` job：Ubuntu + Bun，执行 `bun install --frozen-lockfile`、`bun run typecheck`、`bun run lint`、`bun run format:check`、`bun test`。
- 服务侧 `verify` job 保持 Rust 的格式、Clippy、测试。
- `prepare` 依赖两个 verify job，校验标签和四处版本。
- `build` 在 Windows runner 上执行服务 release 构建、Bun 安装、`bun run tauri build --no-bundle`、WiX 组装和产物上传。
- WiX 组装步骤增加 `DesktopBinary`，指向 `runtime/desktop/src-tauri/target/release/anchor-guard.exe`。
- `publish` 继续用 `softprops/action-gh-release@v3` 上传 MSI、策略工具 ZIP、清单和校验和。

## 安全与信任边界

- 策略签名是唯一信任根。桌面端只负责选择文件，服务负责验签、版本递增、有效期和原子替换。
- 导入开关不依赖 Windows 用户身份；目标环境的所有用户都是管理员，不增加虚假的提权门槛。
- 桌面端不接收任意文件路径作为服务端读取指令；策略内容由用户进程读取后通过管道提交，服务只解析和校验内容。
- 桌面端不直接访问 `audit.db`；审计查询通过服务只读完成，桌面端不提供删除、修改或重建审计记录的入口。
- `anchor-session` 的只读状态管道保持只读；桌面端的导入和审计查询能力放在独立管道，不扩大会话协作程序的权限。
- 桌面端进程被结束或被替换不会改变授权判断；服务继续按自己的策略和审计状态运行。
- 本设计不防御拥有本机管理员权限的人篡改策略库、审计库或二进制文件；这类行为仍属于设计边界外。

## 验证

### 自动化

- `anchor-ipc`：请求/响应 JSON 往返、帧长度、消息上限、策略包上限。
- `anchor-service`：预览不写策略和审计；导入成功替换策略并写审计；签名错误、版本回退、过期、解析失败、超限均保持当前策略；状态摘要字段正确；审计查询只读且能正确分页；桌面端操作者不由请求自报。
- `anchor-system`：`DESKTOP_PIPE` ACL、消息上限、`desktop_running` 的进程名和会话匹配。
- `anchor-core`：`DesktopLaunchFailed` 的 serde 和 `FromStr` 往返。
- `anchor-guard` Rust 后端：候选策略缓存、重复导入、过期 `pending_id`、文件大小和 UTF-8 错误映射；审计分页参数校验。
- 前端：状态文案映射、有效期格式、策略差异计算、拒绝原因映射；`bun run typecheck`、`lint`、`format:check`、`bun test`。
- 根 workspace：`cargo fmt --all`、严格 Clippy、`cargo test --all-targets --all-features`。
- 桌面端 Rust：`cargo fmt`、严格 Clippy、`cargo test`（`runtime/desktop/src-tauri` 独立 workspace）。
- 构建：Windows 上执行 `bun run tauri build --no-bundle`，再执行 WiX 组装；确认 MSI 包含 `anchor-guard.exe`。

### Windows 10 真机

加入 `docs/windows-test-matrix.md` 的场景：

- 登录后托盘出现、窗口默认隐藏、双击和菜单能显示、关闭后只隐藏。
- 结束 `anchor-guard.exe` 后服务重新拉起；服务重启后只保留一个桌面端，不出现重复托盘或重启循环。
- 快速用户切换时每个会话各有一个桌面端，互斥体不会阻塞另一个会话。
- 有效期内导入 v4，界面显示新版本，设备在下一轮核对后按新策略执行，审计记录成功。
- 导入错误签名、过期包、版本回退包和超限包，界面显示具体原因，当前策略不变，审计记录拒绝。
- 无策略、已过期、服务不可用、审计链异常时界面文案和可操作项正确。
- 审计页能按时间、事件类型、用户、策略版本和资源前缀筛选；分页能继续加载；审计链异常时顶部状态正确；页面没有导出或删除入口。
- 开始菜单快捷方式在桌面端未运行时显示窗口；桌面端已运行时不会产生第二个托盘。
- MSI 安装后包含 `anchor-guard.exe` 和快捷方式，卸载后不残留界面文件；WebView2 预装条件下界面可启动。

自动化构建、类型检查和静态测试不能替代真实托盘、文件选择器、窗口隐藏和多会话验收。

## 风险与边界

- WebView2 缺失时界面无法启动。本期依赖预装，安装文档明确要求；不在 MSI 中携带运行时。
- 进程发现按 `anchor-guard.exe` 名称和会话 ID 判断，本机管理员可以伪造同名进程阻止自动拉起；界面不是安全边界。
- 桌面端每 10 秒查询一次状态会触发服务记录可信时间；现有 `anchor-session` 已经每 5 秒轮询，新增查询只增加本地 SQLite 写入频率，不改变授权语义。
- 策略包上限 256 KiB 足以覆盖当前配置规模；超过上限时明确拒绝，不截断策略。
- 审计只做在线查看，不实现导出和离线库打开；设备实际状态和策略编辑不在本轮范围内，界面不展示未实现的入口。

## 实施时同步更新

- `docs/design.md`：补充桌面端、`anchor-ipc`、`Desktop` 管道、在线审计和提前导入边界；把“所有组件使用 Rust 实现”收窄为服务、系统组件和 CLI。
- `docs/windows-test-matrix.md`：加入上述桌面端、托盘和在线审计验收场景。
- `docs/release.md`：说明 MSI 包含桌面端、WebView2 前置条件、在线审计和版本同步要求。
- 安装器、发布工作流和根 workspace 的构建入口按本设计调整。
