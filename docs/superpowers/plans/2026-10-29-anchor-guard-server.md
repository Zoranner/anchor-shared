# Anchor Guard 服务端管理模式实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 增加 Docker 化 B/S 管理服务、通用客户端注册同步和可视化策略管理，使客户端可以通过服务端地址完成安装、审批、硬件上报和策略获取。

**Architecture:** 服务端使用 Rust/Axum 提供管理 API 和设备 API，SeaORM 访问 PostgreSQL，Nuxt 管理台作为同一镜像内的静态 SPA，PostgreSQL 保存设备、硬件和策略数据。客户端是独立 workspace，继续使用本地 Windows 服务做授权判断，在 `client/service` 内新增服务端同步模块，共享 DTO 放入 `anchor-protocol`；通用 Windows 安装器只采集服务端地址和端口。

**Tech Stack:** Rust 2021、Axum、SeaORM 2.0.2（sqlx-postgres）、PostgreSQL、Nuxt 4、Vue、Bun、Docker Compose、WiX 5、Tauri 2、Windows API。

**Spec:** `docs/superpowers/specs/2026-10-29-anchor-guard-server-design.md`

## Global Constraints

- 服务端是单租户自建 B/S 服务，只通过 Docker 镜像和 Docker Compose 部署。
- 管理台只允许管理员登录。
- 客户端安装包是通用 Windows 安装包，安装时填写服务端地址和端口。
- 服务端不按部署实例重新构建镜像或客户端安装包。
- 服务端持有策略签名私钥；私钥不能进入镜像层、数据库明文、日志和客户端安装包。
- 服务端数据库访问统一使用 SeaORM 2.0.2；schema 初始化写在 `server/src/schema/`，不建 `server/migrations/`。
- 本期服务端不保存审计数据，也不提供审计页；审计日志继续由客户端本地查看。
- 设备认证使用服务端生成的 256 位随机令牌；不引入设备密钥对，令牌只经 HTTPS 传输，服务端只保存哈希。
- 设备准入只依赖管理员审批；本期不做机器指纹硬绑定，硬件清单只用于展示和策略配置。
- 仓库只保留 `.github/workflows/release.yml` 一个发布工作流；服务端、web 和客户端校验都并入该工作流，不新增其他 workflow。
- 客户端继续在本地完成策略验签、版本、有效期和审计链判断；服务端只分发签名策略。
- 硬件清单按全量清单设计，不能缩成少量摘要字段。
- 策略编辑必须提供可视化编辑器，不能只提供 TOML/JSON 文本框。
- 设备注册后进入待审批状态，管理员批准后才开始同步策略。
- 服务端不可用时，客户端使用最后可用策略；策略过期时保留在线获取和离线导入两条路径。
- 密钥轮换通过新服务端密钥和密钥环同步完成，旧密钥在迁移窗口内保留用于旧策略验签。

## 目录与命名约束

- 根 `crates/` 只放服务端和客户端共享的 crate：`anchor-core`、`anchor-protocol`。
- `client/` 放所有客户端代码：`client/crates/`、`client/service/`、`client/desktop/`、`client/credential/`、`client/session/`、`client/installer/`。
- 仓库根不定义 Cargo workspace；`client/`、`server/`、`crates/` 各自使用独立 workspace。
- `client/Cargo.toml` 和 `client/src/` 是 `anchor-build` 构建入口，统一负责客户端 Rust、桌面端和 MSI 打包；`client/service/` 仍是独立的 Windows 服务程序。
- `client/crates/` 只放客户端专用 crate：`anchor-ipc`、`anchor-scan`、`anchor-store`、`anchor-system`。
- 客户端访问服务端的 HTTP 代码直接放 `client/service/src/server_sync.rs`，不单独建 crate。只有出现第二个直接调用服务端的消费者时，才重新评估是否抽 crate。
- `server/` 是 `anchor-server` crate 根目录；B/S 管理台放 `server/web/`，不再使用 `server/admin/`。
- 管理员签发由 `server` 负责：`server/src/keys.rs` 和 `/api/admin/policies/sign`；不新建 `tools/` 目录。
- 旧 `admin/anchor-policy` 离线签发 CLI 已删除；服务端签名接口和管理台导出是唯一签发路径。
- 服务端专用 crate 如需拆分，放 `server/crates/`；当前不创建。
- crate 名固定为两个单词：使用 `anchor-protocol`，不使用 `anchor-server-protocol`；也不再有 `anchor-server-client`。

## 数据模型与接口约定

表名、字段名、状态枚举、API 路径、错误码和分页规则以设计文档的“命名与术语”“数据模型”“API 契约”三节为准。实现时不得另起一套命名；新增字段或接口先改设计文档和 `anchor-protocol`，再改服务端和客户端。

## 文件结构

```text
crates/
  Cargo.toml                 共享 crate workspace
  anchor-core/              现有，服务端和客户端共享
  anchor-protocol/          新增，服务端和客户端共享

client/
  Cargo.toml                 客户端 workspace 和 anchor-build 入口
  src/                       anchor-build 构建与打包程序
  crates/
    anchor-ipc/             现有，迁入
    anchor-scan/            现有，迁入
    anchor-store/           现有，迁入
    anchor-system/          现有，迁入
  service/
    src/
      main.rs
      lib.rs
      config.rs
      device_identity.rs
      inventory_report.rs
      server_sync.rs
  desktop/
  credential/
  session/
  installer/
    AnchorGuard.wxs
    AnchorServerDlg.wxs
    action/
    setup/

server/                     anchor-server crate 根目录
  Cargo.toml
  src/
    main.rs
    config.rs
    database.rs
    auth.rs
    keys.rs
    api/
      mod.rs
      admin.rs
      device.rs
    domain/
      device.rs
      inventory.rs
      policy.rs
    entity/
      mod.rs
    schema/
      mod.rs
  web/                      B/S 管理台
    package.json
    bun.lock
    nuxt.config.ts
    app/
      pages/
      components/
      composables/
  Dockerfile
  deploy/
    docker-compose.yml
    .env.example
    .gitignore

docs/
  release.md
  windows-test-matrix.md
```

## 实施任务

### 目录调整与共享协议

**Files:**
- Move: `crates/anchor-ipc` -> `client/crates/anchor-ipc`
- Move: `crates/anchor-scan` -> `client/crates/anchor-scan`
- Move: `crates/anchor-store` -> `client/crates/anchor-store`
- Move: `crates/anchor-system` -> `client/crates/anchor-system`
- Move: `runtime/service` -> `client/service`
- Move: `runtime/desktop` -> `client/desktop`
- Move: `runtime/credential` -> `client/credential`
- Move: `runtime/session` -> `client/session`
- Move: `installer` -> `client/installer`
- Create: `crates/anchor-protocol/Cargo.toml`
- Create: `crates/anchor-protocol/src/lib.rs`
- Modify: `Cargo.toml`
- Modify: `client/desktop/src-tauri/Cargo.toml`
- Modify: `.github/workflows/release.yml`
- Modify: `docs/design.md`
- Modify: `docs/release.md`

**Interfaces:**
- 服务端和客户端共享 `RegisterDeviceRequest`、`RegisterDeviceResponse`、`DeviceStatusResponse`、`HeartbeatRequest`、`HardwareInventory`、`PolicyEnvelope`、`ApiError`。
- `PolicyEnvelope` 包含 `version`、`expires_at`、`policy_json`、`signature_hex`、`server_key_id`。
- 协议版本常量 `PROTOCOL_VERSION = 1`。
- 客户端 HTTP 调用不放进共享 crate；由 `client/service/src/server_sync.rs` 使用 `anchor-protocol` 和 HTTP 客户端实现。

- [ ] **Step 1: 重排 client 目录**

```powershell
New-Item -ItemType Directory -Force client/crates | Out-Null
git mv crates/anchor-ipc client/crates/anchor-ipc
git mv crates/anchor-scan client/crates/anchor-scan
git mv crates/anchor-store client/crates/anchor-store
git mv crates/anchor-system client/crates/anchor-system
git mv runtime/service client/service
git mv runtime/desktop client/desktop
git mv runtime/credential client/credential
git mv runtime/session client/session
git mv installer client/installer
```

`anchor-core` 不移动；服务端会直接复用它。

- [ ] **Step 2: 更新 workspace 和相对路径**

仓库根不保存 `Cargo.toml`；客户端、服务端和共享 crate 分别建立独立 workspace。`client/Cargo.toml` 既是客户端 workspace 根，也是 `anchor-build` 构建入口：

```toml
[workspace]
members = [
    "crates/anchor-ipc",
    "crates/anchor-scan",
    "crates/anchor-store",
    "crates/anchor-system",
    "service",
    "session",
    "credential",
    "installer/action",
    "installer/setup",
]

[workspace.dependencies]
anchor-core = { path = "../crates/anchor-core" }
anchor-protocol = { path = "../crates/anchor-protocol" }
```

`client/desktop/src-tauri/Cargo.toml` 的相对路径改为：

```toml
anchor-ipc = { path = "../../crates/anchor-ipc" }
anchor-system = { path = "../../crates/anchor-system" }
```

`server/Cargo.toml` 和 `crates/Cargo.toml` 各自建立 workspace，分别管理服务端依赖和共享 crate 依赖。同时把 `.github/workflows/release.yml` 里的 `runtime/desktop`、`installer/` 引用改为 `client/desktop`、`client/installer`；`docs/design.md` 的桌面端路径同步为 `client/desktop`。

- [ ] **Step 3: 定义共享 DTO**

在 `anchor-protocol` 中定义设备、硬件清单、策略包、错误码和协议版本；所有 DTO 使用 `serde` 序列化，字段使用 snake_case。只放结构、常量和序列化逻辑，不放 HTTP 请求、注册流程或设备身份存储。

- [ ] **Step 4: 写协议往返测试**

覆盖设备注册、完整硬件清单、策略包和错误响应的 JSON 往返；确认协议版本和未知字段的行为。

- [ ] **Step 5: 验证目录和协议**

Run:

```text
cargo check --workspace
cargo test -p anchor-protocol
```

Expected: PASS。

- [ ] **Step 6: 提交**

在提交授权成立后执行：

```powershell
git add Cargo.toml Cargo.lock crates/anchor-protocol client docs .github/workflows/release.yml
git commit -m "重排客户端和服务端目录并定义共享协议"
```

### 服务端工程和 Docker 地基

**Files:**
- Create: `server/Cargo.toml`
- Create: `server/src/main.rs`
- Create: `server/src/config.rs`
- Create: `server/src/database.rs`
- Create: `server/src/entity/mod.rs`
- Create: `server/src/schema/mod.rs`
- Create: `server/Dockerfile`
- Create: `server/deploy/docker-compose.yml`
- Create: `server/deploy/.env.example`
- Create: `server/deploy/.gitignore`
- Create: `server/.dockerignore`
- Modify: `server/Cargo.toml`

**Interfaces:**
- 服务端读取 `DATABASE_URL`、`DATABASE_MAX_CONNECTIONS`、`ANCHOR_MASTER_KEY_FILE`、`ANCHOR_LISTEN_ADDR`、`ANCHOR_PUBLIC_URL`。
- `anchor-server` 启动时通过 SeaORM 检查数据库连接并执行 schema 初始化。
- `/healthz` 返回服务和数据库状态。

- [ ] **Step 1: 建立服务端 crate、SeaORM 连接和配置**

增加 `anchor-server` 包，实现配置读取、日志、优雅退出和启动时 schema 初始化。`server/Cargo.toml` 作为独立 workspace 根，通过 workspace 依赖引入 `anchor-core` 和 `anchor-protocol`，不复制策略字段或协议 DTO。

`server/Cargo.toml` 增加 SeaORM 依赖：

```toml
sea-orm = { version = "2.0.2", features = ["macros", "runtime-tokio-rustls", "sqlx-postgres"] }
sea-query = "1.0.2"
```

`server/src/database.rs` 使用 `sea_orm::Database::connect`，默认连接池 10，`DATABASE_MAX_CONNECTIONS` 可覆盖；与 `provider-relay` 一致，关闭 SQLx 日志。

- [ ] **Step 2: 建立 SeaORM 实体和初始 schema**

`server/src/entity/` 放 SeaORM 实体；`server/src/schema/mod.rs` 用代码建表，并维护 `anchor_schema_migrations` 版本表。启动时调用 schema 初始化，不读取独立 SQL 迁移文件。

至少建立：

```text
admin_users
admin_sessions
server_settings
devices
device_inventory_snapshots
policies
policy_assignments
```

设备状态使用 `pending`、`active`、`rejected`、`disabled`；策略版本在部署实例内单调递增。

- [ ] **Step 3: 建 Docker 部署**

`server/Dockerfile` 使用多阶段构建：先构建管理台静态资源，再构建 `anchor-server`；运行镜像只包含服务端二进制和静态管理台。

`server/deploy/docker-compose.yml` 参考 `quizbank` 和 `provider-relay` 的部署方式：镜像从 GHCR 拉取，`env_file` 读取 `.env`，PostgreSQL 16，健康检查，外部网络 `anchor`，所有持久化目录使用宿主机 bind mount，不使用 named volume。

```yaml
services:
  anchor-server:
    image: ghcr.io/zoranner/anchor-server:0.1.2
    container_name: anchor-server
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    env_file:
      - .env
    ports:
      - "8080:8080"
    volumes:
      - ./app/config:/app/config:ro
      - ./app/data:/app/data
      - ./app/secrets/anchor_master_key:/run/secrets/anchor_master_key:ro

  postgres:
    image: postgres:16
    container_name: anchor-postgres
    restart: always
    stop_signal: SIGINT
    environment:
      - POSTGRES_DB=anchor
      - POSTGRES_USER=anchor
      - POSTGRES_PASSWORD=anchor
    healthcheck:
      test: ["CMD-SHELL", "sh -c 'pg_isready -U anchor -d anchor'"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 3s
    volumes:
      - ./data/postgres:/var/lib/postgresql/data

networks:
  default:
    external: true
    name: anchor
```

`.env.example` 至少列出 `DATABASE_URL`、`ANCHOR_MASTER_KEY_FILE=/run/secrets/anchor_master_key`、`ANCHOR_LISTEN_ADDR` 和 `ANCHOR_PUBLIC_URL`。主密钥通过 bind mount 的只读文件注入，不写入 Compose 明文。

`server/deploy/.gitignore` 忽略 `.env`、`data/` 和 `app/`，避免数据库、密钥和运行配置进入仓库；`.env.example` 保留为模板。

- [ ] **Step 4: 验证地基**

Run:

```text
docker network create anchor
docker compose -f server/deploy/docker-compose.yml up -d
curl http://127.0.0.1:8080/healthz
docker compose -f server/deploy/docker-compose.yml down
```

Expected: 健康检查返回成功，重启后 `server/deploy/data/postgres` 和 `server/deploy/app/data` 仍存在。

- [ ] **Step 5: 提交**

在提交授权成立后执行：

```powershell
git add Cargo.toml server
git commit -m "搭建服务端 Docker 和数据库地基"
```

### 管理员登录、首次初始化和密钥

**Files:**
- Create: `server/src/auth.rs`
- Create: `server/src/keys.rs`
- Create: `server/src/api/admin.rs`
- Create: `server/src/entity/admin_user.rs`
- Create: `server/src/entity/admin_session.rs`
- Create: `server/src/entity/server_setting.rs`
- Modify: `server/src/main.rs`
- Modify: `server/src/entity/mod.rs`
- Modify: `server/src/schema/mod.rs`

**Interfaces:**
- `POST /api/admin/setup`：首次设置管理员密码、生成或导入密钥对。
- `POST /api/admin/login`：管理员登录，返回 HttpOnly 会话 Cookie。
- `POST /api/admin/logout`：退出。
- `GET /api/admin/me`：返回当前管理员和密钥状态。
- `POST /api/admin/policies/sign`：管理员会话校验后触发签名。

- [ ] **Step 1: 实现管理员密码存储**

密码使用 Argon2id 哈希；管理员会话使用 HttpOnly、Secure、SameSite 会话 Cookie；签名接口必须校验管理员会话和 CSRF。

- [ ] **Step 2: 实现首次初始化**

首次初始化只允许执行一次，必须提供一次性初始化令牌或仅允许本机回环访问；支持生成 Ed25519 密钥对或导入已有私钥；导入时验证私钥能推导出对应公钥。初始化完成后关闭该入口。

- [ ] **Step 3: 保护服务端私钥**

私钥只写入 `server/deploy/app/data` 的 bind mount 目录；服务从 `ANCHOR_MASTER_KEY_FILE` 指向的只读文件读取主密钥，用它派生加密密钥。镜像、数据库和日志不得包含私钥明文。

- [ ] **Step 4: 写认证测试**

覆盖错误密码、未登录访问、重复初始化、错误私钥导入、管理员退出和会话失效。

- [ ] **Step 5: 跑服务端测试**

Run: `cargo test -p anchor-server`

Expected: PASS。

- [ ] **Step 6: 提交**

在提交授权成立后执行：

```powershell
git add server/src/auth.rs server/src/keys.rs server/src/api/admin.rs server/src/entity server/src/schema server/src/main.rs
git commit -m "增加管理员认证和签名密钥管理"
```

### 设备注册、审批和全量硬件清单

**Files:**
- Create: `server/src/domain/device.rs`
- Create: `server/src/domain/inventory.rs`
- Create: `server/src/api/device.rs`
- Create: `server/src/entity/device.rs`
- Create: `server/src/entity/device_inventory_snapshot.rs`
- Modify: `server/src/api/admin.rs`
- Modify: `server/src/main.rs`
- Modify: `server/src/entity/mod.rs`
- Modify: `server/src/schema/mod.rs`
- Modify: `client/crates/anchor-system/src/inventory.rs`
- Create: `client/service/src/inventory_report.rs`

**Interfaces:**
- `POST /api/device/register`：客户端提交设备信息和完整硬件快照；服务端生成一次性设备令牌并返回，设备状态为 `pending`。
- `GET /api/device/status`：客户端携带 Bearer 设备令牌查询审批状态。
- `POST /api/device/heartbeat`：更新最后在线时间、客户端版本和硬件摘要。
- `GET /api/admin/devices`：管理员查看待审批和已批准设备。
- `POST /api/admin/devices/{id}/approve`、`POST /api/admin/devices/{id}/reject`。

- [ ] **Step 1: 定义完整硬件快照**

客户端采集计算机、BIOS、CPU、内存、磁盘、卷、网卡、USB、光驱和 GPU 信息；服务端保存原始快照和结构化摘要。

- [ ] **Step 2: 实现注册和审批**

服务端在注册成功时生成 256 位随机设备令牌，只返回一次；服务端保存令牌哈希，客户端保存到 ACL 保护文件。注册状态为 `pending`，管理员批准后变为 `active`，拒绝后变为 `rejected`。

- [ ] **Step 3: 实现心跳**

心跳更新最后在线时间、客户端版本和硬件变化摘要；断线不删除设备记录。

- [ ] **Step 4: 写集成测试**

覆盖注册、重复注册、审批、拒绝、设备令牌错误、硬件快照保存和心跳更新。

- [ ] **Step 5: 验证**

Run:

```text
Set-Location server
cargo test -p anchor-server
Set-Location ..\client
cargo test -p anchor-system -p anchor-service
```

Expected: PASS；测试服务端中能看到待审批设备和完整硬件分组。

- [ ] **Step 6: 提交**

在提交授权成立后执行：

```powershell
git add server/src/domain server/src/api/device.rs server/src/api/admin.rs server/src/entity server/src/schema server/src/main.rs client/crates/anchor-system/src/inventory.rs client/service/src/inventory_report.rs
git commit -m "增加设备注册审批和全量硬件清单"
```

### 策略模型、签名和分发

**Files:**
- Create: `server/src/domain/policy.rs`
- Create: `server/src/entity/policy.rs`
- Create: `server/src/entity/policy_assignment.rs`
- Modify: `server/src/api/admin.rs`
- Modify: `server/src/api/device.rs`
- Modify: `server/src/keys.rs`
- Modify: `server/src/entity/mod.rs`
- Modify: `server/src/schema/mod.rs`

**Interfaces:**
- `POST /api/admin/policies`：保存策略草稿。
- `POST /api/admin/policies/{id}/sign`：管理员会话校验后签名。
- `POST /api/admin/policies/{id}/assign`：分配给设备或作为默认策略。
- `GET /api/device/policy`：返回当前设备的 `PolicyEnvelope` 或 204。

- [ ] **Step 1: 复用策略模型**

服务端直接使用 `anchor-core` 的 `PolicyPayload`、`PolicyPackage` 和签名逻辑，不复制策略字段。

- [ ] **Step 2: 实现策略版本**

同一部署实例内版本严格递增；签名失败、版本回退、过期策略不能分配；保存签名后的不可变策略包。

- [ ] **Step 3: 实现设备策略选择**

设备优先使用单设备分配，否则使用默认策略；客户端拉取时返回当前签名策略和版本。

- [ ] **Step 4: 写策略测试**

覆盖草稿、签名、版本递增、回退拒绝、分配、无策略返回 204 和客户端验签。

- [ ] **Step 5: 验证**

Run:

```text
Set-Location server
cargo test -p anchor-server
Set-Location ..\crates
cargo test -p anchor-core
```

Expected: PASS。

- [ ] **Step 6: 提交**

在提交授权成立后执行：

```powershell
git add server/src/domain/policy.rs server/src/api/admin.rs server/src/api/device.rs server/src/keys.rs server/src/entity server/src/schema
git commit -m "增加服务端策略签名和分发"
```

### 可视化策略编辑器和管理台

**Files:**
- Create: `server/web/package.json`
- Create: `server/web/bun.lock`
- Create: `server/web/nuxt.config.ts`
- Create: `server/web/app/pages/login.vue`
- Create: `server/web/app/pages/devices.vue`
- Create: `server/web/app/pages/policies.vue`
- Create: `server/web/app/components/policy/UsbRules.vue`
- Create: `server/web/app/components/policy/NetworkRules.vue`
- Create: `server/web/app/components/policy/BurningRules.vue`
- Create: `server/web/app/components/policy/ScanRules.vue`
- Create: `server/web/app/composables/useAdminApi.ts`
- Modify: `server/Dockerfile`

**Interfaces:**
- 管理台通过管理员会话 Cookie 调用 `/api/admin/*`。
- 策略编辑器覆盖 USB、网络、刻录、扫描、例外设备和有效期。
- 设备详情展示完整硬件清单、最后在线时间、策略版本和审批状态。

- [ ] **Step 1: 建立管理台页面**

实现登录、待审批设备、设备详情和策略列表页面；设备详情支持批准、拒绝、禁用和重置令牌；未登录不能访问管理数据。

- [ ] **Step 2: 实现可视化策略编辑**

USB、网络、刻录和扫描分别使用结构化表单；例外设备从设备硬件清单选择，不能只提供 JSON 文本框。

- [ ] **Step 3: 实现草稿、预览、签名和分配**

保存草稿不签名；预览展示当前策略和目标设备差异；签名后版本不可修改；分配后显示客户端最后拉取状态。

- [ ] **Step 4: 接入 Docker 静态资源**

管理台构建为静态 SPA，由 `anchor-server` 提供静态资源；刷新页面不能返回 404。

- [ ] **Step 5: 验证**

Run:

```text
bun install --frozen-lockfile
bun run typecheck
bun run lint
bun run format:check
bun test
```

Expected: PASS。

- [ ] **Step 6: 提交**

在提交授权成立后执行：

```powershell
git add server/web server/Dockerfile
git commit -m "增加服务端管理台和可视化策略编辑器"
```

### 客户端注册、硬件上报和策略同步

**Files:**
- Create: `client/service/src/config.rs`
- Create: `client/service/src/device_identity.rs`
- Create: `client/service/src/server_sync.rs`
- Modify: `client/service/src/main.rs`
- Modify: `client/service/src/lib.rs`
- Modify: `client/service/Cargo.toml`
- Modify: `client/crates/anchor-ipc/src/protocol.rs`
- Modify: `client/desktop/app/pages/index.vue`

**Interfaces:**
- `ServerSyncConfig { base_url, device_token, server_public_key }`。
- `ServerSync::register()`、`status()`、`heartbeat()`、`fetch_policy()`。
- 本地策略写入复用现有 `Store` 和 `anchor-core` 验签逻辑。
- `ServerSync` 直接定义在 `client/service/src/server_sync.rs`，不新增客户端 HTTP crate；请求和响应类型使用 `anchor-protocol`。
- `client/service/Cargo.toml` 增加 `anchor-protocol.workspace = true`。

- [ ] **Step 1: 抽离服务配置**

把 `service.toml` 的读写从 `main.rs` 抽到 `config.rs`，加入服务端地址、端口、设备令牌和验证公钥字段。

- [ ] **Step 2: 实现设备身份和设备令牌**

首次启动生成设备 ID；注册成功后保存服务端下发的 32 字节设备令牌。令牌保存在 ACL 保护的本地文件，DPAPI 作为可选离线保护，服务端只保存哈希。

- [ ] **Step 3: 实现注册和待审批状态**

服务和桌面端显示 `待审批`、`已批准`、`被拒绝`、`服务端不可达`；待审批时不能导入未签名策略。

- [ ] **Step 4: 实现心跳和策略拉取**

按固定周期和网络变化触发心跳和策略拉取；收到策略包后本地验签，成功才原子替换，失败保留旧策略并写审计。

- [ ] **Step 5: 实现缓存和离线行为**

服务端不可用时保留最后策略；策略过期时请求新策略；本地文件导入仍作为兜底。

- [ ] **Step 6: 写客户端集成测试**

使用 mock HTTP 服务覆盖注册、待审批、批准、心跳、策略成功、签名失败、版本回退、服务端不可达和过期。

- [ ] **Step 7: 验证**

Run:

```text
Set-Location client
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Expected: PASS。

- [ ] **Step 8: 提交**

在提交授权成立后执行：

```powershell
git add client/service/src client/desktop/app/pages client/crates/anchor-ipc
git commit -m "增加客户端注册和策略同步"
```

### 通用 Windows 安装器

**Files:**
- Modify: `client/installer/AnchorGuard.wxs`
- Create: `client/installer/AnchorServerDlg.wxs`
- Modify: `.github/workflows/release.yml`
- Modify: `docs/release.md`

**Interfaces:**
- MSI 属性 `ANCHOR_SERVER_ADDRESS`、`ANCHOR_SERVER_PORT`。
- 安装界面校验地址非空、端口为 1-65535。
- 安装完成后把地址和端口写入 `service.toml`。

- [ ] **Step 1: 增加服务器配置对话框**

使用 WiX UI 扩展增加服务端地址和端口输入页；在 `AnchorGuard.wxs` 中 include `AnchorServerDlg.wxs`。不要求验证公钥，不包含任何部署实例公钥。

- [ ] **Step 2: 写安装配置**

安装动作读取 `ANCHOR_SERVER_ADDRESS` 和 `ANCHOR_SERVER_PORT`，生成 `server_url` 写入服务配置；缺失或非法值阻止继续安装。

- [ ] **Step 3: 更新发布工作流**

只修改现有 `.github/workflows/release.yml`，不新增工作流。在现有 verify 流程中加入 `server`、`server/web` 和服务端 schema 测试；在 workflow 顶层增加 `packages: write`，使用 GHCR 登录后构建并推送 `ghcr.io/zoranner/anchor-server:<version>`；继续构建通用 MSI，校验 WiX UI 扩展和服务器输入属性，不生成部署实例专用安装包。

- [ ] **Step 4: 验证 MSI**

Run:

```powershell
wix build client\installer\AnchorGuard.wxs -arch x64 -ext WixToolset.UI.wixext `
  -d "ProductVersion=0.1.2" `
  -d "AnchorServiceBinary=target\release\anchor-service.exe" `
  -d "AnchorSessionBinary=target\release\anchor-session.exe" `
  -d "AnchorSetupBinary=target\release\anchor-setup.exe" `
  -d "AnchorInstallerActionDll=target\release\anchor_installer_action.dll" `
  -d "AnchorCredentialDll=target\release\anchor_credential.dll" `
  -d "DesktopBinary=client\desktop\src-tauri\target\release\anchor-guard.exe" `
  -o target\anchor-guard-msi-check.msi
wix msi validate target\anchor-guard-msi-check.msi
```

Expected: MSI 可双击打开，出现地址和端口输入页，安装后服务配置包含这两个值。

- [ ] **Step 5: 提交**

在提交授权成立后执行：

```powershell
git add client/installer docs/release.md .github/workflows/release.yml
git commit -m "增加通用客户端安装器服务器配置"
```

### 过期解锁、离线兜底和密钥轮换

**Files:**
- Modify: `client/service/src/server_sync.rs`
- Modify: `client/service/src/main.rs`
- Modify: `server/src/keys.rs`
- Modify: `server/src/api/admin.rs`
- Modify: `docs/windows-test-matrix.md`

**Interfaces:**
- 客户端在授权拒绝且策略过期时触发策略刷新。
- 服务端返回签名策略后走现有本地验签和原子替换。
- 服务端不可达时保持锁定，直到本地导入新策略。

- [ ] **Step 1: 实现过期刷新**

客户端检测授权拒绝原因为策略过期时请求 `/api/device/policy`；成功验签后重新判断授权，失败保留锁定状态。

- [ ] **Step 2: 实现服务器密钥轮换**

管理员生成新密钥对；服务端将旧密钥转为 `retired` 并保留用于旧策略验签；客户端通过密钥环同步获取新公钥，迁移窗口结束后撤销旧密钥。

- [ ] **Step 3: 增加验收场景**

在 `docs/windows-test-matrix.md` 增加服务端可达、不可达、过期解锁、离线导入和密钥轮换同步场景。

- [ ] **Step 4: 验证**

Run:

```text
cargo test --all-targets --all-features
```

Expected: PASS；真机验收记录必须单独填写。

- [ ] **Step 5: 提交**

在提交授权成立后执行：

```powershell
git add client/service/src server/src docs/windows-test-matrix.md
git commit -m "增加策略过期刷新和密钥轮换"
```

### 端到端验收

**Files:**
- Test: Windows 10 测试机
- Test: Docker 宿主机
- Modify: `docs/release.md`
- Modify: `docs/windows-test-matrix.md`

**Interfaces:**
- 服务端和客户端只通过 HTTPS 通信。
- 服务端管理台只能管理员登录。
- 客户端安装器只要求服务端地址和端口。

- [ ] **Step 1: 启动服务端**

在 Docker 宿主机启动 Compose，确认管理台可登录、数据库迁移成功、健康检查通过。

- [ ] **Step 2: 安装客户端**

在 Windows 10 测试机双击通用安装器，填写服务端地址和端口；确认安装成功并出现在待审批列表。

- [ ] **Step 3: 审批和设备信息**

管理员批准设备；确认设备详情展示完整硬件清单、最后在线时间和客户端版本。

- [ ] **Step 4: 策略闭环**

在可视化编辑器配置 USB、网络、刻录、扫描和有效期，签名并分配；确认客户端拉取、验签并执行。

- [ ] **Step 5: 断网和过期**

断网重启，确认继续使用缓存策略；策略过期后确认锁定；恢复网络后确认可以拉取新策略解锁；再次断网后确认离线导入可用。

- [ ] **Step 6: 轮换和升级**

生成新服务端密钥，确认客户端同步后使用新公钥、旧策略仍可验证；撤销旧密钥后确认旧策略不再被信任，并确认数据库目录和密钥目录重启后保留。

- [ ] **Step 7: 记录边界**

记录实际 Windows 版本、服务端镜像版本、数据库版本、策略包哈希、执行时间和证据路径。
