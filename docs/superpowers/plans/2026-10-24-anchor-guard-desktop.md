# Anchor Guard Desktop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 Anchor Guard 收敛为一个 `runtime/` 终端程序，增加 Tauri 桌面端、只读在线审计、提前导入策略和托盘常驻，并删除独立的 `anchor-viewer`。

**Architecture:** `runtime/service` 是唯一授权和审计判断者；`runtime/desktop` 通过新的 `AnchorGuard.Desktop` 管道查询状态、预览/导入策略和分页查询审计。桌面端内部完全按 `prelay-client` 的 `app/` + `src-tauri/` 结构组织，服务端通过 Windows Service 按会话发现并拉起 `anchor-guard.exe`。

**Tech Stack:** Rust 2021、Windows Service、Named Pipe、SQLite、Tauri 2、Nuxt 4、Vue、Bun、`@stellar/ui` 0.3.4、Tailwind 4、WiX 5、GitHub Actions。

**Spec:** `docs/superpowers/specs/2026-10-23-anchor-guard-client-ui-design.md`

## Global Constraints

- 顶层只保留 `runtime/`、`installer/`、`admin/`、`crates/`、`installer/`、`docs/` 和现有仓库配置；不使用 `apps/` 或 `bin/`。
- `runtime/` 是唯一终端程序：`desktop`、`service`、`session`、`credential` 都是它的组件。
- `crates/` 只放共享库：`anchor-core`、`anchor-ipc`、`anchor-store`、`anchor-scan`、`anchor-system`。
- `admin/` 只放管理侧工具，当前只有 `anchor-policy`；`anchor-viewer` 删除。
- `runtime/desktop` 的 `app/`、`src-tauri/`、`scripts/`、`tests/` 和配置文件结构完全参考 `prelay-client`；只把全局 single-instance 换成每会话互斥体，把 autostart 换成服务拉起。
- 目标 Windows 10 x64；目标机预装 WebView2；普通用户同时是管理员；导入不增加 UAC 提权路径。
- 审计只做在线查看，不导出、不打开离线复制库；审计页通过服务只读查询。
- 前端只用 Bun，禁止 `npm`、`npx` 或 `package-lock.json`。
- 所有代码格式化：Rust `cargo fmt --all`，严格 Clippy；前端 `bun run typecheck`、`lint`、`format:check`。
- 当前工作区有用户未提交的 Rust/WIP 改动。执行前必须建立独立 worktree，或由用户明确授权如何保留这些改动；不得把用户 WIP 混入本次提交。
- 本设计与计划文件当前尚未提交；如果使用新的 worktree，先把这两份文档复制过去，或在获得授权后单独提交文档。
- 每次提交前必须完整读取 `git-commit` 技能，并按仓库中文提交风格执行；未获提交授权时保留未提交改动。

## File Structure

```text
runtime/
  desktop/
    app/                         Nuxt 4 前端
    src-tauri/                   Tauri 2 后端（独立 Cargo workspace）
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
  service/                       anchor-service
  session/                       anchor-session
  credential/                    anchor-credential
installer/
  AnchorGuard.wxs
  setup/                         anchor-setup（库 + CLI）
  action/                        anchor-installer-action
admin/
  anchor-policy/                 anchor-policy
crates/
  anchor-core/
  anchor-ipc/                    新增共享 IPC 协议
  anchor-store/
  anchor-scan/
  anchor-system/
```

### Task 1: 迁移目录并删除 anchor-viewer

**Files:**
- Move: `crates/anchor-service` → `runtime/service`
- Move: `crates/anchor-session` → `runtime/session`
- Move: `crates/anchor-credential` → `runtime/credential`
- Move: `crates/anchor-setup` → `installer/setup`
- Move: `crates/anchor-installer-action` → `installer/action`
- Move: `crates/anchor-policy` → `admin/anchor-policy`
- Delete: `crates/anchor-viewer`
- Modify: `Cargo.toml`
- Modify: `installer/AnchorGuard.wxs`
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- 所有包名保持不变：`anchor-service`、`anchor-session`、`anchor-credential`、`anchor-setup`、`anchor-installer-action`、`anchor-policy`。
- 所有二进制输出仍在 `target/release`：`anchor-service.exe`、`anchor-session.exe`、`anchor-setup.exe`、`anchor_installer_action.dll`、`anchor_credential.dll`、`anchor-policy.exe`。
- `installer/action` 通过 `../setup` 依赖 `anchor-setup`。

- [ ] **Step 1: 建立隔离工作区**

Run:

```powershell
git status --short
git worktree add .worktrees/anchor-guard-desktop -b feature/anchor-guard-desktop
```

Expected: `.worktrees/anchor-guard-desktop` 存在；当前工作区的未提交 WIP 不被移动或提交。

- [ ] **Step 2: 移动包目录**

Run:

```powershell
New-Item -ItemType Directory runtime, admin -Force | Out-Null
git mv crates/anchor-service runtime/service
git mv crates/anchor-session runtime/session
git mv crates/anchor-credential runtime/credential
git mv crates/anchor-setup installer/setup
git mv crates/anchor-installer-action installer/action
git mv crates/anchor-policy admin/anchor-policy
git rm -r crates/anchor-viewer
```

- [ ] **Step 3: 更新根 workspace members**

把 `Cargo.toml` 的 members 改为：

```toml
members = [
    "crates/anchor-core",
    "crates/anchor-scan",
    "crates/anchor-store",
    "crates/anchor-system",
    "runtime/credential",
    "runtime/service",
    "runtime/session",
    "installer/action",
    "installer/setup",
    "admin/anchor-policy",
]
```

- [ ] **Step 4: 修正路径依赖**

- `runtime/credential/Cargo.toml` 和 `runtime/session/Cargo.toml`：本任务只改路径，暂不改 `anchor-service` 依赖；Task 2 再替换为 `anchor-ipc`。
- `runtime/service/Cargo.toml`：本任务只改路径，暂不增加 `anchor-ipc`；Task 2 再增加。
- 根 `[workspace.dependencies]` 的 `anchor-service = { path = "runtime/service" }` 同步更新。
- `installer/action/Cargo.toml`：`anchor-setup = { path = "../setup" }`。
- `admin/anchor-policy/Cargo.toml`：内部依赖改为 `../../crates/anchor-core`。
- `installer/setup/Cargo.toml`：不需要共享依赖时保持原样。

- [ ] **Step 5: 更新安装器和发布路径**

- `installer/AnchorGuard.wxs` 删除 `ViewerExecutable` 文件引用。
- 保留 `SetupExecutable`、`InstallerActionDll`、`CredentialProviderDll`。
- `.github/workflows/release.yml` 的策略示例路径改为 `admin/anchor-policy/policy-example.toml`。
- WiX 组装脚本删除 `anchor-viewer.exe` 的输入和发布文件。

- [ ] **Step 6: 验证迁移**

Run:

```powershell
cargo metadata --no-deps --format-version 1 | Out-Null
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: metadata 成功；测试和 Clippy 通过。若当前 WIP 导致失败，先记录失败文件，不要在迁移提交中修复无关 WIP。

- [ ] **Step 7: 提交（仅在用户授权提交时）**

```powershell
git add Cargo.toml Cargo.lock crates runtime installer admin .github/workflows/release.yml
git commit -m "重构终端程序目录并移除独立审计工具"
```

### Task 2: 新增 anchor-ipc 并迁移协议

**Files:**
- Create: `crates/anchor-ipc/Cargo.toml`
- Create: `crates/anchor-ipc/src/lib.rs`
- Create: `crates/anchor-ipc/src/protocol.rs`
- Modify: `runtime/service/src/authority.rs`
- Modify: `runtime/service/src/main.rs`
- Modify: `runtime/service/src/lib.rs`
- Modify: `runtime/session/src/lib.rs`
- Modify: `runtime/credential/src/controller.rs`
- Delete: `runtime/service/src/protocol.rs`

**Interfaces:**
- `anchor_ipc::{ServiceRequest, ServiceResponse, AuthorizationResponse, ImportResponse}` 保留原语义。
- 新增 `DesktopRequest`、`DesktopResponse`、`DesktopStatus`、`PolicySummary`、`PolicyInspection`、`AuditFilter`、`AuditViewEvent`、`AuditPage`、`DesktopProtocolError`。
- `MAX_MESSAGE_BYTES = 64 * 1024` 用于控制/会话状态；`MAX_DESKTOP_MESSAGE_BYTES = 1024 * 1024` 用于桌面端；`MAX_POLICY_PACKAGE_BYTES = 256 * 1024`。

- [ ] **Step 1: 写协议往返测试**

```rust
#[test]
fn desktop_inspect_request_roundtrips() {
    let request = DesktopRequest::InspectPolicy {
        package_json: r#"{"version":1}"#.into(),
    };
    let json = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        serde_json::from_slice::<DesktopRequest>(&json).unwrap(),
        request
    );
}

#[test]
fn desktop_audit_request_carries_cursor_and_limit() {
    let request = DesktopRequest::QueryAudit {
        filter: AuditFilter {
            event_type: Some("scan_hit".into()),
            user: Some("alice".into()),
            ..AuditFilter::default()
        },
        after_sequence: Some(42),
        limit: 100,
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"after_sequence\":42"));
    assert!(json.contains("\"limit\":100"));
}
```

- [ ] **Step 2: 实现协议 crate**

在 `protocol.rs` 中定义全局常量、现有协议类型和桌面端类型；`AuditFilter` 实现 `Default`，`event_type` 使用字符串，由服务解析。`DesktopResponse::Error` 使用 `DesktopProtocolError`。

在根 `Cargo.toml` 的 members 中加入 `crates/anchor-ipc`。

- [ ] **Step 3: 更新所有消费方**

- `anchor-session` 只依赖 `anchor-ipc` 的 `ServiceRequest`/`AuthorizationResponse`。
- `anchor-credential` 只依赖 `anchor-ipc` 的协议类型。
- `anchor-service` 使用 `anchor-ipc`；删除 `protocol.rs`。
- `runtime/service/src/lib.rs` 只导出业务模块，不再导出协议。

- [ ] **Step 4: 验证**

Run:

```powershell
cargo test -p anchor-ipc
cargo test -p anchor-session -p anchor-credential -p anchor-service
cargo clippy -p anchor-ipc -p anchor-service -p anchor-session -p anchor-credential --all-targets --all-features -- -D warnings
```

Expected: PASS。

- [ ] **Step 5: 提交**

```powershell
git add crates/anchor-ipc runtime/service runtime/session runtime/credential
git commit -m "抽出共享 IPC 协议"
```

### Task 3: 扩展 Store 的活动策略和审计分页

**Files:**
- Modify: `crates/anchor-store/src/lib.rs`
- Modify: `crates/anchor-store/src/types.rs`
- Test: `crates/anchor-store/src/lib.rs` 的 `#[cfg(test)]`

**Interfaces:**
- `ActivePolicyRecord { package: PolicyPackage, imported_at: DateTime<Utc> }`
- `Store::active_policy_record() -> Result<Option<ActivePolicyRecord>, StoreError>`
- `Store::query_audit_page(filter: &EventFilter, after_sequence: Option<i64>, limit: u32) -> Result<Vec<(i64, AuditEvent)>, StoreError>`

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn active_policy_record_returns_import_time() {
    let store = Store::in_memory().unwrap();
    store
        .import_policy(&package(1), ImportDecision::Accept, "laptop-1", "admin", now())
        .unwrap();
    let record = store.active_policy_record().unwrap().unwrap();
    assert_eq!(record.package.payload.version, 1);
    assert_eq!(record.imported_at, now());
}

#[test]
fn audit_page_respects_cursor_limit_and_filters() {
    let store = Store::in_memory().unwrap();
    for result in ["a", "b", "c"] {
        let mut payload = AuditPayload::new("laptop-1", "alice", EventType::ScanHit, "scan", result);
        payload.timestamp = now();
        store.append_audit(payload).unwrap();
    }
    let first = store
        .query_audit_page(&EventFilter::default(), None, 2)
        .unwrap();
    assert_eq!(first.len(), 2);
    let second = store
        .query_audit_page(&EventFilter::default(), Some(first[1].0), 2)
        .unwrap();
    assert_eq!(second.len(), 1);
}
```

- [ ] **Step 2: 实现查询**

`query_audit_page` 使用 `audit_events.sequence` 作为游标：

```sql
SELECT sequence, event_id, device_id, user_name, timestamp, event_type, process,
       resource, policy_version, action, result, rule_id, prev_hash, event_hash
FROM audit_events
WHERE 1 = 1
  AND sequence > ?1
ORDER BY sequence
LIMIT ?2
```

`limit` 在 Store 内夹到 `1..=200`。筛选条件复用 `query_events` 的 `EventFilter` 字段；不要改 `audit_events` 表结构，也不要把 `sequence` 写入 `AuditEvent` 哈希内容。

- [ ] **Step 3: 验证**

```powershell
cargo test -p anchor-store
cargo clippy -p anchor-store --all-targets --all-features -- -D warnings
```

Expected: PASS。

- [ ] **Step 4: 提交**

```powershell
git add crates/anchor-store
git commit -m "支持活动策略读取和审计分页"
```

### Task 4: 增加桌面端管道和服务处理

**Files:**
- Modify: `crates/anchor-system/src/pipe.rs`
- Modify: `runtime/service/src/authority.rs`
- Modify: `runtime/service/src/main.rs`
- Test: `crates/anchor-system/src/pipe.rs`、`runtime/service/src/authority.rs`

**Interfaces:**
- `DESKTOP_PIPE = r"\\.\pipe\AnchorGuard.Desktop"`
- `DESKTOP_CLIENT_SDDL = "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)"`
- `serve_desktop_once(handler)`、`transact_desktop(request, timeout)`
- `Service::desktop_status(now) -> Result<DesktopStatus, DesktopProtocolError>`
- `Service::inspect_policy(package_json, now) -> Result<PolicyInspection, DesktopProtocolError>`
- `Service::import_policy_json(package_json, user, now) -> Result<ImportResponse, DesktopProtocolError>`
- `Service::query_audit(filter, after_sequence, limit, now) -> Result<AuditPage, DesktopProtocolError>`
- `Service::serve_desktop_pipe_once(now)`

- [ ] **Step 1: 写管道 ACL 和消息上限测试**

```rust
#[test]
fn desktop_pipe_is_available_to_authenticated_users_only() {
    assert_eq!(desktop_client_sddl(), "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)");
    assert_eq!(desktop_pipe_path(), r"\\.\pipe\AnchorGuard.Desktop");
}
```

- [ ] **Step 2: 实现传输层**

把现有 `windows::serve_once`/`transact` 重构为带 `max_message_bytes` 的内部函数；控制管道和会话状态继续使用 64 KiB，桌面管道使用 1 MiB。`serve_desktop_once` 使用 `DESKTOP_CLIENT_SDDL`，客户端 `transact_desktop` 仍校验服务端为 SYSTEM。

- [ ] **Step 3: 写服务行为测试**

```rust
#[test]
fn inspect_does_not_change_active_policy_or_audit() {
    let (service, key) = service_and_key(1);
    let candidate = signed_package_with_key(2, &key);
    let before = service.store.read_audit_events().unwrap().len();
    let inspection = service
        .inspect_policy(&serde_json::to_string(&candidate).unwrap(), now())
        .unwrap();
    assert!(inspection.accepted);
    assert_eq!(service.store.active_policy().unwrap().unwrap().payload.version, 1);
    assert_eq!(service.store.read_audit_events().unwrap().len(), before);
}

#[test]
fn import_rejects_older_version_without_replacing_policy() {
    let (service, key) = service_and_key(2);
    let result = service
        .import_policy_json(
            &serde_json::to_string(&signed_package_with_key(1, &key)).unwrap(),
            "alice",
            now(),
        )
        .unwrap();
    assert!(!result.accepted);
    assert_eq!(result.reason, "version_not_newer");
    assert_eq!(service.store.active_policy().unwrap().unwrap().payload.version, 2);
}

#[test]
fn audit_query_is_paged_and_read_only() {
    let service = service_with_events(3);
    let before = service.store.read_audit_events().unwrap().len();
    let page = service
        .query_audit(AuditFilter::default(), None, 2, now())
        .unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(page.chain_healthy);
    assert_eq!(service.store.read_audit_events().unwrap().len(), before);
}
```

- [ ] **Step 3.1: 添加测试夹具**

在 `authority.rs` 测试模块中加入以下夹具，避免测试依赖未定义的函数：

```rust
use anchor_core::{
    crypto, ActionPolicy, BurningRules, NetworkRules, PolicyPayload, ScanRules, UsbRules,
};
use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
}

fn payload(version: u64) -> PolicyPayload {
    PolicyPayload {
        version,
        expires_at: now() + chrono::Duration::days(7),
        usb: UsbRules { read: ActionPolicy::Deny, write: ActionPolicy::Deny, allowed: vec![] },
        network: NetworkRules { policy: ActionPolicy::Deny, allowed: vec![] },
        burning: BurningRules { policy: ActionPolicy::Deny, allowed: vec![] },
        scan: ScanRules { controlled_dirs: vec![], file_types: vec![], rules: vec![] },
    }
}

fn signed_package_with_key(version: u64, key: &SigningKey) -> PolicyPackage {
    PolicyPackage::sign(payload(version), key).unwrap()
}

fn service_and_key(version: u64) -> (Service, SigningKey) {
    let (key, verifying_key) = crypto::generate_keypair();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");
    service
        .import_policy_json(
            &serde_json::to_string(&signed_package_with_key(version, &key)).unwrap(),
            "admin",
            now(),
        )
        .unwrap();
    (service, key)
}

fn service_with_events(count: usize) -> Service {
    let (service, _) = service_and_key(1);
    for index in 0..count {
        let mut event = AuditPayload::new(
            "laptop-1",
            "alice",
            EventType::ScanHit,
            "scan",
            format!("result-{index}"),
        );
        event.timestamp = now();
        service.store.append_audit(event).unwrap();
    }
    service
}
```

- [ ] **Step 4: 实现服务方法**

`desktop_status` 调用现有 `authorization_state`，再读取 `active_policy_record` 和 `last_trusted_at`。`inspect_policy` 解析并调用 `decide_import`，不写库；解析失败返回 `accepted=false, reason="policy_parse_failed"`。`import_policy_json` 复用媒体导入的判定和 `Store::import_policy`，解析失败追加 `PolicyImportRejected`。`query_audit` 把 `AuditFilter.event_type` 解析为 `EventType`，限制 `limit <= 200`，返回 `AuditPage` 和 `audit_chain_healthy`。

- [ ] **Step 5: 接入服务主循环**

在 `serve_until_stopped` 中增加第三个 `spawn_pipe_listener`：

```rust
let desktop_listener = spawn_pipe_listener(
    Arc::clone(&service),
    Arc::clone(&listener_stop_requested),
    |service, now| service.serve_desktop_pipe_once(now).map(|_| ()),
);
```

停止时 join 该线程。

- [ ] **Step 6: 验证**

```powershell
cargo test -p anchor-system -p anchor-service
cargo clippy -p anchor-system -p anchor-service --all-targets --all-features -- -D warnings
```

Expected: PASS。

- [ ] **Step 7: 提交**

```powershell
git add crates/anchor-system runtime/service
git commit -m "增加桌面端状态导入和在线审计协议"
```

### Task 5: 服务按会话拉起桌面端

**Files:**
- Modify: `crates/anchor-system/src/session.rs`
- Modify: `runtime/service/src/main.rs`
- Modify: `crates/anchor-core/src/audit.rs`
- Test: `crates/anchor-system/src/session.rs`、`runtime/service/src/main.rs`

**Interfaces:**
- `SessionAssistantLauncherBackend::desktop_running(session_id) -> Result<bool, PlatformError>`
- `SessionAssistantLauncherBackend::start_desktop(session_id, executable) -> Result<(), PlatformError>`
- `DesktopLauncher::reconcile() -> Result<Vec<u32>, PlatformError>`（返回本轮启动的会话）
- `EventType::DesktopLaunchFailed`，字符串 `desktop_launch_failed`
- `Service::record_desktop_launch_failure(reason, now)`

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn desktop_launcher_starts_only_missing_sessions() {
    let backend = TestLauncherBackend::with_sessions(vec![
        InteractiveSession::active(1),
        InteractiveSession::active(2),
    ]);
    backend.desktop_running.borrow_mut().insert(1);
    let mut launcher = DesktopLauncher::new(backend, "anchor-guard.exe");
    let started = launcher.reconcile().unwrap();
    assert_eq!(started, vec![2]);
}

#[test]
fn desktop_launch_failure_is_audited_without_denying_authorization() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let service = service_with_key(database.path());
    service
        .record_desktop_launch_failure("session 7 start failed", now())
        .unwrap();
    assert_ne!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
    drop(service);
    assert!(Store::open_read_only(database.path())
        .unwrap()
        .read_audit_events()
        .unwrap()
        .iter()
        .any(|event| event.payload.event_type == EventType::DesktopLaunchFailed));
}
```

- [ ] **Step 1.1: 扩展测试夹具**

在 `anchor-system/src/session.rs` 的现有 `TestLauncherBackend` 增加：

```rust
desktop_running: RefCell<BTreeSet<u32>>,
desktop_starts: RefCell<Vec<u32>>,
```

实现两个新方法：

```rust
fn desktop_running(&self, session_id: u32, _executable_name: &str) -> Result<bool, PlatformError> {
    Ok(self.desktop_running.borrow().contains(&session_id))
}

fn start_desktop(&self, session_id: u32, _executable: &Path) -> Result<(), PlatformError> {
    self.desktop_starts.borrow_mut().push(session_id);
    Ok(())
}
```

在 `runtime/service/src/main.rs` 的测试模块加入：

```rust
fn service_with_key(path: &std::path::Path) -> Service {
    Service::new(
        Store::open(path).unwrap(),
        anchor_core::crypto::generate_keypair().1,
        "laptop-1",
    )
}
```

- [ ] **Step 2: 实现进程发现和启动**

在 `anchor-system::session` 中用 `CreateToolhelp32Snapshot` + `ProcessIdToSessionId` 查找 `anchor-guard.exe`；只按进程名和会话 ID 判断，误判不是安全边界。启动复用现有 `CreateProcessAsUserW` 路径，创建后关闭进程句柄；`CREATE_NO_WINDOW` 只影响控制台，不影响 Tauri 窗口。

- [ ] **Step 3: 实现 DesktopLauncher**

`reconcile` 枚举交互会话，存在 `anchor-guard.exe` 则跳过，不存在则启动；启动失败返回错误。`serve_until_stopped` 每轮调用；连续失败段只写一次 `desktop_launch_failed`，成功一轮后清除失败标记。UI 启动失败不进入 `runtime_failed`。

```rust
pub struct DesktopLauncher<B: SessionAssistantLauncherBackend> {
    backend: B,
    executable: PathBuf,
}

impl<B: SessionAssistantLauncherBackend> DesktopLauncher<B> {
    pub fn new(backend: B, executable: impl Into<PathBuf>) -> Self {
        Self { backend, executable: executable.into() }
    }

    pub fn reconcile(&mut self) -> Result<Vec<u32>, PlatformError> {
        let mut started = Vec::new();
        for session in self.backend.interactive_sessions()? {
            if self
                .backend
                .desktop_running(session.id, "anchor-guard.exe")?
            {
                continue;
            }
            self.backend.start_desktop(session.id, &self.executable)?;
            started.push(session.id);
        }
        Ok(started)
    }
}
```

- [ ] **Step 4: 接入事件类型**

在 `EventType` 增加 `DesktopLaunchFailed`，同步 `as_str` 和 `FromStr`，并更新 roundtrip 测试。

- [ ] **Step 5: 验证**

```powershell
cargo test -p anchor-core -p anchor-system -p anchor-service
cargo clippy -p anchor-core -p anchor-system -p anchor-service --all-targets --all-features -- -D warnings
```

Expected: PASS。

- [ ] **Step 6: 提交**

```powershell
git add crates/anchor-core crates/anchor-system runtime/service
git commit -m "按会话拉起桌面端"
```

### Task 6: 搭建 runtime/desktop（完全参考 prelay）

**Files:**
- Create: `runtime/desktop/package.json`
- Create: `runtime/desktop/nuxt.config.ts`
- Create: `runtime/desktop/tsconfig.json`
- Create: `runtime/desktop/eslint.config.mjs`
- Create: `runtime/desktop/prettier.config.mjs`
- Create: `runtime/desktop/.npmrc`
- Create: `runtime/desktop/.gitignore`
- Create: `runtime/desktop/.editorconfig`
- Create: `runtime/desktop/.gitattributes`
- Create: `runtime/desktop/README.md`
- Create: `runtime/desktop/app/app.vue`
- Create: `runtime/desktop/app/assets/css/main.css`
- Create: `runtime/desktop/app/components/shell/AppTitlebar.vue`
- Create: `runtime/desktop/app/components/shell/AppSidebar.vue`
- Create: `runtime/desktop/src-tauri/Cargo.toml`
- Create: `runtime/desktop/src-tauri/build.rs`
- Create: `runtime/desktop/src-tauri/tauri.conf.json`
- Create: `runtime/desktop/src-tauri/capabilities/default.json`
- Create: `runtime/desktop/src-tauri/src/main.rs`
- Create: `runtime/desktop/src-tauri/src/lib.rs`
- Create: `runtime/desktop/src-tauri/src/app/mod.rs`
- Create: `runtime/desktop/src-tauri/src/app/state.rs`
- Create: `runtime/desktop/src-tauri/src/preferences/mod.rs`
- Create: `runtime/desktop/src-tauri/src/preferences/tray.rs`
- Create: `runtime/desktop/src-tauri/src/commands/mod.rs`
- Create: `runtime/desktop/src-tauri/src/commands/policy.rs`
- Create: `runtime/desktop/src-tauri/src/ipc.rs`

**Interfaces:**
- `package.json` name `anchor-guard`，scripts `dev`、`generate`、`typecheck`、`lint`、`format:check`、`test`、`tauri`。
- `tauri.conf.json` productName `Anchor Guard`，window label `main`，`decorations: false`，`visible: false`，`frontendDist: "../.output/public"`，`beforeBuildCommand: "bun run generate"`。
- `capabilities/default.json` 允许 `core:window:allow-minimize`、`toggle-maximize`、`is-maximized`、`start-dragging`、`close` 和 `dialog:allow-open`。

- [ ] **Step 1: 复制 prelay 的配置骨架**

从 `prelay-client` 复制并改名：

```text
prelay-client/app/                → runtime/desktop/app/
prelay-client/src-tauri/          → runtime/desktop/src-tauri/
prelay-client/package.json        → runtime/desktop/package.json
prelay-client/nuxt.config.ts      → runtime/desktop/nuxt.config.ts
prelay-client/tsconfig.json       → runtime/desktop/tsconfig.json
prelay-client/eslint.config.mjs   → runtime/desktop/eslint.config.mjs
prelay-client/prettier.config.mjs → runtime/desktop/prettier.config.mjs
prelay-client/.npmrc              → runtime/desktop/.npmrc
prelay-client/.gitignore          → runtime/desktop/.gitignore
prelay-client/.editorconfig       → runtime/desktop/.editorconfig
prelay-client/.gitattributes      → runtime/desktop/.gitattributes
```

删除 `imagegen`、agents、relay 等业务模块，只保留 shell、主题和 @stellar/ui 配置。

- [ ] **Step 2: 写 Nuxt 配置**

```ts
import tailwindcss from "@tailwindcss/vite";

export default defineNuxtConfig({
  srcDir: "app/",
  ssr: false,
  modules: ["@nuxt/icon", "@stellar/ui/nuxt"],
  icon: {
    provider: "none",
    componentName: "NuxtIcon",
    clientBundle: { scan: { globInclude: ["**/*.{vue,jsx,tsx,ts,md,mdc,mdx,yml,yaml}"] } },
  },
  compatibilityDate: "2026-08-19",
  devServer: { port: 18082, strictPort: true },
  css: ["~/assets/css/main.css"],
  vite: { plugins: [tailwindcss()] },
  typescript: { strict: true },
});
```

- [ ] **Step 3: 写 Tauri 配置**

`tauri.conf.json` 使用 `productName: "Anchor Guard"`、`identifier: "ink.zoran.anchor-guard"`、`frontendDist: "../.output/public"`、窗口 `960x680`、`minWidth: 800`、`minHeight: 560`、`visible: false`、`decorations: false`、`shadow: false`；不要配置 `tauri-plugin-autostart` 或全局 `single-instance`。

- [ ] **Step 4: 写 Tauri 入口和托盘**

`app/mod.rs`：

```rust
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            crate::preferences::tray::install(app.handle())?;
            Ok(())
        })
        .on_window_event(crate::preferences::tray::hide_on_close)
        .run(tauri::generate_context!())
        .expect("failed to run Anchor Guard desktop");
}
```

托盘菜单：版本项（禁用）、显示窗口、导入策略…、隐藏窗口；不提供退出项。双击显示窗口。

在 `commands/policy.rs` 先定义命令错误类型，后续 Task 7 再补充命令：

```rust
use anchor_ipc::DesktopProtocolError;

#[derive(Debug, serde::Serialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl CommandError {
    pub fn protocol(error: impl std::fmt::Display) -> Self {
        Self { code: "protocol_error".into(), message: error.to_string() }
    }
    pub fn service(message: impl Into<String>) -> Self {
        Self { code: "service_unavailable".into(), message: message.into() }
    }
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self { code: "unexpected_response".into(), message: message.into() }
    }
}

impl From<DesktopProtocolError> for CommandError {
    fn from(error: DesktopProtocolError) -> Self {
        Self { code: error.code, message: error.message }
    }
}
```

- [ ] **Step 5: 写 IPC 客户端**

`src-tauri/src/ipc.rs` 使用 `anchor_system::pipe::transact_desktop`：

```rust
pub fn request(request: &anchor_ipc::DesktopRequest) -> Result<anchor_ipc::DesktopResponse, CommandError> {
    let body = serde_json::to_vec(request).map_err(CommandError::protocol)?;
    let response = anchor_system::pipe::transact_desktop(&body, Duration::from_secs(2))
        .map_err(|error| CommandError::service(error.to_string()))?;
    serde_json::from_slice(&response).map_err(CommandError::protocol)
}
```

`ipc.rs` 顶部加入：

```rust
use std::time::Duration;
use crate::commands::policy::CommandError;
```

`src-tauri/Cargo.toml` 依赖：

```toml
[dependencies]
anchor-ipc = { path = "../../../crates/anchor-ipc" }
anchor-system = { path = "../../../crates/anchor-system" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tauri = { version = "2", features = ["tray-icon"] }
tauri-plugin-dialog = "2"
uuid = { version = "1", features = ["v4"] }

[build-dependencies]
tauri-build = { version = "2", features = [] }
```

- [ ] **Step 6: 安装依赖并验证骨架**

```powershell
Set-Location runtime/desktop
bun install
bun run typecheck
bun run lint
bun run format:check
cargo check --manifest-path src-tauri/Cargo.toml
```

Expected: 全部通过；如果 `src-tauri` 独立 workspace 没有锁文件，先运行 `cargo generate-lockfile --manifest-path src-tauri/Cargo.toml` 并提交 `src-tauri/Cargo.lock`。

- [ ] **Step 7: 提交**

```powershell
git add runtime/desktop
git commit -m "搭建参考 prelay 的桌面端骨架"
```

### Task 7: 策略状态页和导入弹窗

**Files:**
- Create: `runtime/desktop/app/pages/index.vue`
- Create: `runtime/desktop/app/components/status/StatusHero.vue`
- Create: `runtime/desktop/app/components/status/PolicyDomainCard.vue`
- Create: `runtime/desktop/app/components/status/PolicyExceptionsDrawer.vue`
- Create: `runtime/desktop/app/components/import/PolicyImportDialog.vue`
- Create: `runtime/desktop/app/composables/usePolicyStatus.ts`
- Create: `runtime/desktop/app/composables/usePolicyImport.ts`
- Create: `runtime/desktop/app/utils/policy.ts`
- Modify: `runtime/desktop/app/components/shell/AppSidebar.vue`
- Modify: `runtime/desktop/src-tauri/src/app/mod.rs`
- Modify: `runtime/desktop/src-tauri/src/app/state.rs`
- Modify: `runtime/desktop/src-tauri/src/commands/policy.rs`
- Modify: `runtime/desktop/src-tauri/Cargo.toml`

**Interfaces:**
- Tauri commands: `get_policy_status`、`inspect_policy_file`、`import_pending_policy`、`discard_pending_policy`。
- `PolicySummary.payload` 直接映射 `PolicyPayload` 的 `usb/network/burning/scan`。
- 导入预览返回 `pending_id` 和 `PolicyInspection`；确认只发送 `pending_id`。

- [ ] **Step 1: 写前端格式化测试**

```ts
import { describe, expect, test } from "bun:test";
import { describeDenial, formatRemaining, policyDomainRows } from "../app/utils/policy";

test("maps denial reasons to user-facing text", () => {
  expect(describeDenial("no_active_policy")).toBe("尚未导入策略");
  expect(describeDenial("expired")).toBe("策略已到期");
  expect(describeDenial("clock_rollback")).toBe("检测到系统时间回拨");
});

test("formats remaining days without inventing a progress value", () => {
  expect(formatRemaining("2026-10-31T00:00:00Z", new Date("2026-10-24T00:00:00Z"))).toBe("剩余 7 天");
  expect(formatRemaining("2026-10-23T00:00:00Z", new Date("2026-10-24T00:00:00Z"))).toBe("已到期");
});

test("creates four policy domain rows from a payload", () => {
  const rows = policyDomainRows({
    version: 1,
    expires_at: "2026-12-31T00:00:00Z",
    usb: { read: "deny", write: "deny", allowed: [] },
    network: { policy: "deny", allowed: [] },
    burning: { policy: "deny", allowed: [] },
    scan: { controlled_dirs: [], file_types: [], rules: [] },
  });
  expect(rows.map((row) => row.key)).toEqual(["usb", "network", "burning", "scan"]);
});
```

- [ ] **Step 2: 写状态页**

`index.vue` 使用 `StatusHero`、四个 `PolicyDomainCard` 和 `PolicyImportDialog`；侧栏 `AppSidebar` 有“策略状态”“审计日志”两项。状态卡片使用 `Card`、`Badge`、`Tag`、`ProgressBar`、`Alert`、`Drawer`；不直接读写 SQLite。

- [ ] **Step 3: 写导入弹窗**

`PolicyImportDialog` 使用 `Modal` + `Steps`：

1. 选择文件：调用 `usePolicyImport().chooseFile()`；文件过滤器 `policy`、`json`。
2. 预览：调用 `inspect_policy_file(path)`；显示 `current -> candidate` 版本、到期时间和四域变化；`accepted=false` 时禁用“导入并应用”。
3. 结果：调用 `import_pending_policy(pending_id)`；成功刷新状态，失败保留当前策略。

- [ ] **Step 4: 写组合式函数**

`usePolicyStatus` 每 10 秒调用 `get_policy_status`，窗口重新聚焦时刷新；失败保留旧数据并标记过期。`usePolicyImport` 管理 `visible`、`pendingId`、`inspection`、`error`；关闭或取消调用 `discard_pending_policy`。

- [ ] **Step 4.1: 实现策略命令和 pending 缓存**

在 `app/state.rs` 增加：

```rust
pub struct PendingPolicy {
    pub id: String,
    pub package_json: String,
}

#[derive(Default)]
pub struct NativeState {
    pub pending: std::sync::Mutex<Option<PendingPolicy>>,
}
```

在 `commands/policy.rs` 增加：

```rust
use std::fs;
use anchor_ipc::{
    DesktopRequest, DesktopResponse, DesktopStatus, ImportResponse, PolicyInspection,
    MAX_POLICY_PACKAGE_BYTES,
};
use tauri::State;

use crate::app::state::{NativeState, PendingPolicy};
use crate::ipc;

#[derive(Debug, Serialize)]
pub struct InspectResult {
    pub pending_id: String,
    pub inspection: PolicyInspection,
}

#[tauri::command]
pub fn get_policy_status() -> Result<DesktopStatus, CommandError> {
    match ipc::request(&DesktopRequest::GetStatus)? {
        DesktopResponse::Status(status) => Ok(status),
        DesktopResponse::Error(error) => Err(error.into()),
        _ => Err(CommandError::unexpected("expected status response")),
    }
}

#[tauri::command]
pub fn inspect_policy_file(
    path: String,
    state: State<'_, NativeState>,
) -> Result<InspectResult, CommandError> {
    let metadata = fs::metadata(&path)
        .map_err(|error| CommandError::service(format!("无法读取策略文件: {error}")))?;
    if metadata.len() > MAX_POLICY_PACKAGE_BYTES as u64 {
        return Err(CommandError {
            code: "policy_too_large".into(),
            message: "策略文件超过 256 KiB".into(),
        });
    }
    let bytes = fs::read(&path)
        .map_err(|error| CommandError::service(format!("无法读取策略文件: {error}")))?;
    let package_json = String::from_utf8(bytes)
        .map_err(|_| CommandError::protocol("策略文件不是 UTF-8 文本"))?;
    let inspection = match ipc::request(&DesktopRequest::InspectPolicy {
        package_json: package_json.clone(),
    })? {
        DesktopResponse::Inspection(inspection) => inspection,
        DesktopResponse::Error(error) => return Err(error.into()),
        _ => return Err(CommandError::unexpected("expected inspection response")),
    };
    let pending_id = uuid::Uuid::new_v4().to_string();
    *state.pending.lock().expect("pending policy mutex poisoned") = Some(PendingPolicy {
        id: pending_id.clone(),
        package_json,
    });
    Ok(InspectResult { pending_id, inspection })
}

#[tauri::command]
pub fn import_pending_policy(
    pending_id: String,
    state: State<'_, NativeState>,
) -> Result<ImportResponse, CommandError> {
    let pending = {
        let mut guard = state.pending.lock().expect("pending policy mutex poisoned");
        let Some(pending) = guard.as_ref() else {
            return Err(CommandError { code: "pending_not_found".into(), message: "没有待导入的策略".into() });
        };
        if pending.id != pending_id {
            return Err(CommandError { code: "pending_not_found".into(), message: "待导入策略已失效".into() });
        }
        guard.take().expect("pending policy exists")
    };
    match ipc::request(&DesktopRequest::ImportPolicy { package_json: pending.package_json })? {
        DesktopResponse::Import(response) => Ok(response),
        DesktopResponse::Error(error) => Err(error.into()),
        _ => Err(CommandError::unexpected("expected import response")),
    }
}

#[tauri::command]
pub fn discard_pending_policy(pending_id: String, state: State<'_, NativeState>) {
    let mut guard = state.pending.lock().expect("pending policy mutex poisoned");
    if guard.as_ref().is_some_and(|pending| pending.id == pending_id) {
        *guard = None;
    }
}
```

将 Task 6 中 `app/mod.rs` 的 `.setup` 替换为以下内容，并在其后追加 `.invoke_handler`：

```rust
.setup(|app| {
    app.manage(crate::app::state::NativeState::default());
    crate::preferences::tray::install(app.handle())?;
    Ok(())
})
.invoke_handler(tauri::generate_handler![
    commands::policy::get_policy_status,
    commands::policy::inspect_policy_file,
    commands::policy::import_pending_policy,
    commands::policy::discard_pending_policy,
])
```

`uuid` 已在 Task 6 的 `src-tauri/Cargo.toml` 中加入，不需要重复声明。

- [ ] **Step 5: 验证**

```powershell
Set-Location runtime/desktop
bun test
bun run typecheck
bun run lint
bun run format:check
```

Expected: PASS。

- [ ] **Step 6: 提交**

```powershell
git add runtime/desktop/app runtime/desktop/tests
git commit -m "增加策略状态和提前导入界面"
```

### Task 8: 在线审计页

**Files:**
- Create: `runtime/desktop/app/pages/audit.vue`
- Create: `runtime/desktop/app/components/audit/AuditFilterBar.vue`
- Create: `runtime/desktop/app/components/audit/AuditEventTable.vue`
- Create: `runtime/desktop/app/composables/useAudit.ts`
- Create: `runtime/desktop/app/utils/audit.ts`
- Modify: `runtime/desktop/app/components/shell/AppSidebar.vue`
- Modify: `runtime/desktop/src-tauri/src/commands/policy.rs`
- Modify: `runtime/desktop/src-tauri/src/app/mod.rs`
- Test: `runtime/desktop/tests/audit.test.ts`

**Interfaces:**
- `get_audit_page(query)` 调用 `DesktopRequest::QueryAudit`。
- `AuditPage { events, next_after_sequence, chain_healthy }`。
- 页面每页最多 100 条；只读，无导出、无离线库打开。

- [ ] **Step 1: 写前端分页/筛选测试**

```ts
import { expect, test } from "bun:test";
import { auditQueryFromFilters, nextCursorAfterPage } from "../app/utils/audit";

test("maps filters to a cursor query", () => {
  const query = auditQueryFromFilters({
    eventType: "scan_hit",
    user: "alice",
    policyVersion: "3",
    resourcePrefix: "D:\\data",
  }, null, 100);
  expect(query.filter.event_type).toBe("scan_hit");
  expect(query.filter.user).toBe("alice");
  expect(query.filter.policy_version).toBe(3);
  expect(query.after_sequence).toBeNull();
});

test("uses the service cursor for the next page", () => {
  expect(nextCursorAfterPage({ events: [], next_after_sequence: 42, chain_healthy: true })).toBe(42);
});
```

- [ ] **Step 2: 写审计页**

`AuditFilterBar` 使用 `Select`、`Input`、`DatePicker`、`Button`；`AuditEventTable` 使用 `Table` + `Pagination`；顶部用 `Badge`/`Alert` 显示 `chain_healthy`。筛选变化清空游标；加载中保留旧表格并显示局部状态；无匹配事件显示 `EmptyState`；服务不可用显示可重试 `Alert`。

- [ ] **Step 3: 写 Tauri 命令**

```rust
use anchor_ipc::{AuditFilter, AuditPage};

#[derive(Debug, serde::Deserialize)]
pub struct AuditQuery {
    pub filter: AuditFilter,
    pub after_sequence: Option<i64>,
    pub limit: u32,
}

#[tauri::command]
pub fn get_audit_page(query: AuditQuery) -> Result<AuditPage, CommandError> {
    let request = DesktopRequest::QueryAudit {
        filter: query.filter,
        after_sequence: query.after_sequence,
        limit: query.limit.min(200),
    };
    match ipc::request(&request)? {
        DesktopResponse::Audit(page) => Ok(page),
        DesktopResponse::Error(error) => Err(CommandError::from(error)),
        _ => Err(CommandError::unexpected("unexpected desktop response")),
    }
}
```

在 `app/mod.rs` 的 `invoke_handler` 增加：

```rust
commands::policy::get_audit_page,
```

- [ ] **Step 4: 验证**

```powershell
Set-Location runtime/desktop
bun test
bun run typecheck
bun run lint
bun run format:check
cargo test --manifest-path src-tauri/Cargo.toml
```

Expected: PASS。

- [ ] **Step 5: 提交**

```powershell
git add runtime/desktop/app runtime/desktop/tests runtime/desktop/src-tauri/src/commands runtime/desktop/src-tauri/src/app/mod.rs
git commit -m "增加在线审计查看页"
```

### Task 9: 安装器和发布链路

**Files:**
- Modify: `installer/AnchorGuard.wxs`
- Modify: `.github/workflows/release.yml`
- Modify: `docs/release.md`
- Modify: `docs/windows-test-matrix.md`
- Modify: `docs/design.md`

**Interfaces:**
- WiX 新增 `DesktopExecutable`，删除 `ViewerExecutable`。
- 发布工作流增加 `verify-desktop`、版本校验和 `DesktopBinary`。
- MSI 仍只有一个；WebView2 依赖目标机预装。

- [ ] **Step 1: 修改 WiX**

在 `ServiceExecutableComponent` 增加：

```xml
<File Id="DesktopExecutable" Source="$(var.DesktopBinary)" />
```

删除 `ViewerExecutable`。增加开始菜单快捷方式，目标 `[AnchorInstallDirectory]anchor-guard.exe --show`，显示名 Anchor Guard；不创建登录自启动项。

```xml
<StandardDirectory Id="ProgramMenuFolder">
  <Directory Id="AnchorMenuDirectory" Name="Anchor Guard">
    <Component Id="StartMenuShortcutComponent" Guid="3F0C2F0E-5A4B-4A1E-9E1B-2F7A5C6D8E90">
      <Shortcut
        Id="AnchorGuardShortcut"
        Name="Anchor Guard"
        Target="[AnchorInstallDirectory]anchor-guard.exe"
        Arguments="--show"
        WorkingDirectory="AnchorInstallDirectory" />
      <RemoveFolder Id="RemoveAnchorMenuDirectory" On="uninstall" />
      <RegistryValue Root="HKLM" Key="SOFTWARE\Zoranner\Anchor Guard" Name="installed"
                     Type="integer" Value="1" KeyPath="yes" />
    </Component>
  </Directory>
</StandardDirectory>
```

在 `Feature` 中加入 `<ComponentRef Id="StartMenuShortcutComponent" />`。

- [ ] **Step 2: 修改发布组装**

服务构建仍使用 `cargo build --release --locked --workspace`。桌面端构建：

```powershell
Set-Location runtime/desktop
bun install --frozen-lockfile
bun run tauri build --no-bundle
```

组装脚本传入：

```powershell
-d "DesktopBinary=$repositoryRoot\runtime\desktop\src-tauri\target\release\anchor-guard.exe"
```

策略示例路径改为 `admin/anchor-policy/policy-example.toml`；不再要求 `anchor-viewer.exe`。

- [ ] **Step 3: 修改 release.yml**

新增 `verify-desktop` job（Ubuntu + Bun）：`bun install --frozen-lockfile`、`bun run typecheck`、`bun run lint`、`bun run format:check`、`bun test`。`prepare` 依赖 `verify` 和 `verify-desktop`，校验：

```text
tag == workspace.package.version
tag == runtime/desktop/package.json.version
tag == runtime/desktop/src-tauri/tauri.conf.json.version
tag == runtime/desktop/src-tauri/Cargo.toml package.version
```

`build` 在 Windows 上执行服务构建、Bun 安装、Tauri 构建和 WiX 组装。`publish` 继续用 `softprops/action-gh-release@v3`。

- [ ] **Step 4: 更新文档**

- `docs/release.md`：更新 MSI 内容、WebView2 预装条件、桌面端在线审计；删除 `anchor-viewer export` 命令。
- `docs/windows-test-matrix.md`：删除 viewer 导出场景，加入桌面端托盘、提前导入、在线审计、分页和链异常场景。
- `docs/design.md`：补充桌面端、`anchor-ipc`、`AnchorGuard.Desktop`、在线审计和提前导入边界；把“所有组件 Rust”收窄为服务/系统组件/CLI。

- [ ] **Step 5: 验证构建**

```powershell
cargo build --release --locked --workspace
Set-Location runtime/desktop
bun install --frozen-lockfile
bun run tauri build --no-bundle
```

Expected: `runtime/desktop/src-tauri/target/release/anchor-guard.exe` 存在；WiX 组装成功，MSI 包含 `anchor-guard.exe` 且不包含 `anchor-viewer.exe`。

- [ ] **Step 6: 提交**

```powershell
git add installer .github/workflows/release.yml docs/release.md docs/windows-test-matrix.md docs/design.md
git commit -m "把桌面端接入安装和发布链路"
```

### Task 10: 最终验证和收口

**Files:**
- Modify: `docs/superpowers/specs/2026-10-23-anchor-guard-client-ui-design.md`（仅在发现设计偏差时）
- Test: 根 workspace、runtime/desktop、Windows 10 测试机

- [ ] **Step 1: 运行全部静态/单元门禁**

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
Set-Location runtime/desktop
bun install --frozen-lockfile
bun run typecheck
bun run lint
bun run format:check
bun test
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

Expected: 全部 PASS。

- [ ] **Step 2: Windows 10 真机验收**

按 `docs/windows-test-matrix.md` 验证：

- 登录后托盘出现，窗口默认隐藏；关闭只隐藏。
- 结束 `anchor-guard.exe` 后服务重新拉起；服务重启后只保留一个桌面端。
- 快速用户切换每会话一个桌面端。
- 有效期内导入 v4，状态和审计事件正确。
- 无效签名、过期、版本回退、超限包均拒绝且不替换策略。
- 审计页筛选、分页、链异常状态正确；无导出/删除入口。
- MSI 安装/卸载包含/移除 `anchor-guard.exe` 和快捷方式；WebView2 预装条件下可启动。

- [ ] **Step 3: 最终提交**

```powershell
git add runtime crates installer admin docs .github/workflows/release.yml
git commit -m "完成 Anchor Guard 桌面端和在线审计"
```

## Self-Review

- 目录、命名、Tauri 桌面结构、在线审计和 `anchor-viewer` 删除均对应 spec。
- 所有任务都有明确文件、接口、测试命令和预期结果。
- 代码标识保持 `anchor-guard`、`AnchorGuard.Desktop`、`DesktopRequest`、`DesktopLaunchFailed` 一致。
- 当前工作区 WIP 被隔离在独立 worktree，不混入提交。
