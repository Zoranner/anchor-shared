# Windows 本地终端管控实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建管理员离线签发、U 盘导入、到期拒绝 Windows 正常登录并保留本地审计的 Windows 10 终端管控系统。

**Architecture:** `anchor-service` 是策略、授权、设备执行和审计的唯一组织者。`anchor-credential` 只通过 Named Pipe 查询授权并提供导入登录项；策略、存储、扫描、Windows 系统 API 和导出分属独立 crate。

**Tech Stack:** Rust 2021、Windows Service、Credential Provider COM、Named Pipe、SQLite、Ed25519、SHA-256、Clap、TOML、JSON。

**Spec:** `docs/design.md`

## 全局约束

- 仅支持 Windows 10；不实现 Linux、服务端、内网自动更新、远程审批或内核文件拦截。
- 管理员私钥只存于管理电脑；笔记本只保存管理员公钥和 `device_id`。
- 策略包只能从 U 盘根目录的 `anchor-guard.policy` 导入，U 盘不是信任根。
- USB 存储、网卡、刻录默认拒绝；文件扫描只识别并审计，不修改文件。
- 授权不明时只显示导入策略登录项。
- 每项 Rust 改动后执行 `cargo fmt --all` 和 `cargo clippy --all-targets --all-features -- -D warnings`。

## 策略核心与 workspace

**Files:**
- Modify: `Cargo.toml`, `crates/anchor-core/src/lib.rs`, `crates/anchor-core/src/policy.rs`, `crates/anchor-core/src/audit.rs`, `crates/anchor-core/src/error.rs`
- Delete: `crates/anchor-core/src/approval.rs`, `crates/anchor-server/`
- Create: `crates/anchor-policy/`, `crates/anchor-system/`, `crates/anchor-credential/`

**Produces:** `PolicyPackage`, `ImportDecision`, `AuthorizationState`, `evaluate_authorization`。

- [ ] 写入以下失败测试：

```rust
assert_eq!(decide_import(&package, &verifying_key, "laptop-1", Some(1), now), ImportDecision::Accept);
```

- [ ] 运行 `cargo test -p anchor-core signed_current_policy_for_the_registered_device_is_accepted`，确认旧模型缺少 `decide_import`。
- [ ] 将策略载荷替换为 `policy_id`、`version`、`device_id`、`effective_from`、`effective_until`、`clock_rollback_tolerance_secs`、`usb`、`network`、`burning`、`scan` 和签名；删除设备组、设备模式、审批令牌与服务端语义。
- [ ] 实现 `decide_import`，按签名、设备、严格版本递增、当前有效期顺序拒绝无效包；实现 `evaluate_authorization`，按活动包、审计健康、最后可信时间和回拨容差返回 `Allowed` 或明确拒绝原因。
- [ ] 扩展审计事件为导入、授权拒绝、时间回拨、会话锁定和协作程序异常；测试篡改、错误设备、版本回退、未生效、过期、链异常和回拨。
- [ ] 运行 `cargo test -p anchor-core && cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`，然后提交“重构本地策略核心”。

## 管理员策略签发

**Files:**
- Modify: `crates/anchor-policy/Cargo.toml`, `crates/anchor-policy/src/main.rs`
- Create: `crates/anchor-policy/tests/cli.rs`, `docs/policy-example.toml`

**Produces:** 管理电脑上的密钥文件和已签名策略包。

- [ ] 写入端到端失败测试：调用 `anchor-policy keygen --out <临时目录>`、再执行 `sign`，最后用 `anchor-core` 读取公钥验证生成包。
- [ ] 实现 `keygen --out <目录>`，生成 `signing-key.hex` 与 `verifying-key.hex`，任一目标已存在即失败。
- [ ] 实现 `sign --key <私钥> --config <TOML> --out <JSON>`，把 TOML 显式转换为策略载荷再签名；空设备 ID、结束时间不晚于开始时间、负容差、空扫描目录和没有允许规则的配置必须非零退出。
- [ ] 编写无真实设备和私钥的完整示例 TOML，运行 `cargo test -p anchor-policy && cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`，然后提交“增加离线策略签发工具”。

## 本地策略、审计与导入服务

**Files:**
- Replace: `crates/anchor-store/src/lib.rs`, `crates/anchor-store/src/types.rs`
- Create: `crates/anchor-store/src/schema.rs`, `crates/anchor-store/src/repository.rs`
- Replace: `crates/anchor-service/src/lib.rs`, `crates/anchor-service/src/main.rs`
- Create: `crates/anchor-service/src/authority.rs`, `crates/anchor-service/src/import.rs`, `crates/anchor-service/src/protocol.rs`, `crates/anchor-service/tests/import_flow.rs`

**Produces:** `Store::import_policy`、`Store::audit_health`、`Service::authorization_state`、`Service::import_from_removable_roots` 以及只含授权查询和导入请求的 IPC。

- [ ] 写入失败测试，断言设备不匹配的 U 盘包不会替换版本 3 的活动策略，并产生一条拒绝审计事件。
- [ ] 建立 `policies`、`audit_events`、`scan_index`、`device_state`、`runtime_state` 五张表；`import_policy` 在单一事务内先追加审计，再替换活动包和运行状态。
- [ ] `audit_health` 按事件顺序读取并调用 `verify_chain`；数据库不可读、JSON 错误和链断裂必须使服务拒绝授权。
- [ ] 定义 `AgentRequest::GetAuthorization`、`AgentRequest::ImportFromRemovableRoots` 及对应响应；使用长度前缀 JSON，单消息上限 64 KiB，协议错误、超时与服务错误均返回拒绝。
- [ ] 导入器只接受名为 `anchor-guard.policy` 的可移动盘根目录文件；每次未找到、解析失败、验签失败、拒绝和成功都写审计。
- [ ] 运行 `cargo test -p anchor-store -p anchor-service && cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`，然后提交“实现本地策略导入和审计存储”。

## Windows 适配、扫描与设备控制

**Files:**
- Create: `crates/anchor-system/src/removable.rs`, `pipe.rs`, `session.rs`, `usb.rs`, `network.rs`, `burning.rs`
- Replace: `crates/anchor-scan/src/lib.rs`
- Create: `crates/anchor-scan/src/extract.rs`, `matcher.rs`, `index.rs`
- Create: `crates/anchor-service/src/enforce.rs`, `crates/anchor-service/tests/enforce.rs`

**Produces:** 可移动盘枚举、Named Pipe、会话锁定协作程序、USB/网卡/刻录控制器和只读扫描器。

- [ ] 写入失败测试，断言未列入策略的 USB 大容量存储设备被禁用，且扫描命中文件后文件内容未变化。
- [ ] `removable_roots` 只返回 `DRIVE_REMOVABLE` 且已就绪的根目录；Named Pipe 仅允许本机受控 SID 连接；会话模块为每个交互会话启动只调用 `LockWorkStation` 的协作程序。
- [ ] USB 后端只处理大容量存储，按实例 ID、VID/PID、序列号匹配允许规则；网卡和刻录后端仅恢复显式允许对象。控制器先返回观测与动作，服务再写审计和 `device_state`。
- [ ] 扫描器按扩展名与稳定窗口扫描：`txt`、`csv` 读取文本，Office Open XML 从 ZIP XML 提取文本，PDF 标记为不支持提取；关键字使用 Aho-Corasick，正则使用 `regex`。
- [ ] 在服务启动、策略导入、设备状态变化时调用 `Service::apply_policy`；拒绝授权时禁用受控设备再请求会话锁定。扫描命中或错误先写审计后更新索引。
- [ ] 运行 `cargo test -p anchor-scan -p anchor-system -p anchor-service && cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`，然后提交“接入 Windows 本地管控执行”。

## Windows 登录过滤与策略恢复

**Files:**
- Modify: `crates/anchor-credential/Cargo.toml`, `crates/anchor-credential/src/lib.rs`
- Create: `crates/anchor-credential/src/provider.rs`, `filter.rs`, `fields.rs`, `ipc.rs`, `README.md`

**Produces:** `ICredentialProvider` 导入 tile 和 `ICredentialProviderFilter`；二者只使用服务 IPC。

- [ ] 写入失败测试：`AuthorizationState::Denied` 时 `filter_provider_ids` 只返回 Anchor Provider CLSID。
- [ ] 实现 Filter：在控制台登录和工作站解锁场景向服务查询授权，使用固定短超时；无响应等同 `Denied(ServiceUnavailable)`，仅启用 Anchor Provider。
- [ ] 实现 Provider：显示状态与“导入策略”按钮，按钮只发送导入请求，不接收路径、私钥、PIN 或用户凭据；导入成功后调用 `CredentialsChanged` 刷新系统 providers。
- [ ] 任何 COM、IPC、导入或服务错误都保持仅导入状态，并由服务写入审计。README 记录 DLL 注册、服务先启动后注册、虚拟机快照验证和管理员卸载恢复命令，不宣称可阻止本机管理员绕过。
- [ ] 运行 `cargo test -p anchor-credential && cargo build -p anchor-credential && cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`，然后提交“增加授权到期登录过滤”。

## 审计导出与 Windows 验收

**Files:**
- Replace: `crates/anchor-viewer/src/main.rs`
- Create: `crates/anchor-viewer/tests/export.rs`, `docs/windows-test-matrix.md`

**Produces:** `anchor-viewer verify --db <路径>`、`anchor-viewer export --db <路径> --out <目录>`、`audit.jsonl` 与 `verification.json`。

- [ ] 写入失败测试：导出包含审计 JSONL 和状态为 `valid` 的报告；链断裂或数据库不可读时，报告只能为 `invalid` 或 `unavailable`。
- [ ] 实现 `verify` 和 `export`。导出必须先验证链，不能把空库、断链或不可读库写为审计通过。
- [ ] 编写 Windows 10 验收矩阵，逐项覆盖无策略安装、有效与无效 U 盘、设备不匹配、版本回退、到期、时间回拨、服务停止、快速用户切换、重启、设备默认拒绝、扫描命中、链篡改和归还导出；每项给出前置条件、操作、预期登录状态、设备状态和审计事件。
- [ ] 运行 `cargo test --workspace && cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`，然后提交“完善归还审计与验收”。

## 计划自检

- 策略签名、设备绑定、版本、有效期、时间回拨和 U 盘导入由“策略核心与 workspace”“管理员策略签发”“本地策略、审计与导入服务”覆盖。
- SQLite、hash chain、运行状态和归还审计由“本地策略、审计与导入服务”及“审计导出与 Windows 验收”覆盖。
- USB、网卡、刻录和文件风险识别由“Windows 适配、扫描与设备控制”覆盖。
- Credential Provider、动态 Filter、到期锁定和 U 盘恢复由“Windows 登录过滤与策略恢复”覆盖。
