# Windows 发布工作流设计

## 目标

为 Anchor Guard 建立可重复的 Windows 发布流程：版本标签触发构建，产出笔记本 MSI、管理电脑策略工具 ZIP，以及可校验的发布清单。

## 边界

发布流程负责构建、打包、校验和发布产物，不负责服务端分发、远程更新或策略下发。每台设备的 `device_id` 和管理员验证公钥是安装输入，不写入 Git、CI 日志、MSI 或公开发布附件。

当前采用 GitHub Actions，与 `adscope-identity` 一致使用 `v<版本>` 标签和 GitHub Release。当前仓库没有远端配置，工作流只定义仓库内动作，不创建标签、推送或发布。

## 发布物

- `anchor-guard-v<版本>-windows-x64.msi`：包含 Windows 服务、会话协作程序、Credential Provider DLL 和审计导出工具。
- `anchor-guard-policy-v<版本>-windows-x64.zip`：包含管理电脑使用的 `anchor-policy.exe` 与策略示例，不包含私钥。
- `manifest.json`：版本、提交、目标、文件名与 SHA-256。
- `SHA256SUMS`：与清单一致的校验和列表。

策略签发工具与笔记本运行端分离，避免把私钥或策略管理职责带入笔记本。

## 版本与构建

根 `workspace.package.version` 是唯一版本事实。工作流仅接受 `v<版本>` 标签，并验证其等于 workspace 版本。Windows runner 使用 `Cargo.lock` 构建：先执行格式检查、全目标测试和严格 Clippy，再执行 release build 和 WiX MSI 组装；任一步失败均不进入发布。

## 安装配置

MSI 需要两个公开安装属性：`ANCHOR_DEVICE_ID` 和 `ANCHOR_VERIFYING_KEY_HEX`。随包提供的 Rust `anchor-setup` 验证这两项输入并以临时文件替换的方式写入 `C:\ProgramData\Anchor Guard\service.toml`，数据库固定在同目录 `audit.db`。它拒绝空标识、换行和无效 Ed25519 公钥，且永不接受或保存管理员私钥。

MSI 先复制文件和创建数据目录，再写配置，随后安装并启动 `AnchorGuard` 服务。Credential Provider、Filter 与 CLSID 注册项由 MSI 组件管理；卸载移除服务、程序和注册项，但保留 `ProgramData` 审计数据。

## 文件职责

- `.github/workflows/release.yml`：标签校验、Windows 验证与构建、发布物组装和 GitHub Release。
- `crates/anchor-setup/`：安装输入校验和本机服务配置写入。
- `installer/AnchorGuard.wxs`：WiX MSI、服务、配置 custom action 和登录组件注册。
- `docs/release.md`：管理员安装、校验和归还审计边界。

## 验证

Rust 改动运行 `cargo fmt --all`、`cargo test --workspace` 和严格 Clippy。发布工作流校验标签与 workspace 版本，并在构建阶段确认发布输入和二进制齐全。WiX 实际编译仅在 Windows CI 或隔离 Windows 10 虚拟机执行；当前开发机不注册 Credential Provider、不启动真实服务、不调用设备控制 API。
