# Windows Release Workflow Implementation Plan

> 2026-10-23：发布组装已内联到 `.github/workflows/release.yml`，本文列出的发布脚本已删除；以下内容仅保留为历史实施记录。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 生成可校验的 Windows MSI、管理员策略工具 ZIP 和标签驱动的 GitHub Release。

**Architecture:** `anchor-setup` 只校验安装属性并原子写入本机服务配置；WiX 只负责复制、注册和调用该工具。PowerShell 组装脚本生成统一的产物名、哈希和清单，GitHub Actions 负责协调标签校验、构建和发布。

**Tech Stack:** Rust 2021、WiX Toolset 5、PowerShell、GitHub Actions、SHA-256。

**Spec:** `docs/superpowers/specs/2026-08-28-windows-release-workflow-design.md`

## Global Constraints

- 仅构建 Windows x64；不实现服务端分发、自动更新或远程策略下发。
- 根 `workspace.package.version` 是唯一发布版本；仅接受 `v<版本>` 标签。
- 安装必须提供 `ANCHOR_DEVICE_ID` 和 `ANCHOR_VERIFYING_KEY_HEX`；私钥不得进入 MSI、ZIP、日志或清单。
- 不在开发机注册 DLL、启动真实服务或调用设备控制 API。
- 每项 Rust 改动后执行 `cargo fmt --all` 和严格 Clippy。

---

### Task 1: 安装配置写入器

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/anchor-setup/Cargo.toml`
- Create: `crates/anchor-setup/src/main.rs`
- Create: `crates/anchor-setup/tests/configure.rs`

**Interfaces:**
- Consumes: `anchor-setup write-service-config --config <path> --database <path> --device-id <id> --verifying-key-hex <hex>`。
- Produces: 原子创建的 TOML，字段为 `database`、`verifying_key_hex`、`device_id`。

- [ ] 写入失败测试：空设备标识、无效公钥或写入失败不得替换已有配置。
- [ ] 运行 `cargo test -p anchor-setup`，确认当前 crate 不存在。
- [ ] 实现 Clap 子命令、Ed25519 公钥校验、临时文件写入与 `rename` 替换。
- [ ] 运行 `cargo test -p anchor-setup`、`cargo fmt --all` 和严格 Clippy。
- [ ] 提交：`增加终端安装配置工具`。

### Task 2: WiX 运行端安装包

**Files:**
- Create: `installer/AnchorGuard.wxs`
- Create: `installer/LICENSE.rtf`
- Create: `scripts/test-installer-contract.ps1`

**Interfaces:**
- Consumes: `anchor-service.exe`、`anchor-session.exe`、`anchor-viewer.exe`、`anchor-credential.dll`、`anchor-setup.exe` 与 WiX `ProductVersion`。
- Produces: `anchor-guard-v<版本>-windows-x64.msi`。

- [ ] 编写 PowerShell 契约检查，要求 `ANCHOR_DEVICE_ID`、`ANCHOR_VERIFYING_KEY_HEX`、服务安装、两个 CLSID 与 Credential Provider/Filter 注册项，且拒绝私钥或策略文件来源。
- [ ] 运行 `pwsh -NoProfile -File scripts/test-installer-contract.ps1`，确认当前安装器不存在。
- [ ] 以 WiX 定义 Program Files 运行文件、ProgramData 数据目录、deferred non-impersonated 配置 custom action、`AnchorGuard` 服务与登录组件注册；卸载保留审计数据库。
- [ ] 运行安装器契约检查。
- [ ] 提交：`增加 Windows 终端安装包`。

### Task 3: 发布组装与标签工作流

**Files:**
- Create: `scripts/build-release.ps1`
- Create: `scripts/test-release-contract.ps1`
- Create: `.github/workflows/release.yml`
- Create: `docs/release.md`

**Interfaces:**
- Consumes: `VERSION`、release 二进制、WiX 5 和 `Cargo.lock`。
- Produces: MSI、策略工具 ZIP、`manifest.json` 与 `SHA256SUMS`。

- [ ] 编写静态检查，要求 `v*` 标签、版本校验、`cargo test --workspace`、严格 Clippy、上传产物、SHA-256 和 GitHub Release 步骤。
- [ ] 运行 `pwsh -NoProfile -File scripts/test-release-contract.ps1`，确认当前工作流不存在。
- [ ] 实现 PowerShell 组装脚本：检查输入，调用 WiX，压缩仅含 `anchor-policy.exe` 与示例的 ZIP，计算两项产物 SHA-256，写入清单和 `SHA256SUMS`。
- [ ] 实现 Windows GitHub Actions job：验证标签与 Cargo 版本一致，运行格式、测试、Clippy 与锁定构建，安装固定 WiX，组装、上传并创建或更新 GitHub Release。
- [ ] 记录管理员下载、校验、`msiexec` 安装属性和归还审计导出；运行两项 PowerShell 契约检查、Rust 格式、测试与严格 Clippy。
- [ ] 提交：`建立 Windows 发布工作流`。

## Plan Self-Review

- 版本、标签、构建、发布物和 SHA-256 由 Task 3 覆盖。
- 每设备配置、原子写入和私钥排除由 Task 1 覆盖。
- 服务、登录组件注册与审计保留由 Task 2 覆盖。
