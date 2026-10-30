# Windows 发布与安装

## 本地构建与打包

客户端仓库是 `anchor-client`，构建和打包统一由仓库根目录的 `anchor-build` 执行：

```powershell
Set-Location anchor-client
cargo run --release --locked -- release
```

该命令先构建客户端 Rust workspace，再构建桌面端，最后调用 WiX 生成安装包，输出目录为 `anchor-client/release/`。发布工作流的 Windows 构建任务使用同一条命令。

## 创建发布

客户端发布时，修改 `anchor-client/Cargo.toml` 的 workspace 版本，以及 `desktop/package.json`、`desktop/src-tauri/Cargo.toml` 和 `desktop/src-tauri/tauri.conf.json`，在 `anchor-client` 仓库推送 `v<版本>` 标签。客户端工作流会校验版本、测试、格式和 Clippy，并上传：

- `anchor-guard-v<版本>-windows-x64.msi`

服务端发布时，修改 `anchor-server/Cargo.toml` 的 workspace 版本，在 `anchor-server` 仓库推送独立的 `v<版本>` 标签。服务端工作流会校验版本、测试、管理台、格式和 Clippy，并推送镜像 `ghcr.io/zoranner/anchor-server:<版本>`。

共享 crate 发布时，修改 `anchor-shared/Cargo.toml` 的 workspace 版本并推送 `v<版本>` 标签，然后更新 `anchor-client` 和 `anchor-server` 的 `crates/shared` 子模块指针。客户端和服务端版本互不相等，不使用统一版本号。

## 下载与策略

已签名策略包由服务端管理台导出，私钥只保存在服务端加密密钥文件中，不进入 MSI、策略包或发布目录。

策略可以完全锁死，签发不需要为任何设备开例外。更新策略时把新的 `anchor-guard.policy` 放到设备本地卷根目录：无策略、策略过期或服务停止时，登录页保留导入项，可以在登录页直接导入；授权有效时登录页只显示系统登录项，已登录用户可从桌面端提前导入新策略。

## 部署服务端

服务端按版本镜像部署，不按部署实例重新构建。将 `anchor-server/deploy` 复制到宿主机，以 `.env.example` 创建 `.env`，生成主密钥文件和初始化令牌，确认 Compose 使用的镜像是本次发布的版本后启动：

```powershell
docker network create anchor
docker compose -f deploy/docker-compose.yml up -d
```

外部网络 `anchor` 已存在时跳过创建命令。Compose 只使用宿主机目录保存 PostgreSQL 数据、应用数据和主密钥，不使用 named volume；主密钥通过只读 bind mount 注入，不能写入镜像、数据库或日志。

镜像包含管理台静态文件，`anchor-server` 默认从 `ANCHOR_WEB_DIR=/app/web` 提供页面；本地开发可将其指向 `anchor-server/web/.output/public`。管理台会话 Cookie 带 `Secure`，生产访问必须使用 HTTPS。首次启动后在浏览器打开服务地址，使用部署时配置的 `ANCHOR_SETUP_TOKEN` 完成管理员和签名密钥初始化。

## 安装 Windows 客户端

在隔离 Windows 10 测试机的提升权限 PowerShell 中，把安装包解析成绝对路径后填写服务端地址和端口：

```powershell
$msi = (Resolve-Path .\anchor-guard-v0.1.2-windows-x64.msi).Path
msiexec /i $msi /qn ANCHOR_SERVER_ADDRESS="anchor.example.com" ANCHOR_SERVER_PORT="8443"
```

`msiexec /i` 的参数不要保留 `.\` 前缀：部分环境会因此报 MSI 错误 1324（`Folder path '.' contains an invalid character`），并在执行任何动作前中止安装。

`ANCHOR_SERVER_ADDRESS` 只填写主机名或 IP，不包含端口和路径；显式指定协议时只允许回环地址使用 HTTP。`ANCHOR_SERVER_PORT` 省略时默认为 8080。安装器据此生成 `server_url`，写入 `C:\ProgramData\Anchor Guard\service.toml`，审计库位于同目录 `audit.db`；安装服务、会话协作程序、桌面端和登录组件，并创建开始菜单快捷方式。

安装不要求设备标识或验证公钥。客户端首次启动生成安装标识，注册后由管理员在服务端审批，批准后通过服务端同步验证公钥和策略。

卸载会移除受 MSI 管理的程序、服务和登录注册项，并保留 `ProgramData` 中的审计数据库供归还留存。首次安装和卸载恢复只能在隔离 Windows 10 测试机进行。

## 在线审计

登录后服务会拉起当前会话的桌面端，开始菜单快捷方式用于手动恢复窗口。审计日志页通过服务只读查询事件和整库 hash chain 结论，可按事件类型、用户、策略版本和资源前缀筛选，并用游标分页继续加载。

本期不提供独立导出 CLI。需要归还留存时，由管理员按内部流程复制 `C:\ProgramData\Anchor Guard\audit.db`，保留原始数据库；空库、断链或无法读取数据库不能作为有效审计材料。
