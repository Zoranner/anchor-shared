# Anchor Guard Credential Provider

此 crate 产出 Windows Credential Provider DLL。它包含两个 COM 类：

- Provider `{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}`：仅显示状态和“导入策略”命令。
- Filter `{B4D4951B-D540-4421-A90C-19E1BBABAFB8}`：只在登录和解锁时查询本地服务；服务超时、不可用或返回无效响应时拒绝系统登录项，只保留 Provider CLSID。

Provider 不收集路径、密钥、PIN 或用户凭据。导入动作固定向本地服务发送 `ImportFromPolicyMedia`；服务接受导入后，Provider 调用 `CredentialsChanged` 让 LogonUI 重新枚举登录项。

## Windows 注册和验证

只在隔离的 Windows 10 虚拟机中进行。先创建 VM 快照，并保留一个可用的本机管理员恢复账户。以下命令须在提升权限的 PowerShell 中执行，`$dll` 必须替换为已签名 DLL 的绝对路径。

DLL 只导出 COM 激活入口，不提供 `DllRegisterServer`，因此不要使用 `regsvr32`；按下列注册表项显式注册。

```powershell
$dll = 'C:\AnchorGuard\anchor_credential.dll'
$service = 'C:\AnchorGuard\anchor-service.exe'
$config = 'C:\ProgramData\AnchorGuard\service.toml'

@'
database = "C:\\ProgramData\\AnchorGuard\\audit.db"
verifying_key_hex = "管理员验证公钥的64位十六进制值"
device_id = "安装时登记的设备标识"
'@ | Set-Content -LiteralPath $config -Encoding ascii

sc.exe create AnchorGuard binPath= "`"$service`" --config `"$config`"" start= auto
Start-Service AnchorGuard
New-Item -Path 'HKLM:\SOFTWARE\Classes\CLSID\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}\InprocServer32' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\CLSID\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}\InprocServer32' -Name '(Default)' -Value $dll
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\CLSID\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}\InprocServer32' -Name 'ThreadingModel' -Value 'Apartment'
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}' -Name '(Default)' -Value 'Anchor Guard 策略导入'
New-Item -Path 'HKLM:\SOFTWARE\Classes\CLSID\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}\InprocServer32' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\CLSID\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}\InprocServer32' -Name '(Default)' -Value $dll
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\CLSID\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}\InprocServer32' -Name 'ThreadingModel' -Value 'Apartment'
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}' -Name '(Default)' -Value 'Anchor Guard 登录过滤'
```

注册前必须确认 `AnchorGuard` 服务已运行，且其本地 Named Pipe 可用。随后锁定、解锁并重启虚拟机，分别验证有效策略、无策略、服务停止和策略介质导入。任何无法恢复的登录状态都应立即还原 VM 快照。

## 管理员卸载恢复

管理员恢复时，先停止注册后的验证，删除两个认证注册项及对应的 `CLSID` 项，再重启系统：

```powershell
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}' -Recurse -Force
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}' -Recurse -Force
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Classes\CLSID\{B4D4951B-D540-4421-A90C-19E1BBABAFB8}' -Recurse -Force
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Classes\CLSID\{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}' -Recurse -Force
Restart-Computer
```

这是一层本地登录控制，不阻止本机管理员获得系统控制权、移除 DLL 或恢复系统状态。部署前仍须完成真实 Windows LogonUI、服务权限和恢复流程验收。
