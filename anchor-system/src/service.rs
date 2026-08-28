//! 终端守护服务自保护适配。
//!
//! 服务形态：Windows 使用 Windows Service。
//! 后续接入点：Windows Service 受控权限、程序目录权限保护、卸载授权校验，
//! 防止普通方式停止服务、卸载程序或清除本地审计记录。

use crate::error::PlatformError;

/// 守护服务自保护能力。
pub trait ServiceGuard: Send + Sync {
    /// 校验当前卸载流程是否已获授权（如审批令牌）。
    fn is_uninstall_authorized(&self) -> Result<bool, PlatformError>;

    /// 施加服务与程序目录的保护措施。
    fn enforce_protection(&self) -> Result<(), PlatformError>;
}
