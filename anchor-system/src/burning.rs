use crate::error::PlatformError;
#[cfg(windows)]
use crate::pnp;

/// 刻录光驱信息；`drive_id` 是设备实例标识，也是策略匹配的唯一依据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnDriveInfo {
    pub drive_id: String,
    pub name: String,
    pub enabled: bool,
}

/// 光驱状态控制的外部执行边界。
pub trait BurningControlExecutor {
    fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError>;
}

/// Windows 10 刻录光驱状态执行器。
#[derive(Debug, Default)]
pub struct WindowsBurningControlExecutor;

#[cfg(windows)]
impl BurningControlExecutor for WindowsBurningControlExecutor {
    fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError> {
        pnp::set_enabled(&pnp::CDROM_CLASS, drive_id, enabled)
    }
}

#[cfg(not(windows))]
impl BurningControlExecutor for WindowsBurningControlExecutor {
    fn set_enabled(&mut self, _drive_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows 刻录光驱控制"))
    }
}
