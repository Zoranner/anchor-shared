use crate::error::PlatformError;
#[cfg(windows)]
use crate::pnp;
use crate::write_denial::WriteDenialSwitch;

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

/// CD/DVD 写入拒绝开关所在的注册表键；对应 `RemovableStorage.admx` 的机器范围策略。
#[cfg(windows)]
const WRITE_DENIAL_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}";
/// 写入拒绝开关的值名；非零表示拒绝写入 CD/DVD。
#[cfg(windows)]
const WRITE_DENIAL_VALUE: &str = "Deny_Write";

/// Windows 10 刻录光驱状态执行器。
#[derive(Debug, Default)]
pub struct WindowsBurningControlExecutor;

#[cfg(windows)]
impl BurningControlExecutor for WindowsBurningControlExecutor {
    fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError> {
        pnp::set_enabled(&pnp::CDROM_CLASS, drive_id, enabled)
    }
}

#[cfg(windows)]
impl WriteDenialSwitch for WindowsBurningControlExecutor {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        Ok(
            crate::registry::read_machine_dword(WRITE_DENIAL_KEY, WRITE_DENIAL_VALUE)?
                .is_some_and(|value| value != 0),
        )
    }

    fn set_write_denied(&mut self, denied: bool) -> Result<(), PlatformError> {
        crate::registry::write_machine_dword(
            WRITE_DENIAL_KEY,
            WRITE_DENIAL_VALUE,
            u32::from(denied),
        )
    }
}

#[cfg(not(windows))]
impl BurningControlExecutor for WindowsBurningControlExecutor {
    fn set_enabled(&mut self, _drive_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows 刻录光驱控制"))
    }
}

#[cfg(not(windows))]
impl WriteDenialSwitch for WindowsBurningControlExecutor {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported("Windows CD/DVD 写入拒绝"))
    }

    fn set_write_denied(&mut self, _denied: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows CD/DVD 写入拒绝"))
    }
}
