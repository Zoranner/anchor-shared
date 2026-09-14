use crate::error::PlatformError;
#[cfg(windows)]
use crate::pnp;

/// 网卡状态信息；`adapter_id` 是设备实例标识，也是策略匹配的唯一依据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicInfo {
    pub adapter_id: String,
    pub name: String,
    pub enabled: bool,
}

/// 网卡状态控制的外部执行边界。
pub trait NicControlExecutor {
    fn set_enabled(&mut self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError>;
}

/// Windows 10 网卡状态执行器；`adapter_id` 必须是网卡设备实例标识。
#[derive(Debug, Default)]
pub struct WindowsNicControlExecutor;

#[cfg(windows)]
impl NicControlExecutor for WindowsNicControlExecutor {
    fn set_enabled(&mut self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError> {
        pnp::set_enabled(&pnp::NET_CLASS, adapter_id, enabled)
    }
}

#[cfg(not(windows))]
impl NicControlExecutor for WindowsNicControlExecutor {
    fn set_enabled(&mut self, _adapter_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows 网卡控制"))
    }
}
