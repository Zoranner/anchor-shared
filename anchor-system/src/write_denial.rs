//! 系统级介质写入拒绝开关。
//!
//! 登录界面下的只读通道要在系统层面拒绝写入，而不是依赖上层软件自觉：可移动介质用
//! `Control\StorageDevicePolicies` 的 `WriteProtect`，CD/DVD 用 `RemovableStorageDevices`
//! 的 `Deny_Write`。两处语义一致（拒绝该介质类别的写入），因此共用一个边界，由各自的设备
//! 执行器实现。

use crate::error::PlatformError;

/// 系统级写入拒绝开关的外部边界。
///
/// 测试通过该 trait 注入记录型开关；生产环境由 [`crate::usb::WindowsUsbStorageExecutor`] 和
/// [`crate::burning::WindowsBurningControlExecutor`] 落地到机器级注册表。
pub trait WriteDenialSwitch {
    /// 读取写入拒绝开关的当前状态。
    fn write_denied(&mut self) -> Result<bool, PlatformError>;

    /// 设置写入拒绝开关；开启后系统拒绝写入该类介质。
    fn set_write_denied(&mut self, denied: bool) -> Result<(), PlatformError>;
}

#[cfg(test)]
mod tests {
    /// 真实注册表读取：两个写入拒绝开关的读取路径都可用。只读查询，不修改系统状态。
    #[cfg(windows)]
    #[test]
    fn write_denial_switches_are_readable() {
        use crate::{
            burning::WindowsBurningControlExecutor, usb::WindowsUsbStorageExecutor,
            write_denial::WriteDenialSwitch,
        };

        assert!(WindowsUsbStorageExecutor.write_denied().is_ok());
        assert!(WindowsBurningControlExecutor.write_denied().is_ok());
    }
}
