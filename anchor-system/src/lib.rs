//! Anchor Guard 平台适配层：设备、网卡、刻录、密钥保护与服务控制。

pub mod burning;
pub mod error;
pub mod inventory;
pub mod nic;
pub mod pipe;
pub mod pnp;
pub mod policy_media;
pub mod session;
pub mod usb;
pub mod write_denial;

/// 注册表读写只服务于本 crate 的 Windows 适配，不作为对外能力。
#[cfg(windows)]
mod registry;
