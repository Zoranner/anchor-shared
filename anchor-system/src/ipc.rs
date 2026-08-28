//! 本地通信适配。
//!
//! 后续接入点：Windows 使用 Named Pipe。
//! 承载桌面程序到终端守护服务的本地调用；首迭代不启用，仅占位接口。

use crate::error::PlatformError;

/// 本地 IPC 服务端能力。
pub trait LocalIpc: Send + Sync {
    /// 启动本地 IPC 服务并处理调用（占位，后续补充具体协议）。
    fn serve(&self) -> Result<(), PlatformError>;
}
