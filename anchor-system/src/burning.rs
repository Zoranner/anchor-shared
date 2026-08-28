//! 刻录（光驱）监控适配。
//!
//! 后续接入点：Windows 使用设备策略、Shell 刻录策略和服务状态；刻录进程审计与
//! 任务文件扫描由服务与扫描模块配合完成。

use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// 刻录光驱信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnDriveInfo {
    /// 光驱 ID。
    pub drive_id: String,
    /// 光驱名称。
    pub name: String,
    /// 介质是否存在；探测失败时为 None。
    pub media_present: Option<bool>,
    /// 介质是否可写；探测失败时为 None。
    pub writable: Option<bool>,
}

/// 刻录设备监控能力。
pub trait BurningMonitor: Send + Sync {
    /// 列出全部刻录光驱及其介质状态。
    fn list_drives(&self) -> Result<Vec<BurnDriveInfo>, PlatformError>;
}
