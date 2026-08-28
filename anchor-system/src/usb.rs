//! USB 设备监控适配。
//!
//! 后续接入点：Windows 使用设备到达通知和卷挂载事件，Linux 使用 udev 和挂载事件。
//! 事件监听（设备接入、移除、卷挂载）后续迭代补充为独立方法或流式接口。
//! USB 卷内文件监听属于文件事件适配，首迭代由服务直接使用 notify crate 实现，
//! 不属于本 crate 职责。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// USB 设备信任等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// 未识别。
    Unknown,
    /// 未授信，按策略限制使用。
    Untrusted,
    /// 已授信，按策略放行。
    Trusted,
}

/// USB 存储设备信息；探测阶段可能拿不到全部字段，故标识类字段均为 Option。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    /// 设备 ID。
    pub device_id: Option<String>,
    /// 厂商 ID。
    pub vendor_id: Option<String>,
    /// 产品 ID。
    pub product_id: Option<String>,
    /// 设备序列号。
    pub serial: Option<String>,
    /// 卷标识。
    pub volume_id: Option<String>,
    /// 盘符或挂载点。
    pub drive_letter: Option<String>,
    /// 首次接入时间。
    pub first_seen: Option<DateTime<Utc>>,
    /// 最近接入时间。
    pub last_seen: Option<DateTime<Utc>>,
    /// 设备信任等级。
    pub trust_level: TrustLevel,
}

/// USB 设备监控能力。
pub trait UsbMonitor: Send + Sync {
    /// 列出当前已接入的 USB 存储设备。
    fn list_devices(&self) -> Result<Vec<UsbDeviceInfo>, PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::assert_variant_roundtrip;

    #[test]
    fn trust_level_serde_snake_case_roundtrip() {
        assert_variant_roundtrip(&TrustLevel::Unknown, "unknown");
        assert_variant_roundtrip(&TrustLevel::Untrusted, "untrusted");
        assert_variant_roundtrip(&TrustLevel::Trusted, "trusted");
    }
}
