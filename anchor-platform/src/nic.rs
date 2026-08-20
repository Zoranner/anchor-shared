//! 网卡控制适配。
//!
//! 后续接入点：Windows 使用网络适配器管理接口，Linux 使用 NetworkManager、
//! systemd-networkd 或 iproute2；防火墙接口与企业终端管理策略配合执行。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// 网卡类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NicKind {
    /// 有线网卡。
    Wired,
    /// Wi-Fi 网卡。
    WiFi,
    /// 虚拟网卡。
    Virtual,
}

/// 网卡状态信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicInfo {
    /// 网卡 ID。
    pub adapter_id: String,
    /// 网卡名称。
    pub name: String,
    /// 有线、Wi-Fi 或虚拟。
    pub kind: NicKind,
    /// MAC 地址。
    pub mac: Option<String>,
    /// 启用状态。
    pub enabled: bool,
    /// 连接网络摘要。
    pub connected_network: Option<String>,
    /// 内网识别结果。
    pub is_intranet: Option<bool>,
    /// 最近变化时间。
    pub last_change: Option<DateTime<Utc>>,
}

/// 网卡查询与控制能力。
pub trait NicController: Send + Sync {
    /// 列出全部网卡及其状态。
    fn list_adapters(&self) -> Result<Vec<NicInfo>, PlatformError>;

    /// 启用或停用指定网卡。
    fn set_enabled(&self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::assert_variant_roundtrip;

    #[test]
    fn nic_kind_serde_snake_case_roundtrip() {
        assert_variant_roundtrip(&NicKind::Wired, "wired");
        assert_variant_roundtrip(&NicKind::WiFi, "wi_fi");
        assert_variant_roundtrip(&NicKind::Virtual, "virtual");
    }
}
