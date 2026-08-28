//! USB 设备监控适配。
//!
//! 后续接入点：Windows 使用设备到达通知和卷挂载事件。
//! 事件监听（设备接入、移除、卷挂载）后续迭代补充为独立方法或流式接口。
//! USB 卷内文件监听属于文件事件适配，首迭代由服务直接使用 notify crate 实现，
//! 不属于本 crate 职责。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// 大容量存储设备的稳定标识，用于按策略匹配。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbStorageDevice {
    pub instance_id: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial: Option<String>,
}

/// 一条 USB 大容量存储允许规则。所有已填写字段必须同时匹配。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbAllowRule {
    pub instance_id: Option<String>,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial: Option<String>,
}

/// 平台适配层观测到的设备处置意图，不直接调用禁用 API。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsbPlannedAction {
    KeepEnabled,
    DisableMassStorage,
}

/// USB 存储设备的观测与计划处置结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbControlResult {
    pub device: UsbStorageDevice,
    pub matched_rule: Option<usize>,
    pub planned_action: UsbPlannedAction,
}

/// 仅计算 USB 大容量存储设备的处置计划；未被允许的设备默认拒绝。
pub fn plan_usb_storage_control(
    device: UsbStorageDevice,
    allowed: &[UsbAllowRule],
) -> UsbControlResult {
    let matched_rule = allowed.iter().position(|rule| rule_matches(rule, &device));
    let planned_action = if matched_rule.is_some() {
        UsbPlannedAction::KeepEnabled
    } else {
        UsbPlannedAction::DisableMassStorage
    };

    UsbControlResult {
        device,
        matched_rule,
        planned_action,
    }
}

fn rule_matches(rule: &UsbAllowRule, device: &UsbStorageDevice) -> bool {
    matches_optional(&rule.instance_id, Some(&device.instance_id))
        && matches_optional(&rule.vendor_id, device.vendor_id.as_ref())
        && matches_optional(&rule.product_id, device.product_id.as_ref())
        && matches_optional(&rule.serial, device.serial.as_ref())
}

fn matches_optional(expected: &Option<String>, actual: Option<&String>) -> bool {
    expected.as_ref().is_none_or(|value| Some(value) == actual)
}

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

    #[test]
    fn unlisted_mass_storage_is_planned_for_disable() {
        let device = UsbStorageDevice {
            instance_id: "USB\\VID_1234&PID_5678\\1".into(),
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };

        let result = plan_usb_storage_control(device, &[]);

        assert_eq!(result.matched_rule, None);
        assert_eq!(result.planned_action, UsbPlannedAction::DisableMassStorage);
    }

    #[test]
    fn all_specified_rule_fields_must_match() {
        let device = UsbStorageDevice {
            instance_id: "USB\\VID_1234&PID_5678\\1".into(),
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };
        let allowed = [UsbAllowRule {
            vendor_id: Some("1234".into()),
            serial: Some("1".into()),
            ..UsbAllowRule::default()
        }];

        let result = plan_usb_storage_control(device, &allowed);

        assert_eq!(result.matched_rule, Some(0));
        assert_eq!(result.planned_action, UsbPlannedAction::KeepEnabled);
    }
}
