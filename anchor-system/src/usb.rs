//! USB 设备监控适配。
//!
//! 后续接入点：Windows 使用设备到达通知和卷挂载事件。
//! 事件监听（设备接入、移除、卷挂载）后续迭代补充为独立方法或流式接口。
//! USB 卷内文件监听属于文件事件适配，首迭代由服务直接使用 notify crate 实现，
//! 不属于本 crate 职责。

#[cfg(windows)]
use std::process::Command;

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
    /// 仅允许的大容量存储设备恢复启用。
    EnableMassStorage,
    DisableMassStorage,
    /// 不是 USB 大容量存储设备，拒绝执行设备状态变更。
    RejectNonMassStorage,
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
    if !is_usb_mass_storage_instance(&device.instance_id) {
        return UsbControlResult {
            device,
            matched_rule: None,
            planned_action: UsbPlannedAction::RejectNonMassStorage,
        };
    }

    let matched_rule = allowed.iter().position(|rule| rule_matches(rule, &device));
    let planned_action = if matched_rule.is_some() {
        UsbPlannedAction::EnableMassStorage
    } else {
        UsbPlannedAction::DisableMassStorage
    };

    UsbControlResult {
        device,
        matched_rule,
        planned_action,
    }
}

/// 执行 USB 大容量存储设备状态变更的外部边界。
///
/// 测试通过该 trait 注入记录型执行器；生产环境使用
/// [`WindowsUsbStorageExecutor`] 调用 Windows PnPDevice 命令。
pub trait UsbStorageExecutor {
    fn set_mass_storage_enabled(
        &mut self,
        instance_id: &str,
        enabled: bool,
    ) -> Result<(), PlatformError>;
}

/// 按计划执行 USB 大容量存储设备控制。
pub fn apply_usb_storage_control<E>(
    executor: &mut E,
    result: UsbControlResult,
) -> Result<(), PlatformError>
where
    E: UsbStorageExecutor,
{
    match result.planned_action {
        UsbPlannedAction::EnableMassStorage => {
            executor.set_mass_storage_enabled(&result.device.instance_id, true)
        }
        UsbPlannedAction::DisableMassStorage => {
            executor.set_mass_storage_enabled(&result.device.instance_id, false)
        }
        UsbPlannedAction::RejectNonMassStorage => Err(PlatformError::Failed(
            "仅支持 USB 大容量存储设备控制".into(),
        )),
    }
}

/// Windows 10 USB 大容量存储设备执行器。
#[derive(Debug, Default)]
pub struct WindowsUsbStorageExecutor;

#[cfg(windows)]
impl UsbStorageExecutor for WindowsUsbStorageExecutor {
    fn set_mass_storage_enabled(
        &mut self,
        instance_id: &str,
        enabled: bool,
    ) -> Result<(), PlatformError> {
        if !is_usb_mass_storage_instance(instance_id) {
            return Err(PlatformError::Failed(
                "仅支持 USB 大容量存储设备控制".into(),
            ));
        }

        let action = if enabled {
            "Enable-PnpDevice -InstanceId $args[0] -Confirm:$false -ErrorAction Stop"
        } else {
            "Disable-PnpDevice -InstanceId $args[0] -Confirm:$false -ErrorAction Stop"
        };
        run_powershell(action, instance_id, "USB 大容量存储设备")
    }
}

#[cfg(not(windows))]
impl UsbStorageExecutor for WindowsUsbStorageExecutor {
    fn set_mass_storage_enabled(
        &mut self,
        _instance_id: &str,
        _enabled: bool,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows USB 大容量存储设备控制"))
    }
}

fn rule_matches(rule: &UsbAllowRule, device: &UsbStorageDevice) -> bool {
    let has_identifier = [
        rule.instance_id.as_deref(),
        rule.vendor_id.as_deref(),
        rule.product_id.as_deref(),
        rule.serial.as_deref(),
    ]
    .into_iter()
    .any(|value| value.is_some_and(|value| !value.trim().is_empty()));

    has_identifier
        && matches_optional(&rule.instance_id, Some(&device.instance_id))
        && matches_optional(&rule.vendor_id, device.vendor_id.as_ref())
        && matches_optional(&rule.product_id, device.product_id.as_ref())
        && matches_optional(&rule.serial, device.serial.as_ref())
}

fn matches_optional(expected: &Option<String>, actual: Option<&String>) -> bool {
    expected.as_ref().is_none_or(|value| Some(value) == actual)
}

fn is_usb_mass_storage_instance(instance_id: &str) -> bool {
    instance_id
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("USBSTOR\\"))
}

#[cfg(windows)]
fn run_powershell(action: &str, instance_id: &str, target: &str) -> Result<(), PlatformError> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", action])
        .arg(instance_id)
        .output()
        .map_err(|error| PlatformError::Failed(format!("启动 {target} 控制命令失败: {error}")))?;

    if output.status.success() {
        return Ok(());
    }

    Err(PlatformError::Failed(format!(
        "{target} 控制命令失败: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
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
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };

        let result = plan_usb_storage_control(device, &[]);

        assert_eq!(result.matched_rule, None);
        assert_eq!(result.planned_action, UsbPlannedAction::DisableMassStorage);
    }

    #[test]
    fn empty_allow_rule_is_not_a_wildcard_for_mass_storage() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };

        let result = plan_usb_storage_control(device, &[UsbAllowRule::default()]);

        assert_eq!(result.matched_rule, None);
        assert_eq!(result.planned_action, UsbPlannedAction::DisableMassStorage);
    }

    #[test]
    fn all_specified_rule_fields_must_match() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
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
        assert_eq!(result.planned_action, UsbPlannedAction::EnableMassStorage);
    }

    #[test]
    fn unlisted_mass_storage_is_disabled_through_the_injected_executor() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        };
        let mut executor = RecordingUsbExecutor::default();

        apply_usb_storage_control(&mut executor, plan_usb_storage_control(device, &[])).unwrap();

        assert_eq!(
            executor.calls,
            vec![("USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(), false)]
        );
    }

    #[test]
    fn allowed_mass_storage_is_restored_through_the_injected_executor() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        };
        let allowed = [UsbAllowRule {
            instance_id: Some(device.instance_id.clone()),
            ..UsbAllowRule::default()
        }];
        let mut executor = RecordingUsbExecutor::default();

        apply_usb_storage_control(&mut executor, plan_usb_storage_control(device, &allowed))
            .unwrap();

        assert_eq!(
            executor.calls,
            vec![("USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(), true)]
        );
    }

    #[test]
    fn non_mass_storage_never_reaches_the_executor() {
        let device = UsbStorageDevice {
            instance_id: "USB\\VID_1234&PID_5678\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        };
        let mut executor = RecordingUsbExecutor::default();

        let error = apply_usb_storage_control(&mut executor, plan_usb_storage_control(device, &[]))
            .unwrap_err();

        assert!(matches!(error, PlatformError::Failed(_)));
        assert!(executor.calls.is_empty());
    }

    #[derive(Default)]
    struct RecordingUsbExecutor {
        calls: Vec<(String, bool)>,
    }

    impl UsbStorageExecutor for RecordingUsbExecutor {
        fn set_mass_storage_enabled(
            &mut self,
            instance_id: &str,
            enabled: bool,
        ) -> Result<(), PlatformError> {
            self.calls.push((instance_id.into(), enabled));
            Ok(())
        }
    }
}
