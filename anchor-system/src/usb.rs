//! USB 设备监控适配。
//!
//! 后续接入点：Windows 使用设备到达通知和卷挂载事件。
//! 事件监听（设备接入、移除、卷挂载）后续迭代补充为独立方法或流式接口。
//! USB 卷内文件监听属于文件事件适配，首迭代由服务直接使用 notify crate 实现，
//! 不属于本 crate 职责。

use crate::error::PlatformError;
#[cfg(windows)]
use crate::pnp;
use crate::write_denial::WriteDenialSwitch;

/// 大容量存储设备的稳定标识，用于按策略匹配。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbStorageDevice {
    pub instance_id: String,
    /// 观测到的启用状态；被禁用的大容量存储设备不会出现在磁盘枚举中。
    pub enabled: bool,
    /// 介质是否可移动（`CM_DEVCAP_REMOVABLE`）。
    ///
    /// 登录界面只放行可移动介质：它们重新挂载时会读取系统写保护开关，因而能真正变成只读；
    /// 固定类型卷做不到这一点，只能保持禁用。
    pub removable: bool,
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
    /// 登录界面下的可移动介质：启用为只读导入通道。
    EnableMassStorageReadOnly,
    DisableMassStorage,
    /// 保持现状：没有可依据的策略结论，也不属于登录界面的只读通道。
    KeepCurrentState,
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
///
/// `allowlist` 为 `None` 表示没有可依据的策略结论：解锁时不处置设备，登录界面下只放行可移动
/// 介质的只读通道。`logon_ui_active` 为真表示当前显示登录界面，没有已解锁的交互会话，登录
/// 界面必须能读到介质上的策略文件。`matched_rule` 始终反映策略匹配结果，登录界面的通道不改变它。
pub fn plan_usb_storage_control(
    device: UsbStorageDevice,
    allowlist: Option<&[UsbAllowRule]>,
    logon_ui_active: bool,
) -> UsbControlResult {
    if !is_usb_mass_storage_instance(&device.instance_id) {
        return UsbControlResult {
            device,
            matched_rule: None,
            planned_action: UsbPlannedAction::RejectNonMassStorage,
        };
    }

    let matched_rule =
        allowlist.and_then(|allowed| allowed.iter().position(|rule| rule_matches(rule, &device)));
    let planned_action = if logon_ui_active {
        if device.removable {
            UsbPlannedAction::EnableMassStorageReadOnly
        } else if allowlist.is_some() {
            UsbPlannedAction::DisableMassStorage
        } else {
            UsbPlannedAction::KeepCurrentState
        }
    } else if allowlist.is_none() {
        UsbPlannedAction::KeepCurrentState
    } else if matched_rule.is_some() {
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

/// 可移动介质写保护开关所在的注册表键。
#[cfg(windows)]
const WRITE_PROTECT_KEY: &str = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
/// 写保护开关的值名；非零表示可移动介质只读。
#[cfg(windows)]
const WRITE_PROTECT_VALUE: &str = "WriteProtect";

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
        pnp::set_enabled(&pnp::DISK_DRIVE_CLASS, instance_id, enabled)
    }
}

#[cfg(windows)]
impl WriteDenialSwitch for WindowsUsbStorageExecutor {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        Ok(
            crate::registry::read_machine_dword(WRITE_PROTECT_KEY, WRITE_PROTECT_VALUE)?
                .is_some_and(|value| value != 0),
        )
    }

    fn set_write_denied(&mut self, denied: bool) -> Result<(), PlatformError> {
        crate::registry::write_machine_dword(
            WRITE_PROTECT_KEY,
            WRITE_PROTECT_VALUE,
            u32::from(denied),
        )
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

#[cfg(not(windows))]
impl WriteDenialSwitch for WindowsUsbStorageExecutor {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported("Windows 可移动介质写保护"))
    }

    fn set_write_denied(&mut self, _denied: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows 可移动介质写保护"))
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

/// 判断实例标识是否属于 USB 大容量存储设备。
pub fn is_usb_mass_storage_instance(instance_id: &str) -> bool {
    instance_id
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("USBSTOR\\"))
}

/// 从 USB 父设备实例标识解析厂商与产品标识，形如 `USB\VID_0951&PID_1666\...`。
pub fn parse_usb_vendor_product(parent_instance_id: &str) -> (Option<String>, Option<String>) {
    let upper = parent_instance_id.to_ascii_uppercase();
    let field = |prefix: &str| {
        upper
            .find(prefix)
            .and_then(|start| upper.get(start + prefix.len()..start + prefix.len() + 4))
            .filter(|value| value.chars().all(|character| character.is_ascii_hexdigit()))
            .map(str::to_string)
    };
    (field("VID_"), field("PID_"))
}

/// 从 USB 大容量存储实例标识提取序列号，形如 `USBSTOR\Disk&Ven_X&Prod_Y\SERIAL`。
pub fn usb_storage_serial(instance_id: &str) -> Option<String> {
    let mut segments = instance_id.splitn(3, '\\');
    segments.next()?;
    segments.next()?;
    let serial = segments.next()?.trim();
    (!serial.is_empty()).then(|| serial.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_and_product_ids_come_from_the_parent_usb_device() {
        let (vendor_id, product_id) =
            parse_usb_vendor_product("USB\\VID_0951&PID_1666\\0019E06B1234");

        assert_eq!(vendor_id.as_deref(), Some("0951"));
        assert_eq!(product_id.as_deref(), Some("1666"));
        assert_eq!(
            parse_usb_vendor_product("USB\\ROOT_HUB30\\4&abc"),
            (None, None)
        );
    }

    #[test]
    fn storage_serial_is_the_last_instance_id_segment() {
        assert_eq!(
            usb_storage_serial("USBSTOR\\Disk&Ven_Example&Prod_Storage\\0019E06B").as_deref(),
            Some("0019E06B")
        );
        assert_eq!(usb_storage_serial("USBSTOR\\Disk&Ven_Example"), None);
    }

    #[test]
    fn unlisted_mass_storage_is_planned_for_disable() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            enabled: true,
            removable: true,
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };

        let result = plan_usb_storage_control(device, Some(&[]), false);

        assert_eq!(result.matched_rule, None);
        assert_eq!(result.planned_action, UsbPlannedAction::DisableMassStorage);
    }

    #[test]
    fn empty_allow_rule_is_not_a_wildcard_for_mass_storage() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            enabled: true,
            removable: true,
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };

        let result = plan_usb_storage_control(device, Some(&[UsbAllowRule::default()]), false);

        assert_eq!(result.matched_rule, None);
        assert_eq!(result.planned_action, UsbPlannedAction::DisableMassStorage);
    }

    #[test]
    fn all_specified_rule_fields_must_match() {
        let device = UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            enabled: true,
            removable: true,
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        };
        let allowed = [UsbAllowRule {
            vendor_id: Some("1234".into()),
            serial: Some("1".into()),
            ..UsbAllowRule::default()
        }];

        let result = plan_usb_storage_control(device, Some(&allowed), false);

        assert_eq!(result.matched_rule, Some(0));
        assert_eq!(result.planned_action, UsbPlannedAction::EnableMassStorage);
    }

    #[cfg(windows)]
    #[test]
    fn non_mass_storage_is_rejected_before_any_device_control_runs() {
        let device = UsbStorageDevice {
            instance_id: "USB\\VID_1234&PID_5678\\1".into(),
            enabled: true,
            removable: false,
            vendor_id: None,
            product_id: None,
            serial: None,
        };
        assert_eq!(
            plan_usb_storage_control(device, None, false).planned_action,
            UsbPlannedAction::RejectNonMassStorage
        );
        let mut executor = WindowsUsbStorageExecutor;

        let error = executor
            .set_mass_storage_enabled("USB\\VID_1234&PID_5678\\1", false)
            .unwrap_err();

        assert!(matches!(error, PlatformError::Failed(_)));
    }

    fn storage_device(removable: bool, enabled: bool) -> UsbStorageDevice {
        UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            enabled,
            removable,
            vendor_id: Some("1234".into()),
            product_id: Some("5678".into()),
            serial: Some("1".into()),
        }
    }

    #[test]
    fn logon_ui_opens_removable_mass_storage_as_a_read_only_channel() {
        let result = plan_usb_storage_control(storage_device(true, false), Some(&[]), true);

        assert_eq!(result.matched_rule, None);
        assert_eq!(
            result.planned_action,
            UsbPlannedAction::EnableMassStorageReadOnly
        );
    }

    #[test]
    fn logon_ui_keeps_fixed_usb_storage_disabled() {
        // 固定类型卷无法通过重新挂载变成只读，登录界面也不放行。
        let result = plan_usb_storage_control(storage_device(false, true), Some(&[]), true);

        assert_eq!(result.planned_action, UsbPlannedAction::DisableMassStorage);
    }

    #[test]
    fn logon_ui_channel_ignores_the_allowlist() {
        // 允许清单描述解锁后的读写结论；登录界面一律把可移动介质放行成只读。
        let allowed = [UsbAllowRule {
            serial: Some("1".into()),
            ..UsbAllowRule::default()
        }];

        let result = plan_usb_storage_control(storage_device(true, true), Some(&allowed), true);

        assert_eq!(result.matched_rule, Some(0));
        assert_eq!(
            result.planned_action,
            UsbPlannedAction::EnableMassStorageReadOnly
        );
    }

    #[test]
    fn logon_channel_without_a_policy_opens_removable_mass_storage() {
        // 没有策略结论时，登录界面仍要能读到介质上的策略文件。
        let result = plan_usb_storage_control(storage_device(true, false), None, true);

        assert_eq!(result.matched_rule, None);
        assert_eq!(
            result.planned_action,
            UsbPlannedAction::EnableMassStorageReadOnly
        );
    }

    #[test]
    fn storage_is_left_alone_when_there_is_no_policy() {
        // 固定类型卷无法变成只读，也没有策略依据可以据此禁用；解锁后同样不处置设备。
        assert_eq!(
            plan_usb_storage_control(storage_device(false, true), None, true).planned_action,
            UsbPlannedAction::KeepCurrentState
        );
        assert_eq!(
            plan_usb_storage_control(storage_device(true, true), None, false).planned_action,
            UsbPlannedAction::KeepCurrentState
        );
    }
}
