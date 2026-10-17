//! Windows 设备节点访问：PnP 设备枚举、父设备解析与启用状态变更。
//!
//! 枚举使用 SetupAPI（`SetupDiGetClassDevsW` 只返回在场设备，不含幽灵设备），父设备解析
//! 使用 CfgMgr32；不依赖 PowerShell 或 WMI。

use windows::core::{GUID, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Device_ID_Size, CM_Get_Parent, SetupDiCallClassInstaller,
    SetupDiCreateDeviceInfoList, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW,
    SetupDiOpenDeviceInfoW, SetupDiSetClassInstallParamsW, CM_DEVCAP_REMOVABLE,
    CONFIGFLAG_DISABLED, DICS_DISABLE, DICS_ENABLE, DICS_FLAG_GLOBAL, DIF_PROPERTYCHANGE,
    DIGCF_PRESENT, HDEVINFO, SPDRP_CAPABILITIES, SPDRP_CONFIGFLAGS, SPDRP_FRIENDLYNAME,
    SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_PROPCHANGE_PARAMS,
};

use crate::error::PlatformError;

/// 磁盘驱动器设备类。
pub const DISK_DRIVE_CLASS: GUID =
    windows::Win32::Devices::DeviceAndDriverInstallation::GUID_DEVCLASS_DISKDRIVE;
/// 光驱设备类。
pub const CDROM_CLASS: GUID =
    windows::Win32::Devices::DeviceAndDriverInstallation::GUID_DEVCLASS_CDROM;
/// 网络适配器设备类。
pub const NET_CLASS: GUID = windows::Win32::Devices::DeviceAndDriverInstallation::GUID_DEVCLASS_NET;

/// 在场设备的最大实例标识长度（Windows 上限为 200 字符）。
const INSTANCE_ID_CAPACITY: usize = 512;
/// 设备友好名称的最大长度。
const FRIENDLY_NAME_CAPACITY: usize = 512;

/// 一次类别枚举得到的设备节点。
#[derive(Debug, Clone)]
pub struct PnpDevice {
    devinst: u32,
    pub instance_id: String,
    pub friendly_name: Option<String>,
    /// 设备是否被系统禁用（`CONFIGFLAG_DISABLED`）。
    pub disabled: bool,
    /// 设备是否带可移动介质（`CM_DEVCAP_REMOVABLE`）。
    ///
    /// 锁定期间只有可移动介质参与只读导入通道；固定类型卷的 USB 存储保持禁用，
    /// 因为它们无法可靠地写保护。
    pub removable: bool,
}

impl PnpDevice {
    /// 读取父设备实例标识；设备没有父节点时返回 None。
    pub fn parent_instance_id(&self) -> Result<Option<String>, PlatformError> {
        let mut parent = 0u32;
        if unsafe { CM_Get_Parent(&mut parent, self.devinst, 0) }.0
            != windows::Win32::Devices::DeviceAndDriverInstallation::CR_SUCCESS.0
        {
            return Ok(None);
        }
        let mut size = 0u32;
        if unsafe { CM_Get_Device_ID_Size(&mut size, parent, 0) }.0
            != windows::Win32::Devices::DeviceAndDriverInstallation::CR_SUCCESS.0
        {
            return Ok(None);
        }
        if size == 0 {
            return Ok(None);
        }
        let mut buffer = vec![0u16; size as usize + 1];
        if unsafe { CM_Get_Device_IDW(parent, &mut buffer, 0) }.0
            != windows::Win32::Devices::DeviceAndDriverInstallation::CR_SUCCESS.0
        {
            return Ok(None);
        }
        Ok(Some(wide_to_string(&buffer)))
    }
}

/// 枚举某一设备类别中当前在场的设备。
pub fn enumerate(class: &GUID) -> Result<Vec<PnpDevice>, PlatformError> {
    let device_info_set =
        unsafe { SetupDiGetClassDevsW(Some(class), PCWSTR::null(), None, DIGCF_PRESENT) }
            .map_err(|error| PlatformError::Failed(format!("枚举设备类别失败: {error}")))?;
    let _guard = DeviceInfoSetGuard(device_info_set);

    let mut devices = Vec::new();
    let mut index = 0u32;
    loop {
        let mut info = device_info(device_info_set)?;
        match unsafe { SetupDiEnumDeviceInfo(device_info_set, index, &mut info) } {
            Ok(()) => {}
            Err(_) => break,
        }
        index += 1;

        devices.push(PnpDevice {
            devinst: info.DevInst,
            instance_id: device_instance_id(device_info_set, &info)?,
            friendly_name: registry_property_string(device_info_set, &info, SPDRP_FRIENDLYNAME),
            disabled: registry_property_u32(device_info_set, &info, SPDRP_CONFIGFLAGS)
                .is_some_and(|flags| flags & CONFIGFLAG_DISABLED.0 != 0),
            removable: registry_property_u32(device_info_set, &info, SPDRP_CAPABILITIES)
                .is_some_and(|capabilities| capabilities & CM_DEVCAP_REMOVABLE.0 != 0),
        });
    }
    Ok(devices)
}

/// 启用或停用一台设备；调用需要管理员权限。
pub fn set_enabled(class: &GUID, instance_id: &str, enabled: bool) -> Result<(), PlatformError> {
    let change = if enabled { "enable" } else { "disable" };
    trace(&format!("{change} {instance_id} start"));
    let device_info_set = unsafe { SetupDiCreateDeviceInfoList(Some(class), None) }
        .map_err(|error| PlatformError::Failed(format!("创建设备信息列表失败: {error}")))?;
    let _guard = DeviceInfoSetGuard(device_info_set);

    let mut info = device_info(device_info_set)?;
    let target = wide(instance_id);
    unsafe {
        SetupDiOpenDeviceInfoW(
            device_info_set,
            PCWSTR(target.as_ptr()),
            None,
            0,
            Some(&mut info),
        )
    }
    .map_err(|error| {
        trace(&format!("{change} {instance_id} open failed: {error}"));
        PlatformError::Failed(format!("打开设备 {instance_id} 失败: {error}"))
    })?;
    trace(&format!("{change} {instance_id} opened"));

    let params = SP_PROPCHANGE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_PROPERTYCHANGE,
        },
        StateChange: if enabled { DICS_ENABLE } else { DICS_DISABLE },
        Scope: DICS_FLAG_GLOBAL,
        HwProfile: 0,
    };
    unsafe {
        SetupDiSetClassInstallParamsW(
            device_info_set,
            Some(&info),
            Some(&params.ClassInstallHeader),
            size_of::<SP_PROPCHANGE_PARAMS>() as u32,
        )
    }
    .map_err(|error| {
        trace(&format!("{change} {instance_id} params failed: {error}"));
        PlatformError::Failed(format!("设置设备 {instance_id} 状态参数失败: {error}"))
    })?;
    trace(&format!("{change} {instance_id} apply"));
    match unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, device_info_set, Some(&info)) } {
        Ok(()) => {
            trace(&format!("{change} {instance_id} ok"));
            Ok(())
        }
        Err(error) => {
            trace(&format!("{change} {instance_id} failed: {error}"));
            let action = if enabled { "启用" } else { "停用" };
            Err(PlatformError::Failed(format!(
                "{action}设备 {instance_id} 失败: {error}"
            )))
        }
    }
}

fn device_info(_set: HDEVINFO) -> Result<SP_DEVINFO_DATA, PlatformError> {
    Ok(SP_DEVINFO_DATA {
        cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
        ..SP_DEVINFO_DATA::default()
    })
}

fn device_instance_id(set: HDEVINFO, info: &SP_DEVINFO_DATA) -> Result<String, PlatformError> {
    let mut buffer = vec![0u16; INSTANCE_ID_CAPACITY];
    unsafe { SetupDiGetDeviceInstanceIdW(set, info, Some(&mut buffer), None) }
        .map_err(|error| PlatformError::Failed(format!("读取设备实例标识失败: {error}")))?;
    Ok(wide_to_string(&buffer))
}

fn registry_property_u32(
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    property: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
) -> Option<u32> {
    let mut value = 0u32;
    let buffer = unsafe {
        std::slice::from_raw_parts_mut(std::ptr::addr_of_mut!(value).cast::<u8>(), size_of::<u32>())
    };
    unsafe { SetupDiGetDeviceRegistryPropertyW(set, info, property, None, Some(buffer), None) }
        .ok()?;
    Some(value)
}

fn registry_property_string(
    set: HDEVINFO,
    info: &SP_DEVINFO_DATA,
    property: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY,
) -> Option<String> {
    let mut buffer = vec![0u8; FRIENDLY_NAME_CAPACITY];
    unsafe {
        SetupDiGetDeviceRegistryPropertyW(set, info, property, None, Some(&mut buffer), None)
    }
    .ok()?;
    let wide: Vec<u16> = buffer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    let name = String::from_utf16_lossy(&wide);
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// 追加设备控制轨迹到数据目录；写失败不影响处置本身。
///
/// 设备状态变更失败会让服务整体进入不可用状态，出问题时需要知道卡在哪一步，因此单独留一份
/// 可读轨迹，而不只依赖审计事件。
#[cfg(windows)]
fn trace(message: &str) {
    use std::io::Write;

    let Some(root) = std::env::var_os("ProgramData") else {
        return;
    };
    let path = std::path::PathBuf::from(root)
        .join("Anchor Guard")
        .join("device-control.log");
    if let Some(directory) = path.parent() {
        let _ = std::fs::create_dir_all(directory);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{} {message}", chrono::Utc::now().to_rfc3339());
    }
}

struct DeviceInfoSetGuard(HDEVINFO);

impl Drop for DeviceInfoSetGuard {
    fn drop(&mut self) {
        let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_present_devices_of_a_device_class() {
        let devices = enumerate(&NET_CLASS).unwrap();

        assert!(devices
            .iter()
            .all(|device| !device.instance_id.trim().is_empty()));
    }

    #[test]
    fn resolves_parent_device_of_a_usb_storage_device() {
        let devices = enumerate(&DISK_DRIVE_CLASS).unwrap();
        let usb_storage: Vec<&PnpDevice> = devices
            .iter()
            .filter(|device| device.instance_id.starts_with("USBSTOR\\"))
            .collect();

        for device in usb_storage {
            let parent = device.parent_instance_id().unwrap();
            assert!(parent.is_some_and(|parent| parent.starts_with("USB\\")));
        }
    }
}
