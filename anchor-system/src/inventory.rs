//! Windows 设备库存的只读观测适配。

#[cfg(windows)]
use std::process::Command;

use serde::Deserialize;

use crate::{
    burning::BurnDriveInfo,
    error::PlatformError,
    nic::{NicInfo, NicKind},
    usb::UsbStorageDevice,
};

/// 一次设备库存观测的只读快照。
#[derive(Debug, Clone)]
pub struct DeviceInventory {
    pub usb_storage: Vec<UsbStorageDevice>,
    pub network_adapters: Vec<NicInfo>,
    pub burn_drives: Vec<BurnDriveInfo>,
}

/// 读取当前 Windows 设备库存；不执行任何设备状态修改。
pub fn observe_inventory() -> Result<DeviceInventory, PlatformError> {
    #[cfg(windows)]
    {
        let usb_storage = parse_usb_json(&run_powershell(USB_STORAGE_SCRIPT)?)?;
        let network_adapters = parse_nic_json(&run_powershell(NIC_SCRIPT)?)?;
        let burn_drives = parse_burn_json(&run_powershell(BURN_DRIVE_SCRIPT)?)?;
        Ok(DeviceInventory {
            usb_storage,
            network_adapters,
            burn_drives,
        })
    }

    #[cfg(not(windows))]
    {
        Err(PlatformError::Unsupported("Windows 设备库存观测"))
    }
}

fn parse_usb_json(json: &str) -> Result<Vec<UsbStorageDevice>, PlatformError> {
    let devices: Vec<UsbJson> = parse_array(json)?;
    Ok(devices
        .into_iter()
        .map(|device| UsbStorageDevice {
            instance_id: device.instance_id,
            vendor_id: device.vendor_id,
            product_id: device.product_id,
            serial: device.serial,
        })
        .collect())
}

fn parse_nic_json(json: &str) -> Result<Vec<NicInfo>, PlatformError> {
    let adapters: Vec<NicJson> = parse_array(json)?;
    Ok(adapters
        .into_iter()
        .map(|adapter| NicInfo {
            adapter_id: adapter.adapter_id,
            name: adapter.name,
            kind: adapter.kind,
            mac: adapter.mac,
            enabled: adapter.enabled,
            connected_network: None,
            is_intranet: None,
            last_change: None,
        })
        .collect())
}

fn parse_burn_json(json: &str) -> Result<Vec<BurnDriveInfo>, PlatformError> {
    let drives: Vec<BurnJson> = parse_array(json)?;
    Ok(drives
        .into_iter()
        .map(|drive| BurnDriveInfo {
            drive_id: drive.drive_id,
            name: drive.name,
            media_present: drive.media_present,
            writable: drive.writable,
        })
        .collect())
}

fn parse_array<T>(json: &str) -> Result<Vec<T>, PlatformError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(json)
        .map_err(|error| PlatformError::Failed(format!("设备库存 JSON 无效: {error}")))
}

#[derive(Deserialize)]
struct UsbJson {
    instance_id: String,
    vendor_id: Option<String>,
    product_id: Option<String>,
    serial: Option<String>,
}

#[derive(Deserialize)]
struct NicJson {
    adapter_id: String,
    name: String,
    kind: NicKind,
    mac: Option<String>,
    enabled: bool,
}

#[derive(Deserialize)]
struct BurnJson {
    drive_id: String,
    name: String,
    media_present: Option<bool>,
    writable: Option<bool>,
}

#[cfg(windows)]
fn run_powershell(script: &str) -> Result<String, PlatformError> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|error| PlatformError::Failed(format!("启动设备库存查询失败: {error}")))?;
    if !output.status.success() {
        return Err(PlatformError::Failed(format!(
            "设备库存查询失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(windows)]
const USB_STORAGE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
@(
  Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.InterfaceType -eq 'USB' } | ForEach-Object {
    $match = [regex]::Match($_.PNPDeviceID, 'VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})')
    [pscustomobject]@{
      instance_id = $_.PNPDeviceID
      vendor_id = if ($match.Success) { $match.Groups[1].Value } else { $null }
      product_id = if ($match.Success) { $match.Groups[2].Value } else { $null }
      serial = if ($_.SerialNumber) { $_.SerialNumber.Trim() } else { $null }
    }
  }
) | ConvertTo-Json -Compress
"#;

#[cfg(windows)]
const NIC_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
@(
  Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
    $kind = if ($_.Virtual) { 'virtual' } elseif ($_.NdisPhysicalMedium -eq 9) { 'wi_fi' } else { 'wired' }
    [pscustomobject]@{
      adapter_id = $_.InterfaceGuid.Guid
      name = $_.Name
      kind = $kind
      mac = $_.MacAddress
      enabled = $_.Status -ne 'Disabled'
    }
  }
) | ConvertTo-Json -Compress
"#;

#[cfg(windows)]
const BURN_DRIVE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
@(
  Get-CimInstance Win32_CDROMDrive -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      drive_id = $_.PNPDeviceID
      name = $_.Name
      media_present = $_.MediaLoaded
      writable = $null
    }
  }
) | ConvertTo-Json -Compress
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_observed_device_json_without_running_powershell() {
        let usb = parse_usb_json(
            r#"[{"instance_id":"USBSTOR\\Disk&Ven_ACME\\1","vendor_id":"1234","product_id":"5678","serial":"one"}]"#,
        )
        .unwrap();
        let nics = parse_nic_json(
            r#"[{"adapter_id":"guid-1","name":"Ethernet","kind":"wired","mac":"AA-BB","enabled":true}]"#,
        )
        .unwrap();
        let drives = parse_burn_json(
            r#"[{"drive_id":"SCSI\\CDROM\\1","name":"Writer","media_present":false,"writable":null}]"#,
        )
        .unwrap();

        assert_eq!(usb[0].serial.as_deref(), Some("one"));
        assert_eq!(nics[0].kind, NicKind::Wired);
        assert!(!drives[0].media_present.unwrap());
        assert_eq!(drives[0].writable, None);
    }

    #[cfg(windows)]
    #[test]
    fn inventory_scripts_make_query_failures_terminating() {
        for script in [USB_STORAGE_SCRIPT, NIC_SCRIPT, BURN_DRIVE_SCRIPT] {
            assert!(script.contains("$ErrorActionPreference = 'Stop'"));
            assert!(script.contains("-ErrorAction Stop"));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_inventory_is_explicitly_unsupported() {
        assert!(matches!(
            observe_inventory(),
            Err(PlatformError::Unsupported("Windows 设备库存观测"))
        ));
    }
}
