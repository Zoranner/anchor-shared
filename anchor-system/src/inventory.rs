//! Windows 设备库存的只读观测。

use crate::{
    burning::BurnDriveInfo,
    error::PlatformError,
    nic::NicInfo,
    usb::{parse_usb_vendor_product, usb_storage_serial, UsbStorageDevice},
};

/// 一次设备库存观测的只读快照。
#[derive(Debug, Clone)]
pub struct DeviceInventory {
    pub usb_storage: Vec<UsbStorageDevice>,
    pub network_adapters: Vec<NicInfo>,
    pub burn_drives: Vec<BurnDriveInfo>,
}

/// 读取当前 Windows 设备库存；只查询在场设备，不执行任何设备状态修改。
pub fn observe_inventory() -> Result<DeviceInventory, PlatformError> {
    #[cfg(windows)]
    {
        use crate::{pnp, usb::is_usb_mass_storage_instance};

        let usb_storage = pnp::enumerate(&pnp::DISK_DRIVE_CLASS)?
            .into_iter()
            .filter(|device| is_usb_mass_storage_instance(&device.instance_id))
            .map(|device| {
                let (vendor_id, product_id) = device
                    .parent_instance_id()
                    .ok()
                    .flatten()
                    .map(|parent| parse_usb_vendor_product(&parent))
                    .unwrap_or((None, None));
                UsbStorageDevice {
                    serial: usb_storage_serial(&device.instance_id),
                    enabled: !device.disabled,
                    removable: device.removable,
                    instance_id: device.instance_id,
                    vendor_id,
                    product_id,
                }
            })
            .collect();

        let network_adapters = pnp::enumerate(&pnp::NET_CLASS)?
            .into_iter()
            .map(|device| NicInfo {
                name: device
                    .friendly_name
                    .unwrap_or_else(|| device.instance_id.clone()),
                adapter_id: device.instance_id,
                enabled: !device.disabled,
            })
            .collect();

        let burn_drives = pnp::enumerate(&pnp::CDROM_CLASS)?
            .into_iter()
            .map(|device| BurnDriveInfo {
                name: device
                    .friendly_name
                    .unwrap_or_else(|| device.instance_id.clone()),
                drive_id: device.instance_id,
                enabled: !device.disabled,
            })
            .collect();

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

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实设备观测：只读查询本机，确认每类设备都带有可用于策略匹配的标识。
    #[cfg(windows)]
    #[test]
    fn inventory_observation_carries_stable_device_ids() {
        let inventory = observe_inventory().unwrap();

        assert!(inventory
            .network_adapters
            .iter()
            .all(|adapter| !adapter.adapter_id.trim().is_empty()));
        assert!(inventory
            .usb_storage
            .iter()
            .all(|device| !device.instance_id.trim().is_empty()));
        assert!(inventory
            .burn_drives
            .iter()
            .all(|drive| !drive.drive_id.trim().is_empty()));
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
