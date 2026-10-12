//! 策略介质根目录枚举。
//!
//! 导入通道不能与被管控的设备重合：策略本身可能禁用 USB 大容量存储或刻录，如果只认
//! 可移动盘，禁用之后设备就再也拿不到新策略。信任来自策略签名，介质类型不是安全边界，
//! 因此这里接受任意本地就绪卷（可移动盘、固定盘、光驱与内存盘），只排除网络位置。

use std::path::PathBuf;

/// 返回已就绪的策略介质根目录。
///
/// 其他平台没有等价的受支持实现，因而明确返回空结果，调用方保持策略导入不可用。
#[must_use]
pub fn policy_media_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_policy_media_roots()
    }

    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// 判断驱动器类型是否可作为策略介质。
///
/// 网络位置与未就绪的驱动器不作为介质：前者会让导入依赖网络，后者没有可读的根目录。
#[must_use]
pub fn is_policy_media(drive_type: u32) -> bool {
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_CDROM: u32 = 5;
    const DRIVE_RAMDISK: u32 = 6;

    matches!(
        drive_type,
        DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_CDROM | DRIVE_RAMDISK
    )
}

#[cfg(windows)]
fn windows_policy_media_roots() -> Vec<PathBuf> {
    let mask = unsafe { get_logical_drives() };
    (0..26)
        .filter_map(|index| {
            if mask & (1 << index) == 0 {
                return None;
            }
            let root = format!("{}:\\", char::from(b'A' + index as u8));
            let wide: Vec<u16> = root.encode_utf16().chain(Some(0)).collect();
            let drive_type = unsafe { get_drive_type_w(wide.as_ptr()) };
            let path = PathBuf::from(root);
            (is_policy_media(drive_type) && path.exists()).then_some(path)
        })
        .collect()
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "GetLogicalDrives"]
    fn get_logical_drives() -> u32;
    #[link_name = "GetDriveTypeW"]
    fn get_drive_type_w(root_path_name: *const u16) -> u32;
}

#[cfg(test)]
mod tests {
    use super::is_policy_media;

    #[test]
    fn local_drives_are_policy_media() {
        assert!(is_policy_media(2), "可移动盘");
        assert!(is_policy_media(3), "固定盘");
        assert!(is_policy_media(5), "光驱");
        assert!(is_policy_media(6), "内存盘");
    }

    #[test]
    fn network_and_unknown_drives_are_not_policy_media() {
        assert!(!is_policy_media(0), "未知类型");
        assert!(!is_policy_media(1), "无根目录");
        assert!(!is_policy_media(4), "网络位置");
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_returns_no_policy_media_roots() {
        assert!(super::policy_media_roots().is_empty());
    }
}
