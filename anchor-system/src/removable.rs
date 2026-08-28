//! 可移动盘根目录枚举。

use std::path::PathBuf;

/// 返回已就绪的可移动盘根目录。
///
/// Windows 仅接受 `DRIVE_REMOVABLE` 驱动器；其他平台没有等价的受支持实现，
/// 因而明确返回空结果，调用方保持策略导入不可用。
#[must_use]
pub fn removable_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_removable_roots()
    }

    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn windows_removable_roots() -> Vec<PathBuf> {
    const DRIVE_REMOVABLE: u32 = 2;

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
            (drive_type == DRIVE_REMOVABLE && path.exists()).then_some(path)
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
    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_returns_no_removable_roots() {
        assert!(super::removable_roots().is_empty());
    }
}
