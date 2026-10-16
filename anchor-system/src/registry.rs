//! Windows 注册表 DWORD 值读写适配。
//!
//! 只覆盖机器级（`HKEY_LOCAL_MACHINE`）单个 DWORD 值的读写，键不存在时创建。调用方用键路径
//! 和值名描述目标，键句柄与 64 位视图的选择留在本模块，不泄漏到上层。

use std::{mem::size_of, ptr};

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD,
    REG_OPTION_NON_VOLATILE,
};

use crate::error::PlatformError;

/// 一个 DWORD 值的字节数；注册表读写都以它作为长度。
const DWORD_BYTES: u32 = size_of::<u32>() as u32;

/// 读取机器级 DWORD 值；键或值不存在时返回 `None`。
pub(crate) fn read_machine_dword(
    key_path: &str,
    value_name: &str,
) -> Result<Option<u32>, PlatformError> {
    let key_path_wide = HSTRING::from(key_path);
    let value_name_wide = HSTRING::from(value_name);
    let mut key = HKEY::default();
    let error = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            &key_path_wide,
            None,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if error == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if error != ERROR_SUCCESS {
        return Err(registry_failure("打开", key_path, error));
    }
    let _key = KeyHandle(key);

    let mut value = 0u32;
    let mut kind = REG_DWORD;
    let mut size = DWORD_BYTES;
    let error = unsafe {
        RegQueryValueExW(
            key,
            &value_name_wide,
            None,
            Some(&mut kind),
            Some(ptr::from_mut(&mut value).cast::<u8>()),
            Some(&mut size),
        )
    };
    match error {
        ERROR_SUCCESS if kind == REG_DWORD && size == DWORD_BYTES => Ok(Some(value)),
        ERROR_SUCCESS => Err(PlatformError::Failed(format!(
            "注册表值不是 32 位数值：{key_path}\\{value_name}"
        ))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        error => Err(registry_failure("读取", key_path, error)),
    }
}

/// 写入机器级 DWORD 值；键不存在时创建。
pub(crate) fn write_machine_dword(
    key_path: &str,
    value_name: &str,
    value: u32,
) -> Result<(), PlatformError> {
    let key_path_wide = HSTRING::from(key_path);
    let value_name_wide = HSTRING::from(value_name);
    let mut key = HKEY::default();
    let error = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            &key_path_wide,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            None,
            &mut key,
            None,
        )
    };
    if error != ERROR_SUCCESS {
        return Err(registry_failure("创建或打开", key_path, error));
    }
    let _key = KeyHandle(key);

    let error = unsafe {
        RegSetValueExW(
            key,
            &value_name_wide,
            None,
            REG_DWORD,
            Some(&value.to_le_bytes()),
        )
    };
    if error != ERROR_SUCCESS {
        return Err(registry_failure("写入", key_path, error));
    }
    Ok(())
}

/// 关闭注册表键的守卫，保证提前返回也会释放句柄。
struct KeyHandle(HKEY);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn registry_failure(action: &str, key_path: &str, error: WIN32_ERROR) -> PlatformError {
    PlatformError::Failed(format!(
        "{action}注册表键 {key_path} 失败：Win32 错误 {}",
        error.0
    ))
}
