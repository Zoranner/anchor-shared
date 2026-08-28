//! 本地密钥保护适配。
//!
//! 后续接入点：Windows 使用 DPAPI。
//! 用于加密本地敏感字段（审计库密钥、策略材料等），输出为不透明的平台密文 blob。

use crate::error::PlatformError;

/// 本地密钥保护能力。
pub trait KeyProtector: Send + Sync {
    /// 加密明文，返回平台相关的密文 blob。
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError>;

    /// 解密密文 blob，还原明文。
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, PlatformError>;
}

/// 使用本机范围 Windows DPAPI 的本地密钥保护器。
///
/// 输出仅可作为不透明 blob 传回此保护器解密；它不可跨机器迁移。
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDpapiKeyProtector;

impl KeyProtector for WindowsDpapiKeyProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
        #[cfg(windows)]
        {
            windows::protect(plaintext)
        }

        #[cfg(not(windows))]
        {
            let _ = plaintext;
            Err(PlatformError::Unsupported("Windows DPAPI"))
        }
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, PlatformError> {
        #[cfg(windows)]
        {
            windows::unprotect(blob)
        }

        #[cfg(not(windows))]
        {
            let _ = blob;
            Err(PlatformError::Unsupported("Windows DPAPI"))
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use crate::error::PlatformError;

    const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

    #[repr(C)]
    #[derive(Default)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    impl DataBlob {
        fn from_input(input: &[u8]) -> Result<Self, PlatformError> {
            if input.is_empty() {
                return Err(PlatformError::Failed("DPAPI 输入不能为空".into()));
            }

            let cb_data = u32::try_from(input.len())
                .map_err(|_| PlatformError::Failed("DPAPI 输入超过 4 GiB 上限".into()))?;
            Ok(Self {
                cb_data,
                pb_data: input.as_ptr().cast_mut(),
            })
        }
    }

    #[derive(Default)]
    struct LocalDataBlob(DataBlob);

    impl LocalDataBlob {
        fn copy_bytes(&self, operation: &str) -> Result<Vec<u8>, PlatformError> {
            if self.0.pb_data.is_null() || self.0.cb_data == 0 {
                return Err(PlatformError::Failed(format!(
                    "{operation} 返回了空的 DPAPI blob"
                )));
            }

            let bytes =
                unsafe { std::slice::from_raw_parts(self.0.pb_data, self.0.cb_data as usize) };
            Ok(bytes.to_vec())
        }
    }

    impl Drop for LocalDataBlob {
        fn drop(&mut self) {
            if !self.0.pb_data.is_null() {
                unsafe {
                    local_free(self.0.pb_data.cast());
                }
            }
        }
    }

    pub(super) fn protect(plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let input = DataBlob::from_input(plaintext)?;
        let mut output = LocalDataBlob::default();
        let protected = unsafe {
            crypt_protect_data(
                &input,
                null(),
                null(),
                null_mut(),
                null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output.0,
            )
        };
        if protected == 0 {
            return Err(last_error("CryptProtectData 失败"));
        }

        output.copy_bytes("CryptProtectData")
    }

    pub(super) fn unprotect(blob: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let input = DataBlob::from_input(blob)?;
        let mut output = LocalDataBlob::default();
        let unprotected = unsafe {
            crypt_unprotect_data(
                &input,
                null_mut(),
                null(),
                null_mut(),
                null(),
                0,
                &mut output.0,
            )
        };
        if unprotected == 0 {
            return Err(last_error("CryptUnprotectData 失败"));
        }

        output.copy_bytes("CryptUnprotectData")
    }

    fn last_error(context: &str) -> PlatformError {
        PlatformError::Failed(format!("{context}: {}", std::io::Error::last_os_error()))
    }

    #[link(name = "crypt32")]
    extern "system" {
        #[link_name = "CryptProtectData"]
        fn crypt_protect_data(
            data_in: *const DataBlob,
            description: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt_struct: *const c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;

        #[link_name = "CryptUnprotectData"]
        fn crypt_unprotect_data(
            data_in: *const DataBlob,
            description: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt_struct: *const c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "LocalFree"]
        fn local_free(memory: *mut c_void) -> *mut c_void;
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyProtector, PlatformError, WindowsDpapiKeyProtector};

    #[cfg(not(windows))]
    #[test]
    fn non_windows_protection_is_explicitly_unsupported() {
        let protector = WindowsDpapiKeyProtector;

        assert!(matches!(
            protector.protect(b"test-only"),
            Err(PlatformError::Unsupported("Windows DPAPI"))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn empty_plaintext_is_rejected_before_calling_dpapi() {
        let protector = WindowsDpapiKeyProtector;

        assert!(matches!(
            protector.protect(&[]),
            Err(PlatformError::Failed(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "仅在隔离 Windows 测试环境中验证 DPAPI roundtrip"]
    fn dpapi_roundtrip_returns_the_original_test_bytes() {
        let protector = WindowsDpapiKeyProtector;
        let plaintext = b"anchor-guard-dpapi-test";

        let blob = protector.protect(plaintext).unwrap();

        assert_ne!(blob, plaintext);
        assert_eq!(protector.unprotect(&blob).unwrap(), plaintext);
    }
}
