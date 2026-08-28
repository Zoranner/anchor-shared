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
