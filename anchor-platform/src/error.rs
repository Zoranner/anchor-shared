//! 平台适配层统一错误类型。

use thiserror::Error;

/// 平台适配操作的错误。
#[derive(Debug, Error)]
pub enum PlatformError {
    /// 对应平台或能力尚未接入真实实现，由调用方决定降级策略。
    #[error("平台能力未接入：{0}")]
    Unsupported(&'static str),

    /// 平台调用已接入但执行失败。
    #[error("平台操作失败：{0}")]
    Failed(String),
}
