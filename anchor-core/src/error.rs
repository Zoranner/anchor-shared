use thiserror::Error;

/// 核心层统一错误类型。
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("密钥编码无效: {0}")]
    InvalidKey(String),
    #[error("序列化失败: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("无效枚举值 {kind}: {value}")]
    InvalidEnumValue {
        kind: &'static str,
        value: String,
    },
    #[error("审计链在事件 {event_id} 处断裂: {reason}")]
    ChainBroken { event_id: String, reason: String },
}
