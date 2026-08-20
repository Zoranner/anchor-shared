use thiserror::Error;

/// 本地存储统一错误类型。
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("数据库错误: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("序列化错误: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("核心类型错误: {0}")]
    Core(#[from] anchor_core::CoreError),
    #[error("时间解析失败: {0}")]
    TimeParse(String),
    #[error("扫描状态无效: {0}")]
    InvalidScanStatus(String),
    #[error("数据库连接锁已失效")]
    LockPoisoned,
}
