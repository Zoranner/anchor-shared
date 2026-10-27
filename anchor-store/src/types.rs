//! 存储层使用的记录与过滤类型。

use std::str::FromStr;

use anchor_core::{EventType, PolicyPackage};
use chrono::{DateTime, Utc};

use crate::error::StoreError;

/// 当前活动策略及其导入时间。
#[derive(Debug, Clone, PartialEq)]
pub struct ActivePolicyRecord {
    pub package: PolicyPackage,
    pub imported_at: DateTime<Utc>,
}

/// 扫描状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Pending,
    Clean,
    Hit,
    Error,
}

impl ScanStatus {
    /// 落库用的小写字符串表示。
    pub fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Pending => "pending",
            ScanStatus::Clean => "clean",
            ScanStatus::Hit => "hit",
            ScanStatus::Error => "error",
        }
    }
}

impl FromStr for ScanStatus {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(ScanStatus::Pending),
            "clean" => Ok(ScanStatus::Clean),
            "hit" => Ok(ScanStatus::Hit),
            "error" => Ok(ScanStatus::Error),
            other => Err(StoreError::InvalidScanStatus(other.to_string())),
        }
    }
}

/// scan_index 表记录：文件指纹、扫描状态和命中摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRecord {
    pub file_id: String,
    pub path: String,
    pub volume_id: Option<String>,
    pub size: u64,
    pub mtime: i64,
    pub hash: String,
    pub scan_version: u64,
    pub status: ScanStatus,
    pub matched_rules: Vec<String>,
    pub last_event_id: Option<String>,
}

impl ScanRecord {
    /// 创建记录，file_id 由路径与指纹推导（确定性，免额外依赖）。
    pub fn new(
        path: impl Into<String>,
        size: u64,
        mtime: i64,
        hash: impl Into<String>,
        scan_version: u64,
        status: ScanStatus,
    ) -> Self {
        let path = path.into();
        let hash = hash.into();
        let file_id = anchor_core::crypto::sha256_hex(format!("{path}:{mtime}:{size}").as_bytes())
            [..16]
            .to_string();
        Self {
            file_id,
            path,
            volume_id: None,
            size,
            mtime,
            hash,
            scan_version,
            status,
            matched_rules: Vec::new(),
            last_event_id: None,
        }
    }
}

/// device_state 表记录：USB、光驱、网卡最近状态。
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceStateRecord {
    pub kind: String,
    pub device_id: String,
    pub state: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// 审计事件查询过滤器。None 字段不参与过滤。
#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub event_type: Option<EventType>,
    pub user: Option<String>,
    pub device_id: Option<String>,
    pub resource_prefix: Option<String>,
    pub policy_version: Option<u64>,
    pub limit: Option<u32>,
}
