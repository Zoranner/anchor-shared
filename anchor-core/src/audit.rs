//! 审计事件：本地追加写入，prev_hash/event_hash 构成 hash chain。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto;
use crate::error::CoreError;

/// 链上第一条事件的 prev_hash。
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 核心事件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    PolicyImported,
    PolicyImportRejected,
    AuthorizationDenied,
    ClockRollback,
    SessionLocked,
    SessionAssistantFailed,
    FileWrite,
    ScanHit,
    UsbAttach,
    UsbWrite,
    UsbRead,
    UsbRemove,
    BurnTask,
    NicChange,
    InventoryObservationFailed,
    ServiceStart,
    ServiceStop,
    UninstallAttempt,
    ConfigChange,
    AuditVerify,
}

impl EventType {
    /// 落库用的 snake_case 字符串表示，与 serde 序列化一致。
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::PolicyImported => "policy_imported",
            EventType::PolicyImportRejected => "policy_import_rejected",
            EventType::AuthorizationDenied => "authorization_denied",
            EventType::ClockRollback => "clock_rollback",
            EventType::SessionLocked => "session_locked",
            EventType::SessionAssistantFailed => "session_assistant_failed",
            EventType::FileWrite => "file_write",
            EventType::ScanHit => "scan_hit",
            EventType::UsbAttach => "usb_attach",
            EventType::UsbWrite => "usb_write",
            EventType::UsbRead => "usb_read",
            EventType::UsbRemove => "usb_remove",
            EventType::BurnTask => "burn_task",
            EventType::NicChange => "nic_change",
            EventType::InventoryObservationFailed => "inventory_observation_failed",
            EventType::ServiceStart => "service_start",
            EventType::ServiceStop => "service_stop",
            EventType::UninstallAttempt => "uninstall_attempt",
            EventType::ConfigChange => "config_change",
            EventType::AuditVerify => "audit_verify",
        }
    }
}

impl std::str::FromStr for EventType {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let found = match s {
            "policy_imported" => EventType::PolicyImported,
            "policy_import_rejected" => EventType::PolicyImportRejected,
            "authorization_denied" => EventType::AuthorizationDenied,
            "clock_rollback" => EventType::ClockRollback,
            "session_locked" => EventType::SessionLocked,
            "session_assistant_failed" => EventType::SessionAssistantFailed,
            "file_write" => EventType::FileWrite,
            "scan_hit" => EventType::ScanHit,
            "usb_attach" => EventType::UsbAttach,
            "usb_write" => EventType::UsbWrite,
            "usb_read" => EventType::UsbRead,
            "usb_remove" => EventType::UsbRemove,
            "burn_task" => EventType::BurnTask,
            "nic_change" => EventType::NicChange,
            "inventory_observation_failed" => EventType::InventoryObservationFailed,
            "service_start" => EventType::ServiceStart,
            "service_stop" => EventType::ServiceStop,
            "uninstall_attempt" => EventType::UninstallAttempt,
            "config_change" => EventType::ConfigChange,
            "audit_verify" => EventType::AuditVerify,
            other => {
                return Err(CoreError::InvalidEnumValue {
                    kind: "EventType",
                    value: other.to_string(),
                })
            }
        };
        Ok(found)
    }
}

/// 审计事件载荷（不含 event_hash）。prev_hash 计入哈希，
/// 保证链上任何一环被篡改都会破坏后续哈希。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPayload {
    pub event_id: String,
    pub device_id: String,
    pub user: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub process: Option<String>,
    pub resource: Option<String>,
    pub policy_version: Option<u64>,
    pub action: String,
    pub result: String,
    pub rule_id: Option<String>,
    pub prev_hash: String,
}

impl AuditPayload {
    /// 创建载荷，可选字段初始为 None，prev_hash 初始为创世值。
    pub fn new(
        device_id: impl Into<String>,
        user: impl Into<String>,
        event_type: EventType,
        action: impl Into<String>,
        result: impl Into<String>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            device_id: device_id.into(),
            user: user.into(),
            timestamp: Utc::now(),
            event_type,
            process: None,
            resource: None,
            policy_version: None,
            action: action.into(),
            result: result.into(),
            rule_id: None,
            prev_hash: GENESIS_HASH.to_string(),
        }
    }

    pub fn with_process(mut self, process: impl Into<String>) -> Self {
        self.process = Some(process.into());
        self
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_policy_version(mut self, version: u64) -> Self {
        self.policy_version = Some(version);
        self
    }

    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }
}

/// 完整审计事件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    #[serde(flatten)]
    pub payload: AuditPayload,
    pub event_hash: String,
}

impl AuditEvent {
    /// 以前一条事件哈希为锚创建事件并计算自身哈希。
    pub fn new(mut payload: AuditPayload, prev_hash: &str) -> Result<Self, CoreError> {
        payload.prev_hash = prev_hash.to_string();
        let event_hash = crypto::sha256_hex(&serde_json::to_vec(&payload)?);
        Ok(Self {
            payload,
            event_hash,
        })
    }

    /// 重算事件哈希。
    pub fn recompute_hash(&self) -> Result<String, CoreError> {
        Ok(crypto::sha256_hex(&serde_json::to_vec(&self.payload)?))
    }

    /// 校验事件自身哈希是否一致。
    pub fn verify_self(&self) -> Result<bool, CoreError> {
        Ok(self.recompute_hash()? == self.event_hash)
    }
}

/// 校验完整 hash chain：链接连续且每个事件哈希可重算。
pub fn verify_chain(events: &[AuditEvent]) -> Result<(), CoreError> {
    let mut prev = GENESIS_HASH.to_string();
    for event in events {
        if event.payload.prev_hash != prev {
            return Err(CoreError::ChainBroken {
                event_id: event.payload.event_id.clone(),
                reason: "prev_hash 与上一条事件不连续".into(),
            });
        }
        if !event.verify_self()? {
            return Err(CoreError::ChainBroken {
                event_id: event.payload.event_id.clone(),
                reason: "event_hash 重算不一致".into(),
            });
        }
        prev = event.event_hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(device: &str, action: &str) -> AuditPayload {
        AuditPayload::new(device, "alice", EventType::FileWrite, action, "success")
            .with_resource("D:\\data\\a.txt")
    }

    #[test]
    fn event_hash_is_deterministic() {
        let payload = sample_payload("dev-1", "record");
        let e1 = AuditEvent::new(payload.clone(), GENESIS_HASH).unwrap();
        let e2 = AuditEvent::new(payload, GENESIS_HASH).unwrap();
        assert_eq!(e1.event_hash, e2.event_hash);
        assert_eq!(e1.event_hash.len(), 64);
        assert!(e1.verify_self().unwrap());
    }

    #[test]
    fn chain_links_and_verifies() {
        let e1 = AuditEvent::new(sample_payload("dev-1", "record"), GENESIS_HASH).unwrap();
        let e2 = AuditEvent::new(sample_payload("dev-1", "mark"), &e1.event_hash).unwrap();
        let e3 = AuditEvent::new(sample_payload("dev-1", "quarantine"), &e2.event_hash).unwrap();
        assert_eq!(e2.payload.prev_hash, e1.event_hash);
        verify_chain(&[e1, e2, e3]).unwrap();
    }

    #[test]
    fn chain_detects_tampered_event() {
        let e1 = AuditEvent::new(sample_payload("dev-1", "record"), GENESIS_HASH).unwrap();
        let mut e2 = AuditEvent::new(sample_payload("dev-1", "mark"), &e1.event_hash).unwrap();
        e2.payload.action = "delete".into();
        let err = verify_chain(&[e1, e2]).unwrap_err();
        assert!(matches!(err, CoreError::ChainBroken { .. }));
    }

    #[test]
    fn chain_detects_broken_link() {
        let e1 = AuditEvent::new(sample_payload("dev-1", "record"), GENESIS_HASH).unwrap();
        let e2 = AuditEvent::new(sample_payload("dev-1", "mark"), GENESIS_HASH).unwrap();
        let err = verify_chain(&[e1, e2]).unwrap_err();
        assert!(matches!(err, CoreError::ChainBroken { .. }));
    }

    #[test]
    fn empty_chain_is_valid() {
        verify_chain(&[]).unwrap();
    }

    #[test]
    fn event_type_str_roundtrip() {
        for et in [
            EventType::PolicyImported,
            EventType::AuthorizationDenied,
            EventType::ClockRollback,
            EventType::SessionLocked,
            EventType::SessionAssistantFailed,
            EventType::ScanHit,
            EventType::UsbWrite,
            EventType::InventoryObservationFailed,
            EventType::ServiceStart,
            EventType::AuditVerify,
        ] {
            assert_eq!(et.as_str().parse::<EventType>().unwrap(), et);
        }
        assert!("not_a_type".parse::<EventType>().is_err());
        // 与 serde 序列化保持一致
        assert_eq!(
            serde_json::to_string(&EventType::PolicyImported).unwrap(),
            "\"policy_imported\""
        );
    }

    #[test]
    fn json_roundtrip() {
        let e1 = AuditEvent::new(sample_payload("dev-1", "record"), GENESIS_HASH).unwrap();
        let json = serde_json::to_string(&e1).unwrap();
        assert!(json.contains("\"prev_hash\""));
        assert!(json.contains("\"event_hash\""));
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e1);
    }
}
