use anchor_core::{AuditEvent, PolicyPayload};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 控制管道和会话状态管道使用的单条消息上限。
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// 桌面端管道使用的单条消息上限。
pub const MAX_DESKTOP_MESSAGE_BYTES: usize = 1024 * 1024;
/// 单个策略包的内容上限。
pub const MAX_POLICY_PACKAGE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRequest {
    GetAuthorization,
    ImportFromPolicyMedia,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceResponse {
    Authorization(AuthorizationResponse),
    Import(ImportResponse),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationResponse {
    Allowed,
    Denied { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportResponse {
    pub accepted: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopRequest {
    GetStatus,
    InspectPolicy {
        package_json: String,
    },
    ImportPolicy {
        package_json: String,
    },
    QueryAudit {
        filter: AuditFilter,
        after_sequence: Option<i64>,
        limit: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopResponse {
    Status(DesktopStatus),
    Inspection(PolicyInspection),
    Import(ImportResponse),
    Audit(AuditPage),
    Error(DesktopProtocolError),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesktopStatus {
    pub authorization: AuthorizationResponse,
    pub policy: Option<PolicySummary>,
    pub last_trusted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub imported_at: Option<DateTime<Utc>>,
    pub payload: PolicyPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyInspection {
    pub accepted: bool,
    pub reason: String,
    pub current: Option<PolicySummary>,
    pub candidate: Option<PolicySummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFilter {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub user: Option<String>,
    pub policy_version: Option<u64>,
    pub resource_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditViewEvent {
    pub sequence: i64,
    pub event: AuditEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPage {
    pub events: Vec<AuditViewEvent>,
    pub next_after_sequence: Option<i64>,
    pub chain_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopProtocolError {
    pub code: String,
    pub message: String,
}

impl DesktopProtocolError {
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("消息超过 {0} 字节上限")]
    MessageTooLarge(usize),
    #[error("长度前缀与实际消息长度不一致")]
    InvalidFrameLength,
    #[error("JSON 编解码失败: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    encode_frame_with_limit(message, MAX_MESSAGE_BYTES)
}

pub fn encode_frame_with_limit<T: Serialize>(
    message: &T,
    limit: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(message)?;
    if payload.len() > limit {
        return Err(ProtocolError::MessageTooLarge(limit));
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    decode_frame_with_limit(frame, MAX_MESSAGE_BYTES)
}

pub fn decode_frame_with_limit<T: DeserializeOwned>(
    frame: &[u8],
    limit: usize,
) -> Result<T, ProtocolError> {
    let Some(header) = frame.get(..4) else {
        return Err(ProtocolError::InvalidFrameLength);
    };
    let length = u32::from_le_bytes(header.try_into().expect("固定为四字节")) as usize;
    if length > limit {
        return Err(ProtocolError::MessageTooLarge(limit));
    }
    let Some(payload) = frame.get(4..) else {
        return Err(ProtocolError::InvalidFrameLength);
    };
    if payload.len() != length {
        return Err(ProtocolError::InvalidFrameLength);
    }
    Ok(serde_json::from_slice(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixed_json_request_roundtrips() {
        let frame = encode_frame(&ServiceRequest::ImportFromPolicyMedia).unwrap();

        assert_eq!(
            decode_frame::<ServiceRequest>(&frame).unwrap(),
            ServiceRequest::ImportFromPolicyMedia
        );
    }

    #[test]
    fn oversized_or_truncated_frames_are_rejected() {
        assert!(decode_frame::<ServiceRequest>(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(decode_frame::<ServiceRequest>(&[2, 0, 0, 0, b'{']).is_err());
    }

    #[test]
    fn desktop_inspect_request_roundtrips() {
        let request = DesktopRequest::InspectPolicy {
            package_json: r#"{"version":1}"#.into(),
        };
        let json = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<DesktopRequest>(&json).unwrap(),
            request
        );
    }

    #[test]
    fn desktop_audit_request_carries_cursor_and_limit() {
        let request = DesktopRequest::QueryAudit {
            filter: AuditFilter {
                event_type: Some("scan_hit".into()),
                user: Some("alice".into()),
                ..AuditFilter::default()
            },
            after_sequence: Some(42),
            limit: 100,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"after_sequence\":42"));
        assert!(json.contains("\"limit\":100"));
    }
}
