use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

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

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("消息超过 {MAX_MESSAGE_BYTES} 字节上限")]
    MessageTooLarge,
    #[error("长度前缀与实际消息长度不一致")]
    InvalidFrameLength,
    #[error("JSON 编解码失败: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    let Some(header) = frame.get(..4) else {
        return Err(ProtocolError::InvalidFrameLength);
    };
    let length = u32::from_le_bytes(header.try_into().expect("固定为四字节")) as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge);
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
}
