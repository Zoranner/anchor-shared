//! 服务端和 Windows 客户端共享的 HTTP 协议。
//!
//! 这里只放 DTO、状态、错误码和协议版本，不放 HTTP 客户端、数据库或
//! Windows 平台逻辑。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 当前服务端与客户端之间的协议版本。
pub const PROTOCOL_VERSION: u32 = 1;

/// 当前硬件清单结构版本。
pub const HARDWARE_INVENTORY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Pending,
    Active,
    Rejected,
    Disabled,
}

impl DeviceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rejected => "rejected",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "rejected" => Some(Self::Rejected),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiErrorCode {
    InvalidRequest,
    ProtocolVersionUnsupported,
    Unauthorized,
    InvalidCredentials,
    CsrfInvalid,
    SetupUnavailable,
    SetupComplete,
    SetupTokenInvalid,
    DevicePending,
    DeviceRejected,
    DeviceDisabled,
    DeviceNotFound,
    AlreadyActive,
    InvalidDeviceState,
    InventoryChanged,
    TokenInvalid,
    PolicyNotFound,
    PolicyNotSigned,
    VersionConflict,
    RateLimited,
    PayloadTooLarge,
    UnsupportedMediaType,
    Internal,
    Unknown(String),
}

impl ApiErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::ProtocolVersionUnsupported => "protocol_version_unsupported",
            Self::Unauthorized => "unauthorized",
            Self::InvalidCredentials => "invalid_credentials",
            Self::CsrfInvalid => "csrf_invalid",
            Self::SetupUnavailable => "setup_unavailable",
            Self::SetupComplete => "setup_complete",
            Self::SetupTokenInvalid => "setup_token_invalid",
            Self::DevicePending => "device_pending",
            Self::DeviceRejected => "device_rejected",
            Self::DeviceDisabled => "device_disabled",
            Self::DeviceNotFound => "device_not_found",
            Self::AlreadyActive => "already_active",
            Self::InvalidDeviceState => "invalid_device_state",
            Self::InventoryChanged => "inventory_changed",
            Self::TokenInvalid => "token_invalid",
            Self::PolicyNotFound => "policy_not_found",
            Self::PolicyNotSigned => "policy_not_signed",
            Self::VersionConflict => "version_conflict",
            Self::RateLimited => "rate_limited",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::Internal => "internal",
            Self::Unknown(value) => value,
        }
    }
}

impl Serialize for ApiErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ApiErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "invalid_request" => Self::InvalidRequest,
            "protocol_version_unsupported" => Self::ProtocolVersionUnsupported,
            "unauthorized" => Self::Unauthorized,
            "invalid_credentials" => Self::InvalidCredentials,
            "csrf_invalid" => Self::CsrfInvalid,
            "setup_unavailable" => Self::SetupUnavailable,
            "setup_complete" => Self::SetupComplete,
            "setup_token_invalid" => Self::SetupTokenInvalid,
            "device_pending" => Self::DevicePending,
            "device_rejected" => Self::DeviceRejected,
            "device_disabled" => Self::DeviceDisabled,
            "device_not_found" => Self::DeviceNotFound,
            "already_active" => Self::AlreadyActive,
            "invalid_device_state" => Self::InvalidDeviceState,
            "inventory_changed" => Self::InventoryChanged,
            "token_invalid" => Self::TokenInvalid,
            "policy_not_found" => Self::PolicyNotFound,
            "policy_not_signed" => Self::PolicyNotSigned,
            "version_conflict" => Self::VersionConflict,
            "rate_limited" => Self::RateLimited,
            "payload_too_large" => Self::PayloadTooLarge,
            "unsupported_media_type" => Self::UnsupportedMediaType,
            "internal" => Self::Internal,
            _ => Self::Unknown(value),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub installation_id: String,
    pub hostname: String,
    pub client_version: String,
    pub inventory: HardwareInventory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
    pub status: DeviceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatusResponse {
    pub status: DeviceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub client_version: String,
    pub inventory_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<HardwareInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEnvelope {
    pub version: u64,
    pub expires_at: DateTime<Utc>,
    pub policy_json: serde_json::Value,
    pub signature_hex: String,
    pub server_key_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerKeyStatus {
    Active,
    Retired,
}

impl ServerKeyStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerKey {
    pub key_id: String,
    pub public_key_hex: String,
    pub status: ServerKeyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerKeyringResponse {
    pub keys: Vec<ServerKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareInventory {
    pub schema_version: u32,
    pub captured_at: DateTime<Utc>,
    pub computer: ComputerInventory,
    pub operating_system: OperatingSystemInventory,
    pub cpu: CpuInventory,
    pub memory_modules: Vec<MemoryModuleInventory>,
    pub disks: Vec<DiskInventory>,
    pub volumes: Vec<VolumeInventory>,
    pub network_adapters: Vec<NetworkAdapterInventory>,
    pub usb_devices: Vec<UsbDeviceInventory>,
    pub optical_drives: Vec<OpticalDriveInventory>,
    pub gpus: Vec<GpuInventory>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerInventory {
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub bios_vendor: String,
    #[serde(default)]
    pub bios_version: String,
    #[serde(default)]
    pub bios_release_date: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatingSystemInventory {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub hostname: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuInventory {
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub cores: u32,
    #[serde(default)]
    pub threads: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryModuleInventory {
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub part_number: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub capacity_bytes: u64,
    #[serde(default)]
    pub speed_mhz: u32,
    #[serde(default)]
    pub slot: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskInventory {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub media_type: String,
    #[serde(default)]
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInventory {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub filesystem: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub free_bytes: u64,
    #[serde(default)]
    pub serial_number: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAdapterInventory {
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mac_address: String,
    #[serde(default)]
    pub link_up: bool,
    #[serde(default)]
    pub driver_version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDeviceInventory {
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub vendor_id: String,
    #[serde(default)]
    pub product_id: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub device_class: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpticalDriveInventory {
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub media_present: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuInventory {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub memory_bytes: u64,
    #[serde(default)]
    pub driver_version: String,
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn inventory() -> HardwareInventory {
        HardwareInventory {
            schema_version: 1,
            captured_at: Utc.with_ymd_and_hms(2026, 10, 29, 8, 0, 0).unwrap(),
            computer: ComputerInventory {
                manufacturer: "Example".into(),
                model: "Laptop".into(),
                serial_number: "SERIAL".into(),
                bios_vendor: "Example".into(),
                bios_version: "1.0".into(),
                bios_release_date: "2026-01-01".into(),
            },
            operating_system: OperatingSystemInventory {
                name: "Windows 10".into(),
                version: "10.0".into(),
                build: "19045".into(),
                architecture: "x86_64".into(),
                locale: "zh-CN".into(),
                hostname: "test-pc".into(),
            },
            cpu: CpuInventory {
                manufacturer: "Example".into(),
                model: "CPU".into(),
                cores: 4,
                threads: 8,
            },
            memory_modules: vec![],
            disks: vec![],
            volumes: vec![],
            network_adapters: vec![],
            usb_devices: vec![],
            optical_drives: vec![],
            gpus: vec![],
        }
    }

    #[test]
    fn register_request_round_trips() {
        let request = RegisterDeviceRequest {
            installation_id: "3f0f5c1e-6d1a-4dd0-9d32-9e5b2a1c8f44".into(),
            hostname: "test-pc".into(),
            client_version: "0.1.2".into(),
            inventory: inventory(),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: RegisterDeviceRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn policy_envelope_round_trips() {
        let envelope = PolicyEnvelope {
            version: 3,
            expires_at: Utc.with_ymd_and_hms(2026, 12, 31, 15, 59, 59).unwrap(),
            policy_json: serde_json::json!({ "network": { "policy": "deny" } }),
            signature_hex: "00".into(),
            server_key_id: "test-key".into(),
        };
        let encoded = serde_json::to_string(&envelope).unwrap();
        let decoded: PolicyEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn keyring_round_trips() {
        let keyring = ServerKeyringResponse {
            keys: vec![ServerKey {
                key_id: "a".repeat(64),
                public_key_hex: "b".repeat(64),
                status: ServerKeyStatus::Active,
            }],
        };
        let encoded = serde_json::to_string(&keyring).unwrap();
        let decoded: ServerKeyringResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, keyring);
        assert!(encoded.contains("\"status\":\"active\""));
    }

    #[test]
    fn error_uses_snake_case_code() {
        let error = ApiError {
            code: ApiErrorCode::DevicePending,
            message: "device approval pending".into(),
            details: None,
        };
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], "device_pending");
    }

    #[test]
    fn unknown_error_codes_are_preserved() {
        let error: ApiError = serde_json::from_value(serde_json::json!({
            "code": "future_error",
            "message": "new server error"
        }))
        .unwrap();
        assert_eq!(error.code, ApiErrorCode::Unknown("future_error".into()));
        assert_eq!(serde_json::to_value(error).unwrap()["code"], "future_error");
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn device_status_has_a_stable_wire_mapping() {
        for status in [
            DeviceStatus::Pending,
            DeviceStatus::Active,
            DeviceStatus::Rejected,
            DeviceStatus::Disabled,
        ] {
            assert_eq!(DeviceStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(DeviceStatus::parse("enabled"), None);
        assert_eq!(HARDWARE_INVENTORY_SCHEMA_VERSION, 1);
    }
}
