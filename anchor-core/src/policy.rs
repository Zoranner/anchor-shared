//! 策略包：管理员离线签发、终端本地验签和授权判断。

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::CoreError;

/// 设备管控的允许或拒绝动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPolicy {
    Allow,
    Deny,
}

/// 网卡控制规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRules {
    pub policy: ActionPolicy,
    #[serde(default)]
    pub allowed: Vec<NetworkAllowRule>,
}

/// 一条网卡允许规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAllowRule {
    pub adapter_id: String,
}

/// USB 存储控制规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbRules {
    pub read: ActionPolicy,
    pub write: ActionPolicy,
    #[serde(default)]
    pub allowed: Vec<UsbAllowRule>,
}

/// 一条 USB 大容量存储允许规则。所有已填写字段必须同时匹配。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbAllowRule {
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub vendor_id: Option<String>,
    #[serde(default)]
    pub product_id: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
}

/// 刻录控制规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurningRules {
    pub policy: ActionPolicy,
    #[serde(default)]
    pub allowed: Vec<BurningAllowRule>,
}

/// 一条刻录光驱允许规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurningAllowRule {
    pub drive_id: String,
}

/// 扫描规则类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanRuleKind {
    Keyword,
    Regex,
}

/// 单条文件风险识别规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRule {
    pub rule_id: String,
    pub kind: ScanRuleKind,
    pub pattern: String,
}

/// 文件风险识别规则。扫描只记录风险，不隔离或删除文件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRules {
    #[serde(default)]
    pub controlled_dirs: Vec<String>,
    #[serde(default)]
    pub rules: Vec<ScanRule>,
}

/// 策略包载荷（不含签名）。结构体字段顺序固定，
/// `serde_json::to_vec` 输出确定字节，可直接作为签名载荷。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub version: u64,
    /// 策略到期时间；策略从导入时刻起生效。
    pub expires_at: DateTime<Utc>,
    pub usb: UsbRules,
    pub network: NetworkRules,
    pub burning: BurningRules,
    pub scan: ScanRules,
}

/// 允许的系统时间回拨容差；超出该范围即视为时间篡改并拒绝授权。
pub const CLOCK_ROLLBACK_TOLERANCE_SECS: u64 = 300;

/// 带管理员签名的策略包。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPackage {
    #[serde(flatten)]
    pub payload: PolicyPayload,
    pub signature: String,
}

impl PolicyPackage {
    /// 对载荷签名并打包。
    pub fn sign(payload: PolicyPayload, key: &SigningKey) -> Result<Self, CoreError> {
        let bytes = serde_json::to_vec(&payload)?;
        Ok(Self {
            payload,
            signature: crypto::sign_bytes(&bytes, key),
        })
    }

    /// 序列化后的签名载荷字节。
    pub fn payload_bytes(&self) -> Result<Vec<u8>, CoreError> {
        Ok(serde_json::to_vec(&self.payload)?)
    }

    /// 验证管理员签名。
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        match self.payload_bytes() {
            Ok(bytes) => crypto::verify_bytes(&bytes, key, &self.signature),
            Err(_) => false,
        }
    }
}

/// 从可移动介质导入策略的校验结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDecision {
    /// 签名、版本和到期时间均通过，可以替换本地策略。
    Accept,
    /// 策略包签名无效。
    InvalidSignature,
    /// 策略版本没有严格递增。
    VersionNotNewer,
    /// 策略已过期。
    Expired,
}

/// 验证从 U 盘导入的策略包。
pub fn decide_import(
    pkg: &PolicyPackage,
    key: &VerifyingKey,
    current_version: Option<u64>,
    now: DateTime<Utc>,
) -> ImportDecision {
    if !pkg.verify_signature(key) {
        return ImportDecision::InvalidSignature;
    }
    if current_version.is_some_and(|version| pkg.payload.version <= version) {
        return ImportDecision::VersionNotNewer;
    }
    if now > pkg.payload.expires_at {
        return ImportDecision::Expired;
    }
    ImportDecision::Accept
}

/// 授权拒绝的具体原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDenial {
    NoActivePolicy,
    Expired,
    TrustedTimeUnavailable,
    ClockRollback,
    AuditUnhealthy,
    EnforcementUnhealthy,
}

/// Windows 正常登录和受控设备执行共用的授权状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationState {
    Allowed,
    Denied(AuthorizationDenial),
}

/// 根据已验签的活动策略和本地健康状态判断授权。
///
/// 活动策略只由导入流程写入，因此签名验证不在此处重复进行。没有可验证的
/// 审计链或最后可信时间时保持拒绝，避免把状态不明误判为已授权。
pub fn evaluate_authorization(
    active_policy: Option<&PolicyPackage>,
    now: DateTime<Utc>,
    last_trusted_at: Option<DateTime<Utc>>,
    audit_healthy: bool,
) -> AuthorizationState {
    if !audit_healthy {
        return AuthorizationState::Denied(AuthorizationDenial::AuditUnhealthy);
    }

    let Some(policy) = active_policy else {
        return AuthorizationState::Denied(AuthorizationDenial::NoActivePolicy);
    };
    if now > policy.payload.expires_at {
        return AuthorizationState::Denied(AuthorizationDenial::Expired);
    }

    let Some(last_trusted_at) = last_trusted_at else {
        return AuthorizationState::Denied(AuthorizationDenial::TrustedTimeUnavailable);
    };
    let tolerance =
        Duration::try_seconds(CLOCK_ROLLBACK_TOLERANCE_SECS.min(i64::MAX as u64) as i64)
            .unwrap_or(Duration::MAX);
    let earliest_allowed = last_trusted_at
        .checked_sub_signed(tolerance)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    if now < earliest_allowed {
        return AuthorizationState::Denied(AuthorizationDenial::ClockRollback);
    }

    AuthorizationState::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
    }

    fn sample_payload(version: u64) -> PolicyPayload {
        PolicyPayload {
            version,
            expires_at: now() + Duration::days(7),
            usb: UsbRules {
                read: ActionPolicy::Deny,
                write: ActionPolicy::Deny,
                allowed: vec![],
            },
            network: NetworkRules {
                policy: ActionPolicy::Deny,
                allowed: vec![],
            },
            burning: BurningRules {
                policy: ActionPolicy::Deny,
                allowed: vec![],
            },
            scan: ScanRules {
                controlled_dirs: vec!["D:\\data".into()],
                rules: vec![ScanRule {
                    rule_id: "r-1".into(),
                    kind: ScanRuleKind::Keyword,
                    pattern: "机密".into(),
                }],
            },
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, vk) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(1), &sk).unwrap();
        assert!(pkg.verify_signature(&vk));
    }

    #[test]
    fn verify_rejects_tampered_package() {
        let (sk, vk) = crypto::generate_keypair();
        let mut pkg = PolicyPackage::sign(sample_payload(1), &sk).unwrap();
        pkg.payload.version = 99;
        assert!(!pkg.verify_signature(&vk));
    }

    #[test]
    fn json_roundtrip_keeps_flat_shape() {
        let (sk, _) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(3), &sk).unwrap();
        let json = serde_json::to_string(&pkg).unwrap();
        assert!(json.contains("\"version\":3"));
        assert!(json.contains("\"expires_at\":"));
        assert!(json.contains("\"signature\":"));
        let back: PolicyPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pkg);
    }

    #[test]
    fn policy_json_serializes_explicit_device_allowlists_and_defaults_them_to_empty() {
        let payload = serde_json::json!({
            "version": 1,
            "expires_at": "2026-09-04T08:00:00Z",
            "usb": {
                "read": "allow",
                "write": "deny",
                "allowed": [{
                    "instance_id": "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1",
                    "vendor_id": "1234",
                    "product_id": "5678",
                    "serial": "1"
                }]
            },
            "network": {
                "policy": "allow",
                "allowed": [{ "adapter_id": "nic-private" }]
            },
            "burning": {
                "policy": "deny",
                "allowed": [{ "drive_id": "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1" }]
            },
            "scan": {
                "controlled_dirs": ["D:\\data"],
                "rules": []
            }
        });

        let parsed: PolicyPayload = serde_json::from_value(payload).unwrap();
        let serialized = serde_json::to_value(parsed).unwrap();

        assert_eq!(
            serialized["usb"]["allowed"][0]["instance_id"],
            "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1"
        );
        assert_eq!(
            serialized["network"]["allowed"][0]["adapter_id"],
            "nic-private"
        );
        assert_eq!(
            serialized["burning"]["allowed"][0]["drive_id"],
            "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1"
        );

        let without_allowlists = serde_json::json!({
            "version": 1,
            "expires_at": "2026-09-04T08:00:00Z",
            "usb": { "read": "deny", "write": "deny" },
            "network": { "policy": "deny" },
            "burning": { "policy": "deny" },
            "scan": { "controlled_dirs": ["D:\\data"], "rules": [] }
        });
        let parsed: PolicyPayload = serde_json::from_value(without_allowlists).unwrap();
        let serialized = serde_json::to_value(parsed).unwrap();

        assert_eq!(serialized["usb"]["allowed"], serde_json::json!([]));
        assert_eq!(serialized["network"]["allowed"], serde_json::json!([]));
        assert_eq!(serialized["burning"]["allowed"], serde_json::json!([]));
    }

    #[test]
    fn signed_current_policy_is_accepted() {
        let (sk, vk) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(2), &sk).unwrap();

        assert_eq!(
            decide_import(&pkg, &vk, Some(1), now()),
            ImportDecision::Accept
        );
    }

    #[test]
    fn import_rejects_tampered_package_before_other_checks() {
        let (sk, vk) = crypto::generate_keypair();
        let mut pkg = PolicyPackage::sign(sample_payload(1), &sk).unwrap();
        pkg.payload.version = 99;

        assert_eq!(
            decide_import(&pkg, &vk, Some(1), now()),
            ImportDecision::InvalidSignature
        );
    }

    #[test]
    fn import_rejects_non_increasing_versions() {
        let (sk, vk) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(2), &sk).unwrap();

        assert_eq!(
            decide_import(&pkg, &vk, Some(2), now()),
            ImportDecision::VersionNotNewer
        );
    }

    #[test]
    fn import_rejects_an_expired_policy() {
        let (sk, vk) = crypto::generate_keypair();
        let mut expired = sample_payload(3);
        expired.expires_at = now() - Duration::minutes(1);
        let expired = PolicyPackage::sign(expired, &sk).unwrap();

        assert_eq!(
            decide_import(&expired, &vk, Some(1), now()),
            ImportDecision::Expired
        );
    }

    #[test]
    fn active_policy_with_a_healthy_audit_allows_authorization() {
        let (sk, _) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(1), &sk).unwrap();

        assert_eq!(
            evaluate_authorization(Some(&pkg), now(), Some(now()), true),
            AuthorizationState::Allowed
        );
    }

    #[test]
    fn authorization_rejects_missing_or_invalid_local_state() {
        let (sk, _) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(1), &sk).unwrap();

        assert_eq!(
            evaluate_authorization(None, now(), Some(now()), true),
            AuthorizationState::Denied(AuthorizationDenial::NoActivePolicy)
        );
        assert_eq!(
            evaluate_authorization(Some(&pkg), now(), Some(now()), false),
            AuthorizationState::Denied(AuthorizationDenial::AuditUnhealthy)
        );
        assert_eq!(
            evaluate_authorization(Some(&pkg), now(), None, true),
            AuthorizationState::Denied(AuthorizationDenial::TrustedTimeUnavailable)
        );
    }

    #[test]
    fn authorization_rejects_an_expired_policy_and_clock_rollback() {
        let (sk, _) = crypto::generate_keypair();
        let mut expired = sample_payload(1);
        expired.expires_at = now() - Duration::seconds(1);
        let expired = PolicyPackage::sign(expired, &sk).unwrap();
        let current = PolicyPackage::sign(sample_payload(2), &sk).unwrap();

        assert_eq!(
            evaluate_authorization(Some(&expired), now(), Some(now()), true),
            AuthorizationState::Denied(AuthorizationDenial::Expired)
        );
        assert_eq!(
            evaluate_authorization(
                Some(&current),
                now(),
                Some(now() + Duration::seconds(301)),
                true,
            ),
            AuthorizationState::Denied(AuthorizationDenial::ClockRollback)
        );
    }

    #[test]
    fn clock_rollback_within_the_tolerance_is_allowed() {
        let (sk, _) = crypto::generate_keypair();
        let pkg = PolicyPackage::sign(sample_payload(1), &sk).unwrap();

        assert_eq!(
            evaluate_authorization(
                Some(&pkg),
                now(),
                Some(now() + Duration::seconds(CLOCK_ROLLBACK_TOLERANCE_SECS as i64)),
                true,
            ),
            AuthorizationState::Allowed
        );
    }
}
