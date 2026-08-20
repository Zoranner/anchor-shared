//! 策略包：服务端签发、终端本地验证和执行。

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::CoreError;

/// 设备联网类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMode {
    Internet,
    Controlled,
}

impl DeviceMode {
    /// 落库用的小写字符串表示，与 serde 序列化一致。
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceMode::Internet => "internet",
            DeviceMode::Controlled => "controlled",
        }
    }
}

impl std::str::FromStr for DeviceMode {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "internet" => Ok(DeviceMode::Internet),
            "controlled" => Ok(DeviceMode::Controlled),
            other => Err(CoreError::InvalidEnumValue {
                kind: "DeviceMode",
                value: other.to_string(),
            }),
        }
    }
}

/// 终端或终端组范围。两个列表均为空时表示全部终端。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceScope {
    #[serde(default)]
    pub devices: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

impl DeviceScope {
    /// 判断设备是否落在范围内。
    pub fn matches(&self, device_id: &str, device_groups: &[String]) -> bool {
        if self.devices.is_empty() && self.groups.is_empty() {
            return true;
        }
        if self.devices.iter().any(|d| d == device_id) {
            return true;
        }
        self.groups.iter().any(|g| device_groups.contains(g))
    }
}

/// 通道级策略动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPolicy {
    Allow,
    Record,
    RequireApproval,
    Deny,
}

/// 命中后的处置动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Record,
    Mark,
    Quarantine,
    Delete,
    RequireApproval,
}

/// 网卡控制规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRules {
    pub policy: ActionPolicy,
}

/// USB 输入输出规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbRules {
    pub read: ActionPolicy,
    pub write: ActionPolicy,
}

/// 刻录控制规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurningRules {
    pub policy: ActionPolicy,
}

/// 敏感规则类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanRuleKind {
    Keyword,
    Regex,
}

/// 单条敏感规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRule {
    pub rule_id: String,
    pub kind: ScanRuleKind,
    pub pattern: String,
    pub disposition: Disposition,
}

/// 文件扫描规则。敏感词库随策略包下发，扫描规则版本即策略版本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRules {
    #[serde(default)]
    pub controlled_dirs: Vec<String>,
    #[serde(default)]
    pub rules: Vec<ScanRule>,
    pub default_disposition: Disposition,
}

/// 自保护规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfProtectionRules {
    pub enabled: bool,
}

/// 审批令牌验证规则。trusted_approvers 为空表示不限制审批人。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRules {
    #[serde(default)]
    pub trusted_approvers: Vec<String>,
}

/// 策略包载荷（不含签名）。结构体字段顺序固定，
/// `serde_json::to_vec` 输出确定字节，可直接作为签名载荷。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub policy_id: String,
    pub version: u64,
    pub device_scope: DeviceScope,
    pub device_mode: DeviceMode,
    pub effective_from: DateTime<Utc>,
    pub offline_until: DateTime<Utc>,
    pub default_action: Disposition,
    pub network: NetworkRules,
    pub usb: UsbRules,
    pub burning: BurningRules,
    pub scan: ScanRules,
    pub self_protection: SelfProtectionRules,
    pub approval: ApprovalRules,
}

/// 带服务端签名的策略包。
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

    /// 验证服务端签名。
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        match self.payload_bytes() {
            Ok(bytes) => crypto::verify_bytes(&bytes, key, &self.signature),
            Err(_) => false,
        }
    }
}

/// 新到策略包的校验结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// 签名通过且版本更新：替换本地有效策略。
    LoadNew,
    /// 签名通过但版本不新：维持当前策略。
    KeepCurrent,
    /// 尚未到生效时间：维持当前策略。
    NotYetEffective,
    /// 签名校验异常：继续执行上一份有效策略。
    InvalidSignature,
}

/// 校验新到策略包。签名优先，其次生效时间，最后版本。
pub fn validate_incoming(
    pkg: &PolicyPackage,
    key: &VerifyingKey,
    now: DateTime<Utc>,
    current_version: Option<u64>,
) -> PolicyVerdict {
    if !pkg.verify_signature(key) {
        return PolicyVerdict::InvalidSignature;
    }
    if now < pkg.payload.effective_from {
        return PolicyVerdict::NotYetEffective;
    }
    match current_version {
        Some(v) if pkg.payload.version <= v => PolicyVerdict::KeepCurrent,
        _ => PolicyVerdict::LoadNew,
    }
}

/// 判断当前有效策略的离线有效期是否已到达。
/// 到达后终端应按 default_action 进入严格策略。
pub fn is_offline_expired(pkg: &PolicyPackage, now: DateTime<Utc>) -> bool {
    now > pkg.payload.offline_until
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn sample_payload(version: u64) -> PolicyPayload {
        PolicyPayload {
            policy_id: "policy-1".into(),
            version,
            device_scope: DeviceScope::default(),
            device_mode: DeviceMode::Controlled,
            effective_from: Utc::now() - Duration::hours(1),
            offline_until: Utc::now() + Duration::days(7),
            default_action: Disposition::Record,
            network: NetworkRules {
                policy: ActionPolicy::Record,
            },
            usb: UsbRules {
                read: ActionPolicy::Record,
                write: ActionPolicy::RequireApproval,
            },
            burning: BurningRules {
                policy: ActionPolicy::Deny,
            },
            scan: ScanRules {
                controlled_dirs: vec!["D:\\data".into()],
                rules: vec![ScanRule {
                    rule_id: "r-1".into(),
                    kind: ScanRuleKind::Keyword,
                    pattern: "机密".into(),
                    disposition: Disposition::Quarantine,
                }],
                default_disposition: Disposition::Record,
            },
            self_protection: SelfProtectionRules { enabled: true },
            approval: ApprovalRules::default(),
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
        assert!(json.contains("\"policy_id\":\"policy-1\""));
        assert!(json.contains("\"signature\":"));
        let back: PolicyPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pkg);
    }

    #[test]
    fn verdict_branches() {
        let (sk, vk) = crypto::generate_keypair();
        let now = Utc::now();

        let pkg_v2 = PolicyPackage::sign(sample_payload(2), &sk).unwrap();
        assert_eq!(
            validate_incoming(&pkg_v2, &vk, now, Some(1)),
            PolicyVerdict::LoadNew
        );
        assert_eq!(
            validate_incoming(&pkg_v2, &vk, now, Some(2)),
            PolicyVerdict::KeepCurrent
        );
        assert_eq!(
            validate_incoming(&pkg_v2, &vk, now, Some(3)),
            PolicyVerdict::KeepCurrent
        );
        assert_eq!(
            validate_incoming(&pkg_v2, &vk, now, None),
            PolicyVerdict::LoadNew
        );

        let mut future = sample_payload(4);
        future.effective_from = now + Duration::hours(2);
        let future_pkg = PolicyPackage::sign(future, &sk).unwrap();
        assert_eq!(
            validate_incoming(&future_pkg, &vk, now, Some(1)),
            PolicyVerdict::NotYetEffective
        );

        let mut bad = PolicyPackage::sign(sample_payload(5), &sk).unwrap();
        bad.payload.policy_id = "forged".into();
        assert_eq!(
            validate_incoming(&bad, &vk, now, Some(1)),
            PolicyVerdict::InvalidSignature
        );
    }

    #[test]
    fn offline_expiry_check() {
        let (sk, _) = crypto::generate_keypair();
        let mut payload = sample_payload(1);
        payload.offline_until = Utc::now() + Duration::hours(1);
        let pkg = PolicyPackage::sign(payload, &sk).unwrap();
        assert!(!is_offline_expired(&pkg, Utc::now()));
        assert!(is_offline_expired(&pkg, Utc::now() + Duration::hours(2)));
    }

    #[test]
    fn device_mode_str_roundtrip() {
        for mode in [DeviceMode::Internet, DeviceMode::Controlled] {
            assert_eq!(mode.as_str().parse::<DeviceMode>().unwrap(), mode);
        }
        assert!("offline".parse::<DeviceMode>().is_err());
        assert_eq!(
            serde_json::to_string(&DeviceMode::Controlled).unwrap(),
            "\"controlled\""
        );
    }

    #[test]
    fn scope_matching() {
        let all = DeviceScope::default();
        assert!(all.matches("dev-1", &[]));

        let scoped = DeviceScope {
            devices: vec!["dev-1".into()],
            groups: vec!["finance".into()],
        };
        assert!(scoped.matches("dev-1", &[]));
        assert!(scoped.matches("dev-2", &["finance".to_string()]));
        assert!(!scoped.matches("dev-2", &[]));
        assert!(!scoped.matches("dev-2", &["rd".to_string()]));
    }
}
