//! 审批令牌：服务端签发，终端本地验证并临时放行。

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::CoreError;
use crate::policy::DeviceScope;

/// 支持的放行动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAction {
    /// 临时允许 USB 存储写入。
    UsbWrite,
    /// 临时允许 USB 存储读入。
    UsbRead,
    /// 临时允许刻录。
    Burn,
    /// 临时允许网卡启用。
    NicEnable,
    /// 临时允许指定目录文件写入。
    DirWrite,
    /// 临时降低某个敏感规则的处置等级。
    DowngradeRule,
}

/// 审批令牌载荷（不含签名）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalPayload {
    pub approval_id: String,
    pub applicant: String,
    pub approver: String,
    pub device_scope: DeviceScope,
    pub action: ApprovalAction,
    /// 资源范围。"*" 匹配全部；末尾 "*" 表示前缀匹配；其余为精确匹配。
    pub resource: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub reason: String,
}

/// 带服务端签名的审批令牌。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalToken {
    #[serde(flatten)]
    pub payload: ApprovalPayload,
    pub signature: String,
}

impl ApprovalToken {
    /// 对载荷签名并打包。
    pub fn sign(payload: ApprovalPayload, key: &SigningKey) -> Result<Self, CoreError> {
        let bytes = serde_json::to_vec(&payload)?;
        Ok(Self {
            payload,
            signature: crypto::sign_bytes(&bytes, key),
        })
    }

    /// 验证服务端签名。
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        match serde_json::to_vec(&self.payload) {
            Ok(bytes) => crypto::verify_bytes(&bytes, key, &self.signature),
            Err(_) => false,
        }
    }
}

/// 资源匹配：通配、前缀或精确。
pub fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    pattern == resource
}

/// 在本地令牌缓存中匹配一次放行。验签、动作、设备范围、
/// 资源范围和时间窗全部通过才命中。
pub fn match_approval<'a>(
    tokens: &'a [ApprovalToken],
    key: &VerifyingKey,
    device_id: &str,
    device_groups: &[String],
    action: ApprovalAction,
    resource: &str,
    now: DateTime<Utc>,
) -> Option<&'a ApprovalToken> {
    tokens.iter().find(|t| {
        t.verify_signature(key)
            && t.payload.action == action
            && t.payload.device_scope.matches(device_id, device_groups)
            && resource_matches(&t.payload.resource, resource)
            && now >= t.payload.valid_from
            && now <= t.payload.valid_until
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn sample_payload() -> ApprovalPayload {
        ApprovalPayload {
            approval_id: "appr-1".into(),
            applicant: "alice".into(),
            approver: "bob".into(),
            device_scope: DeviceScope {
                devices: vec!["dev-1".into()],
                groups: vec![],
            },
            action: ApprovalAction::UsbWrite,
            resource: "E:\\*".into(),
            valid_from: Utc::now() - Duration::hours(1),
            valid_until: Utc::now() + Duration::hours(4),
            reason: "外出拷贝资料".into(),
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, vk) = crypto::generate_keypair();
        let token = ApprovalToken::sign(sample_payload(), &sk).unwrap();
        assert!(token.verify_signature(&vk));

        let mut forged = token.clone();
        forged.payload.applicant = "mallory".into();
        assert!(!forged.verify_signature(&vk));
    }

    #[test]
    fn resource_match_rules() {
        assert!(resource_matches("*", "anything"));
        assert!(resource_matches("E:\\*", "E:\\docs\\a.txt"));
        assert!(!resource_matches("E:\\*", "F:\\a.txt"));
        assert!(resource_matches("E:\\a.txt", "E:\\a.txt"));
        assert!(!resource_matches("E:\\a.txt", "E:\\b.txt"));
    }

    #[test]
    fn matching_hits_on_valid_token() {
        let (sk, vk) = crypto::generate_keypair();
        let token = ApprovalToken::sign(sample_payload(), &sk).unwrap();
        let tokens = vec![token];
        let hit = match_approval(
            &tokens,
            &vk,
            "dev-1",
            &[],
            ApprovalAction::UsbWrite,
            "E:\\docs\\a.txt",
            Utc::now(),
        );
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().payload.approval_id, "appr-1");
    }

    #[test]
    fn matching_rejects_wrong_dimensions() {
        let (sk, vk) = crypto::generate_keypair();
        let token = ApprovalToken::sign(sample_payload(), &sk).unwrap();
        let tokens = vec![token];
        let now = Utc::now();

        // 设备不匹配
        assert!(match_approval(
            &tokens,
            &vk,
            "dev-2",
            &[],
            ApprovalAction::UsbWrite,
            "E:\\a",
            now
        )
        .is_none());
        // 动作不匹配
        assert!(match_approval(
            &tokens,
            &vk,
            "dev-1",
            &[],
            ApprovalAction::Burn,
            "E:\\a",
            now
        )
        .is_none());
        // 资源不匹配
        assert!(match_approval(
            &tokens,
            &vk,
            "dev-1",
            &[],
            ApprovalAction::UsbWrite,
            "F:\\a",
            now
        )
        .is_none());
        // 时间窗外
        assert!(match_approval(
            &tokens,
            &vk,
            "dev-1",
            &[],
            ApprovalAction::UsbWrite,
            "E:\\a",
            now + Duration::hours(5)
        )
        .is_none());

        // 伪造签名
        let mut forged = ApprovalToken::sign(sample_payload(), &sk).unwrap();
        forged.payload.reason = "forged".into();
        let forged_tokens = vec![forged];
        assert!(match_approval(
            &forged_tokens,
            &vk,
            "dev-1",
            &[],
            ApprovalAction::UsbWrite,
            "E:\\a",
            now
        )
        .is_none());
    }
}
