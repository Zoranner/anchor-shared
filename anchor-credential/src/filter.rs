use anchor_core::AuthorizationState;

/// Anchor 策略导入 Credential Provider 的注册 CLSID。
pub const ANCHOR_PROVIDER_CLSID: &str = "{7D56DFA0-7C16-4F0B-BB35-AD2E4A3B7021}";

/// Anchor 登录过滤器的注册 CLSID。
pub const ANCHOR_FILTER_CLSID: &str = "{B4D4951B-D540-4421-A90C-19E1BBABAFB8}";

/// 根据服务授权结论选择登录页可见的 Credential Provider。
///
/// 策略导入入口始终保留：锁屏期间它是设备唯一的策略更新通道，授权有效时管理员
/// 也需要在锁屏页导入下一份策略。授权不明和拒绝状态只显示这一个入口。
#[must_use]
pub fn filter_provider_ids(
    authorization: &AuthorizationState,
    system_provider_ids: &[String],
) -> Vec<String> {
    let mut visible = match authorization {
        AuthorizationState::Allowed => system_provider_ids.to_vec(),
        AuthorizationState::Denied(_) => Vec::new(),
    };
    if !visible.iter().any(|id| id == ANCHOR_PROVIDER_CLSID) {
        visible.push(ANCHOR_PROVIDER_CLSID.to_string());
    }
    visible
}

#[cfg(test)]
mod tests {
    use anchor_core::{AuthorizationDenial, AuthorizationState};

    use super::*;

    #[test]
    fn denied_authorization_only_keeps_the_anchor_import_provider() {
        let visible = filter_provider_ids(
            &AuthorizationState::Denied(AuthorizationDenial::Expired),
            &["password".into(), "pin".into(), "hello".into()],
        );

        assert_eq!(visible, vec![ANCHOR_PROVIDER_CLSID.to_string()]);
    }

    #[test]
    fn allowed_authorization_preserves_system_providers() {
        let visible = filter_provider_ids(
            &AuthorizationState::Allowed,
            &["password".into(), "pin".into(), "hello".into()],
        );

        assert_eq!(
            visible,
            vec!["password", "pin", "hello", ANCHOR_PROVIDER_CLSID]
        );
    }

    #[test]
    fn the_import_entry_is_never_duplicated() {
        let visible = filter_provider_ids(
            &AuthorizationState::Allowed,
            &[ANCHOR_PROVIDER_CLSID.to_string(), "password".into()],
        );

        assert_eq!(visible, vec![ANCHOR_PROVIDER_CLSID, "password"]);
    }
}
