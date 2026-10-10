use std::fs;
use std::path::Path;

use anchor_core::{
    decide_import, evaluate_authorization, AuditPayload, AuthorizationDenial, AuthorizationState,
    EventType, ImportDecision,
};
use anchor_store::Store;
use anchor_system::{
    error::PlatformError,
    pipe::{serve_once, serve_session_status_once, PipeServeOutcome, DEFAULT_CONTROL_PIPE},
    removable::removable_roots,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

use crate::protocol::{AuthorizationResponse, ImportResponse, ServiceRequest, ServiceResponse};

const POLICY_FILE_NAME: &str = "anchor-guard.policy";

/// 服务层对一次导入请求的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    pub accepted: bool,
    pub reason: String,
}

/// 本地授权的唯一组织者。
pub struct Service {
    pub(crate) store: Store,
    verifying_key: VerifyingKey,
    pub(crate) device_id: String,
}

impl Service {
    pub fn new(store: Store, verifying_key: VerifyingKey, device_id: impl Into<String>) -> Self {
        Self {
            store,
            verifying_key,
            device_id: device_id.into(),
        }
    }

    /// 返回 Windows 登录和设备执行共用的当前授权结论。
    /// 存储不可读、链异常或运行状态无法解析时一律拒绝。
    pub fn authorization_state(&self, now: DateTime<Utc>) -> AuthorizationState {
        self.authorization_state_with_enforcement_failure(now, true)
    }

    /// 记录用户会话协作程序故障并进入运行期 fail-closed 状态。
    pub fn record_session_assistant_failure(
        &self,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), anchor_store::StoreError> {
        let mut event = AuditPayload::new(
            &self.device_id,
            "AnchorGuard",
            EventType::SessionAssistantFailed,
            "session_assistant",
            "failed",
        );
        event.timestamp = now;
        event.resource = Some(reason.into());
        self.store
            .append_audit_and_set_enforcement_failure(event, "session_assistant_failed", now)
    }

    /// 记录服务启动、审计校验与停止等生命周期事件。
    pub fn record_lifecycle_event(
        &self,
        event_type: EventType,
        action: &str,
        result: &str,
        now: DateTime<Utc>,
    ) -> Result<(), anchor_store::StoreError> {
        let mut event =
            AuditPayload::new(&self.device_id, "AnchorGuard", event_type, action, result);
        event.timestamp = now;
        self.store.append_audit(event)
    }

    /// 返回本地审计链是否完整。
    pub fn audit_chain_healthy(&self) -> Result<bool, anchor_store::StoreError> {
        self.store.audit_chain_healthy()
    }

    pub(crate) fn authorization_state_for_enforcement(
        &self,
        now: DateTime<Utc>,
    ) -> AuthorizationState {
        self.authorization_state_with_enforcement_failure(now, false)
    }

    fn authorization_state_with_enforcement_failure(
        &self,
        now: DateTime<Utc>,
        check_enforcement_failure: bool,
    ) -> AuthorizationState {
        if check_enforcement_failure {
            match self.store.enforcement_failure() {
                Ok(Some(_)) => {
                    return AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
                }
                Ok(None) => {}
                Err(_) => return AuthorizationState::Denied(AuthorizationDenial::AuditUnhealthy),
            }
        }
        let active_policy = match self.store.active_policy() {
            Ok(policy) => policy,
            Err(_) => return AuthorizationState::Denied(AuthorizationDenial::AuditUnhealthy),
        };
        let audit_healthy = self.store.audit_chain_healthy().unwrap_or(false);
        let last_trusted_at = match self.store.last_trusted_at() {
            Ok(timestamp) => timestamp,
            Err(_) => {
                return AuthorizationState::Denied(AuthorizationDenial::TrustedTimeUnavailable)
            }
        };

        let authorization =
            evaluate_authorization(active_policy.as_ref(), now, last_trusted_at, audit_healthy);
        if authorization == AuthorizationState::Allowed
            && self.store.record_trusted_time(now).is_err()
        {
            return AuthorizationState::Denied(AuthorizationDenial::TrustedTimeUnavailable);
        }
        authorization
    }

    /// 处理 Credential Provider 可调用的有限请求集。
    pub fn handle_request(
        &self,
        request: ServiceRequest,
        user: &str,
        now: DateTime<Utc>,
    ) -> ServiceResponse {
        match request {
            ServiceRequest::GetAuthorization => ServiceResponse::Authorization(
                authorization_response(self.authorization_state(now)),
            ),
            ServiceRequest::ImportFromRemovableRoots => {
                let outcome = self.import_from_removable_roots(user, now);
                ServiceResponse::Import(ImportResponse {
                    accepted: outcome.accepted,
                    reason: outcome.reason,
                })
            }
        }
    }

    /// 处理 Named Pipe 传入的 JSON 载荷。
    ///
    /// 长度前缀由 `anchor-system::pipe` 负责，业务层仅编解码请求和响应 JSON，
    /// 以避免在 Credential Provider 与服务之间重复封帧。
    pub fn handle_json_request(
        &self,
        request: &[u8],
        user: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let request = serde_json::from_slice(request)?;
        serde_json::to_vec(&self.handle_request(request, user, now))
    }

    /// 处理用户会话状态端点传入的 JSON 授权查询。
    ///
    /// 此端点面向已登录用户，固定只读；策略导入仍只能通过受 `SYSTEM` 限制的控制端点
    /// 发起，避免会话协作程序获得导入能力。
    pub fn handle_session_status_request(
        &self,
        request: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>, PlatformError> {
        let request = serde_json::from_slice(request)
            .map_err(|error| PlatformError::Failed(format!("会话状态 JSON 协议错误: {error}")))?;
        let ServiceRequest::GetAuthorization = request else {
            return Err(PlatformError::Failed("会话状态端点只接受授权查询".into()));
        };
        serde_json::to_vec(&ServiceResponse::Authorization(authorization_response(
            self.authorization_state(now),
        )))
        .map_err(|error| PlatformError::Failed(format!("会话状态 JSON 编码错误: {error}")))
    }

    /// 在固定控制端点处理一条 Credential Provider 请求。
    ///
    /// Credential Provider 由 LogonUI 承载，审计主体使用受控进程名称而不是客户端
    /// 可伪造的输入。Windows Service 的事件循环应重复调用本方法。
    pub fn serve_control_pipe_once(
        &self,
        now: DateTime<Utc>,
    ) -> Result<PipeServeOutcome, PlatformError> {
        serve_once(DEFAULT_CONTROL_PIPE, |request| {
            self.handle_json_request(request, "LogonUI", now)
                .map_err(|error| {
                    PlatformError::Failed(format!("Named Pipe JSON 协议错误: {error}"))
                })
        })
    }

    /// 在会话状态端点处理一条仅查询授权的请求。
    pub fn serve_session_status_pipe_once(
        &self,
        now: DateTime<Utc>,
    ) -> Result<PipeServeOutcome, PlatformError> {
        serve_session_status_once(|request| self.handle_session_status_request(request, now))
    }

    /// 枚举 Windows 已就绪可移动盘根目录后导入固定策略文件。
    pub fn import_from_removable_roots(&self, user: &str, now: DateTime<Utc>) -> ImportOutcome {
        let roots = removable_roots();
        let roots: Vec<&Path> = roots.iter().map(Path::new).collect();
        self.import_from_roots(&roots, user, now)
    }

    /// 从调用方提供的根目录导入策略。此接口同时用于 Windows 枚举和无设备依赖测试。
    pub fn import_from_roots(
        &self,
        roots: &[&Path],
        user: &str,
        now: DateTime<Utc>,
    ) -> ImportOutcome {
        let mut found_policy = false;
        let mut last_rejection = None;

        for root in roots {
            let policy_path = root.join(POLICY_FILE_NAME);
            if !policy_path.is_file() {
                continue;
            }
            found_policy = true;

            let package = match fs::read(&policy_path)
                .ok()
                .and_then(|content| serde_json::from_slice(&content).ok())
            {
                Some(package) => package,
                None => {
                    let reason = "policy_parse_failed";
                    if self.append_import_rejection(user, now, reason).is_err() {
                        return ImportOutcome::denied("audit_write_failed");
                    }
                    last_rejection = Some(reason);
                    continue;
                }
            };
            let current_version = match self.store.active_policy() {
                Ok(package) => package.map(|package| package.payload.version),
                Err(_) => return ImportOutcome::denied("store_unavailable"),
            };
            let decision = decide_import(&package, &self.verifying_key, current_version, now);
            if self
                .store
                .import_policy(&package, decision, &self.device_id, user, now)
                .is_err()
            {
                return ImportOutcome::denied("store_unavailable");
            }
            if decision == ImportDecision::Accept {
                return ImportOutcome::accepted();
            }
            last_rejection = Some(import_rejection_reason(decision));
        }

        if !found_policy {
            if self
                .append_import_rejection(user, now, "policy_not_found")
                .is_err()
            {
                return ImportOutcome::denied("audit_write_failed");
            }
            return ImportOutcome::denied("policy_not_found");
        }
        ImportOutcome::denied(last_rejection.unwrap_or("policy_not_accepted"))
    }

    fn append_import_rejection(
        &self,
        user: &str,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<(), anchor_store::StoreError> {
        let mut event = AuditPayload::new(
            &self.device_id,
            user,
            EventType::PolicyImportRejected,
            "import_policy",
            reason,
        );
        event.timestamp = now;
        self.store.append_audit(event)
    }
}

impl ImportOutcome {
    fn accepted() -> Self {
        Self {
            accepted: true,
            reason: "accepted".into(),
        }
    }

    fn denied(reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            reason: reason.into(),
        }
    }
}

fn import_rejection_reason(decision: ImportDecision) -> &'static str {
    match decision {
        ImportDecision::Accept => "accepted",
        ImportDecision::InvalidSignature => "invalid_signature",
        ImportDecision::VersionNotNewer => "version_not_newer",
        ImportDecision::Expired => "expired",
    }
}

fn authorization_response(state: AuthorizationState) -> AuthorizationResponse {
    match state {
        AuthorizationState::Allowed => AuthorizationResponse::Allowed,
        AuthorizationState::Denied(reason) => AuthorizationResponse::Denied {
            reason: match reason {
                AuthorizationDenial::NoActivePolicy => "no_active_policy",
                AuthorizationDenial::Expired => "expired",
                AuthorizationDenial::TrustedTimeUnavailable => "trusted_time_unavailable",
                AuthorizationDenial::ClockRollback => "clock_rollback",
                AuthorizationDenial::AuditUnhealthy => "audit_unhealthy",
                AuthorizationDenial::EnforcementUnhealthy => "enforcement_unhealthy",
            }
            .into(),
        },
    }
}
