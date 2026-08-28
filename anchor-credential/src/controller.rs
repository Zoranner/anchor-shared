use std::time::Duration;

use anchor_core::{AuthorizationDenial, AuthorizationState};
use anchor_service::protocol::{AuthorizationResponse, ServiceRequest, ServiceResponse};
use anchor_system::pipe::{transact, DEFAULT_CONTROL_PIPE};

use crate::filter::filter_provider_ids;

/// Credential Provider 调用本地守护服务的最大等待时间。
pub const SERVICE_IPC_TIMEOUT: Duration = Duration::from_millis(500);

/// 本地守护服务的最小调用边界。
///
/// Windows Named Pipe 实现由原生层注入。测试和非 Windows 平台使用同一边界，
/// 从而确保本地服务无响应时保持拒绝。
pub trait CredentialServiceTransport {
    type Error;

    fn transact(
        &self,
        request: ServiceRequest,
        timeout: Duration,
    ) -> Result<ServiceResponse, Self::Error>;
}

/// 使用 Anchor Guard 固定本地 Named Pipe 的传输实现。
///
/// 平台层在非 Windows 上返回不支持错误，调用方据此保持拒绝。
#[derive(Debug, Clone, Copy, Default)]
pub struct AnchorPipeTransport;

impl CredentialServiceTransport for AnchorPipeTransport {
    type Error = String;

    fn transact(
        &self,
        request: ServiceRequest,
        timeout: Duration,
    ) -> Result<ServiceResponse, Self::Error> {
        let request = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
        let response =
            transact(DEFAULT_CONTROL_PIPE, &request, timeout).map_err(|error| error.to_string())?;
        serde_json::from_slice(&response).map_err(|error| error.to_string())
    }
}

/// 通知 LogonUI 重新枚举 Credential Provider 的回调。
pub trait CredentialsChanged {
    fn credentials_changed(&mut self);
}

/// 导入 tile 展示的结果状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportTileStatus {
    Ready,
    Imported(String),
    Rejected(String),
    ServiceUnavailable,
}

impl ImportTileStatus {
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Ready => "等待导入策略",
            Self::Imported(message) | Self::Rejected(message) => message,
            Self::ServiceUnavailable => "本地守护服务不可用",
        }
    }
}

/// 最小策略导入 tile 的显示状态与动作。
///
/// 它不保存或收集路径、密钥、PIN 或用户凭据；动作固定委托给本地服务的可移动
/// 根目录导入命令。
pub struct ImportTile<T> {
    controller: CredentialProviderController<T>,
    status: ImportTileStatus,
}

impl<T> ImportTile<T>
where
    T: CredentialServiceTransport,
{
    #[must_use]
    pub fn new(controller: CredentialProviderController<T>) -> Self {
        Self {
            controller,
            status: ImportTileStatus::Ready,
        }
    }

    #[must_use]
    pub const fn status(&self) -> &ImportTileStatus {
        &self.status
    }

    pub fn import_from_removable_roots<C: CredentialsChanged>(
        &mut self,
        credentials_changed: &mut C,
    ) {
        self.status = self
            .controller
            .import_from_removable_roots(credentials_changed);
    }
}

/// 连接登录过滤和策略导入 tile 的无状态控制器。
pub struct CredentialProviderController<T> {
    transport: T,
}

impl<T> CredentialProviderController<T>
where
    T: CredentialServiceTransport,
{
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// 从本地服务取得授权结论。通信失败、超时和无效响应均作为拒绝。
    #[must_use]
    pub fn filter_provider_ids(&self, system_provider_ids: &[String]) -> Vec<String> {
        filter_provider_ids(&self.authorization_state(), system_provider_ids)
    }

    /// 本地服务是否允许显示系统登录 Provider。
    ///
    /// 通信失败、超时和无效响应均不允许显示。
    #[must_use]
    pub fn allows_system_providers(&self) -> bool {
        self.authorization_state() == AuthorizationState::Allowed
    }

    /// 请求服务扫描可移动介质根目录并导入策略。
    ///
    /// 此边界只发送固定命令，不接收或传递路径、密钥、PIN 或用户凭据。
    #[must_use]
    pub fn import_from_removable_roots<C: CredentialsChanged>(
        &self,
        credentials_changed: &mut C,
    ) -> ImportTileStatus {
        match self.transport.transact(
            ServiceRequest::ImportFromRemovableRoots,
            SERVICE_IPC_TIMEOUT,
        ) {
            Ok(ServiceResponse::Import(response)) if response.accepted => {
                credentials_changed.credentials_changed();
                ImportTileStatus::Imported(response.reason)
            }
            Ok(ServiceResponse::Import(response)) => ImportTileStatus::Rejected(response.reason),
            Ok(ServiceResponse::Authorization(_)) | Err(_) => ImportTileStatus::ServiceUnavailable,
        }
    }

    fn authorization_state(&self) -> AuthorizationState {
        match self
            .transport
            .transact(ServiceRequest::GetAuthorization, SERVICE_IPC_TIMEOUT)
        {
            Ok(ServiceResponse::Authorization(AuthorizationResponse::Allowed)) => {
                AuthorizationState::Allowed
            }
            Ok(ServiceResponse::Authorization(AuthorizationResponse::Denied { .. }))
            | Ok(ServiceResponse::Import(_))
            | Err(_) => AuthorizationState::Denied(AuthorizationDenial::NoActivePolicy),
        }
    }
}
