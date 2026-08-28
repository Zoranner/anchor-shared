//! 用户会话中的本地授权轮询与锁定协作。
//!
//! 此 crate 只在已启动的用户会话中工作：周期查询本地守护服务，拒绝或服务不可用时
//! 锁定当前会话。任务注册、进程启动和注册表配置由部署层负责。

use std::time::Duration;

use anchor_service::protocol::{AuthorizationResponse, ServiceRequest, ServiceResponse};
use anchor_system::{
    error::PlatformError,
    pipe::{transact, SESSION_STATUS_PIPE},
    session::SessionLocker,
};

/// 单次本地授权查询的最大等待时间。
pub const SERVICE_IPC_TIMEOUT: Duration = Duration::from_millis(500);

/// 当前用户会话的授权检查周期。
pub const AUTHORIZATION_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// 向本地守护服务查询当前授权状态的边界。
pub trait AuthorizationClient {
    type Error;

    /// 查询当前授权结论。
    fn get_authorization(&self, timeout: Duration) -> Result<AuthorizationResponse, Self::Error>;
}

/// 使用 Anchor Guard 固定本地 Named Pipe 的授权查询实现。
#[derive(Debug, Clone, Copy, Default)]
pub struct AnchorPipeAuthorizationClient;

impl AuthorizationClient for AnchorPipeAuthorizationClient {
    type Error = String;

    fn get_authorization(&self, timeout: Duration) -> Result<AuthorizationResponse, Self::Error> {
        let request = serde_json::to_vec(&ServiceRequest::GetAuthorization)
            .map_err(|error| error.to_string())?;
        let response =
            transact(SESSION_STATUS_PIPE, &request, timeout).map_err(|error| error.to_string())?;
        match serde_json::from_slice(&response).map_err(|error| error.to_string())? {
            ServiceResponse::Authorization(response) => Ok(response),
            ServiceResponse::Import(_) => Err("本地守护服务返回了非授权响应".into()),
        }
    }
}

/// 单次授权检查的可观察结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCheckOutcome {
    /// 服务明确允许当前会话继续使用。
    Authorized,
    /// 服务明确拒绝，当前会话已请求锁定。
    LockedAfterDenied,
    /// 服务不可用或协议响应无效，当前会话已请求锁定。
    LockedAfterUnavailable,
}

/// 用户会话中的授权检查协作程序。
pub struct SessionAssistant<C, L> {
    client: C,
    locker: L,
}

impl<C, L> SessionAssistant<C, L>
where
    C: AuthorizationClient,
    L: SessionLocker,
{
    #[must_use]
    pub fn new(client: C, locker: L) -> Self {
        Self { client, locker }
    }

    /// 执行一次授权查询；拒绝、通信错误和无效响应均锁定当前会话。
    pub fn run_once(&self) -> Result<SessionCheckOutcome, PlatformError> {
        match self.client.get_authorization(SERVICE_IPC_TIMEOUT) {
            Ok(AuthorizationResponse::Allowed) => Ok(SessionCheckOutcome::Authorized),
            Ok(AuthorizationResponse::Denied { .. }) => {
                self.locker.lock_current_session()?;
                Ok(SessionCheckOutcome::LockedAfterDenied)
            }
            Err(_) => {
                self.locker.lock_current_session()?;
                Ok(SessionCheckOutcome::LockedAfterUnavailable)
            }
        }
    }

    /// 按固定周期持续检查当前会话授权。
    pub fn run_forever(&self) -> ! {
        loop {
            if let Err(error) = self.run_once() {
                eprintln!("当前会话锁定失败: {error}");
            }
            std::thread::sleep(AUTHORIZATION_POLL_INTERVAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use anchor_service::protocol::AuthorizationResponse;
    use anchor_system::{
        error::PlatformError,
        session::{SessionLockResult, SessionLocker},
    };

    #[derive(Clone)]
    struct RecordingClient {
        response: Result<AuthorizationResponse, &'static str>,
        timeouts: Arc<Mutex<Vec<Duration>>>,
    }

    impl RecordingClient {
        fn responding(response: Result<AuthorizationResponse, &'static str>) -> Self {
            Self {
                response,
                timeouts: Arc::default(),
            }
        }
    }

    impl super::AuthorizationClient for RecordingClient {
        type Error = &'static str;

        fn get_authorization(
            &self,
            timeout: Duration,
        ) -> Result<AuthorizationResponse, Self::Error> {
            self.timeouts.lock().unwrap().push(timeout);
            self.response.clone()
        }
    }

    #[derive(Clone, Default)]
    struct RecordingLocker(Arc<Mutex<usize>>);

    impl SessionLocker for RecordingLocker {
        fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError> {
            *self.0.lock().unwrap() += 1;
            Ok(SessionLockResult::Locked)
        }
    }

    #[test]
    fn denied_authorization_locks_the_current_session() {
        let client = RecordingClient::responding(Ok(AuthorizationResponse::Denied {
            reason: "expired".into(),
        }));
        let locker = RecordingLocker::default();
        let assistant = super::SessionAssistant::new(client.clone(), locker.clone());

        let outcome = assistant.run_once().unwrap();

        assert_eq!(outcome, super::SessionCheckOutcome::LockedAfterDenied);
        assert_eq!(*locker.0.lock().unwrap(), 1);
        assert_eq!(
            *client.timeouts.lock().unwrap(),
            vec![super::SERVICE_IPC_TIMEOUT]
        );
    }

    #[test]
    fn unavailable_authorization_service_locks_the_current_session() {
        let client = RecordingClient::responding(Err("pipe unavailable"));
        let locker = RecordingLocker::default();
        let assistant = super::SessionAssistant::new(client, locker.clone());

        let outcome = assistant.run_once().unwrap();

        assert_eq!(outcome, super::SessionCheckOutcome::LockedAfterUnavailable);
        assert_eq!(*locker.0.lock().unwrap(), 1);
    }

    #[test]
    fn allowed_authorization_does_not_lock_the_current_session() {
        let client = RecordingClient::responding(Ok(AuthorizationResponse::Allowed));
        let locker = RecordingLocker::default();
        let assistant = super::SessionAssistant::new(client, locker.clone());

        let outcome = assistant.run_once().unwrap();

        assert_eq!(outcome, super::SessionCheckOutcome::Authorized);
        assert_eq!(*locker.0.lock().unwrap(), 0);
    }
}
