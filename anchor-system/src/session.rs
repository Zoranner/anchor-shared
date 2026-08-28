//! 当前交互会话锁定适配。
//!
//! Windows 实现仅调用 `LockWorkStation`。策略判断与会话协作程序的启动由服务层负责，
//! 本模块只提供可替换的锁定动作。

use crate::error::PlatformError;

/// 当前交互会话的锁定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLockResult {
    /// Windows 已接受当前工作站的锁定请求。
    Locked,
}

/// 当前交互会话的锁定能力。
///
/// 服务层在授权拒绝后通过该接口发起锁定，并可在测试中替换实现。
pub trait SessionLocker: Send + Sync {
    /// 锁定当前交互会话。
    fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError>;
}

/// 当前平台的本地会话锁定实现。
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalSessionLocker;

impl SessionLocker for LocalSessionLocker {
    fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError> {
        lock_current_session()
    }
}

#[cfg(windows)]
fn lock_current_session() -> Result<SessionLockResult, PlatformError> {
    if unsafe { lock_work_station() } == 0 {
        return Err(PlatformError::Failed("LockWorkStation 调用失败".into()));
    }
    Ok(SessionLockResult::Locked)
}

#[cfg(not(windows))]
fn lock_current_session() -> Result<SessionLockResult, PlatformError> {
    Err(PlatformError::Unsupported(
        "Windows workstation session lock",
    ))
}

#[cfg(windows)]
#[link(name = "user32")]
extern "system" {
    #[link_name = "LockWorkStation"]
    fn lock_work_station() -> i32;
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_locker_interface_reports_a_locked_result() {
        struct TestLocker;

        impl super::SessionLocker for TestLocker {
            fn lock_current_session(
                &self,
            ) -> Result<super::SessionLockResult, crate::error::PlatformError> {
                Ok(super::SessionLockResult::Locked)
            }
        }

        let result = super::SessionLocker::lock_current_session(&TestLocker).unwrap();

        assert_eq!(result, super::SessionLockResult::Locked);
    }

    #[cfg(not(windows))]
    #[test]
    fn local_session_locker_reports_unsupported_outside_windows() {
        assert!(matches!(
            super::SessionLocker::lock_current_session(&super::LocalSessionLocker),
            Err(crate::error::PlatformError::Unsupported(
                "Windows workstation session lock"
            ))
        ));
    }
}
