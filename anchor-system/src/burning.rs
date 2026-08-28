//! 刻录（光驱）监控适配。
//!
//! 后续接入点：Windows 使用设备策略、Shell 刻录策略和服务状态；刻录进程审计与
//! 任务文件扫描由服务与扫描模块配合完成。

#[cfg(windows)]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// 刻录光驱信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnDriveInfo {
    /// 光驱 ID；Windows 后端要求为 PnP InstanceId。
    pub drive_id: String,
    /// 光驱名称。
    pub name: String,
    /// 介质是否存在；探测失败时为 None。
    pub media_present: Option<bool>,
    /// 介质是否可写；探测失败时为 None。
    pub writable: Option<bool>,
}

/// 刻录设备监控能力。
pub trait BurningMonitor: Send + Sync {
    /// 列出全部刻录光驱及其介质状态。
    fn list_drives(&self) -> Result<Vec<BurnDriveInfo>, PlatformError>;
}

/// 光驱状态控制的外部执行边界。
pub trait BurningControlExecutor {
    fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError>;
}

/// 光驱控制请求的可观察结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurningControlOutcome {
    /// 已按明确允许或默认拒绝规则交给执行器处置。
    Applied,
}

/// 对已观测刻录光驱执行状态变更；不在允许集合的对象一律禁用。
pub fn apply_burning_control<E>(
    executor: &mut E,
    drive_id: &str,
    enabled: bool,
    controlled_drive_ids: &[String],
) -> Result<BurningControlOutcome, PlatformError>
where
    E: BurningControlExecutor,
{
    let enabled = enabled && controlled_drive_ids.iter().any(|id| id == drive_id);
    executor.set_enabled(drive_id, enabled)?;
    Ok(BurningControlOutcome::Applied)
}

/// Windows 10 刻录光驱状态执行器。
#[derive(Debug, Default)]
pub struct WindowsBurningControlExecutor;

#[cfg(windows)]
impl BurningControlExecutor for WindowsBurningControlExecutor {
    fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError> {
        let action = if enabled {
            "& { $device = Get-PnpDevice -InstanceId $args[0] -ErrorAction Stop; if ($device.Class -ne 'CDROM') { throw '目标不是光驱' }; Enable-PnpDevice -InstanceId $args[0] -Confirm:$false -ErrorAction Stop }"
        } else {
            "& { $device = Get-PnpDevice -InstanceId $args[0] -ErrorAction Stop; if ($device.Class -ne 'CDROM') { throw '目标不是光驱' }; Disable-PnpDevice -InstanceId $args[0] -Confirm:$false -ErrorAction Stop }"
        };
        run_powershell(action, drive_id)
    }
}

#[cfg(not(windows))]
impl BurningControlExecutor for WindowsBurningControlExecutor {
    fn set_enabled(&mut self, _drive_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows 刻录光驱控制"))
    }
}

#[cfg(windows)]
fn run_powershell(action: &str, drive_id: &str) -> Result<(), PlatformError> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", action])
        .arg(drive_id)
        .output()
        .map_err(|error| PlatformError::Failed(format!("启动光驱控制命令失败: {error}")))?;

    if output.status.success() {
        return Ok(());
    }

    Err(PlatformError::Failed(format!(
        "光驱控制命令失败: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlisted_burn_drive_is_disabled_through_the_executor() {
        let mut executor = RecordingBurningExecutor::default();

        let outcome = apply_burning_control(
            &mut executor,
            "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1",
            false,
            &["SCSI\\CDROM&VEN_OTHER&PROD_WRITER\\2".into()],
        )
        .unwrap();

        assert_eq!(outcome, BurningControlOutcome::Applied);
        assert_eq!(
            executor.calls,
            vec![("SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1".into(), false)]
        );
    }

    #[test]
    fn controlled_burn_drive_is_restored_through_the_injected_executor() {
        let mut executor = RecordingBurningExecutor::default();

        let outcome = apply_burning_control(
            &mut executor,
            "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1",
            true,
            &["SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1".into()],
        )
        .unwrap();

        assert_eq!(outcome, BurningControlOutcome::Applied);
        assert_eq!(
            executor.calls,
            vec![("SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1".into(), true)]
        );
    }

    #[derive(Default)]
    struct RecordingBurningExecutor {
        calls: Vec<(String, bool)>,
    }

    impl BurningControlExecutor for RecordingBurningExecutor {
        fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError> {
            self.calls.push((drive_id.into(), enabled));
            Ok(())
        }
    }
}
