//! 网卡控制适配。
//!
//! 后续接入点：Windows 使用网络适配器管理接口；防火墙接口与企业终端管理策略配合执行。

#[cfg(windows)]
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// 网卡类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NicKind {
    /// 有线网卡。
    Wired,
    /// Wi-Fi 网卡。
    WiFi,
    /// 虚拟网卡。
    Virtual,
}

/// 网卡状态信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicInfo {
    /// 网卡 ID；Windows 后端要求为 `Get-NetAdapter` 返回的 InterfaceGuid。
    pub adapter_id: String,
    /// 网卡名称。
    pub name: String,
    /// 有线、Wi-Fi 或虚拟。
    pub kind: NicKind,
    /// MAC 地址。
    pub mac: Option<String>,
    /// 启用状态。
    pub enabled: bool,
    /// 连接网络摘要。
    pub connected_network: Option<String>,
    /// 内网识别结果。
    pub is_intranet: Option<bool>,
    /// 最近变化时间。
    pub last_change: Option<DateTime<Utc>>,
}

/// 网卡查询与控制能力。
pub trait NicController: Send + Sync {
    /// 列出全部网卡及其状态。
    fn list_adapters(&self) -> Result<Vec<NicInfo>, PlatformError>;

    /// 启用或停用指定网卡。
    fn set_enabled(&self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError>;
}

/// 网卡状态控制的外部执行边界。
pub trait NicControlExecutor {
    fn set_enabled(&mut self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError>;
}

/// 网卡控制请求的可观察结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicControlOutcome {
    /// 已按明确允许或默认拒绝规则交给执行器处置。
    Applied,
}

/// 对已观测网卡执行状态变更；不在允许集合的对象一律禁用。
pub fn apply_nic_control<E>(
    executor: &mut E,
    adapter_id: &str,
    enabled: bool,
    controlled_adapter_ids: &[String],
) -> Result<NicControlOutcome, PlatformError>
where
    E: NicControlExecutor,
{
    let enabled = enabled && controlled_adapter_ids.iter().any(|id| id == adapter_id);
    executor.set_enabled(adapter_id, enabled)?;
    Ok(NicControlOutcome::Applied)
}

/// Windows 10 网卡状态执行器。
///
/// `adapter_id` 必须是 `Get-NetAdapter` 返回的 InterfaceGuid。
#[derive(Debug, Default)]
pub struct WindowsNicControlExecutor;

#[cfg(windows)]
impl NicControlExecutor for WindowsNicControlExecutor {
    fn set_enabled(&mut self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError> {
        let action = if enabled {
            "Get-NetAdapter -InterfaceGuid $args[0] -ErrorAction Stop | Enable-NetAdapter -Confirm:$false -ErrorAction Stop"
        } else {
            "Get-NetAdapter -InterfaceGuid $args[0] -ErrorAction Stop | Disable-NetAdapter -Confirm:$false -ErrorAction Stop"
        };
        run_powershell(action, adapter_id)
    }
}

#[cfg(not(windows))]
impl NicControlExecutor for WindowsNicControlExecutor {
    fn set_enabled(&mut self, _adapter_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Windows 网卡控制"))
    }
}

#[cfg(windows)]
fn run_powershell(action: &str, adapter_id: &str) -> Result<(), PlatformError> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", action])
        .arg(adapter_id)
        .output()
        .map_err(|error| PlatformError::Failed(format!("启动网卡控制命令失败: {error}")))?;

    if output.status.success() {
        return Ok(());
    }

    Err(PlatformError::Failed(format!(
        "网卡控制命令失败: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::assert_variant_roundtrip;

    #[test]
    fn nic_kind_serde_snake_case_roundtrip() {
        assert_variant_roundtrip(&NicKind::Wired, "wired");
        assert_variant_roundtrip(&NicKind::WiFi, "wi_fi");
        assert_variant_roundtrip(&NicKind::Virtual, "virtual");
    }

    #[test]
    fn unlisted_adapter_is_disabled_through_the_executor() {
        let mut executor = RecordingNicExecutor::default();

        let outcome =
            apply_nic_control(&mut executor, "nic-public", true, &["nic-private".into()]).unwrap();

        assert_eq!(outcome, NicControlOutcome::Applied);
        assert_eq!(executor.calls, vec![("nic-public".into(), false)]);
    }

    #[test]
    fn controlled_adapter_is_restored_through_the_injected_executor() {
        let mut executor = RecordingNicExecutor::default();

        let outcome =
            apply_nic_control(&mut executor, "nic-private", true, &["nic-private".into()]).unwrap();

        assert_eq!(outcome, NicControlOutcome::Applied);
        assert_eq!(executor.calls, vec![("nic-private".into(), true)]);
    }

    #[derive(Default)]
    struct RecordingNicExecutor {
        calls: Vec<(String, bool)>,
    }

    impl NicControlExecutor for RecordingNicExecutor {
        fn set_enabled(&mut self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError> {
            self.calls.push((adapter_id.into(), enabled));
            Ok(())
        }
    }
}
