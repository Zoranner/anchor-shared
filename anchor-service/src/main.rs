use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anchor_service::{enforce::ObservedDevices, Service};
use anchor_store::Store;
use anchor_system::{
    burning::BurningControlExecutor, error::PlatformError, inventory::DeviceInventory,
    nic::NicControlExecutor, session::SessionLocker, usb::UsbStorageExecutor,
};
use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

#[cfg(not(windows))]
use anyhow::bail;

#[cfg(windows)]
use clap::Parser;

#[cfg(windows)]
use anchor_system::{
    burning::WindowsBurningControlExecutor, inventory::observe_inventory,
    nic::WindowsNicControlExecutor, session::SessionLockResult, usb::WindowsUsbStorageExecutor,
};

#[cfg(windows)]
use std::{
    ffi::OsString,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const SERVICE_NAME: &str = "AnchorGuard";
const LISTEN_FAILURE_BACKOFF: Duration = Duration::from_millis(100);

fn run_enforcement_once<O, L, U, N, B>(
    service: &Service,
    observe: O,
    locker: &L,
    usb_executor: &mut U,
    nic_executor: &mut N,
    burning_executor: &mut B,
    now: chrono::DateTime<Utc>,
) -> Result<()>
where
    O: FnOnce() -> Result<DeviceInventory, PlatformError>,
    L: SessionLocker,
    U: UsbStorageExecutor,
    N: NicControlExecutor,
    B: BurningControlExecutor,
{
    let inventory = match observe() {
        Ok(inventory) => inventory,
        Err(error) => {
            service
                .record_inventory_failure(&error.to_string(), now)
                .context("记录库存观测失败状态失败")?;
            return Err(error.into());
        }
    };
    service
        .enforce_policy(
            locker,
            usb_executor,
            nic_executor,
            burning_executor,
            ObservedDevices::from(inventory),
            now,
        )
        .map(|_| ())
        .map_err(Into::into)
}

#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
struct ServiceSessionLocker;

#[cfg(windows)]
impl SessionLocker for ServiceSessionLocker {
    fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError> {
        Err(PlatformError::Failed(
            "Windows Service 在 Session 0 中不能锁定交互用户会话".into(),
        ))
    }
}

#[cfg(windows)]
fn run_windows_enforcement_once(service: &Service, now: chrono::DateTime<Utc>) -> Result<()> {
    let locker = ServiceSessionLocker;
    let mut usb = WindowsUsbStorageExecutor;
    let mut nic = WindowsNicControlExecutor;
    let mut burning = WindowsBurningControlExecutor;
    run_enforcement_once(
        service,
        observe_inventory,
        &locker,
        &mut usb,
        &mut nic,
        &mut burning,
        now,
    )
}

/// 安装程序写入的本地服务配置。
#[derive(Debug, Deserialize)]
struct ServiceConfig {
    database: PathBuf,
    verifying_key_hex: String,
    device_id: String,
}

#[cfg(windows)]
#[derive(Debug, Parser)]
struct ServiceArguments {
    /// 安装程序写入的本地服务配置文件。
    #[arg(long)]
    config: PathBuf,
}

impl ServiceConfig {
    fn parse(content: &str) -> Result<Self> {
        Ok(toml::from_str(content)?)
    }

    fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("读取服务配置失败: {}", path.display()))?;
        Self::parse(&content).with_context(|| format!("解析服务配置失败: {}", path.display()))
    }

    fn open_service(&self) -> Result<Service> {
        let bytes = hex::decode(&self.verifying_key_hex).context("管理员公钥不是十六进制")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("管理员公钥必须是 32 字节"))?;
        let verifying_key = VerifyingKey::from_bytes(&key).context("管理员公钥无效")?;
        let store = Store::open(&self.database)
            .with_context(|| format!("打开本地审计库失败: {}", self.database.display()))?;
        Ok(Service::new(store, verifying_key, &self.device_id))
    }
}

fn serve_until_stopped<F>(config: ServiceConfig, should_stop: F) -> Result<()>
where
    F: Fn() -> bool,
{
    let service = config.open_service()?;
    while !should_stop() {
        let now = Utc::now();
        #[cfg(windows)]
        let enforcement_failed = run_windows_enforcement_once(&service, now).is_err();
        #[cfg(not(windows))]
        let enforcement_failed = false;
        let control_result = service.serve_control_pipe_once(now);
        let session_status_result = service.serve_session_status_pipe_once(now);
        if control_result.is_err()
            || session_status_result.is_err()
            || cfg!(windows) && enforcement_failed
        {
            thread::sleep(LISTEN_FAILURE_BACKOFF);
        }
    }
    Ok(())
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn main() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("启动 Windows Service 分发器失败")?;
    Ok(())
}

#[cfg(not(windows))]
fn main() -> Result<()> {
    bail!("anchor-service 仅支持作为 Windows Service 运行")
}

#[cfg(windows)]
fn service_main(arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service(arguments) {
        eprintln!("Anchor Guard 服务启动失败: {error:#}");
    }
}

#[cfg(windows)]
fn run_windows_service(arguments: Vec<OsString>) -> Result<()> {
    let config_path = ServiceArguments::try_parse_from(
        std::iter::once(OsString::from(SERVICE_NAME)).chain(arguments),
    )
    .context("解析 Windows Service 参数失败")?
    .config;
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_signal = Arc::clone(&stop_requested);
    let status_handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop => {
            stop_signal.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .context("注册 Windows Service 控制器失败")?;

    let result = (|| {
        status_handle
            .set_service_status(service_status(
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
                0,
            ))
            .context("报告服务启动状态失败")?;
        let config = ServiceConfig::load(&config_path)?;
        status_handle
            .set_service_status(service_status(
                ServiceState::Running,
                ServiceControlAccept::STOP,
                0,
            ))
            .context("报告服务运行状态失败")?;
        serve_until_stopped(config, || stop_requested.load(Ordering::SeqCst))
    })();
    status_handle
        .set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            u32::from(result.is_err()),
        ))
        .context("报告服务停止状态失败")?;
    result
}

#[cfg(windows)]
fn service_status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: u32,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anchor_core::{crypto, AuthorizationDenial, AuthorizationState, EventType};
    use anchor_service::Service;
    use anchor_store::Store;
    use anchor_system::{
        burning::WindowsBurningControlExecutor,
        error::PlatformError,
        nic::WindowsNicControlExecutor,
        session::{SessionLockResult, SessionLocker},
        usb::WindowsUsbStorageExecutor,
    };
    use chrono::{TimeZone, Utc};

    use super::{run_enforcement_once, ServiceConfig};

    #[derive(Default)]
    struct ServiceSessionLocker {
        calls: AtomicUsize,
    }

    impl SessionLocker for ServiceSessionLocker {
        fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(PlatformError::Failed("test service session".into()))
        }
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
    }

    #[test]
    fn service_config_requires_database_key_and_device_id() {
        let config = ServiceConfig::parse(
            r#"
database = "C:\\ProgramData\\AnchorGuard\\audit.db"
verifying_key_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
device_id = "laptop-1"
"#,
        )
        .unwrap();

        assert_eq!(config.device_id, "laptop-1");
        assert_eq!(config.verifying_key_hex.len(), 64);
    }

    #[test]
    fn failed_inventory_records_audited_runtime_denial_without_a_session_zero_lock() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(database.path()).unwrap();
        let service = Service::new(store, crypto::generate_keypair().1, "laptop-1");
        let locker = ServiceSessionLocker::default();
        let mut usb = WindowsUsbStorageExecutor;
        let mut nic = WindowsNicControlExecutor;
        let mut burning = WindowsBurningControlExecutor;

        let error = run_enforcement_once(
            &service,
            || Err(PlatformError::Failed("inventory unavailable".into())),
            &locker,
            &mut usb,
            &mut nic,
            &mut burning,
            now(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("inventory unavailable"));
        assert_eq!(locker.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            service.authorization_state(now()),
            AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
        );
        let events = Store::open_read_only(database.path())
            .unwrap()
            .read_audit_events()
            .unwrap();
        assert!(events.iter().any(|event| {
            event.payload.event_type == EventType::InventoryObservationFailed
                && event.payload.action == "observe_inventory"
                && event.payload.result == "failed"
                && event
                    .payload
                    .resource
                    .as_deref()
                    .is_some_and(|reason| reason.contains("inventory unavailable"))
        }));
    }
}
