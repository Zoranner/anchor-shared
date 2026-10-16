use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anchor_core::EventType;
#[cfg(windows)]
use anchor_service::scan_runtime::spawn_active_notify_scan_runtime;
use anchor_service::{enforce::ObservedDevices, Service};
use anchor_store::Store;
use anchor_system::{
    burning::BurningControlExecutor,
    error::PlatformError,
    inventory::DeviceInventory,
    nic::NicControlExecutor,
    session::{SessionAssistantLauncher, SessionAssistantLauncherBackend},
    usb::UsbStorageExecutor,
    write_denial::WriteDenialSwitch,
};
use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

#[cfg(not(windows))]
use anyhow::bail;

#[cfg(windows)]
use anchor_system::{
    burning::WindowsBurningControlExecutor,
    inventory::observe_inventory,
    nic::WindowsNicControlExecutor,
    session::{logon_ui_active, LocalSessionAssistantBackend},
    usb::WindowsUsbStorageExecutor,
};

#[cfg(windows)]
use std::ffi::OsString;

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
/// 设备处置失败后的重试间隔。
const LISTEN_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
/// 设备状态与策略期望的核对周期。观测状态已符合策略的设备不会产生任何处置或审计。
const ENFORCEMENT_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(windows)]
const SCAN_STABLE_DELAY: Duration = Duration::from_millis(300);

fn run_enforcement_once<O, U, N, B>(
    service: &Service,
    observe: O,
    usb_executor: &mut U,
    nic_executor: &mut N,
    burning_executor: &mut B,
    logon_ui_active: bool,
    now: chrono::DateTime<Utc>,
) -> Result<()>
where
    O: FnOnce() -> Result<DeviceInventory, PlatformError>,
    U: UsbStorageExecutor + WriteDenialSwitch,
    N: NicControlExecutor,
    B: BurningControlExecutor + WriteDenialSwitch,
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
            usb_executor,
            nic_executor,
            burning_executor,
            ObservedDevices::from(inventory),
            logon_ui_active,
            now,
        )
        .map(|_| ())
        .map_err(Into::into)
}

#[cfg(windows)]
fn run_windows_enforcement_once(service: &Service, now: chrono::DateTime<Utc>) -> Result<()> {
    let mut usb = WindowsUsbStorageExecutor;
    let mut nic = WindowsNicControlExecutor;
    let mut burning = WindowsBurningControlExecutor;
    run_enforcement_once(
        service,
        observe_inventory,
        &mut usb,
        &mut nic,
        &mut burning,
        logon_ui_active(),
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

fn spawn_pipe_listener<T, F>(
    service: Arc<T>,
    stop_requested: Arc<AtomicBool>,
    serve_once: F,
) -> thread::JoinHandle<()>
where
    T: Send + Sync + 'static,
    F: Fn(&T, chrono::DateTime<Utc>) -> Result<(), PlatformError> + Send + 'static,
{
    thread::spawn(move || {
        while !stop_requested.load(Ordering::SeqCst) {
            if serve_once(&service, Utc::now()).is_err() {
                thread::sleep(LISTEN_FAILURE_BACKOFF);
            }
        }
    })
}

fn session_assistant_executable(service_executable: &Path) -> Result<PathBuf> {
    let directory = service_executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("无法确定 Windows Service 可执行文件目录"))?;
    Ok(directory.join("anchor-session.exe"))
}

fn reconcile_session_assistant_once<B>(
    service: &Service,
    launcher: &mut SessionAssistantLauncher<B>,
    now: chrono::DateTime<Utc>,
) -> Result<()>
where
    B: SessionAssistantLauncherBackend,
{
    if let Err(error) = launcher.reconcile() {
        let reason = error.to_string();
        service
            .record_session_assistant_failure(&reason, now)
            .context("记录会话协作程序故障失败")?;
        return Err(error.into());
    }
    Ok(())
}

#[cfg(windows)]
fn local_session_assistant_executable() -> Result<PathBuf> {
    let service_executable =
        std::env::current_exe().context("读取 Windows Service 可执行文件失败")?;
    session_assistant_executable(&service_executable)
}

fn serve_until_stopped<F>(config: ServiceConfig, should_stop: F) -> Result<()>
where
    F: Fn() -> bool,
{
    let service = Arc::new(config.open_service()?);
    service.record_lifecycle_event(
        EventType::ServiceStart,
        "service_start",
        "running",
        Utc::now(),
    )?;
    let audit_healthy = service.audit_chain_healthy().unwrap_or(false);
    service.record_lifecycle_event(
        EventType::AuditVerify,
        "audit_chain",
        if audit_healthy { "valid" } else { "invalid" },
        Utc::now(),
    )?;
    #[cfg(windows)]
    let _scan_runtime = spawn_active_notify_scan_runtime(Arc::clone(&service), SCAN_STABLE_DELAY)
        .context("启动文件扫描监听失败")?;
    #[cfg(windows)]
    let mut session_assistant = SessionAssistantLauncher::new(
        LocalSessionAssistantBackend,
        local_session_assistant_executable()?,
    );
    let listener_stop_requested = Arc::new(AtomicBool::new(false));
    let control_listener = spawn_pipe_listener(
        Arc::clone(&service),
        Arc::clone(&listener_stop_requested),
        |service, now| service.serve_control_pipe_once(now).map(|_| ()),
    );
    let session_status_listener = spawn_pipe_listener(
        Arc::clone(&service),
        Arc::clone(&listener_stop_requested),
        |service, now| service.serve_session_status_pipe_once(now).map(|_| ()),
    );

    while !should_stop() {
        let now = Utc::now();
        #[cfg(windows)]
        let runtime_failed = run_windows_enforcement_once(&service, now).is_err()
            || reconcile_session_assistant_once(&service, &mut session_assistant, now).is_err();
        #[cfg(not(windows))]
        let runtime_failed = false;
        if runtime_failed {
            thread::sleep(LISTEN_FAILURE_BACKOFF);
        } else {
            thread::sleep(ENFORCEMENT_INTERVAL);
        }
    }

    service.record_lifecycle_event(
        EventType::ServiceStop,
        "service_stop",
        "stopped",
        Utc::now(),
    )?;
    listener_stop_requested.store(true, Ordering::SeqCst);
    control_listener
        .join()
        .map_err(|_| anyhow::anyhow!("控制 Named Pipe 监听线程异常退出"))?;
    session_status_listener
        .join()
        .map_err(|_| anyhow::anyhow!("会话状态 Named Pipe 监听线程异常退出"))?;
    Ok(())
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

/// 服务启动轨迹文件名，与 `service.toml` 同目录。
#[cfg(windows)]
const STARTUP_LOG: &str = "service-startup.log";
/// 首次记录使用的阶段名；它会重写文件，保证文件只保留最近一次启动的轨迹。
#[cfg(windows)]
const STARTUP_FIRST_STAGE: &str = "dispatch";
/// 读不到 `ProgramData` 时的兜底根目录。
#[cfg(windows)]
const DEFAULT_PROGRAM_DATA: &str = r"C:\ProgramData";

/// 记录服务启动阶段。
///
/// 服务启动失败在系统只留下“服务未能启动”一句，因此把启动阶段写进数据目录的
/// `service-startup.log`：文件停在哪个阶段，卡点就在它之后。写入尽力而为，不影响服务本身。
#[cfg(windows)]
fn record_startup_stage(stage: &str) {
    let _ = record_startup_stage_at(&startup_log_path(), stage);
}

#[cfg(windows)]
fn startup_log_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROGRAM_DATA))
        .join("Anchor Guard")
        .join(STARTUP_LOG)
}

#[cfg(windows)]
fn record_startup_stage_at(path: &Path, stage: &str) -> std::io::Result<()> {
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory)?;
    }
    let line = format!("{} {stage}\r\n", Utc::now().to_rfc3339());
    if stage == STARTUP_FIRST_STAGE {
        fs::write(path, line)
    } else {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(line.as_bytes())
    }
}

/// 服务配置的默认位置，与安装程序写入的位置一致。
#[cfg(windows)]
fn default_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROGRAM_DATA))
        .join("Anchor Guard")
        .join("service.toml")
}

/// 从服务参数里取配置路径，支持 `--config <路径>` 与 `--config=<路径>`。
///
/// 参数由服务控制管理器决定，内容不由本程序控制，因此其余参数一律忽略，缺省时使用
/// 默认位置。安装程序不再传这个参数，它只保留给人工启动时覆盖用。
#[cfg(windows)]
fn config_path_from_arguments(arguments: &[OsString]) -> PathBuf {
    for (index, argument) in arguments.iter().enumerate() {
        let argument = argument.to_string_lossy();
        if let Some(value) = argument.strip_prefix("--config=") {
            if !value.is_empty() {
                return PathBuf::from(value);
            }
        } else if argument == "--config" {
            if let Some(value) = arguments.get(index + 1).filter(|value| !value.is_empty()) {
                return PathBuf::from(value);
            }
        }
    }
    default_config_path()
}

/// 启动轨迹里记录服务参数；长度受限，避免异常参数把日志写爆。
#[cfg(windows)]
fn arguments_summary(arguments: &[OsString]) -> String {
    let joined = arguments
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" | ");
    let mut summary: String = joined.chars().take(300).collect();
    if summary.len() < joined.len() {
        summary.push('…');
    }
    summary
}

#[cfg(windows)]
fn main() -> Result<()> {
    record_startup_stage(STARTUP_FIRST_STAGE);
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
    record_startup_stage(&format!(
        "service-main args=[{}]",
        arguments_summary(&arguments)
    ));
    if let Err(error) = run_windows_service(arguments) {
        record_startup_stage(&format!("service-main failed: {error:#}"));
    }
}

#[cfg(windows)]
fn run_windows_service(arguments: Vec<OsString>) -> Result<()> {
    let config_path = config_path_from_arguments(&arguments);
    record_startup_stage(&format!("config-path {}", config_path.display()));
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
    record_startup_stage("handler-registered");

    let result = (|| {
        status_handle
            .set_service_status(service_status(
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
                0,
            ))
            .context("报告服务启动状态失败")?;
        record_startup_stage("start-pending");
        let config = ServiceConfig::load(&config_path)?;
        record_startup_stage("config-loaded");
        status_handle
            .set_service_status(service_status(
                ServiceState::Running,
                ServiceControlAccept::STOP,
                0,
            ))
            .context("报告服务运行状态失败")?;
        record_startup_stage("running");
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
    use std::{
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread,
        time::Duration,
    };

    use anchor_core::{crypto, AuthorizationDenial, AuthorizationState, EventType};
    use anchor_service::Service;
    use anchor_store::Store;
    use anchor_system::{
        burning::WindowsBurningControlExecutor,
        error::PlatformError,
        nic::WindowsNicControlExecutor,
        session::{
            InteractiveSession, SessionAssistantLauncher, SessionAssistantLauncherBackend,
            SessionAssistantProcess,
        },
        usb::WindowsUsbStorageExecutor,
    };
    use chrono::{TimeZone, Utc};

    use super::{
        reconcile_session_assistant_once, run_enforcement_once, session_assistant_executable,
        spawn_pipe_listener, ServiceConfig,
    };

    struct ActiveSessionAssistantBackend;

    impl SessionAssistantLauncherBackend for ActiveSessionAssistantBackend {
        fn interactive_sessions(&self) -> Result<Vec<InteractiveSession>, PlatformError> {
            Ok(vec![InteractiveSession::active(7)])
        }

        fn start_session_assistant(
            &self,
            session_id: u32,
            executable: &Path,
        ) -> Result<SessionAssistantProcess, PlatformError> {
            assert_eq!(session_id, 7);
            assert_eq!(executable, Path::new("anchor-session.exe"));
            Ok(SessionAssistantProcess(42))
        }

        fn is_session_assistant_running(
            &self,
            _process: SessionAssistantProcess,
        ) -> Result<bool, PlatformError> {
            Ok(true)
        }

        fn release_session_assistant(&self, _process: SessionAssistantProcess) {}
    }

    struct FailingSessionAssistantBackend;

    impl SessionAssistantLauncherBackend for FailingSessionAssistantBackend {
        fn interactive_sessions(&self) -> Result<Vec<InteractiveSession>, PlatformError> {
            Err(PlatformError::Failed("session enumeration failed".into()))
        }

        fn start_session_assistant(
            &self,
            _session_id: u32,
            _executable: &Path,
        ) -> Result<SessionAssistantProcess, PlatformError> {
            unreachable!("会话枚举失败后不应启动协作程序")
        }

        fn is_session_assistant_running(
            &self,
            _process: SessionAssistantProcess,
        ) -> Result<bool, PlatformError> {
            unreachable!("会话枚举失败后不应检查协作程序")
        }

        fn release_session_assistant(&self, _process: SessionAssistantProcess) {}
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

    #[cfg(windows)]
    #[test]
    fn service_config_path_prefers_an_explicit_argument() {
        let default = super::default_config_path();
        assert!(default.ends_with("Anchor Guard/service.toml"));

        assert_eq!(super::config_path_from_arguments(&[]), default);
        assert_eq!(
            super::config_path_from_arguments(&[
                std::ffi::OsString::from("--config"),
                std::ffi::OsString::from(r"D:\cfg\service.toml"),
            ]),
            std::path::PathBuf::from(r"D:\cfg\service.toml")
        );
        assert_eq!(
            super::config_path_from_arguments(&[std::ffi::OsString::from(
                r"--config=D:\cfg\service.toml"
            )]),
            std::path::PathBuf::from(r"D:\cfg\service.toml")
        );
    }

    #[cfg(windows)]
    #[test]
    fn startup_log_keeps_only_the_latest_start() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service-startup.log");
        let first_stage = super::STARTUP_FIRST_STAGE;

        super::record_startup_stage_at(&path, first_stage).unwrap();
        super::record_startup_stage_at(&path, "running").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(first_stage), "{content}");
        assert!(content.contains("running"), "{content}");

        super::record_startup_stage_at(&path, first_stage).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("running"), "{content}");
    }

    #[test]
    fn lifecycle_events_are_recorded_in_order() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let service = Service::new(
            Store::open(database.path()).unwrap(),
            crypto::generate_keypair().1,
            "laptop-1",
        );

        service
            .record_lifecycle_event(EventType::ServiceStart, "service_start", "running", now())
            .unwrap();
        service
            .record_lifecycle_event(EventType::AuditVerify, "audit_chain", "valid", now())
            .unwrap();
        service
            .record_lifecycle_event(EventType::ServiceStop, "service_stop", "stopped", now())
            .unwrap();

        let events = Store::open_read_only(database.path())
            .unwrap()
            .read_audit_events()
            .unwrap();
        let types: Vec<EventType> = events
            .iter()
            .map(|event| event.payload.event_type)
            .collect();
        assert_eq!(
            types,
            vec![
                EventType::ServiceStart,
                EventType::AuditVerify,
                EventType::ServiceStop
            ]
        );
        assert!(events
            .iter()
            .all(|event| event.payload.user == "AnchorGuard"));
    }

    #[test]
    fn failed_inventory_records_audited_runtime_denial_once() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(database.path()).unwrap();
        let service = Service::new(store, crypto::generate_keypair().1, "laptop-1");
        let mut usb = WindowsUsbStorageExecutor;
        let mut nic = WindowsNicControlExecutor;
        let mut burning = WindowsBurningControlExecutor;

        let error = run_enforcement_once(
            &service,
            || Err(PlatformError::Failed("inventory unavailable".into())),
            &mut usb,
            &mut nic,
            &mut burning,
            false,
            now(),
        )
        .unwrap_err();
        let repeat = run_enforcement_once(
            &service,
            || Err(PlatformError::Failed("inventory unavailable".into())),
            &mut usb,
            &mut nic,
            &mut burning,
            false,
            now(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("inventory unavailable"));
        assert!(repeat.to_string().contains("inventory unavailable"));
        assert_eq!(
            service.authorization_state(now()),
            AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
        );
        let events = Store::open_read_only(database.path())
            .unwrap()
            .read_audit_events()
            .unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.payload.event_type == EventType::InventoryObservationFailed
                        && event.payload.action == "observe_inventory"
                        && event.payload.result == "failed"
                })
                .count(),
            1
        );
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

    #[test]
    fn session_assistant_executable_uses_the_service_executable_directory() {
        let service_directory = tempfile::tempdir().unwrap();
        let service_executable = service_directory.path().join("anchor-service.exe");

        let assistant = session_assistant_executable(&service_executable).unwrap();

        assert_eq!(
            assistant,
            service_directory.path().join("anchor-session.exe")
        );
    }

    #[test]
    fn session_assistant_reconciliation_starts_each_interactive_session() {
        let service = Service::new(
            Store::in_memory().unwrap(),
            crypto::generate_keypair().1,
            "laptop-1",
        );
        let mut launcher =
            SessionAssistantLauncher::new(ActiveSessionAssistantBackend, "anchor-session.exe");

        reconcile_session_assistant_once(&service, &mut launcher, now()).unwrap();

        assert_eq!(launcher.process_for(7), Some(SessionAssistantProcess(42)));
    }

    #[test]
    fn session_assistant_reconciliation_failure_is_audited_and_denied() {
        let database = tempfile::NamedTempFile::new().unwrap();
        let service = Service::new(
            Store::open(database.path()).unwrap(),
            crypto::generate_keypair().1,
            "laptop-1",
        );
        let mut launcher =
            SessionAssistantLauncher::new(FailingSessionAssistantBackend, "anchor-session.exe");

        let error = reconcile_session_assistant_once(&service, &mut launcher, now()).unwrap_err();

        assert!(error.to_string().contains("session enumeration failed"));
        assert_eq!(
            service.authorization_state(now()),
            AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
        );
        drop(service);
        let events = Store::open_read_only(database.path())
            .unwrap()
            .read_audit_events()
            .unwrap();
        assert!(events.iter().any(|event| {
            event.payload.event_type == EventType::SessionAssistantFailed
                && event.payload.action == "session_assistant"
                && event.payload.result == "failed"
                && event
                    .payload
                    .resource
                    .as_deref()
                    .is_some_and(|reason| reason.contains("session enumeration failed"))
        }));
    }

    #[test]
    fn session_listener_runs_while_control_listener_is_waiting_for_a_client() {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let control_stop = Arc::clone(&stop_requested);
        let session_stop = Arc::clone(&stop_requested);
        let (control_started, control_started_receiver) = mpsc::channel();
        let (session_served, session_served_receiver) = mpsc::channel();

        let control_listener =
            spawn_pipe_listener(Arc::new(()), Arc::clone(&stop_requested), move |_, _| {
                control_started.send(()).unwrap();
                while !control_stop.load(Ordering::SeqCst) {
                    thread::yield_now();
                }
                Ok(())
            });
        control_started_receiver
            .recv_timeout(Duration::from_millis(100))
            .unwrap();

        let session_listener =
            spawn_pipe_listener(Arc::new(()), Arc::clone(&stop_requested), move |_, _| {
                session_served.send(()).unwrap();
                session_stop.store(true, Ordering::SeqCst);
                Ok(())
            });

        session_served_receiver
            .recv_timeout(Duration::from_millis(100))
            .unwrap();
        control_listener.join().unwrap();
        session_listener.join().unwrap();
    }
}
