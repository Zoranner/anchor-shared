use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anchor_service::Service;
use anchor_store::Store;
use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

#[cfg(not(windows))]
use anyhow::bail;

#[cfg(windows)]
use clap::Parser;

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
        if service.serve_control_pipe_once(Utc::now()).is_err() {
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
    use super::ServiceConfig;

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
}
