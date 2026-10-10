//! 受控目录文件变更的本地扫描运行时。
//!
//! `ScanEventSource` 把 notify 的平台细节隔离在外；服务循环可在独立线程运行，测试
//! 只提供确定性的事件流，不会在开发机上注册目录监听。

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::Duration,
};

use anchor_core::{AuditPayload, EventType};
use anchor_scan::scan_file;
use anchor_store::{ScanRecord, ScanStatus, StoreError};
use anchor_system::session::active_session_operator;
use chrono::{DateTime, Utc};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use thiserror::Error;

use crate::Service;

/// 已去除 notify 平台细节的文件变更。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanEvent {
    Changed(PathBuf),
}

/// 可注入的扫描事件源。返回 None 表示流结束。
pub trait ScanEventSource {
    fn recv(&mut self) -> Result<Option<ScanEvent>, ScanRuntimeError>;
}

/// notify 驱动的生产事件源；watcher 与接收端绑定，避免监听器提前析构。
pub struct NotifyScanEventSource {
    _watcher: RecommendedWatcher,
    receiver: Receiver<notify::Result<Event>>,
}

impl NotifyScanEventSource {
    pub fn watch(controlled_dirs: &[String]) -> Result<Self, ScanRuntimeError> {
        let (sender, receiver) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = sender.send(event);
        })
        .map_err(ScanRuntimeError::Notify)?;
        for directory in controlled_dirs {
            watcher
                .watch(Path::new(directory), RecursiveMode::Recursive)
                .map_err(ScanRuntimeError::Notify)?;
        }
        Ok(Self {
            _watcher: watcher,
            receiver,
        })
    }
}

impl ScanEventSource for NotifyScanEventSource {
    fn recv(&mut self) -> Result<Option<ScanEvent>, ScanRuntimeError> {
        loop {
            let event = match self.receiver.recv() {
                Ok(event) => event.map_err(ScanRuntimeError::Notify)?,
                Err(_) => return Ok(None),
            };
            if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                continue;
            }
            if let Some(path) = event.paths.into_iter().find(|path| path.is_file()) {
                return Ok(Some(ScanEvent::Changed(path)));
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ScanRuntimeError {
    #[error("目录监听失败: {0}")]
    Notify(#[from] notify::Error),
    #[error("扫描索引或审计写入失败: {0}")]
    Store(#[from] StoreError),
}

/// 处理文件变更的运行时。稳定等待只为避免扫描仍在写入的文件。
pub struct ScanRuntime {
    stable_delay: Duration,
}

impl ScanRuntime {
    pub fn new(stable_delay: Duration) -> Self {
        Self { stable_delay }
    }

    /// 消费事件直至事件源结束。调用方将其置于独立线程运行。
    pub fn run<S: ScanEventSource>(
        &self,
        service: &Service,
        source: &mut S,
    ) -> Result<(), ScanRuntimeError> {
        while let Some(event) = source.recv()? {
            let ScanEvent::Changed(path) = event;
            self.scan_changed_path(service, &path, Utc::now())?;
        }
        Ok(())
    }

    /// 对一次已防抖的文件变更做扫描；不属于受控目录和已删除文件直接忽略。
    pub fn scan_changed_path(
        &self,
        service: &Service,
        path: &Path,
        now: DateTime<Utc>,
    ) -> Result<Option<ScanRecord>, ScanRuntimeError> {
        let Some(policy) = service.store.active_policy()? else {
            return Ok(None);
        };
        if !is_controlled(path, &policy.payload.scan.controlled_dirs) || !path.is_file() {
            return Ok(None);
        }
        if !matches_file_type(path, &policy.payload.scan.file_types) {
            return Ok(None);
        }
        let before = match file_fingerprint(path) {
            Ok(fingerprint) => fingerprint,
            Err(_) => return Ok(None),
        };
        if !self.stable_delay.is_zero() {
            thread::sleep(self.stable_delay);
            if file_fingerprint(path).ok().as_ref() != Some(&before) {
                return Ok(None);
            }
        }

        let result = scan_file(path, &policy.payload.scan);
        let (status, matched_rules) = match result {
            Ok(result) if result.matches.is_empty() => (ScanStatus::Clean, Vec::new()),
            Ok(result) => (
                ScanStatus::Hit,
                result
                    .matches
                    .into_iter()
                    .map(|rule| rule.rule_id)
                    .collect(),
            ),
            Err(_) => (ScanStatus::Error, Vec::new()),
        };
        let mut record = ScanRecord::new(
            path.to_string_lossy(),
            before.size,
            before.mtime,
            before.hash,
            policy.payload.version,
            status,
        );
        record.matched_rules = matched_rules;
        let operator = active_session_operator();
        let (event_type, result) = match status {
            ScanStatus::Hit => (EventType::ScanHit, "hit"),
            ScanStatus::Clean => (EventType::ScanCompleted, "clean"),
            ScanStatus::Error | ScanStatus::Pending => (EventType::ScanCompleted, "error"),
        };
        let audit = {
            let mut event = AuditPayload::new(
                &service.device_id,
                operator
                    .as_ref()
                    .map_or("unknown", |operator| operator.user.as_str()),
                event_type,
                "scan_file",
                result,
            );
            event.timestamp = now;
            event.resource = Some(record.path.clone());
            event.policy_version = Some(policy.payload.version);
            event.rule_id = record.matched_rules.first().cloned();
            event.process = operator.map(|operator| format!("session-{}", operator.session_id));
            record.last_event_id = Some(event.event_id.clone());
            event
        };
        service
            .store
            .upsert_scan_record(&record, Some(audit), now)?;
        Ok(Some(record))
    }
}

/// 为一组受控目录启动独立扫描线程。
///
/// 调用者从当前活动策略取得目录，并持有线程句柄负责其生命周期；本函数不在调用
/// 线程执行 watcher，以免文件事件阻塞登录控制和设备处置。
pub fn spawn_notify_scan_runtime(
    service: Arc<Service>,
    controlled_dirs: Vec<String>,
    stable_delay: Duration,
) -> Result<thread::JoinHandle<Result<(), ScanRuntimeError>>, ScanRuntimeError> {
    let source = NotifyScanEventSource::watch(&controlled_dirs)?;
    Ok(thread::spawn(move || {
        let mut source = source;
        ScanRuntime::new(stable_delay).run(&service, &mut source)
    }))
}

/// 按当前活动策略的受控目录启动扫描线程；尚无策略或未配置目录时不启动监听。
pub fn spawn_active_notify_scan_runtime(
    service: Arc<Service>,
    stable_delay: Duration,
) -> Result<Option<thread::JoinHandle<Result<(), ScanRuntimeError>>>, ScanRuntimeError> {
    let Some(policy) = service.store.active_policy()? else {
        return Ok(None);
    };
    if policy.payload.scan.controlled_dirs.is_empty() {
        return Ok(None);
    }
    spawn_notify_scan_runtime(service, policy.payload.scan.controlled_dirs, stable_delay).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    size: u64,
    mtime: i64,
    hash: String,
}

fn file_fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    let metadata = fs::metadata(path)?;
    let mtime = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let bytes = fs::read(path)?;
    Ok(FileFingerprint {
        size: metadata.len(),
        mtime,
        hash: anchor_core::crypto::sha256_hex(&bytes),
    })
}

fn is_controlled(path: &Path, controlled_dirs: &[String]) -> bool {
    controlled_dirs
        .iter()
        .any(|directory| path.starts_with(Path::new(directory)))
}

/// 按策略声明的扩展名筛选；空列表表示扫描全部支持的类型。
fn matches_file_type(path: &Path, file_types: &[String]) -> bool {
    if file_types.is_empty() {
        return true;
    }
    let Some(extension) = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return false;
    };
    file_types.iter().any(|allowed| {
        allowed
            .trim_start_matches('.')
            .eq_ignore_ascii_case(&extension)
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anchor_core::{
        ActionPolicy, BurningRules, NetworkRules, PolicyPackage, PolicyPayload, ScanRule,
        ScanRuleKind, ScanRules, UsbRules,
    };
    use anchor_store::Store;
    use chrono::{Duration, TimeZone};
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
    }

    fn service(directory: &Path) -> Service {
        service_with_file_types(directory, vec![])
    }

    fn service_with_file_types(directory: &Path, file_types: Vec<String>) -> Service {
        let policy = PolicyPackage::sign(
            PolicyPayload {
                version: 1,
                expires_at: now() + Duration::days(1),
                usb: UsbRules {
                    read: ActionPolicy::Deny,
                    write: ActionPolicy::Deny,
                    allowed: vec![],
                },
                network: NetworkRules {
                    policy: ActionPolicy::Deny,
                    allowed: vec![],
                },
                burning: BurningRules {
                    policy: ActionPolicy::Deny,
                    allowed: vec![],
                },
                scan: ScanRules {
                    controlled_dirs: vec![directory.to_string_lossy().into_owned()],
                    file_types,
                    rules: vec![ScanRule {
                        rule_id: "secret".into(),
                        kind: ScanRuleKind::Keyword,
                        pattern: "机密".into(),
                    }],
                },
            },
            &SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        let store = Store::in_memory().unwrap();
        store
            .import_policy(
                &policy,
                anchor_core::ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();
        Service::new(store, anchor_core::crypto::generate_keypair().1, "laptop-1")
    }

    #[test]
    fn changed_controlled_file_updates_index_and_audits_hit() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("report.txt");
        fs::write(&path, "机密计划").unwrap();
        let service = service(directory.path());

        let record = ScanRuntime::new(std::time::Duration::ZERO)
            .scan_changed_path(&service, &path, now())
            .unwrap()
            .unwrap();

        assert_eq!(record.status, ScanStatus::Hit);
        assert_eq!(record.matched_rules, vec!["secret"]);
        assert_eq!(
            service.store.scan_record(&record.path).unwrap(),
            Some(record)
        );
        assert!(service
            .store
            .read_audit_events()
            .unwrap()
            .iter()
            .any(|event| event.payload.event_type == EventType::ScanHit));
    }

    #[test]
    fn ignores_paths_outside_controlled_directories() {
        let controlled = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let path = outside.path().join("report.txt");
        fs::write(&path, "机密计划").unwrap();

        assert!(ScanRuntime::new(std::time::Duration::ZERO)
            .scan_changed_path(&service(controlled.path()), &path, now())
            .unwrap()
            .is_none());
    }

    #[test]
    fn ignores_files_outside_the_declared_file_types() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("report.log");
        fs::write(&path, "机密计划").unwrap();
        let service = service_with_file_types(directory.path(), vec!["txt".into()]);

        let record = ScanRuntime::new(std::time::Duration::ZERO)
            .scan_changed_path(&service, &path, now())
            .unwrap();

        assert!(record.is_none());
        assert!(!service
            .store
            .read_audit_events()
            .unwrap()
            .iter()
            .any(|event| event.payload.action == "scan_file"));
    }

    #[test]
    fn clean_scan_is_indexed_and_audited_once() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("report.txt");
        fs::write(&path, "普通内容").unwrap();
        let service = service(directory.path());

        let record = ScanRuntime::new(std::time::Duration::ZERO)
            .scan_changed_path(&service, &path, now())
            .unwrap()
            .unwrap();

        assert_eq!(record.status, ScanStatus::Clean);
        let events = service.store.read_audit_events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.payload.event_type == EventType::ScanCompleted
                    && event.payload.result == "clean")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.payload.action == "scan_file")
                .count(),
            1
        );
    }

    #[test]
    fn file_type_matching_accepts_declared_extensions_only() {
        let txt = Path::new("D:\\work\\report.TXT");
        let log = Path::new("D:\\work\\report.log");
        let without_extension = Path::new("D:\\work\\report");

        assert!(matches_file_type(txt, &[]));
        assert!(matches_file_type(txt, &[".txt".into()]));
        assert!(!matches_file_type(log, &["txt".into()]));
        assert!(!matches_file_type(without_extension, &["txt".into()]));
    }
}
