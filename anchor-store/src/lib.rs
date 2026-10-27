//! Anchor Guard 终端本地 SQLite 存储。

mod error;
mod types;

pub use error::StoreError;
pub use types::{ActivePolicyRecord, DeviceStateRecord, EventFilter, ScanRecord, ScanStatus};

use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use anchor_core::{
    verify_chain, AuditEvent, AuditPayload, EventType, ImportDecision, PolicyPackage, GENESIS_HASH,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};

const ENFORCEMENT_FAILURE_KEY: &str = "enforcement_failure";
const AUTHORIZATION_DENIAL_KEY: &str = "authorization_denial";

/// 本机 SQLite 存储。所有写入经由单个连接串行化，以维持审计链顺序。
pub struct Store {
    connection: Mutex<Connection>,
    enforcement_failure_write_failed: AtomicBool,
}

impl Store {
    /// 打开或创建本地数据库，并建立所有本地状态表。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    /// 以只读方式打开既有审计库，不创建数据库或修改其中任何状态。
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self {
            connection: Mutex::new(connection),
            enforcement_failure_write_failed: AtomicBool::new(false),
        })
    }

    /// 用于测试和进程内临时存储的内存数据库。
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StoreError> {
        let store = Self {
            connection: Mutex::new(connection),
            enforcement_failure_write_failed: AtomicBool::new(false),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY,
                version INTEGER NOT NULL,
                package_json TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
                UNIQUE (version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_policy
                ON policies(active) WHERE active = 1;
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                device_id TEXT NOT NULL,
                user_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                process TEXT,
                resource TEXT,
                policy_version INTEGER,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                rule_id TEXT,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS scan_index (
                file_id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                volume_id TEXT,
                size INTEGER NOT NULL,
                mtime INTEGER NOT NULL,
                hash TEXT NOT NULL,
                scan_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                matched_rules_json TEXT NOT NULL,
                last_event_id TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_state (
                kind TEXT NOT NULL,
                device_id TEXT NOT NULL,
                state_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (kind, device_id)
            );
            CREATE TABLE IF NOT EXISTS runtime_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    /// 记录导入尝试。拒绝结果只追加拒绝审计，不变更已生效策略；接受结果在同一事务内
    /// 先追加审计，再替换活动策略和最后可信时间。
    pub fn import_policy(
        &self,
        package: &PolicyPackage,
        decision: ImportDecision,
        device_id: &str,
        user: &str,
        now: DateTime<Utc>,
    ) -> Result<ImportDecision, StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        let (event_type, result) = match decision {
            ImportDecision::Accept => (EventType::PolicyImported, "accepted"),
            ImportDecision::InvalidSignature => {
                (EventType::PolicyImportRejected, "invalid_signature")
            }
            ImportDecision::VersionNotNewer => {
                (EventType::PolicyImportRejected, "version_not_newer")
            }
            ImportDecision::Expired => (EventType::PolicyImportRejected, "expired"),
        };
        let mut payload = AuditPayload::new(device_id, user, event_type, "import_policy", result)
            .with_policy_version(package.payload.version);
        payload.timestamp = now;
        Self::append_audit_in(&transaction, payload)?;

        if decision == ImportDecision::Accept {
            transaction.execute("UPDATE policies SET active = 0 WHERE active = 1", [])?;
            transaction.execute(
                "INSERT INTO policies (version, package_json, imported_at, active)
                 VALUES (?1, ?2, ?3, 1)
                 ON CONFLICT(version) DO UPDATE SET
                   package_json = excluded.package_json,
                   imported_at = excluded.imported_at,
                   active = 1",
                params![
                    package.payload.version as i64,
                    serde_json::to_string(package)?,
                    now.to_rfc3339(),
                ],
            )?;
            Self::set_runtime_in(
                &transaction,
                "active_policy_version",
                &package.payload.version.to_string(),
                now,
            )?;
            Self::set_runtime_in(&transaction, "last_trusted_at", &now.to_rfc3339(), now)?;
            transaction.execute(
                "DELETE FROM runtime_state WHERE key = ?1",
                params![ENFORCEMENT_FAILURE_KEY],
            )?;
        }
        transaction.commit()?;
        if decision == ImportDecision::Accept {
            self.enforcement_failure_write_failed
                .store(false, Ordering::SeqCst);
        }
        Ok(decision)
    }

    /// 返回当前唯一活动策略；没有导入成功策略时返回 None。
    pub fn active_policy(&self) -> Result<Option<PolicyPackage>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let package = connection
            .query_row(
                "SELECT package_json FROM policies WHERE active = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        package
            .map(|json| serde_json::from_str(&json).map_err(StoreError::from))
            .transpose()
    }

    /// 返回当前活动策略和导入时间；没有活动策略时返回 None。
    pub fn active_policy_record(&self) -> Result<Option<ActivePolicyRecord>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let record = connection
            .query_row(
                "SELECT package_json, imported_at FROM policies WHERE active = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        record
            .map(|(json, imported_at)| {
                Ok(ActivePolicyRecord {
                    package: serde_json::from_str(&json)?,
                    imported_at: DateTime::parse_from_rfc3339(&imported_at)
                        .map_err(|_| StoreError::TimeParse(imported_at))?
                        .with_timezone(&Utc),
                })
            })
            .transpose()
    }

    /// 读取最近一次成功导入策略时记录的可信时间。
    pub fn last_trusted_at(&self) -> Result<Option<DateTime<Utc>>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let value = connection
            .query_row(
                "SELECT value FROM runtime_state WHERE key = 'last_trusted_at'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        value
            .map(|timestamp| {
                DateTime::parse_from_rfc3339(&timestamp)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|_| StoreError::TimeParse(timestamp))
            })
            .transpose()
    }

    /// 单调记录最近一次授权成功时的可信时间，绝不以更早时间覆盖既有记录。
    pub fn record_trusted_time(&self, now: DateTime<Utc>) -> Result<(), StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        let value = transaction
            .query_row(
                "SELECT value FROM runtime_state WHERE key = 'last_trusted_at'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let last_trusted_at = value
            .map(|timestamp| {
                DateTime::parse_from_rfc3339(&timestamp)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|_| StoreError::TimeParse(timestamp))
            })
            .transpose()?;
        if last_trusted_at.is_none_or(|current| now > current) {
            Self::set_runtime_in(&transaction, "last_trusted_at", &now.to_rfc3339(), now)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// 记录本轮设备处置或状态持久化失败的原因。
    pub fn set_enforcement_failure(
        &self,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        let result = (|| {
            Self::set_runtime_in(&transaction, ENFORCEMENT_FAILURE_KEY, reason, now)?;
            transaction.commit()?;
            Ok(())
        })();
        if result.is_err() {
            self.enforcement_failure_write_failed
                .store(true, Ordering::SeqCst);
        }
        result
    }

    /// 清除已由完整处置或成功策略导入恢复的运行期失败状态。
    pub fn clear_enforcement_failure(&self) -> Result<(), StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let result = connection.execute(
            "DELETE FROM runtime_state WHERE key = ?1",
            params![ENFORCEMENT_FAILURE_KEY],
        );
        match result {
            Ok(_) => {
                self.enforcement_failure_write_failed
                    .store(false, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                self.enforcement_failure_write_failed
                    .store(true, Ordering::SeqCst);
                Err(error.into())
            }
        }
    }

    /// 读取尚未恢复的设备处置或状态持久化失败原因。
    pub fn enforcement_failure(&self) -> Result<Option<String>, StoreError> {
        if self.enforcement_failure_write_failed.load(Ordering::SeqCst) {
            return Ok(Some("enforcement_state_persistence_failed".into()));
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        connection
            .query_row(
                "SELECT value FROM runtime_state WHERE key = ?1",
                params![ENFORCEMENT_FAILURE_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// 读取上一次已记录的授权拒绝原因；未记录拒绝时为 None。
    pub fn authorization_denial(&self) -> Result<Option<String>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        connection
            .query_row(
                "SELECT value FROM runtime_state WHERE key = ?1",
                params![AUTHORIZATION_DENIAL_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// 在同一事务中记录授权拒绝审计并保存当前拒绝原因。
    pub fn append_audit_and_set_authorization_denial(
        &self,
        payload: AuditPayload,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        Self::append_audit_in(&transaction, payload)?;
        Self::set_runtime_in(&transaction, AUTHORIZATION_DENIAL_KEY, reason, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// 清除已记录的授权拒绝原因；授权恢复后下一次拒绝必须重新记录。
    pub fn clear_authorization_denial(&self) -> Result<(), StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        connection.execute(
            "DELETE FROM runtime_state WHERE key = ?1",
            params![AUTHORIZATION_DENIAL_KEY],
        )?;
        Ok(())
    }

    /// 原子写入设备最近状态；同一设备类别和设备 ID 始终保留最新记录。
    pub fn upsert_device_state(
        &self,
        kind: &str,
        device_id: &str,
        state: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        Self::upsert_device_state_in(&connection, kind, device_id, state, now)
    }

    /// 在同一事务中先追加审计事件，再写入设备最近状态。
    ///
    /// 状态 JSON 在事务开始前序列化，序列化失败时不会产生审计副作用。
    pub fn append_audit_and_upsert_device_state(
        &self,
        payload: AuditPayload,
        kind: &str,
        device_id: &str,
        state: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let state_json = serde_json::to_string(state)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        Self::append_audit_in(&transaction, payload)?;
        Self::upsert_device_state_json_in(&transaction, kind, device_id, &state_json, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// 在同一事务中记录处置失败审计并设置运行期失败状态。
    pub fn append_audit_and_set_enforcement_failure(
        &self,
        payload: AuditPayload,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        let result = (|| {
            Self::append_audit_in(&transaction, payload)?;
            Self::set_runtime_in(&transaction, ENFORCEMENT_FAILURE_KEY, reason, now)?;
            transaction.commit()?;
            Ok(())
        })();
        if result.is_err() {
            self.enforcement_failure_write_failed
                .store(true, Ordering::SeqCst);
        }
        result
    }

    fn upsert_device_state_in(
        connection: &Connection,
        kind: &str,
        device_id: &str,
        state: &serde_json::Value,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let state_json = serde_json::to_string(state)?;
        Self::upsert_device_state_json_in(connection, kind, device_id, &state_json, now)
    }

    fn upsert_device_state_json_in(
        connection: &Connection,
        kind: &str,
        device_id: &str,
        state_json: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        connection.execute(
            "INSERT INTO device_state (kind, device_id, state_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(kind, device_id) DO UPDATE SET
               state_json = excluded.state_json,
               updated_at = excluded.updated_at",
            params![kind, device_id, state_json, now.to_rfc3339()],
        )?;
        Ok(())
    }

    /// 读取指定设备最近一次保存的状态。
    pub fn device_state(
        &self,
        kind: &str,
        device_id: &str,
    ) -> Result<Option<DeviceStateRecord>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let record = connection
            .query_row(
                "SELECT kind, device_id, state_json, updated_at
                 FROM device_state WHERE kind = ?1 AND device_id = ?2",
                params![kind, device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        record
            .map(|(kind, device_id, state_json, updated_at)| {
                Ok(DeviceStateRecord {
                    kind,
                    device_id,
                    state: serde_json::from_str(&state_json)?,
                    updated_at: DateTime::parse_from_rfc3339(&updated_at)
                        .map_err(|_| StoreError::TimeParse(updated_at))?
                        .with_timezone(&Utc),
                })
            })
            .transpose()
    }

    /// 列出某一设备类别下已保存的全部设备状态。
    pub fn device_states(&self, kind: &str) -> Result<Vec<DeviceStateRecord>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT device_id, state_json, updated_at FROM device_state
             WHERE kind = ?1 ORDER BY device_id",
        )?;
        let rows = statement.query_map([kind], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (device_id, state_json, updated_at) = row?;
            records.push(DeviceStateRecord {
                kind: kind.to_string(),
                device_id,
                state: serde_json::from_str(&state_json)?,
                updated_at: DateTime::parse_from_rfc3339(&updated_at)
                    .map_err(|_| StoreError::TimeParse(updated_at.clone()))?
                    .with_timezone(&Utc),
            });
        }
        Ok(records)
    }

    /// 删除单个设备状态；设备移除后重新接入必须重新处置并重新记录。
    pub fn delete_device_state(&self, kind: &str, device_id: &str) -> Result<(), StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        connection.execute(
            "DELETE FROM device_state WHERE kind = ?1 AND device_id = ?2",
            params![kind, device_id],
        )?;
        Ok(())
    }

    /// 原子更新一条文件扫描索引，并可同时追加对应的命中审计。
    pub fn upsert_scan_record(
        &self,
        record: &ScanRecord,
        audit: Option<AuditPayload>,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let matched_rules_json = serde_json::to_string(&record.matched_rules)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        if let Some(audit) = audit {
            Self::append_audit_in(&transaction, audit)?;
        }
        transaction.execute(
            "INSERT INTO scan_index (file_id, path, volume_id, size, mtime, hash, scan_version, status, matched_rules_json, last_event_id, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(file_id) DO UPDATE SET path = excluded.path, volume_id = excluded.volume_id,
               size = excluded.size, mtime = excluded.mtime, hash = excluded.hash, scan_version = excluded.scan_version,
               status = excluded.status, matched_rules_json = excluded.matched_rules_json,
               last_event_id = excluded.last_event_id, updated_at = excluded.updated_at",
            params![record.file_id, record.path, record.volume_id, record.size as i64, record.mtime,
                record.hash, record.scan_version as i64, record.status.as_str(), matched_rules_json,
                record.last_event_id, now.to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// 查询按路径保存的最新扫描记录。
    pub fn scan_record(&self, path: &str) -> Result<Option<ScanRecord>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        connection.query_row(
            "SELECT file_id, path, volume_id, size, mtime, hash, scan_version, status, matched_rules_json, last_event_id
             FROM scan_index WHERE path = ?1 ORDER BY updated_at DESC LIMIT 1",
            [path],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, String>(5)?, row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?, row.get::<_, String>(8)?, row.get::<_, Option<String>>(9)?)),
        ).optional()?.map(|(file_id, path, volume_id, size, mtime, hash, scan_version, status, matched_rules_json, last_event_id)| {
            Ok(ScanRecord { file_id, path, volume_id, size: size as u64, mtime, hash, scan_version: scan_version as u64,
                status: status.parse()?, matched_rules: serde_json::from_str(&matched_rules_json)?, last_event_id })
        }).transpose()
    }

    /// 原子追加一条本地审计事件，并与上一条事件的 hash 连接。
    pub fn append_audit(&self, payload: AuditPayload) -> Result<(), StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        Self::append_audit_in(&transaction, payload)?;
        transaction.commit()?;
        Ok(())
    }

    /// 按写入顺序读取全部审计事件，供只读导出与完整性校验使用。
    pub fn read_audit_events(&self) -> Result<Vec<AuditEvent>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        Self::read_audit_events_in(&connection)
    }

    /// 返回审计 hash chain 是否完整。空链可验证，数据库读取失败仍返回错误。
    pub fn audit_chain_healthy(&self) -> Result<bool, StoreError> {
        Ok(verify_chain(&self.read_audit_events()?).is_ok())
    }

    /// 按条件查询审计事件；None 字段不参与过滤，结果按写入顺序返回。
    pub fn query_events(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut sql = String::from(
            "SELECT event_id, device_id, user_name, timestamp, event_type, process, resource,
                    policy_version, action, result, rule_id, prev_hash, event_hash
             FROM audit_events WHERE 1 = 1",
        );
        let mut parameters: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(since) = filter.since {
            sql.push_str(" AND timestamp >= ?");
            parameters.push(Box::new(since.to_rfc3339()));
        }
        if let Some(until) = filter.until {
            sql.push_str(" AND timestamp <= ?");
            parameters.push(Box::new(until.to_rfc3339()));
        }
        if let Some(event_type) = filter.event_type {
            sql.push_str(" AND event_type = ?");
            parameters.push(Box::new(event_type.as_str().to_string()));
        }
        if let Some(user) = &filter.user {
            sql.push_str(" AND user_name = ?");
            parameters.push(Box::new(user.clone()));
        }
        if let Some(device_id) = &filter.device_id {
            sql.push_str(" AND device_id = ?");
            parameters.push(Box::new(device_id.clone()));
        }
        if let Some(prefix) = &filter.resource_prefix {
            sql.push_str(" AND resource LIKE ?");
            parameters.push(Box::new(format!("{prefix}%")));
        }
        if let Some(version) = filter.policy_version {
            sql.push_str(" AND policy_version = ?");
            parameters.push(Box::new(version as i64));
        }
        sql.push_str(" ORDER BY sequence");
        if let Some(limit) = filter.limit {
            sql.push_str(" LIMIT ?");
            parameters.push(Box::new(limit as i64));
        }

        let mut statement = connection.prepare(&sql)?;
        let references: Vec<&dyn rusqlite::ToSql> =
            parameters.iter().map(|value| value.as_ref()).collect();
        let rows = statement.query_map(references.as_slice(), Self::audit_event_from_row)?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    /// 按游标分页查询审计事件；`after_sequence` 为上一页最后一条事件的序号。
    pub fn query_audit_page(
        &self,
        filter: &EventFilter,
        after_sequence: Option<i64>,
        limit: u32,
    ) -> Result<Vec<(i64, AuditEvent)>, StoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut sql = String::from(
            "SELECT event_id, device_id, user_name, timestamp, event_type, process, resource,
                    policy_version, action, result, rule_id, prev_hash, event_hash, sequence
             FROM audit_events WHERE 1 = 1",
        );
        let mut parameters: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(since) = filter.since {
            sql.push_str(" AND timestamp >= ?");
            parameters.push(Box::new(since.to_rfc3339()));
        }
        if let Some(until) = filter.until {
            sql.push_str(" AND timestamp <= ?");
            parameters.push(Box::new(until.to_rfc3339()));
        }
        if let Some(event_type) = filter.event_type {
            sql.push_str(" AND event_type = ?");
            parameters.push(Box::new(event_type.as_str().to_string()));
        }
        if let Some(user) = &filter.user {
            sql.push_str(" AND user_name = ?");
            parameters.push(Box::new(user.clone()));
        }
        if let Some(device_id) = &filter.device_id {
            sql.push_str(" AND device_id = ?");
            parameters.push(Box::new(device_id.clone()));
        }
        if let Some(prefix) = &filter.resource_prefix {
            sql.push_str(" AND resource LIKE ?");
            parameters.push(Box::new(format!("{prefix}%")));
        }
        if let Some(version) = filter.policy_version {
            sql.push_str(" AND policy_version = ?");
            parameters.push(Box::new(version as i64));
        }
        sql.push_str(" AND sequence > ? ORDER BY sequence LIMIT ?");
        parameters.push(Box::new(after_sequence.unwrap_or(0)));

        let mut statement = connection.prepare(&sql)?;
        let references: Vec<&dyn rusqlite::ToSql> =
            parameters.iter().map(|value| value.as_ref()).collect();
        let limit = limit.clamp(1, 200) as i64;
        let mut query_references = references;
        query_references.push(&limit);
        let rows = statement.query_map(query_references.as_slice(), |row| {
            let event = Self::audit_event_from_row(row)?;
            let sequence = row.get::<_, i64>(13)?;
            Ok((sequence, event))
        })?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    fn read_audit_events_in(connection: &Connection) -> Result<Vec<AuditEvent>, StoreError> {
        let mut statement = connection.prepare(
            "SELECT event_id, device_id, user_name, timestamp, event_type, process, resource,
                    policy_version, action, result, rule_id, prev_hash, event_hash
             FROM audit_events ORDER BY sequence",
        )?;
        let rows = statement.query_map([], Self::audit_event_from_row)?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    fn audit_event_from_row(row: &rusqlite::Row<'_>) -> Result<AuditEvent, rusqlite::Error> {
        let timestamp = row.get::<_, String>(3)?;
        let event_type = row.get::<_, String>(4)?;
        let invalid = |index: usize, error: StoreError| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        };
        Ok(AuditEvent {
            payload: AuditPayload {
                event_id: row.get(0)?,
                device_id: row.get(1)?,
                user: row.get(2)?,
                timestamp: DateTime::parse_from_rfc3339(&timestamp)
                    .map_err(|_| invalid(3, StoreError::TimeParse(timestamp.clone())))?
                    .with_timezone(&Utc),
                event_type: event_type
                    .parse()
                    .map_err(|error: anchor_core::CoreError| invalid(4, StoreError::Core(error)))?,
                process: row.get(5)?,
                resource: row.get(6)?,
                policy_version: row.get::<_, Option<i64>>(7)?.map(|version| version as u64),
                action: row.get(8)?,
                result: row.get(9)?,
                rule_id: row.get(10)?,
                prev_hash: row.get(11)?,
            },
            event_hash: row.get(12)?,
        })
    }

    fn append_audit_in(
        transaction: &Transaction<'_>,
        payload: AuditPayload,
    ) -> Result<(), StoreError> {
        let previous_hash = transaction
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let event = AuditEvent::new(payload, &previous_hash)?;
        transaction.execute(
            "INSERT INTO audit_events (
                 event_id, device_id, user_name, timestamp, event_type, process, resource,
                 policy_version, action, result, rule_id, prev_hash, event_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event.payload.event_id,
                event.payload.device_id,
                event.payload.user,
                event.payload.timestamp.to_rfc3339(),
                event.payload.event_type.as_str(),
                event.payload.process,
                event.payload.resource,
                event.payload.policy_version.map(|version| version as i64),
                event.payload.action,
                event.payload.result,
                event.payload.rule_id,
                event.payload.prev_hash,
                event.event_hash,
            ],
        )?;
        Ok(())
    }

    fn set_runtime_in(
        transaction: &Transaction<'_>,
        key: &str,
        value: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        transaction.execute(
            "INSERT INTO runtime_state (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, now.to_rfc3339()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anchor_core::{
        crypto, ActionPolicy, BurningRules, NetworkRules, PolicyPayload, ScanRules, UsbRules,
    };
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
    }

    fn package(version: u64) -> PolicyPackage {
        let (key, _) = crypto::generate_keypair();
        PolicyPackage::sign(
            PolicyPayload {
                version,
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
                    controlled_dirs: vec![],
                    file_types: vec![],
                    rules: vec![],
                },
            },
            &key,
        )
        .unwrap()
    }

    #[test]
    fn rejected_import_keeps_active_policy_and_appends_a_rejection_event() {
        let store = Store::in_memory().unwrap();
        let active = package(1);
        store
            .import_policy(&active, ImportDecision::Accept, "laptop-1", "admin", now())
            .unwrap();

        assert_eq!(
            store
                .import_policy(
                    &package(1),
                    ImportDecision::VersionNotNewer,
                    "laptop-1",
                    "admin",
                    now()
                )
                .unwrap(),
            ImportDecision::VersionNotNewer,
        );
        assert_eq!(store.active_policy().unwrap().unwrap().payload.version, 1);
        assert!(store.audit_chain_healthy().unwrap());
    }

    #[test]
    fn invalid_package_cannot_replace_an_active_policy() {
        let store = Store::in_memory().unwrap();
        store
            .import_policy(
                &package(1),
                ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();

        assert_eq!(
            store
                .import_policy(
                    &package(2),
                    ImportDecision::InvalidSignature,
                    "laptop-1",
                    "admin",
                    now(),
                )
                .unwrap(),
            ImportDecision::InvalidSignature,
        );
        assert_eq!(store.active_policy().unwrap().unwrap().payload.version, 1);
        assert!(store.audit_chain_healthy().unwrap());
    }

    #[test]
    fn accepted_import_replaces_active_policy_and_keeps_a_healthy_audit_chain() {
        let store = Store::in_memory().unwrap();
        store
            .import_policy(
                &package(1),
                ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();
        store
            .import_policy(
                &package(2),
                ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();

        assert_eq!(store.active_policy().unwrap().unwrap().payload.version, 2);
        assert!(store.audit_chain_healthy().unwrap());
    }

    #[test]
    fn accepted_import_records_the_last_trusted_time() {
        let store = Store::in_memory().unwrap();
        store
            .import_policy(
                &package(1),
                ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();

        assert_eq!(store.last_trusted_at().unwrap(), Some(now()));
    }

    #[test]
    fn active_policy_record_returns_import_time() {
        let store = Store::in_memory().unwrap();
        store
            .import_policy(
                &package(1),
                ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();

        let record = store.active_policy_record().unwrap().unwrap();

        assert_eq!(record.package.payload.version, 1);
        assert_eq!(record.imported_at, now());
    }

    #[test]
    fn audit_page_respects_cursor_limit_and_filters() {
        let store = Store::in_memory().unwrap();
        for result in ["a", "b", "c"] {
            let mut payload =
                AuditPayload::new("laptop-1", "alice", EventType::ScanHit, "scan", result);
            payload.timestamp = now();
            store.append_audit(payload).unwrap();
        }

        let first = store
            .query_audit_page(&EventFilter::default(), None, 2)
            .unwrap();
        assert_eq!(first.len(), 2);
        let second = store
            .query_audit_page(&EventFilter::default(), Some(first[1].0), 2)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].1.payload.result, "c");
    }

    #[test]
    fn independently_appended_event_keeps_the_audit_chain_healthy() {
        let store = Store::in_memory().unwrap();
        let mut payload = AuditPayload::new(
            "laptop-1",
            "developer",
            EventType::AuthorizationDenied,
            "login",
            "denied",
        );
        payload.timestamp = now();

        store.append_audit(payload).unwrap();
        assert!(store.audit_chain_healthy().unwrap());
    }

    #[test]
    fn read_only_open_reads_existing_audit_without_creating_state() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(file.path()).unwrap();
        let mut payload = AuditPayload::new(
            "laptop-1",
            "developer",
            EventType::AuthorizationDenied,
            "login",
            "denied",
        );
        payload.timestamp = now();
        store.append_audit(payload).unwrap();
        drop(store);

        let read_only = Store::open_read_only(file.path()).unwrap();
        assert_eq!(read_only.read_audit_events().unwrap().len(), 1);
    }

    #[test]
    fn upsert_device_state_replaces_the_latest_state_for_the_same_device() {
        let store = Store::in_memory().unwrap();
        let first_updated_at = now();
        let latest_updated_at = now() + Duration::minutes(5);

        store
            .upsert_device_state(
                "usb",
                "USB\\VID_1234&PID_5678",
                &serde_json::json!({ "enabled": false }),
                first_updated_at,
            )
            .unwrap();
        store
            .upsert_device_state(
                "usb",
                "USB\\VID_1234&PID_5678",
                &serde_json::json!({ "enabled": true }),
                latest_updated_at,
            )
            .unwrap();

        assert_eq!(
            store.device_state("usb", "USB\\VID_1234&PID_5678").unwrap(),
            Some(DeviceStateRecord {
                kind: "usb".into(),
                device_id: "USB\\VID_1234&PID_5678".into(),
                state: serde_json::json!({ "enabled": true }),
                updated_at: latest_updated_at,
            }),
        );
        assert_eq!(store.device_state("usb", "missing").unwrap(), None);
    }

    #[test]
    fn append_audit_and_upsert_device_state_persists_both_records() {
        let store = Store::in_memory().unwrap();
        let mut payload = AuditPayload::new(
            "laptop-1",
            "service",
            EventType::AuthorizationDenied,
            "apply_policy",
            "disabled",
        );
        payload.timestamp = now();

        store
            .append_audit_and_upsert_device_state(
                payload,
                "usb",
                "USB\\VID_1234&PID_5678",
                &serde_json::json!({ "enabled": false }),
                now(),
            )
            .unwrap();

        assert_eq!(store.read_audit_events().unwrap().len(), 1);
        assert!(store.audit_chain_healthy().unwrap());
        assert_eq!(
            store
                .device_state("usb", "USB\\VID_1234&PID_5678")
                .unwrap()
                .unwrap()
                .state,
            serde_json::json!({ "enabled": false }),
        );
    }

    #[test]
    fn failed_device_state_write_rolls_back_the_appended_audit_event() {
        let store = Store::in_memory().unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_device_state_insert
                 BEFORE INSERT ON device_state
                 BEGIN
                   SELECT RAISE(ABORT, 'device state rejected');
                 END;",
            )
            .unwrap();
        let mut payload = AuditPayload::new(
            "laptop-1",
            "service",
            EventType::AuthorizationDenied,
            "apply_policy",
            "disabled",
        );
        payload.timestamp = now();

        assert!(matches!(
            store.append_audit_and_upsert_device_state(
                payload,
                "usb",
                "USB\\VID_1234&PID_5678",
                &serde_json::json!({ "enabled": false }),
                now(),
            ),
            Err(StoreError::Db(_))
        ));
        assert!(store.read_audit_events().unwrap().is_empty());
        assert_eq!(
            store.device_state("usb", "USB\\VID_1234&PID_5678").unwrap(),
            None,
        );
    }

    #[test]
    fn enforcement_failure_is_readable_and_can_be_cleared() {
        let store = Store::in_memory().unwrap();

        store
            .set_enforcement_failure("USB control failed", now())
            .unwrap();
        assert_eq!(
            store.enforcement_failure().unwrap(),
            Some("USB control failed".into())
        );

        store.clear_enforcement_failure().unwrap();
        assert_eq!(store.enforcement_failure().unwrap(), None);
    }

    #[test]
    fn accepted_policy_import_clears_enforcement_failure() {
        let store = Store::in_memory().unwrap();
        store
            .set_enforcement_failure("USB control failed", now())
            .unwrap();

        store
            .import_policy(
                &package(1),
                ImportDecision::Accept,
                "laptop-1",
                "admin",
                now(),
            )
            .unwrap();

        assert_eq!(store.enforcement_failure().unwrap(), None);
    }

    #[test]
    fn query_events_filters_by_type_user_resource_and_limit() {
        let store = Store::in_memory().unwrap();
        let append = |event_type: EventType, user: &str, resource: Option<&str>, result: &str| {
            let mut payload = AuditPayload::new("laptop-1", user, event_type, "test", result);
            payload.timestamp = now();
            payload.resource = resource.map(str::to_string);
            store.append_audit(payload).unwrap();
        };
        append(EventType::ServiceStart, "AnchorGuard", None, "running");
        append(
            EventType::ScanHit,
            "alice",
            Some("D:\\workspace\\report.txt"),
            "hit",
        );
        append(
            EventType::ScanCompleted,
            "alice",
            Some("D:\\workspace\\notes.txt"),
            "clean",
        );

        let all = store.query_events(&EventFilter::default()).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            store
                .query_events(&EventFilter {
                    event_type: Some(EventType::ScanHit),
                    ..EventFilter::default()
                })
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .query_events(&EventFilter {
                    user: Some("alice".into()),
                    ..EventFilter::default()
                })
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .query_events(&EventFilter {
                    resource_prefix: Some("D:\\workspace\\report".into()),
                    ..EventFilter::default()
                })
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .query_events(&EventFilter {
                    limit: Some(2),
                    ..EventFilter::default()
                })
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .query_events(&EventFilter {
                    since: Some(now() + Duration::seconds(1)),
                    ..EventFilter::default()
                })
                .unwrap()
                .len(),
            0
        );
    }
}
