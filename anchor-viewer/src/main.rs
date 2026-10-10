use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anchor_core::{verify_chain, AuditEvent, EventType};
use anchor_store::{EventFilter, Store};
use clap::{Parser, Subcommand};
use serde::Serialize;

#[derive(Parser)]
#[command(name = "anchor-viewer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 验证本地审计库完整性。
    Verify {
        #[arg(long)]
        db: PathBuf,
    },
    /// 导出审计事件和验证结论。
    Export {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// 只导出该时间之后的事件（RFC 3339）。
        #[arg(long)]
        since: Option<String>,
        /// 只导出该时间之前的事件（RFC 3339）。
        #[arg(long)]
        until: Option<String>,
        /// 只导出指定事件类型。
        #[arg(long)]
        event_type: Option<String>,
        /// 只导出指定操作者的事件。
        #[arg(long)]
        user: Option<String>,
        /// 只导出指定设备标识的事件。
        #[arg(long)]
        device_id: Option<String>,
        /// 只导出资源以该前缀开头的事件。
        #[arg(long)]
        resource_prefix: Option<String>,
        /// 只导出指定策略版本的事件。
        #[arg(long)]
        policy_version: Option<u64>,
        /// 最多导出的事件条数。
        #[arg(long)]
        limit: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VerificationStatus {
    Valid,
    Invalid,
    Unavailable,
}

#[derive(Serialize)]
struct VerificationReport {
    status: VerificationStatus,
    event_count: usize,
}

fn verify_database(path: &Path) -> VerificationReport {
    match Store::open_read_only(path).and_then(|store| store.read_audit_events()) {
        Ok(events) if events.is_empty() => VerificationReport {
            status: VerificationStatus::Invalid,
            event_count: 0,
        },
        Ok(events) if verify_chain(&events).is_ok() => VerificationReport {
            status: VerificationStatus::Valid,
            event_count: events.len(),
        },
        Ok(events) => VerificationReport {
            status: VerificationStatus::Invalid,
            event_count: events.len(),
        },
        Err(_) => VerificationReport {
            status: VerificationStatus::Unavailable,
            event_count: 0,
        },
    }
}

fn write_export(
    out: &Path,
    verification: &VerificationReport,
    events: &[AuditEvent],
) -> anyhow::Result<()> {
    fs::create_dir_all(out)?;
    let mut audit = File::create(out.join("audit.jsonl"))?;
    for event in events {
        serde_json::to_writer(&mut audit, event)?;
        audit.write_all(b"\n")?;
    }
    serde_json::to_writer_pretty(File::create(out.join("verification.json"))?, verification)?;
    Ok(())
}

fn parse_time(value: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|error| anyhow::anyhow!("{value} 不是 RFC 3339 时间: {error}"))?
        .with_timezone(&chrono::Utc))
}

fn exit_code(status: VerificationStatus) -> ExitCode {
    match status {
        VerificationStatus::Valid => ExitCode::SUCCESS,
        VerificationStatus::Invalid | VerificationStatus::Unavailable => ExitCode::FAILURE,
    }
}

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let verification = match cli.command {
        Command::Verify { db } => verify_database(&db),
        Command::Export {
            db,
            out,
            since,
            until,
            event_type,
            user,
            device_id,
            resource_prefix,
            policy_version,
            limit,
        } => {
            let verification = verify_database(&db);
            let filter = EventFilter {
                since: since.as_deref().map(parse_time).transpose()?,
                until: until.as_deref().map(parse_time).transpose()?,
                event_type: event_type
                    .as_deref()
                    .map(|value| value.parse::<EventType>())
                    .transpose()?,
                user,
                device_id,
                resource_prefix,
                policy_version,
                limit,
            };
            let events = if verification.status == VerificationStatus::Unavailable {
                Vec::new()
            } else {
                Store::open_read_only(&db)?.query_events(&filter)?
            };
            write_export(&out, &verification, &events)?;
            verification
        }
    };
    println!("{}", serde_json::to_string(&verification)?);
    Ok(exit_code(verification.status))
}
