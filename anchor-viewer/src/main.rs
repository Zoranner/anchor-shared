use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anchor_core::{verify_chain, AuditEvent};
use anchor_store::Store;
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

struct Verification {
    report: VerificationReport,
    events: Vec<AuditEvent>,
}

fn verify_database(path: &Path) -> Verification {
    match Store::open_read_only(path).and_then(|store| store.read_audit_events()) {
        Ok(events) if events.is_empty() => Verification {
            report: VerificationReport {
                status: VerificationStatus::Invalid,
                event_count: 0,
            },
            events,
        },
        Ok(events) if verify_chain(&events).is_ok() => Verification {
            report: VerificationReport {
                status: VerificationStatus::Valid,
                event_count: events.len(),
            },
            events,
        },
        Ok(events) => Verification {
            report: VerificationReport {
                status: VerificationStatus::Invalid,
                event_count: events.len(),
            },
            events,
        },
        Err(_) => Verification {
            report: VerificationReport {
                status: VerificationStatus::Unavailable,
                event_count: 0,
            },
            events: Vec::new(),
        },
    }
}

fn write_export(out: &Path, verification: &Verification) -> anyhow::Result<()> {
    fs::create_dir_all(out)?;
    let mut audit = File::create(out.join("audit.jsonl"))?;
    for event in &verification.events {
        serde_json::to_writer(&mut audit, event)?;
        audit.write_all(b"\n")?;
    }
    serde_json::to_writer_pretty(
        File::create(out.join("verification.json"))?,
        &verification.report,
    )?;
    Ok(())
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
        Command::Export { db, out } => {
            let verification = verify_database(&db);
            write_export(&out, &verification)?;
            verification
        }
    };
    println!("{}", serde_json::to_string(&verification.report)?);
    Ok(exit_code(verification.report.status))
}
