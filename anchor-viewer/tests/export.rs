use std::fs;
use std::process::Command;

use anchor_core::{AuditPayload, EventType};
use anchor_store::Store;
use chrono::{TimeZone, Utc};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

fn viewer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_anchor-viewer"))
}

fn append_event(database: &std::path::Path) {
    let store = Store::open(database).unwrap();
    append_event_of_type(&store, EventType::AuthorizationDenied, "developer", None);
}

fn append_event_of_type(store: &Store, event_type: EventType, user: &str, resource: Option<&str>) {
    let mut payload = AuditPayload::new("laptop-1", user, event_type, "login", "denied");
    payload.timestamp = Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap();
    payload.resource = resource.map(str::to_string);
    store.append_audit(payload).unwrap();
}

fn report(path: &std::path::Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path.join("verification.json")).unwrap()).unwrap()
}

#[test]
fn export_writes_audit_and_valid_verification_for_a_complete_nonempty_chain() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("audit.db");
    let output = directory.path().join("export");
    append_event(&database);

    let result = viewer()
        .args(["export", "--db"])
        .arg(&database)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();

    assert!(result.status.success());
    assert_eq!(report(&output)["status"], "valid");
    let lines = fs::read_to_string(output.join("audit.jsonl")).unwrap();
    assert_eq!(lines.lines().count(), 1);
    assert!(serde_json::from_str::<Value>(lines.trim()).unwrap()["event_hash"].is_string());
}

#[test]
fn export_marks_a_broken_chain_invalid_without_reporting_success() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("audit.db");
    let output = directory.path().join("export");
    append_event(&database);
    Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE audit_events SET prev_hash = 'tampered' WHERE sequence = 1",
            [],
        )
        .unwrap();

    let result = viewer()
        .args(["export", "--db"])
        .arg(&database)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert_eq!(report(&output)["status"], "invalid");
}

#[test]
fn export_marks_an_empty_audit_database_invalid() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("audit.db");
    let output = directory.path().join("export");
    Store::open(&database).unwrap();

    let result = viewer()
        .args(["export", "--db"])
        .arg(&database)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert_eq!(report(&output)["status"], "invalid");
}

#[test]
fn verify_and_export_mark_an_unreadable_database_unavailable() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("not-a-database.db");
    let output = directory.path().join("export");
    fs::write(&database, "not sqlite").unwrap();

    let verify = viewer()
        .args(["verify", "--db"])
        .arg(&database)
        .output()
        .unwrap();
    assert!(!verify.status.success());
    assert!(String::from_utf8(verify.stdout)
        .unwrap()
        .contains("unavailable"));

    let export = viewer()
        .args(["export", "--db"])
        .arg(&database)
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!export.status.success());
    assert_eq!(report(&output)["status"], "unavailable");
    assert!(output.join("audit.jsonl").is_file());
}

#[test]
fn export_applies_event_filters_while_verifying_the_whole_chain() {
    let directory = TempDir::new().unwrap();
    let database = directory.path().join("audit.db");
    let output = directory.path().join("filtered");
    let store = Store::open(&database).unwrap();
    append_event_of_type(&store, EventType::ServiceStart, "AnchorGuard", None);
    append_event_of_type(
        &store,
        EventType::ScanHit,
        "alice",
        Some("D:\\workspace\\a.txt"),
    );
    append_event_of_type(
        &store,
        EventType::ScanCompleted,
        "alice",
        Some("D:\\workspace\\b.txt"),
    );
    drop(store);

    let result = viewer()
        .args(["export", "--db"])
        .arg(&database)
        .arg("--out")
        .arg(&output)
        .args(["--user", "alice", "--event-type", "scan_hit"])
        .output()
        .unwrap();

    assert!(result.status.success());
    assert_eq!(report(&output)["status"], "valid");
    assert_eq!(report(&output)["event_count"], 3);
    let exported = fs::read_to_string(output.join("audit.jsonl")).unwrap();
    assert_eq!(exported.lines().count(), 1);
    assert!(exported.contains("D:\\\\workspace\\\\a.txt"));
}
