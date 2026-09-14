use std::fs;

use anchor_core::{
    crypto, ActionPolicy, AuthorizationDenial, AuthorizationState, BurningRules, ImportDecision,
    NetworkRules, PolicyPackage, PolicyPayload, ScanRules, UsbRules,
};
use anchor_service::protocol::{AuthorizationResponse, ServiceRequest, ServiceResponse};
use anchor_service::Service;
use anchor_store::Store;
use chrono::{Duration, TimeZone, Utc};
use tempfile::tempdir;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
}

fn package(version: u64, key: &ed25519_dalek::SigningKey) -> PolicyPackage {
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
                policy: ActionPolicy::Allow,
                allowed: vec![],
            },
            burning: BurningRules {
                policy: ActionPolicy::Deny,
                allowed: vec![],
            },
            scan: ScanRules {
                controlled_dirs: vec!["D:\\workspace".into()],
                rules: vec![],
            },
        },
        key,
    )
    .unwrap()
}

#[test]
fn valid_package_in_a_removable_root_restores_authorization() {
    let root = tempdir().unwrap();
    let (signing_key, verifying_key) = crypto::generate_keypair();
    fs::write(
        root.path().join("anchor-guard.policy"),
        serde_json::to_vec(&package(1, &signing_key)).unwrap(),
    )
    .unwrap();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");

    assert!(
        service
            .import_from_roots(&[root.path()], "alice", now())
            .accepted
    );
    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Allowed
    );
}

#[test]
fn authorization_remembers_the_latest_trusted_time_for_rollback_detection() {
    let root = tempdir().unwrap();
    let (signing_key, verifying_key) = crypto::generate_keypair();
    fs::write(
        root.path().join("anchor-guard.policy"),
        serde_json::to_vec(&package(1, &signing_key)).unwrap(),
    )
    .unwrap();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");
    assert!(
        service
            .import_from_roots(&[root.path()], "alice", now())
            .accepted
    );

    assert_eq!(
        service.authorization_state(now() + Duration::seconds(100)),
        AuthorizationState::Allowed
    );
    assert!(matches!(
        service.authorization_state(now() - Duration::seconds(250)),
        AuthorizationState::Denied(_)
    ));
}

#[test]
fn enforcement_failure_denies_authorization_until_a_policy_is_imported() {
    let (signing_key, verifying_key) = crypto::generate_keypair();
    let store = Store::in_memory().unwrap();
    store
        .import_policy(
            &package(1, &signing_key),
            ImportDecision::Accept,
            "laptop-1",
            "alice",
            now(),
        )
        .unwrap();
    store
        .set_enforcement_failure("USB control failed", now())
        .unwrap();
    let service = Service::new(store, verifying_key, "laptop-1");

    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
    assert_eq!(
        serde_json::from_slice::<ServiceResponse>(
            &service
                .handle_session_status_request(
                    &serde_json::to_vec(&ServiceRequest::GetAuthorization).unwrap(),
                    now(),
                )
                .unwrap(),
        )
        .unwrap(),
        ServiceResponse::Authorization(AuthorizationResponse::Denied {
            reason: "enforcement_unhealthy".into(),
        })
    );

    let root = tempdir().unwrap();
    fs::write(
        root.path().join("anchor-guard.policy"),
        serde_json::to_vec(&package(2, &signing_key)).unwrap(),
    )
    .unwrap();
    assert!(
        service
            .import_from_roots(&[root.path()], "alice", now())
            .accepted
    );
    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Allowed
    );
}

#[test]
fn session_assistant_failure_enters_runtime_fail_closed_state() {
    let (_, verifying_key) = crypto::generate_keypair();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");

    service
        .record_session_assistant_failure("session status pipe unavailable", now())
        .unwrap();

    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
}

#[test]
fn authorization_request_returns_a_denied_ipc_response_without_a_policy() {
    let (_, verifying_key) = crypto::generate_keypair();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");

    assert_eq!(
        service.handle_request(ServiceRequest::GetAuthorization, "alice", now()),
        ServiceResponse::Authorization(AuthorizationResponse::Denied {
            reason: "no_active_policy".into(),
        })
    );
}

#[test]
fn json_authorization_request_returns_a_denied_response_without_a_policy() {
    let (_, verifying_key) = crypto::generate_keypair();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");

    let response = service
        .handle_json_request(
            &serde_json::to_vec(&ServiceRequest::GetAuthorization).unwrap(),
            "LogonUI",
            now(),
        )
        .unwrap();

    assert_eq!(
        serde_json::from_slice::<ServiceResponse>(&response).unwrap(),
        ServiceResponse::Authorization(AuthorizationResponse::Denied {
            reason: "no_active_policy".into(),
        })
    );
}

#[test]
fn session_status_pipe_rejects_policy_import_requests() {
    let (_, verifying_key) = crypto::generate_keypair();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");

    let error = service
        .handle_session_status_request(
            &serde_json::to_vec(&ServiceRequest::ImportFromRemovableRoots).unwrap(),
            now(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("只接受授权查询"));
}
