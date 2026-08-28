use std::fs;

use anchor_core::{
    crypto, ActionPolicy, AuthorizationState, BurningRules, NetworkRules, PolicyPackage,
    PolicyPayload, ScanRules, UsbRules,
};
use anchor_service::protocol::{AuthorizationResponse, ServiceRequest, ServiceResponse};
use anchor_service::Service;
use anchor_store::Store;
use chrono::{Duration, TimeZone, Utc};
use tempfile::tempdir;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
}

fn package(device_id: &str, version: u64, key: &ed25519_dalek::SigningKey) -> PolicyPackage {
    PolicyPackage::sign(
        PolicyPayload {
            policy_id: "policy-laptop-1".into(),
            version,
            device_id: device_id.into(),
            effective_from: now() - Duration::hours(1),
            effective_until: now() + Duration::days(1),
            clock_rollback_tolerance_secs: 300,
            usb: UsbRules {
                read: ActionPolicy::Deny,
                write: ActionPolicy::Deny,
            },
            network: NetworkRules {
                policy: ActionPolicy::Allow,
            },
            burning: BurningRules {
                policy: ActionPolicy::Deny,
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
        serde_json::to_vec(&package("laptop-1", 1, &signing_key)).unwrap(),
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
fn package_for_another_device_keeps_service_denied() {
    let root = tempdir().unwrap();
    let (signing_key, verifying_key) = crypto::generate_keypair();
    fs::write(
        root.path().join("anchor-guard.policy"),
        serde_json::to_vec(&package("other-laptop", 1, &signing_key)).unwrap(),
    )
    .unwrap();
    let service = Service::new(Store::in_memory().unwrap(), verifying_key, "laptop-1");

    assert!(
        !service
            .import_from_roots(&[root.path()], "alice", now())
            .accepted
    );
    assert!(matches!(
        service.authorization_state(now()),
        AuthorizationState::Denied(_)
    ));
}

#[test]
fn authorization_remembers_the_latest_trusted_time_for_rollback_detection() {
    let root = tempdir().unwrap();
    let (signing_key, verifying_key) = crypto::generate_keypair();
    fs::write(
        root.path().join("anchor-guard.policy"),
        serde_json::to_vec(&package("laptop-1", 1, &signing_key)).unwrap(),
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
