use anchor_core::{
    ActionPolicy, AuthorizationDenial, AuthorizationState, BurningRules, ImportDecision,
    NetworkRules, PolicyPackage, PolicyPayload, ScanRules, UsbAllowRule, UsbRules,
};
use anchor_service::{
    enforce::{EnforcementOutcome, ObservedDevices},
    Service,
};
use anchor_store::Store;
use anchor_system::{
    burning::BurningControlExecutor,
    error::PlatformError,
    nic::NicControlExecutor,
    session::{SessionLockResult, SessionLocker},
    usb::{UsbPlannedAction, UsbStorageDevice, UsbStorageExecutor},
};
use chrono::{TimeZone, Utc};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
}

#[derive(Default)]
struct RecordingLocker {
    calls: std::sync::atomic::AtomicUsize,
}

impl SessionLocker for RecordingLocker {
    fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(SessionLockResult::Locked)
    }
}

#[derive(Default)]
struct RecordingUsbExecutor {
    calls: Vec<(String, bool)>,
}

impl UsbStorageExecutor for RecordingUsbExecutor {
    fn set_mass_storage_enabled(
        &mut self,
        instance_id: &str,
        enabled: bool,
    ) -> Result<(), PlatformError> {
        self.calls.push((instance_id.into(), enabled));
        Ok(())
    }
}

#[derive(Default)]
struct RecordingNicExecutor;

impl NicControlExecutor for RecordingNicExecutor {
    fn set_enabled(&mut self, _adapter_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingBurningExecutor;

impl BurningControlExecutor for RecordingBurningExecutor {
    fn set_enabled(&mut self, _drive_id: &str, _enabled: bool) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[derive(Default)]
struct FailingFirstUsbExecutor {
    calls: Vec<String>,
}

impl UsbStorageExecutor for FailingFirstUsbExecutor {
    fn set_mass_storage_enabled(
        &mut self,
        instance_id: &str,
        _enabled: bool,
    ) -> Result<(), PlatformError> {
        self.calls.push(instance_id.into());
        if instance_id.ends_with("\\1") {
            return Err(PlatformError::Failed("simulated control failure".into()));
        }
        Ok(())
    }
}

fn service_with_active_policy() -> Service {
    service_with_usb_rules(ActionPolicy::Allow, ActionPolicy::Allow, vec![])
}

fn service_with_usb_rules(
    read: ActionPolicy,
    write: ActionPolicy,
    allowed: Vec<UsbAllowRule>,
) -> Service {
    let store = Store::in_memory().unwrap();
    let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
    let package = PolicyPackage::sign(
        PolicyPayload {
            policy_id: "policy-1".into(),
            version: 1,
            device_id: "laptop-1".into(),
            effective_from: now() - chrono::Duration::hours(1),
            effective_until: now() + chrono::Duration::days(1),
            clock_rollback_tolerance_secs: 300,
            usb: UsbRules {
                read,
                write,
                allowed,
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
                rules: vec![],
            },
        },
        &signing_key,
    )
    .unwrap();
    store
        .import_policy(&package, ImportDecision::Accept, "laptop-1", "test", now())
        .unwrap();
    Service::new(store, verifying_key, "laptop-1")
}

fn active_policy_package(signing_key: &ed25519_dalek::SigningKey) -> PolicyPackage {
    PolicyPackage::sign(
        PolicyPayload {
            policy_id: "policy-1".into(),
            version: 1,
            device_id: "laptop-1".into(),
            effective_from: now() - chrono::Duration::hours(1),
            effective_until: now() + chrono::Duration::days(1),
            clock_rollback_tolerance_secs: 300,
            usb: UsbRules {
                read: ActionPolicy::Allow,
                write: ActionPolicy::Allow,
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
                rules: vec![],
            },
        },
        signing_key,
    )
    .unwrap()
}

#[test]
fn denied_authorization_locks_the_session() {
    let service = Service::new(
        Store::in_memory().unwrap(),
        anchor_core::crypto::generate_keypair().1,
        "laptop-1",
    );
    let locker = RecordingLocker::default();

    let outcome = service
        .apply_policy(&locker, ObservedDevices::default(), now())
        .unwrap();

    assert_eq!(locker.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(matches!(outcome, EnforcementOutcome::SessionLocked { .. }));
}

#[test]
fn allowed_policy_plans_unlisted_usb_mass_storage_for_disable() {
    let service = service_with_active_policy();
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
        ..ObservedDevices::default()
    };

    let outcome = service.apply_policy(&locker, observed, now()).unwrap();

    assert!(matches!(
        outcome,
        EnforcementOutcome::DevicePlans(ref plans)
            if plans.usb[0].planned_action == UsbPlannedAction::DisableMassStorage
    ));
}

#[test]
fn read_only_usb_policy_keeps_even_allowlisted_mass_storage_disabled() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let service = service_with_usb_rules(
        ActionPolicy::Allow,
        ActionPolicy::Deny,
        vec![UsbAllowRule {
            instance_id: Some(instance_id.into()),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
    );
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![UsbStorageDevice {
            instance_id: instance_id.into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
        ..ObservedDevices::default()
    };

    let outcome = service.apply_policy(&locker, observed, now()).unwrap();

    assert!(matches!(
        outcome,
        EnforcementOutcome::DevicePlans(ref plans)
            if plans.usb[0].planned_action == UsbPlannedAction::DisableMassStorage
    ));
}

#[test]
fn enforce_policy_executes_unlisted_usb_disable_after_planning() {
    let service = service_with_active_policy();
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
        ..ObservedDevices::default()
    };
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor;
    let mut burning = RecordingBurningExecutor;

    let outcome = service
        .enforce_policy(&locker, &mut usb, &mut nic, &mut burning, observed, now())
        .unwrap();

    assert!(matches!(outcome, EnforcementOutcome::DevicePlans(_)));
    assert_eq!(
        usb.calls,
        vec![("USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(), false)]
    );
}

#[test]
fn successful_enforcement_clears_a_previous_runtime_failure() {
    let store = Store::in_memory().unwrap();
    let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
    let package = active_policy_package(&signing_key);
    store
        .import_policy(&package, ImportDecision::Accept, "laptop-1", "test", now())
        .unwrap();
    store
        .set_enforcement_failure("USB control failed", now())
        .unwrap();
    let service = Service::new(store, verifying_key, "laptop-1");
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
        ..ObservedDevices::default()
    };
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor;
    let mut burning = RecordingBurningExecutor;

    service
        .enforce_policy(&locker, &mut usb, &mut nic, &mut burning, observed, now())
        .unwrap();

    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Allowed
    );
    assert_eq!(locker.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn device_control_failure_still_processes_all_devices_then_locks_the_session() {
    let service = service_with_active_policy();
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![
            UsbStorageDevice {
                instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
                vendor_id: None,
                product_id: None,
                serial: None,
            },
            UsbStorageDevice {
                instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\2".into(),
                vendor_id: None,
                product_id: None,
                serial: None,
            },
        ],
        ..ObservedDevices::default()
    };
    let mut usb = FailingFirstUsbExecutor::default();
    let mut nic = RecordingNicExecutor;
    let mut burning = RecordingBurningExecutor;

    let error = service
        .enforce_policy(&locker, &mut usb, &mut nic, &mut burning, observed, now())
        .unwrap_err();

    assert!(matches!(
        error,
        anchor_service::enforce::EnforcementError::DeviceControl(_)
    ));
    assert_eq!(usb.calls.len(), 2);
    assert_eq!(locker.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
}

#[test]
fn state_persistence_failure_after_device_control_locks_the_session() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(database.path()).unwrap();
    let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
    let package = active_policy_package(&signing_key);
    store
        .import_policy(&package, ImportDecision::Accept, "laptop-1", "test", now())
        .unwrap();
    rusqlite::Connection::open(database.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_device_state_insert
             BEFORE INSERT ON device_state
             BEGIN
               SELECT RAISE(ABORT, 'device state rejected');
             END;",
        )
        .unwrap();
    let service = Service::new(store, verifying_key, "laptop-1");
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
        ..ObservedDevices::default()
    };
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor;
    let mut burning = RecordingBurningExecutor;

    let error = service
        .enforce_policy(&locker, &mut usb, &mut nic, &mut burning, observed, now())
        .unwrap_err();

    assert!(matches!(
        error,
        anchor_service::enforce::EnforcementError::StatePersistence(_)
    ));
    assert_eq!(usb.calls.len(), 1);
    assert_eq!(locker.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
}

#[test]
fn runtime_failure_state_write_failure_does_not_leave_service_authorized() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(database.path()).unwrap();
    let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
    let package = active_policy_package(&signing_key);
    store
        .import_policy(&package, ImportDecision::Accept, "laptop-1", "test", now())
        .unwrap();
    rusqlite::Connection::open(database.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_enforcement_failure
             BEFORE INSERT ON runtime_state
             WHEN NEW.key = 'enforcement_failure'
             BEGIN
               SELECT RAISE(ABORT, 'enforcement failure rejected');
             END;",
        )
        .unwrap();
    let service = Service::new(store, verifying_key, "laptop-1");
    let locker = RecordingLocker::default();
    let observed = ObservedDevices {
        usb_storage: vec![UsbStorageDevice {
            instance_id: "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1".into(),
            vendor_id: None,
            product_id: None,
            serial: None,
        }],
        ..ObservedDevices::default()
    };
    let mut usb = FailingFirstUsbExecutor::default();
    let mut nic = RecordingNicExecutor;
    let mut burning = RecordingBurningExecutor;

    let error = service
        .enforce_policy(&locker, &mut usb, &mut nic, &mut burning, observed, now())
        .unwrap_err();

    assert!(matches!(
        error,
        anchor_service::enforce::EnforcementError::StatePersistence(_)
    ));
    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
    let events = Store::open_read_only(database.path())
        .unwrap()
        .read_audit_events()
        .unwrap();
    assert!(!events
        .iter()
        .any(|event| event.payload.action == "apply_usb_control"));
}
