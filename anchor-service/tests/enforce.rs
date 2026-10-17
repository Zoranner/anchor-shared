use anchor_core::{
    ActionPolicy, AuditEvent, AuthorizationDenial, AuthorizationState, BurningRules, EventType,
    ImportDecision, NetworkAllowRule, NetworkRules, PolicyPackage, PolicyPayload, ScanRules,
    UsbAllowRule, UsbRules,
};
use anchor_service::{
    enforce::{AppliedDispositions, EnforcementError, EnforcementOutcome, ObservedDevices},
    Service,
};
use anchor_store::Store;
use anchor_system::{
    burning::{BurnDriveInfo, BurningControlExecutor},
    error::PlatformError,
    nic::{NicControlExecutor, NicInfo},
    usb::{UsbStorageDevice, UsbStorageExecutor},
    write_denial::WriteDenialSwitch,
};
use chrono::{TimeZone, Utc};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 28, 8, 0, 0).unwrap()
}

/// 每个用例独占一个数据库文件，以便在处置之后按只读方式核对审计链。
struct TestService {
    service: Service,
    database: tempfile::NamedTempFile,
}

impl TestService {
    fn with_rules(usb: UsbRules, network: NetworkRules, burning: BurningRules) -> Self {
        let database = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(database.path()).unwrap();
        let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
        let package = PolicyPackage::sign(
            PolicyPayload {
                version: 1,
                expires_at: now() + chrono::Duration::days(1),
                usb,
                network,
                burning,
                scan: ScanRules {
                    controlled_dirs: vec![],
                    file_types: vec![],
                    rules: vec![],
                },
            },
            &signing_key,
        )
        .unwrap();
        store
            .import_policy(&package, ImportDecision::Accept, "laptop-1", "test", now())
            .unwrap();
        Self {
            service: Service::new(store, verifying_key, "laptop-1"),
            database,
        }
    }

    fn without_policy() -> Self {
        let database = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(database.path()).unwrap();
        Self {
            service: Service::new(store, anchor_core::crypto::generate_keypair().1, "laptop-1"),
            database,
        }
    }

    fn events(&self) -> Vec<AuditEvent> {
        Store::open_read_only(self.database.path())
            .unwrap()
            .read_audit_events()
            .unwrap()
    }
}

fn usb_allow_everything() -> UsbRules {
    UsbRules {
        read: ActionPolicy::Allow,
        write: ActionPolicy::Allow,
        allowed: vec![],
    }
}

fn usb_denied() -> UsbRules {
    UsbRules {
        read: ActionPolicy::Deny,
        write: ActionPolicy::Deny,
        allowed: vec![],
    }
}

fn network_denied() -> NetworkRules {
    NetworkRules {
        policy: ActionPolicy::Deny,
        allowed: vec![],
    }
}

fn burning_denied() -> BurningRules {
    BurningRules {
        policy: ActionPolicy::Deny,
        allowed: vec![],
    }
}

/// 记录型系统级写入拒绝开关；USB 与刻录执行器各持有一个。
#[derive(Default)]
struct RecordingWriteDenial {
    denied: bool,
    calls: Vec<bool>,
    failures: usize,
}

impl WriteDenialSwitch for RecordingWriteDenial {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        Ok(self.denied)
    }

    fn set_write_denied(&mut self, denied: bool) -> Result<(), PlatformError> {
        self.calls.push(denied);
        if self.failures > 0 {
            self.failures -= 1;
            return Err(PlatformError::Failed(
                "simulated write denial failure".into(),
            ));
        }
        self.denied = denied;
        Ok(())
    }
}

#[derive(Default)]
struct RecordingUsbExecutor {
    calls: Vec<(String, bool)>,
    failures: Vec<String>,
    denial: RecordingWriteDenial,
}

impl RecordingUsbExecutor {
    fn failing_for(instance_id: &str) -> Self {
        Self {
            failures: vec![instance_id.into()],
            ..Self::default()
        }
    }
}

impl UsbStorageExecutor for RecordingUsbExecutor {
    fn set_mass_storage_enabled(
        &mut self,
        instance_id: &str,
        enabled: bool,
    ) -> Result<(), PlatformError> {
        self.calls.push((instance_id.into(), enabled));
        if self.failures.iter().any(|failed| failed == instance_id) {
            return Err(PlatformError::Failed("simulated control failure".into()));
        }
        Ok(())
    }
}

impl WriteDenialSwitch for RecordingUsbExecutor {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        self.denial.write_denied()
    }

    fn set_write_denied(&mut self, denied: bool) -> Result<(), PlatformError> {
        self.denial.set_write_denied(denied)
    }
}

#[derive(Default)]
struct RecordingNicExecutor {
    calls: Vec<(String, bool)>,
}

impl NicControlExecutor for RecordingNicExecutor {
    fn set_enabled(&mut self, adapter_id: &str, enabled: bool) -> Result<(), PlatformError> {
        self.calls.push((adapter_id.into(), enabled));
        Ok(())
    }
}

#[derive(Default)]
struct RecordingBurningExecutor {
    calls: Vec<(String, bool)>,
    denial: RecordingWriteDenial,
}

impl BurningControlExecutor for RecordingBurningExecutor {
    fn set_enabled(&mut self, drive_id: &str, enabled: bool) -> Result<(), PlatformError> {
        self.calls.push((drive_id.into(), enabled));
        Ok(())
    }
}

impl WriteDenialSwitch for RecordingBurningExecutor {
    fn write_denied(&mut self) -> Result<bool, PlatformError> {
        self.denial.write_denied()
    }

    fn set_write_denied(&mut self, denied: bool) -> Result<(), PlatformError> {
        self.denial.set_write_denied(denied)
    }
}

fn usb_device(instance_id: &str, enabled: bool) -> UsbStorageDevice {
    UsbStorageDevice {
        instance_id: instance_id.into(),
        enabled,
        removable: true,
        vendor_id: None,
        product_id: None,
        serial: None,
    }
}

fn nic_adapter(adapter_id: &str, enabled: bool) -> NicInfo {
    NicInfo {
        adapter_id: adapter_id.into(),
        name: adapter_id.into(),
        enabled,
    }
}

fn burn_drive(drive_id: &str, enabled: bool) -> BurnDriveInfo {
    BurnDriveInfo {
        drive_id: drive_id.into(),
        name: drive_id.into(),
        enabled,
    }
}

fn observed_usb(device: UsbStorageDevice) -> ObservedDevices {
    ObservedDevices {
        usb_storage: vec![device],
        ..ObservedDevices::default()
    }
}

fn enforce(
    service: &Service,
    observed: ObservedDevices,
) -> Result<EnforcementOutcome, EnforcementError> {
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();
    service.enforce_policy(&mut usb, &mut nic, &mut burning, observed, false, now())
}

#[test]
fn denied_authorization_is_recorded_once_across_sweeps() {
    let test = TestService::without_policy();

    let first = enforce(&test.service, ObservedDevices::default()).unwrap();
    let second = enforce(&test.service, ObservedDevices::default()).unwrap();

    assert_eq!(
        first,
        EnforcementOutcome::Denied {
            reason: AuthorizationDenial::NoActivePolicy
        }
    );
    assert_eq!(second, first);
    assert_eq!(
        test.events()
            .iter()
            .filter(|event| event.payload.action == "authorization")
            .count(),
        1
    );
}

#[test]
fn compliant_devices_are_not_touched_or_audited() {
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    for _ in 0..3 {
        let outcome = test
            .service
            .enforce_policy(
                &mut usb,
                &mut nic,
                &mut burning,
                observed_usb(usb_device(instance_id, false)),
                false,
                now(),
            )
            .unwrap();
        assert_eq!(
            outcome,
            EnforcementOutcome::Reconciled(AppliedDispositions::default())
        );
    }

    assert!(usb.calls.is_empty());
    assert_eq!(
        test.events()
            .iter()
            .filter(|event| event.payload.action == "apply_usb_control")
            .count(),
        0
    );
}

#[test]
fn unlisted_usb_storage_is_disabled_once_and_then_left_alone() {
    let test = TestService::with_rules(usb_allow_everything(), network_denied(), burning_denied());
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let first = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, true)),
            false,
            now(),
        )
        .unwrap();
    let second = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, false)),
            false,
            now(),
        )
        .unwrap();

    assert_eq!(
        first,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: instance_id.into(),
                enabled: false,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(
        second,
        EnforcementOutcome::Reconciled(AppliedDispositions::default())
    );
    assert_eq!(usb.calls, vec![(instance_id.to_string(), false)]);

    let events = test.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.payload.action == "apply_usb_control" && event.payload.result == "disabled"
            })
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.payload.action == "usb_presence" && event.payload.result == "attached"
            })
            .count(),
        1
    );
    let store = Store::open_read_only(test.database.path()).unwrap();
    let state = store.device_state("usb", instance_id).unwrap().unwrap();
    assert_eq!(state.state["enabled"], serde_json::json!(false));
}

#[test]
fn allowlisted_usb_storage_is_enabled_when_observed_disabled() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(
        UsbRules {
            read: ActionPolicy::Allow,
            write: ActionPolicy::Allow,
            allowed: vec![UsbAllowRule {
                instance_id: Some(instance_id.into()),
                vendor_id: None,
                product_id: None,
                serial: None,
            }],
        },
        network_denied(),
        burning_denied(),
    );
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let restored = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, false)),
            false,
            now(),
        )
        .unwrap();
    let stable = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, true)),
            false,
            now(),
        )
        .unwrap();

    assert_eq!(
        restored,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: instance_id.into(),
                enabled: true,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(
        stable,
        EnforcementOutcome::Reconciled(AppliedDispositions::default())
    );
    assert_eq!(usb.calls, vec![(instance_id.to_string(), true)]);
}

#[test]
fn read_only_usb_policy_keeps_even_allowlisted_mass_storage_disabled() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(
        UsbRules {
            read: ActionPolicy::Allow,
            write: ActionPolicy::Deny,
            allowed: vec![UsbAllowRule {
                instance_id: Some(instance_id.into()),
                vendor_id: None,
                product_id: None,
                serial: None,
            }],
        },
        network_denied(),
        burning_denied(),
    );

    let outcome = enforce(&test.service, observed_usb(usb_device(instance_id, true))).unwrap();

    assert_eq!(
        outcome,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: instance_id.into(),
                enabled: false,
            }],
            ..AppliedDispositions::default()
        })
    );
}

#[test]
fn non_mass_storage_devices_are_never_controlled() {
    let test = TestService::with_rules(usb_allow_everything(), network_denied(), burning_denied());

    let outcome = enforce(
        &test.service,
        observed_usb(usb_device("USB\\VID_1234&PID_5678\\1", true)),
    )
    .unwrap();

    assert_eq!(
        outcome,
        EnforcementOutcome::Reconciled(AppliedDispositions::default())
    );
    let events = test.events();
    assert!(!events
        .iter()
        .any(|event| event.payload.action.starts_with("apply_")));
    assert!(!events
        .iter()
        .any(|event| event.payload.action == "usb_presence"));
}

#[test]
fn deny_all_policy_disables_every_observed_controlled_device() {
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let usb_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let wired = "PCI\\VEN_8086&DEV_15BE&SUBSYS_00000000&REV_00\\3&11583659&0&C8";
    let wireless = "USB\\VID_0BDA&PID_8153\\000001";
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let outcome = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            ObservedDevices {
                usb_storage: vec![usb_device(usb_id, true)],
                adapters: vec![nic_adapter(wired, true), nic_adapter(wireless, true)],
                burn_drives: vec![burn_drive(drive_id, true)],
            },
            false,
            now(),
        )
        .unwrap();

    assert_eq!(
        outcome,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: usb_id.into(),
                enabled: false,
            }],
            adapters: vec![
                anchor_service::enforce::NicDisposition {
                    adapter_id: wired.into(),
                    enabled: false,
                },
                anchor_service::enforce::NicDisposition {
                    adapter_id: wireless.into(),
                    enabled: false,
                },
            ],
            burn_drives: vec![anchor_service::enforce::BurningDisposition {
                drive_id: drive_id.into(),
                enabled: false,
            }],
        })
    );
    assert_eq!(
        nic.calls,
        vec![(wired.to_string(), false), (wireless.to_string(), false)]
    );
    assert_eq!(usb.calls, vec![(usb_id.to_string(), false)]);
    assert_eq!(burning.calls, vec![(drive_id.to_string(), false)]);
}

#[test]
fn usb_removal_is_audited_once_for_a_previously_enabled_device() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(
        UsbRules {
            read: ActionPolicy::Allow,
            write: ActionPolicy::Allow,
            allowed: vec![UsbAllowRule {
                instance_id: Some(instance_id.into()),
                vendor_id: None,
                product_id: None,
                serial: None,
            }],
        },
        network_denied(),
        burning_denied(),
    );

    enforce(&test.service, observed_usb(usb_device(instance_id, true))).unwrap();
    enforce(&test.service, ObservedDevices::default()).unwrap();
    enforce(&test.service, ObservedDevices::default()).unwrap();

    let events = test.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.payload.action == "usb_presence" && event.payload.result == "removed"
            })
            .count(),
        1
    );
    let store = Store::open_read_only(test.database.path()).unwrap();
    assert!(store.device_state("usb", instance_id).unwrap().is_none());
}

#[test]
fn disabled_device_leaving_the_inventory_is_not_reported_as_a_removal() {
    let test = TestService::with_rules(usb_allow_everything(), network_denied(), burning_denied());
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";

    enforce(&test.service, observed_usb(usb_device(instance_id, true))).unwrap();
    enforce(&test.service, ObservedDevices::default()).unwrap();

    let events = test.events();
    assert!(!events
        .iter()
        .any(|event| event.payload.action == "usb_presence" && event.payload.result == "removed"));
    let store = Store::open_read_only(test.database.path()).unwrap();
    assert!(store.device_state("usb", instance_id).unwrap().is_none());
}

#[test]
fn network_state_drift_is_corrected_and_compliant_adapters_are_left_alone() {
    let test = TestService::with_rules(
        usb_denied(),
        NetworkRules {
            policy: ActionPolicy::Allow,
            allowed: vec![NetworkAllowRule {
                adapter_id: "nic-allowed".into(),
            }],
        },
        burning_denied(),
    );
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let first = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            ObservedDevices {
                adapters: vec![
                    nic_adapter("nic-allowed", true),
                    nic_adapter("nic-other", true),
                ],
                ..ObservedDevices::default()
            },
            false,
            now(),
        )
        .unwrap();
    let second = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            ObservedDevices {
                adapters: vec![
                    nic_adapter("nic-allowed", true),
                    nic_adapter("nic-other", false),
                ],
                ..ObservedDevices::default()
            },
            false,
            now(),
        )
        .unwrap();

    assert_eq!(
        first,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            adapters: vec![anchor_service::enforce::NicDisposition {
                adapter_id: "nic-other".into(),
                enabled: false,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(
        second,
        EnforcementOutcome::Reconciled(AppliedDispositions::default())
    );
    assert_eq!(nic.calls, vec![("nic-other".to_string(), false)]);
}

#[test]
fn burning_drive_state_drift_is_corrected() {
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";

    let outcome = enforce(
        &test.service,
        ObservedDevices {
            burn_drives: vec![burn_drive(drive_id, true)],
            ..ObservedDevices::default()
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            burn_drives: vec![anchor_service::enforce::BurningDisposition {
                drive_id: drive_id.into(),
                enabled: false,
            }],
            ..AppliedDispositions::default()
        })
    );
}

#[test]
fn device_control_failure_is_audited_once_and_keeps_the_service_denied() {
    let test = TestService::with_rules(usb_allow_everything(), network_denied(), burning_denied());
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let mut usb = RecordingUsbExecutor::failing_for(instance_id);
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    for _ in 0..2 {
        let error = test
            .service
            .enforce_policy(
                &mut usb,
                &mut nic,
                &mut burning,
                observed_usb(usb_device(instance_id, true)),
                false,
                now(),
            )
            .unwrap_err();
        assert!(matches!(error, EnforcementError::DeviceControl(_)));
    }

    assert_eq!(usb.calls.len(), 2);
    assert_eq!(
        test.events()
            .iter()
            .filter(|event| {
                event.payload.action == "apply_usb_control" && event.payload.result == "failed"
            })
            .count(),
        1
    );
    assert_eq!(
        test.service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
}

#[test]
fn successful_reconciliation_clears_a_previous_runtime_failure() {
    let store = Store::in_memory().unwrap();
    let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
    let package = PolicyPackage::sign(
        PolicyPayload {
            version: 1,
            expires_at: now() + chrono::Duration::days(1),
            usb: usb_allow_everything(),
            network: network_denied(),
            burning: burning_denied(),
            scan: ScanRules {
                controlled_dirs: vec![],
                file_types: vec![],
                rules: vec![],
            },
        },
        &signing_key,
    )
    .unwrap();
    store
        .import_policy(&package, ImportDecision::Accept, "laptop-1", "test", now())
        .unwrap();
    store
        .set_enforcement_failure("device_control_failed", now())
        .unwrap();
    let service = Service::new(store, verifying_key, "laptop-1");
    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );

    enforce(&service, ObservedDevices::default()).unwrap();

    assert_eq!(
        service.authorization_state(now()),
        AuthorizationState::Allowed
    );
}

#[test]
fn state_persistence_failure_keeps_the_service_denied() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(database.path()).unwrap();
    let (signing_key, verifying_key) = anchor_core::crypto::generate_keypair();
    let package = PolicyPackage::sign(
        PolicyPayload {
            version: 1,
            expires_at: now() + chrono::Duration::days(1),
            usb: usb_allow_everything(),
            network: network_denied(),
            burning: burning_denied(),
            scan: ScanRules {
                controlled_dirs: vec![],
                file_types: vec![],
                rules: vec![],
            },
        },
        &signing_key,
    )
    .unwrap();
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
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";

    let error = enforce(&service, observed_usb(usb_device(instance_id, true))).unwrap_err();

    assert!(matches!(error, EnforcementError::StatePersistence(_)));
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
    let package = PolicyPackage::sign(
        PolicyPayload {
            version: 1,
            expires_at: now() + chrono::Duration::days(1),
            usb: usb_allow_everything(),
            network: network_denied(),
            burning: burning_denied(),
            scan: ScanRules {
                controlled_dirs: vec![],
                file_types: vec![],
                rules: vec![],
            },
        },
        &signing_key,
    )
    .unwrap();
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
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let mut usb = RecordingUsbExecutor::failing_for(instance_id);
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let error = service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, true)),
            false,
            now(),
        )
        .unwrap_err();

    assert!(matches!(error, EnforcementError::StatePersistence(_)));
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
    assert!(!events
        .iter()
        .any(|event| { event.payload.event_type == EventType::AuthorizationDenied }));
}

/// 固定类型卷的 USB 存储：无法通过重新挂载变成只读。
fn fixed_usb_device(instance_id: &str, enabled: bool) -> UsbStorageDevice {
    UsbStorageDevice {
        removable: false,
        ..usb_device(instance_id, enabled)
    }
}

/// 统计指定动作与结果的审计事件数。
fn audited_events(test: &TestService, action: &str, result: &str) -> usize {
    test.events()
        .iter()
        .filter(|event| event.payload.action == action && event.payload.result == result)
        .count()
}

#[test]
fn logon_ui_opens_a_read_only_channel_for_unlisted_removable_storage() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let first = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, false)),
            true,
            now(),
        )
        .unwrap();
    let second = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, true)),
            true,
            now(),
        )
        .unwrap();

    assert_eq!(
        first,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: instance_id.into(),
                enabled: true,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(
        second,
        EnforcementOutcome::Reconciled(AppliedDispositions::default())
    );
    assert_eq!(usb.denial.calls, vec![true]);
    assert_eq!(usb.calls, vec![(instance_id.to_string(), true)]);
    assert_eq!(
        audited_events(&test, "apply_usb_write_protection", "enabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_usb_control", "enabled_read_only"),
        1
    );
}

#[test]
fn logon_ui_remounts_removable_storage_that_is_already_enabled() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(
        UsbRules {
            read: ActionPolicy::Allow,
            write: ActionPolicy::Allow,
            allowed: vec![UsbAllowRule {
                instance_id: Some(instance_id.into()),
                vendor_id: None,
                product_id: None,
                serial: None,
            }],
        },
        network_denied(),
        burning_denied(),
    );
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let outcome = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, true)),
            true,
            now(),
        )
        .unwrap();

    // 写保护只对开启之后挂载的介质生效，因此已启用的设备要先卸载再挂载一次。
    assert_eq!(
        usb.calls,
        vec![
            (instance_id.to_string(), false),
            (instance_id.to_string(), true)
        ]
    );
    assert_eq!(usb.denial.calls, vec![true]);
    assert_eq!(
        outcome,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: instance_id.into(),
                enabled: true,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(
        audited_events(&test, "apply_usb_control", "enabled_read_only"),
        1
    );
}

#[test]
fn logon_ui_keeps_fixed_usb_storage_disabled() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(usb_allow_everything(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let outcome = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(fixed_usb_device(instance_id, true)),
            true,
            now(),
        )
        .unwrap();

    assert_eq!(
        outcome,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            usb: vec![anchor_service::enforce::UsbDisposition {
                instance_id: instance_id.into(),
                enabled: false,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(usb.calls, vec![(instance_id.to_string(), false)]);
    assert_eq!(audited_events(&test, "apply_usb_control", "disabled"), 1);
    assert_eq!(
        audited_events(&test, "apply_usb_control", "enabled_read_only"),
        0
    );
}

#[test]
fn missing_write_protection_keeps_the_logon_channel_closed() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor {
        denial: RecordingWriteDenial {
            failures: 1,
            ..RecordingWriteDenial::default()
        },
        ..RecordingUsbExecutor::default()
    };
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let error = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, false)),
            true,
            now(),
        )
        .unwrap_err();

    assert!(matches!(error, EnforcementError::DeviceControl(_)));
    // 写保护没落地时设备保持禁用，登录界面拿不到写通道。
    assert!(usb.calls.is_empty());
    assert_eq!(
        audited_events(&test, "apply_usb_write_protection", "failed"),
        1
    );
    assert_eq!(
        test.service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );

    // 下一轮写保护落地成功后，只读通道重新放行。
    test.service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, false)),
            true,
            now(),
        )
        .unwrap();
    assert_eq!(usb.calls, vec![(instance_id.to_string(), true)]);
    assert_eq!(
        audited_events(&test, "apply_usb_control", "enabled_read_only"),
        1
    );
}

#[test]
fn unlocked_sweep_turns_removable_write_protection_off() {
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor {
        denial: RecordingWriteDenial {
            denied: true,
            ..RecordingWriteDenial::default()
        },
        ..RecordingUsbExecutor::default()
    };
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    test.service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(usb_device(instance_id, false)),
            false,
            now(),
        )
        .unwrap();

    assert_eq!(usb.denial.calls, vec![false]);
    assert!(!usb.denial.denied);
    assert_eq!(
        audited_events(&test, "apply_usb_write_protection", "disabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_usb_control", "enabled_read_only"),
        0
    );
}

fn observed_burn_drive(drive_id: &str, enabled: bool) -> ObservedDevices {
    ObservedDevices {
        burn_drives: vec![burn_drive(drive_id, enabled)],
        ..ObservedDevices::default()
    }
}

#[test]
fn logon_ui_opens_optical_drives_as_a_read_only_channel() {
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let first = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_burn_drive(drive_id, false),
            true,
            now(),
        )
        .unwrap();
    let second = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_burn_drive(drive_id, true),
            true,
            now(),
        )
        .unwrap();

    assert_eq!(
        first,
        EnforcementOutcome::Reconciled(AppliedDispositions {
            burn_drives: vec![anchor_service::enforce::BurningDisposition {
                drive_id: drive_id.into(),
                enabled: true,
            }],
            ..AppliedDispositions::default()
        })
    );
    assert_eq!(
        second,
        EnforcementOutcome::Reconciled(AppliedDispositions::default())
    );
    assert_eq!(burning.denial.calls, vec![true]);
    assert_eq!(burning.calls, vec![(drive_id.to_string(), true)]);
    assert_eq!(
        audited_events(&test, "apply_burning_write_denial", "enabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_burning_control", "enabled_read_only"),
        1
    );
}

#[test]
fn missing_cd_write_denial_keeps_optical_drives_disabled() {
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor {
        denial: RecordingWriteDenial {
            failures: 1,
            ..RecordingWriteDenial::default()
        },
        ..RecordingBurningExecutor::default()
    };

    let error = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_burn_drive(drive_id, true),
            true,
            now(),
        )
        .unwrap_err();

    assert!(matches!(error, EnforcementError::DeviceControl(_)));
    // 写入拒绝没落地时光驱不被放行，已是启用状态的要收回到禁用。
    assert_eq!(burning.calls, vec![(drive_id.to_string(), false)]);
    assert_eq!(
        audited_events(&test, "apply_burning_write_denial", "failed"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_burning_control", "enabled_read_only"),
        0
    );
    assert_eq!(
        test.service.authorization_state(now()),
        AuthorizationState::Denied(AuthorizationDenial::EnforcementUnhealthy)
    );
}

#[test]
fn unlocked_sweep_clears_the_cd_write_denial_and_applies_the_policy() {
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";
    let test = TestService::with_rules(usb_denied(), network_denied(), burning_denied());
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor {
        denial: RecordingWriteDenial {
            denied: true,
            ..RecordingWriteDenial::default()
        },
        ..RecordingBurningExecutor::default()
    };

    test.service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_burn_drive(drive_id, true),
            false,
            now(),
        )
        .unwrap();

    assert_eq!(burning.denial.calls, vec![false]);
    assert!(!burning.denial.denied);
    assert_eq!(burning.calls, vec![(drive_id.to_string(), false)]);
    assert_eq!(
        audited_events(&test, "apply_burning_write_denial", "disabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_burning_control", "disabled"),
        1
    );
}

#[test]
fn denied_authorization_still_opens_the_logon_read_only_channel() {
    let test = TestService::without_policy();
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let outcome = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            ObservedDevices {
                usb_storage: vec![usb_device(instance_id, false)],
                burn_drives: vec![burn_drive(drive_id, false)],
                ..ObservedDevices::default()
            },
            true,
            now(),
        )
        .unwrap();

    // 没有活动策略时登录界面仍要能读到介质上的策略文件。
    assert_eq!(
        outcome,
        EnforcementOutcome::Denied {
            reason: AuthorizationDenial::NoActivePolicy
        }
    );
    assert_eq!(usb.calls, vec![(instance_id.to_string(), true)]);
    assert_eq!(burning.calls, vec![(drive_id.to_string(), true)]);
    assert_eq!(usb.denial.calls, vec![true]);
    assert_eq!(burning.denial.calls, vec![true]);
    assert_eq!(
        audited_events(&test, "apply_usb_write_protection", "enabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_burning_write_denial", "enabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_usb_control", "enabled_read_only"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_burning_control", "enabled_read_only"),
        1
    );
    assert_eq!(
        audited_events(&test, "authorization", "no_active_policy"),
        1
    );
}

#[test]
fn denied_authorization_closes_the_logon_channel_when_unlocked() {
    let test = TestService::without_policy();
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let drive_id = "SCSI\\CDROM&VEN_VENDOR&PROD_WRITER\\1";
    let mut usb = RecordingUsbExecutor {
        denial: RecordingWriteDenial {
            denied: true,
            ..RecordingWriteDenial::default()
        },
        ..RecordingUsbExecutor::default()
    };
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor {
        denial: RecordingWriteDenial {
            denied: true,
            ..RecordingWriteDenial::default()
        },
        ..RecordingBurningExecutor::default()
    };

    let outcome = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            ObservedDevices {
                usb_storage: vec![usb_device(instance_id, true)],
                burn_drives: vec![burn_drive(drive_id, true)],
                ..ObservedDevices::default()
            },
            false,
            now(),
        )
        .unwrap();

    assert_eq!(
        outcome,
        EnforcementOutcome::Denied {
            reason: AuthorizationDenial::NoActivePolicy
        }
    );
    // 解锁后写入拒绝关闭，且不处置设备。
    assert_eq!(usb.denial.calls, vec![false]);
    assert_eq!(burning.denial.calls, vec![false]);
    assert!(usb.calls.is_empty());
    assert!(burning.calls.is_empty());
    assert_eq!(
        audited_events(&test, "apply_usb_write_protection", "disabled"),
        1
    );
    assert_eq!(
        audited_events(&test, "apply_burning_write_denial", "disabled"),
        1
    );
}

#[test]
fn logon_channel_leaves_fixed_usb_storage_alone_without_a_policy() {
    let test = TestService::without_policy();
    let instance_id = "USBSTOR\\Disk&Ven_Example&Prod_Storage\\1";
    let mut usb = RecordingUsbExecutor::default();
    let mut nic = RecordingNicExecutor::default();
    let mut burning = RecordingBurningExecutor::default();

    let outcome = test
        .service
        .enforce_policy(
            &mut usb,
            &mut nic,
            &mut burning,
            observed_usb(fixed_usb_device(instance_id, true)),
            true,
            now(),
        )
        .unwrap();

    // 固定类型卷无法变成只读，没有策略依据时也不据此禁用。
    assert_eq!(
        outcome,
        EnforcementOutcome::Denied {
            reason: AuthorizationDenial::NoActivePolicy
        }
    );
    assert!(usb.calls.is_empty());
    assert_eq!(audited_events(&test, "apply_usb_control", "disabled"), 0);
}
