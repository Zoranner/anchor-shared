//! 活动策略的授权结论与设备差异处置编排。
//!
//! 本模块只接收已观测的设备并下发与策略不一致的处置：观测状态已经符合策略的设备不会
//! 被重复处置，也不会重复写审计。真实 Windows 枚举和设备控制属于 `anchor-system`。

use anchor_core::{
    ActionPolicy, AuditPayload, AuthorizationDenial, AuthorizationState, BurningRules, EventType,
    NetworkRules, UsbRules,
};
use anchor_store::StoreError;
use anchor_system::{
    burning::{BurnDriveInfo, BurningControlExecutor},
    error::PlatformError,
    inventory::DeviceInventory,
    nic::{NicControlExecutor, NicInfo},
    usb::{
        plan_usb_storage_control, UsbAllowRule, UsbPlannedAction, UsbStorageDevice,
        UsbStorageExecutor,
    },
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use thiserror::Error;

use crate::Service;

/// 设备状态类别：USB 大容量存储。
const USB_STATE_KIND: &str = "usb";
/// 设备状态类别：网卡。
const NIC_STATE_KIND: &str = "nic";
/// 设备状态类别：刻录光驱。
const BURNING_STATE_KIND: &str = "burning";
/// 设备库存观测失败的运行期原因。
const INVENTORY_FAILURE_REASON: &str = "inventory_observation_failed";

/// 服务本轮已观测到的受控设备。调用方负责观测，本模块不枚举设备。
#[derive(Debug, Default)]
pub struct ObservedDevices {
    pub usb_storage: Vec<UsbStorageDevice>,
    pub adapters: Vec<NicInfo>,
    pub burn_drives: Vec<BurnDriveInfo>,
}

impl From<DeviceInventory> for ObservedDevices {
    fn from(inventory: DeviceInventory) -> Self {
        Self {
            usb_storage: inventory.usb_storage,
            adapters: inventory.network_adapters,
            burn_drives: inventory.burn_drives,
        }
    }
}

/// 已按策略差异下发的 USB 大容量存储处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDisposition {
    pub instance_id: String,
    pub enabled: bool,
}

/// 已按策略差异下发的网卡处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicDisposition {
    pub adapter_id: String,
    pub enabled: bool,
}

/// 已按策略差异下发的刻录光驱处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurningDisposition {
    pub drive_id: String,
    pub enabled: bool,
}

/// 本轮实际下发的设备处置；观测状态已符合策略的设备不会出现。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AppliedDispositions {
    pub usb: Vec<UsbDisposition>,
    pub adapters: Vec<NicDisposition>,
    pub burn_drives: Vec<BurningDisposition>,
}

/// 策略编排的可观察结论。
#[derive(Debug, PartialEq, Eq)]
pub enum EnforcementOutcome {
    Denied { reason: AuthorizationDenial },
    Reconciled(AppliedDispositions),
}

/// 编排时的存储或设备控制失败。
#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("本地状态或审计写入失败: {0}")]
    Store(#[from] StoreError),
    #[error("设备控制执行失败: {0}")]
    DeviceControl(PlatformError),
    #[error("设备处置后的审计或状态持久化失败: {0}")]
    StatePersistence(StoreError),
}

/// 单台设备处置失败的原因；失败不中断其余设备的处置。
enum ExecutionFailure {
    DeviceControl(PlatformError),
    StatePersistence(StoreError),
}

impl ExecutionFailure {
    fn into_error(self) -> EnforcementError {
        match self {
            Self::DeviceControl(error) => EnforcementError::DeviceControl(error),
            Self::StatePersistence(error) => EnforcementError::StatePersistence(error),
        }
    }
}

fn remember_failure(slot: &mut Option<ExecutionFailure>, failure: ExecutionFailure) {
    if slot.is_none() {
        *slot = Some(failure);
    }
}

fn authorization_denial_reason(reason: AuthorizationDenial) -> &'static str {
    match reason {
        AuthorizationDenial::NoActivePolicy => "no_active_policy",
        AuthorizationDenial::Expired => "expired",
        AuthorizationDenial::ClockRollback => "clock_rollback",
        AuthorizationDenial::AuditUnhealthy => "audit_unhealthy",
        AuthorizationDenial::TrustedTimeUnavailable => "trusted_time_unavailable",
        AuthorizationDenial::EnforcementUnhealthy => "enforcement_unhealthy",
    }
}

fn execution_failure_reason(failure: &ExecutionFailure) -> &'static str {
    match failure {
        ExecutionFailure::DeviceControl(_) => "device_control_failed",
        ExecutionFailure::StatePersistence(_) => "state_persistence_failed",
    }
}

impl Service {
    /// 记录库存观测失败并进入运行期 fail-closed 状态；同一原因只记录一次。
    pub fn record_inventory_failure(
        &self,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if self.store.enforcement_failure()?.as_deref() == Some(INVENTORY_FAILURE_REASON) {
            return Ok(());
        }
        let mut event = self.audit_payload(
            EventType::InventoryObservationFailed,
            "observe_inventory",
            "failed",
            None,
            now,
        );
        event.resource = Some(reason.into());
        self.store
            .append_audit_and_set_enforcement_failure(event, INVENTORY_FAILURE_REASON, now)
    }

    /// 按当前授权结论和活动策略处置已观测设备。
    ///
    /// 授权拒绝时只记录一次拒绝结论；锁定交互会话由该会话内的协作程序负责，服务运行在
    /// Session 0，不调用锁屏 API。授权允许时，只对观测状态与策略期望不一致的设备下发
    /// 处置，并只为这些设备写入审计事件。
    pub fn enforce_policy<U, N, B>(
        &self,
        usb_executor: &mut U,
        nic_executor: &mut N,
        burning_executor: &mut B,
        observed: ObservedDevices,
        now: DateTime<Utc>,
    ) -> Result<EnforcementOutcome, EnforcementError>
    where
        U: UsbStorageExecutor,
        N: NicControlExecutor,
        B: BurningControlExecutor,
    {
        if let AuthorizationState::Denied(reason) = self.authorization_state_for_enforcement(now) {
            self.record_denial_once(reason, now)?;
            return Ok(EnforcementOutcome::Denied { reason });
        }
        self.clear_denial_once()?;

        let active_policy = self
            .store
            .active_policy()?
            .expect("allowed authorization requires an active policy");
        let policy = &active_policy.payload;
        let policy_version = policy.version;

        let mut applied = AppliedDispositions::default();
        let mut failure = None;

        let (usb, usb_failure) = self.reconcile_usb_storage(
            usb_executor,
            &policy.usb,
            &observed.usb_storage,
            policy_version,
            now,
        )?;
        applied.usb = usb;
        failure = failure.or(usb_failure);

        let (adapters, nic_failure) = self.reconcile_network(
            nic_executor,
            &policy.network,
            &observed.adapters,
            policy_version,
            now,
        )?;
        applied.adapters = adapters;
        failure = failure.or(nic_failure);

        let (burn_drives, burning_failure) = self.reconcile_burning(
            burning_executor,
            &policy.burning,
            &observed.burn_drives,
            policy_version,
            now,
        )?;
        applied.burn_drives = burn_drives;
        failure = failure.or(burning_failure);

        match failure {
            Some(failure) => Err(failure.into_error()),
            None => {
                self.store.clear_enforcement_failure()?;
                Ok(EnforcementOutcome::Reconciled(applied))
            }
        }
    }

    /// 记录授权拒绝；相同原因连续出现时只保留一次审计。
    fn record_denial_once(
        &self,
        reason: AuthorizationDenial,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let reason = authorization_denial_reason(reason);
        if self.store.authorization_denial()?.as_deref() == Some(reason) {
            return Ok(());
        }
        let event = self.audit_payload(
            EventType::AuthorizationDenied,
            "authorization",
            reason,
            None,
            now,
        );
        self.store
            .append_audit_and_set_authorization_denial(event, reason, now)
    }

    /// 授权恢复后清除已记录的拒绝原因，使下一次拒绝重新进入审计。
    fn clear_denial_once(&self) -> Result<(), StoreError> {
        if self.store.authorization_denial()?.is_some() {
            self.store.clear_authorization_denial()?;
        }
        Ok(())
    }

    fn reconcile_usb_storage<U>(
        &self,
        executor: &mut U,
        rules: &UsbRules,
        observed: &[UsbStorageDevice],
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(Vec<UsbDisposition>, Option<ExecutionFailure>), StoreError>
    where
        U: UsbStorageExecutor,
    {
        let allowlist = usb_allowlist(rules);
        let recorded = self.store.device_states(USB_STATE_KIND)?;
        let mut applied = Vec::new();
        let mut failure = None;
        let mut present = Vec::new();

        for device in observed {
            let plan = plan_usb_storage_control(device.clone(), &allowlist);
            if plan.planned_action == UsbPlannedAction::RejectNonMassStorage {
                continue;
            }
            let instance_id = plan.device.instance_id.clone();
            present.push(instance_id.clone());
            let desired_enabled = plan.planned_action == UsbPlannedAction::EnableMassStorage;

            if !recorded
                .iter()
                .any(|record| record.device_id == instance_id)
            {
                let event =
                    self.audit_payload(EventType::UsbAttach, "usb_presence", "attached", None, now);
                let state = usb_state(device, device.enabled);
                if let Err(error) = self.store.append_audit_and_upsert_device_state(
                    event,
                    USB_STATE_KIND,
                    &instance_id,
                    &state,
                    now,
                ) {
                    let recorded_failure = self.note_execution_failure(
                        ExecutionFailure::StatePersistence(error),
                        EventType::UsbAttach,
                        "persist_usb_control",
                        &instance_id,
                        policy_version,
                        now,
                    );
                    remember_failure(&mut failure, recorded_failure);
                }
            }

            if device.enabled == desired_enabled {
                continue;
            }

            if let Err(error) = executor.set_mass_storage_enabled(&instance_id, desired_enabled) {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::DeviceControl(error),
                    EventType::UsbAttach,
                    "apply_usb_control",
                    &instance_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
                continue;
            }

            let result = if desired_enabled {
                "enabled"
            } else {
                "disabled"
            };
            let event = self.audit_payload(
                EventType::UsbAttach,
                "apply_usb_control",
                result,
                Some((&instance_id, policy_version)),
                now,
            );
            let state = usb_state(device, desired_enabled);
            applied.push(UsbDisposition {
                instance_id: instance_id.clone(),
                enabled: desired_enabled,
            });
            if let Err(error) = self.store.append_audit_and_upsert_device_state(
                event,
                USB_STATE_KIND,
                &instance_id,
                &state,
                now,
            ) {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::StatePersistence(error),
                    EventType::UsbAttach,
                    "persist_usb_control",
                    &instance_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
            }
        }

        for record in &recorded {
            if present
                .iter()
                .any(|device_id| device_id == &record.device_id)
            {
                continue;
            }
            if record.state.get("enabled").and_then(Value::as_bool) == Some(true) {
                let event =
                    self.audit_payload(EventType::UsbRemove, "usb_presence", "removed", None, now);
                if let Err(error) = self.store.append_audit(event) {
                    let recorded_failure = self.note_execution_failure(
                        ExecutionFailure::StatePersistence(error),
                        EventType::UsbRemove,
                        "persist_usb_control",
                        &record.device_id,
                        policy_version,
                        now,
                    );
                    remember_failure(&mut failure, recorded_failure);
                }
            }
            if let Err(error) = self
                .store
                .delete_device_state(USB_STATE_KIND, &record.device_id)
            {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::StatePersistence(error),
                    EventType::UsbRemove,
                    "persist_usb_control",
                    &record.device_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
            }
        }

        Ok((applied, failure))
    }

    fn reconcile_network<N>(
        &self,
        executor: &mut N,
        rules: &NetworkRules,
        observed: &[NicInfo],
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(Vec<NicDisposition>, Option<ExecutionFailure>), StoreError>
    where
        N: NicControlExecutor,
    {
        let mut applied = Vec::new();
        let mut failure = None;

        for adapter in observed {
            let desired_enabled = rules.policy == ActionPolicy::Allow
                && rules
                    .allowed
                    .iter()
                    .any(|rule| rule.adapter_id == adapter.adapter_id);
            if adapter.enabled == desired_enabled {
                continue;
            }

            if let Err(error) = executor.set_enabled(&adapter.adapter_id, desired_enabled) {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::DeviceControl(error),
                    EventType::NicChange,
                    "apply_nic_control",
                    &adapter.adapter_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
                continue;
            }

            let result = if desired_enabled {
                "enabled"
            } else {
                "disabled"
            };
            let event = self.audit_payload(
                EventType::NicChange,
                "apply_nic_control",
                result,
                Some((&adapter.adapter_id, policy_version)),
                now,
            );
            applied.push(NicDisposition {
                adapter_id: adapter.adapter_id.clone(),
                enabled: desired_enabled,
            });
            if let Err(error) = self.store.append_audit_and_upsert_device_state(
                event,
                NIC_STATE_KIND,
                &adapter.adapter_id,
                &json!({ "planned_enabled": desired_enabled }),
                now,
            ) {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::StatePersistence(error),
                    EventType::NicChange,
                    "persist_nic_control",
                    &adapter.adapter_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
            }
        }

        Ok((applied, failure))
    }

    fn reconcile_burning<B>(
        &self,
        executor: &mut B,
        rules: &BurningRules,
        observed: &[BurnDriveInfo],
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(Vec<BurningDisposition>, Option<ExecutionFailure>), StoreError>
    where
        B: BurningControlExecutor,
    {
        let mut applied = Vec::new();
        let mut failure = None;

        for drive in observed {
            let desired_enabled = rules.policy == ActionPolicy::Allow
                && rules
                    .allowed
                    .iter()
                    .any(|rule| rule.drive_id == drive.drive_id);
            if drive.enabled == desired_enabled {
                continue;
            }

            if let Err(error) = executor.set_enabled(&drive.drive_id, desired_enabled) {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::DeviceControl(error),
                    EventType::BurnTask,
                    "apply_burning_control",
                    &drive.drive_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
                continue;
            }

            let result = if desired_enabled {
                "enabled"
            } else {
                "disabled"
            };
            let event = self.audit_payload(
                EventType::BurnTask,
                "apply_burning_control",
                result,
                Some((&drive.drive_id, policy_version)),
                now,
            );
            applied.push(BurningDisposition {
                drive_id: drive.drive_id.clone(),
                enabled: desired_enabled,
            });
            if let Err(error) = self.store.append_audit_and_upsert_device_state(
                event,
                BURNING_STATE_KIND,
                &drive.drive_id,
                &json!({ "planned_enabled": desired_enabled }),
                now,
            ) {
                let recorded_failure = self.note_execution_failure(
                    ExecutionFailure::StatePersistence(error),
                    EventType::BurnTask,
                    "persist_burning_control",
                    &drive.drive_id,
                    policy_version,
                    now,
                );
                remember_failure(&mut failure, recorded_failure);
            }
        }

        Ok((applied, failure))
    }

    /// 记录处置失败并进入 fail-closed 状态；同一原因连续失败时不再重复写审计。
    fn note_execution_failure(
        &self,
        failure: ExecutionFailure,
        event_type: EventType,
        action: &str,
        resource: &str,
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> ExecutionFailure {
        let reason = execution_failure_reason(&failure);
        if self.store.enforcement_failure().ok().flatten().as_deref() == Some(reason) {
            return failure;
        }
        let event = self.audit_payload(
            event_type,
            action,
            "failed",
            Some((resource, policy_version)),
            now,
        );
        match self
            .store
            .append_audit_and_set_enforcement_failure(event, reason, now)
        {
            Ok(()) => failure,
            Err(error) => ExecutionFailure::StatePersistence(error),
        }
    }

    fn audit_payload(
        &self,
        event_type: EventType,
        action: &str,
        result: &str,
        resource_and_policy: Option<(&str, u64)>,
        now: DateTime<Utc>,
    ) -> AuditPayload {
        let mut event =
            AuditPayload::new(&self.device_id, "AnchorGuard", event_type, action, result);
        event.timestamp = now;
        if let Some((resource, policy_version)) = resource_and_policy {
            event.resource = Some(resource.into());
            event.policy_version = Some(policy_version);
        }
        event
    }
}

/// USB 设备状态记录：最近一次观测到的启用状态与可用于归还审计的硬件摘要。
fn usb_state(device: &UsbStorageDevice, enabled: bool) -> Value {
    json!({
        "enabled": enabled,
        "vendor_id": device.vendor_id,
        "product_id": device.product_id,
        "serial": device.serial,
    })
}

/// 只有读写都被明确允许时，允许清单才参与匹配。
fn usb_allowlist(rules: &UsbRules) -> Vec<UsbAllowRule> {
    if rules.read != ActionPolicy::Allow || rules.write != ActionPolicy::Allow {
        return Vec::new();
    }
    rules
        .allowed
        .iter()
        .map(|rule| UsbAllowRule {
            instance_id: rule.instance_id.clone(),
            vendor_id: rule.vendor_id.clone(),
            product_id: rule.product_id.clone(),
            serial: rule.serial.clone(),
        })
        .collect()
}
