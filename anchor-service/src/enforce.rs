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
    write_denial::WriteDenialSwitch,
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
/// 审计资源：系统级可移动介质写保护开关。
const REMOVABLE_MEDIA_RESOURCE: &str = "removable-media";
/// 审计资源：系统级 CD/DVD 写入拒绝开关。
const OPTICAL_MEDIA_RESOURCE: &str = "optical-media";

/// 一次写入拒绝开关落地对应的审计标识。
#[derive(Debug, Clone, Copy)]
struct WriteDenialAudit {
    event_type: EventType,
    action: &'static str,
    resource: &'static str,
}

/// 可移动介质写保护开关的审计标识。
const REMOVABLE_WRITE_DENIAL: WriteDenialAudit = WriteDenialAudit {
    event_type: EventType::UsbAttach,
    action: "apply_usb_write_protection",
    resource: REMOVABLE_MEDIA_RESOURCE,
};

/// CD/DVD 写入拒绝开关的审计标识。
const OPTICAL_WRITE_DENIAL: WriteDenialAudit = WriteDenialAudit {
    event_type: EventType::BurnTask,
    action: "apply_burning_write_denial",
    resource: OPTICAL_MEDIA_RESOURCE,
};

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

/// 本轮系统级写入拒绝开关的落地结论。
struct WriteDenialState {
    /// 开关已与登录界面状态一致；假表示开关没能落地，只读通道不得放行设备。
    ready: bool,
    /// 本轮刚开启写入拒绝：靠挂载时读取该开关才生效的介质要重新挂载一次。
    just_enabled: bool,
    /// 开关落地失败时的执行失败，由调用方与其他设备失败一起上报。
    failure: Option<ExecutionFailure>,
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
    ///
    /// `logon_ui_active` 为真表示当前显示登录界面：可移动介质与光驱按只读通道放行，供登录
    /// 界面读取介质上的策略文件，放行前必须先确认系统级写入拒绝生效。只读通道不来自策略，
    /// 因此授权拒绝时也维护它；授权拒绝时只跳过按策略下发的网卡处置。
    pub fn enforce_policy<U, N, B>(
        &self,
        usb_executor: &mut U,
        nic_executor: &mut N,
        burning_executor: &mut B,
        observed: ObservedDevices,
        logon_ui_active: bool,
        now: DateTime<Utc>,
    ) -> Result<EnforcementOutcome, EnforcementError>
    where
        U: UsbStorageExecutor + WriteDenialSwitch,
        N: NicControlExecutor,
        B: BurningControlExecutor + WriteDenialSwitch,
    {
        let denial = match self.authorization_state_for_enforcement(now) {
            AuthorizationState::Allowed => {
                self.clear_denial_once()?;
                None
            }
            AuthorizationState::Denied(reason) => {
                self.record_denial_once(reason, now)?;
                Some(reason)
            }
        };
        let policy = self.store.active_policy()?;
        let policy_version = policy.as_ref().map(|package| package.payload.version);
        // 策略结论只在授权允许时下发；授权拒绝时设备处置无从依据，只保留登录界面的只读通道。
        let policy_backed = denial.is_none();

        let mut applied = AppliedDispositions::default();
        let mut failure = None;

        let (usb, usb_failure) = self.reconcile_usb_storage(
            usb_executor,
            policy
                .as_ref()
                .filter(|_| policy_backed)
                .map(|package| &package.payload.usb),
            &observed.usb_storage,
            logon_ui_active,
            policy_version,
            now,
        )?;
        applied.usb = usb;
        failure = failure.or(usb_failure);

        if let Some(package) = policy.as_ref().filter(|_| policy_backed) {
            let (adapters, nic_failure) = self.reconcile_network(
                nic_executor,
                &package.payload.network,
                &observed.adapters,
                policy_version.expect("策略存在时其版本可用"),
                now,
            )?;
            applied.adapters = adapters;
            failure = failure.or(nic_failure);
        }

        let (burn_drives, burning_failure) = self.reconcile_burning(
            burning_executor,
            policy
                .as_ref()
                .filter(|_| policy_backed)
                .map(|package| &package.payload.burning),
            &observed.burn_drives,
            logon_ui_active,
            policy_version,
            now,
        )?;
        applied.burn_drives = burn_drives;
        failure = failure.or(burning_failure);

        if let Some(failure) = failure {
            return Err(failure.into_error());
        }
        if policy_backed {
            self.store.clear_enforcement_failure()?;
        }
        Ok(match denial {
            Some(reason) => EnforcementOutcome::Denied { reason },
            None => EnforcementOutcome::Reconciled(applied),
        })
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
        rules: Option<&UsbRules>,
        observed: &[UsbStorageDevice],
        logon_ui_active: bool,
        policy_version: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<(Vec<UsbDisposition>, Option<ExecutionFailure>), StoreError>
    where
        U: UsbStorageExecutor + WriteDenialSwitch,
    {
        let allowlist = rules.map(usb_allowlist);
        let recorded = self.store.device_states(USB_STATE_KIND)?;
        let mut applied = Vec::new();
        let mut present = Vec::new();

        // 只读通道先落地写保护再放行设备：写保护只对该开关开启之后挂载的介质生效。
        let denial = self.reconcile_write_denial(
            executor,
            REMOVABLE_WRITE_DENIAL,
            logon_ui_active,
            policy_version,
            now,
        )?;
        let mut failure = denial.failure;

        for device in observed {
            let plan =
                plan_usb_storage_control(device.clone(), allowlist.as_deref(), logon_ui_active);
            let planned_action = plan.planned_action;
            if planned_action == UsbPlannedAction::RejectNonMassStorage {
                continue;
            }
            let instance_id = plan.device.instance_id.clone();
            // 设备在场：保持现状的设备也要计入，避免被当成已移除。
            present.push(instance_id.clone());
            // 写保护没能落地时，只读通道保持禁用，不下发放行处置。
            let desired_enabled = match planned_action {
                UsbPlannedAction::EnableMassStorage => true,
                UsbPlannedAction::EnableMassStorageReadOnly => denial.ready,
                UsbPlannedAction::DisableMassStorage => false,
                // 保持现状：没有可依据的策略结论，设备留在 Windows 默认状态。
                UsbPlannedAction::KeepCurrentState | UsbPlannedAction::RejectNonMassStorage => {
                    continue;
                }
            };
            let read_only = planned_action == UsbPlannedAction::EnableMassStorageReadOnly;

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
                // 写保护刚开启时，已经挂载的可移动介质要重新挂载一次才是只读。
                if !(read_only && denial.just_enabled && device.enabled) {
                    continue;
                }
                if let Err(error) = executor.set_mass_storage_enabled(&instance_id, false) {
                    let recorded_failure = self.note_execution_failure(
                        ExecutionFailure::DeviceControl(error),
                        EventType::UsbAttach,
                        "remount_usb_read_only",
                        &instance_id,
                        policy_version,
                        now,
                    );
                    remember_failure(&mut failure, recorded_failure);
                    continue;
                }
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

            let result = if !desired_enabled {
                "disabled"
            } else if read_only {
                "enabled_read_only"
            } else {
                "enabled"
            };
            let event = self.audit_payload(
                EventType::UsbAttach,
                "apply_usb_control",
                result,
                policy_version.map(|version| (instance_id.as_str(), version)),
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

    /// 让指定的系统级写入拒绝开关与登录界面状态一致。
    ///
    /// 开关已经符合期望时不做任何写入；不一致时下发并把结果写进审计。失败时记录运行期失败
    /// 并返回未就绪，调用方据此不放行对应的只读通道。
    fn reconcile_write_denial<D>(
        &self,
        executor: &mut D,
        audit: WriteDenialAudit,
        logon_ui_active: bool,
        policy_version: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<WriteDenialState, StoreError>
    where
        D: WriteDenialSwitch,
    {
        let settled = WriteDenialState {
            ready: true,
            just_enabled: false,
            failure: None,
        };
        if executor
            .write_denied()
            .is_ok_and(|denied| denied == logon_ui_active)
        {
            return Ok(settled);
        }

        if let Err(error) = executor.set_write_denied(logon_ui_active) {
            let failure = self.note_execution_failure(
                ExecutionFailure::DeviceControl(error),
                audit.event_type,
                audit.action,
                audit.resource,
                policy_version,
                now,
            );
            return Ok(WriteDenialState {
                ready: false,
                just_enabled: false,
                failure: Some(failure),
            });
        }

        let event = self.audit_payload(
            audit.event_type,
            audit.action,
            if logon_ui_active {
                "enabled"
            } else {
                "disabled"
            },
            policy_version.map(|version| (audit.resource, version)),
            now,
        );
        if let Err(error) = self.store.append_audit(event) {
            let failure = self.note_execution_failure(
                ExecutionFailure::StatePersistence(error),
                audit.event_type,
                audit.action,
                audit.resource,
                policy_version,
                now,
            );
            return Ok(WriteDenialState {
                ready: false,
                just_enabled: false,
                failure: Some(failure),
            });
        }
        Ok(WriteDenialState {
            just_enabled: logon_ui_active,
            ..settled
        })
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
                    Some(policy_version),
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
                    Some(policy_version),
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
        rules: Option<&BurningRules>,
        observed: &[BurnDriveInfo],
        logon_ui_active: bool,
        policy_version: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<(Vec<BurningDisposition>, Option<ExecutionFailure>), StoreError>
    where
        B: BurningControlExecutor + WriteDenialSwitch,
    {
        // 登录界面的只读通道先落地 CD/DVD 写入拒绝，再放行光驱读取。
        let denial = self.reconcile_write_denial(
            executor,
            OPTICAL_WRITE_DENIAL,
            logon_ui_active,
            policy_version,
            now,
        )?;
        let mut applied = Vec::new();
        let mut failure = denial.failure;

        for drive in observed {
            // 登录界面下光驱一律只读可用：写入拒绝没落地时保持禁用。
            let desired_enabled = match (rules, logon_ui_active) {
                (_, true) => denial.ready,
                (Some(rules), false) => {
                    rules.policy == ActionPolicy::Allow
                        && rules
                            .allowed
                            .iter()
                            .any(|rule| rule.drive_id == drive.drive_id)
                }
                // 没有策略依据时不下发处置，光驱留在原状。
                (None, false) => continue,
            };
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

            let result = if !desired_enabled {
                "disabled"
            } else if logon_ui_active {
                "enabled_read_only"
            } else {
                "enabled"
            };
            let event = self.audit_payload(
                EventType::BurnTask,
                "apply_burning_control",
                result,
                policy_version.map(|version| (drive.drive_id.as_str(), version)),
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
        policy_version: Option<u64>,
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
            policy_version.map(|version| (resource, version)),
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
