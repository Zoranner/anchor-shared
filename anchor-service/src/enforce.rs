//! 活动策略的会话与设备处置编排。
//!
//! 本模块只接收已观测的设备并生成处置计划；真实 Windows 枚举和设备控制属于
//! `anchor-system` 的独立边界。

use anchor_core::{ActionPolicy, AuditPayload, AuthorizationDenial, AuthorizationState, EventType};
use anchor_store::StoreError;
use anchor_system::{
    burning::{apply_burning_control, BurnDriveInfo, BurningControlExecutor},
    error::PlatformError,
    nic::{apply_nic_control, NicControlExecutor, NicInfo},
    session::SessionLocker,
    usb::{
        apply_usb_storage_control, plan_usb_storage_control, UsbAllowRule, UsbControlResult,
        UsbStorageDevice, UsbStorageExecutor,
    },
};
use chrono::{DateTime, Utc};
use serde_json::json;
use thiserror::Error;

use crate::Service;

/// 服务本轮已观测到的受控设备。调用方负责观测，本模块不枚举设备。
#[derive(Debug, Default)]
pub struct ObservedDevices {
    pub usb_storage: Vec<UsbStorageDevice>,
    pub adapters: Vec<NicInfo>,
    pub burn_drives: Vec<BurnDriveInfo>,
}

/// 网卡的计划处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicDisposition {
    pub adapter_id: String,
    pub enabled: bool,
}

/// 刻录光驱的计划处置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurningDisposition {
    pub drive_id: String,
    pub enabled: bool,
}

/// 本轮设备计划，尚未调用任何设备控制 API。
#[derive(Debug, Default)]
pub struct DevicePlans {
    pub usb: Vec<UsbControlResult>,
    pub adapters: Vec<NicDisposition>,
    pub burn_drives: Vec<BurningDisposition>,
}

/// 策略编排的可观察结论。
#[derive(Debug)]
pub enum EnforcementOutcome {
    SessionLocked { reason: AuthorizationDenial },
    DevicePlans(DevicePlans),
}

/// 编排时的存储或锁屏失败。
#[derive(Debug, Error)]
pub enum EnforcementError {
    #[error("本地状态或审计写入失败: {0}")]
    Store(#[from] StoreError),
    #[error("锁定当前会话失败: {0}")]
    SessionLock(#[from] PlatformError),
    #[error("设备控制执行失败: {0}")]
    DeviceControl(PlatformError),
    #[error("设备控制与后续会话锁定均失败: 设备={device}; 锁定={session}")]
    DeviceControlAndSessionLock {
        device: PlatformError,
        session: PlatformError,
    },
    #[error("设备处置后的审计或状态持久化失败: {0}")]
    StatePersistence(StoreError),
    #[error("设备处置后的状态持久化与会话锁定均失败: 状态={state}; 锁定={session}")]
    StatePersistenceAndSessionLock {
        state: StoreError,
        session: PlatformError,
    },
}

enum ExecutionFailure {
    DeviceControl(PlatformError),
    StatePersistence(StoreError),
}

struct DeviceStateUpdate<'a> {
    kind: &'a str,
    device_id: &'a str,
    state: &'a serde_json::Value,
}

impl ExecutionFailure {
    fn into_error(self) -> EnforcementError {
        match self {
            Self::DeviceControl(error) => EnforcementError::DeviceControl(error),
            Self::StatePersistence(error) => EnforcementError::StatePersistence(error),
        }
    }

    fn with_session_lock_error(self, session: PlatformError) -> EnforcementError {
        match self {
            Self::DeviceControl(device) => {
                EnforcementError::DeviceControlAndSessionLock { device, session }
            }
            Self::StatePersistence(state) => {
                EnforcementError::StatePersistenceAndSessionLock { state, session }
            }
        }
    }
}

impl Service {
    /// 根据当前活动策略处理已观测设备。
    ///
    /// 授权拒绝时立即请求锁定会话并写入审计。授权允许时，仅根据明确 allowlist
    /// 生成设备启用计划；未列入 allowlist 的 USB、网卡和光驱均保持默认拒绝。
    pub fn apply_policy<L>(
        &self,
        locker: &L,
        observed: ObservedDevices,
        now: DateTime<Utc>,
    ) -> Result<EnforcementOutcome, EnforcementError>
    where
        L: SessionLocker,
    {
        match self.authorization_state(now) {
            AuthorizationState::Denied(reason) => self.lock_denied_session(locker, reason, now),
            AuthorizationState::Allowed => self.plan_allowed_devices(observed, now),
        }
    }

    /// 执行活动策略的设备计划。
    ///
    /// 调用方显式提供三类执行器，使服务循环和测试环境不会隐式调用真实 Windows
    /// 控制 API。设备状态和成功审计仅在对应执行器成功后写入。
    pub fn enforce_policy<L, U, N, B>(
        &self,
        locker: &L,
        usb_executor: &mut U,
        nic_executor: &mut N,
        burning_executor: &mut B,
        observed: ObservedDevices,
        now: DateTime<Utc>,
    ) -> Result<EnforcementOutcome, EnforcementError>
    where
        L: SessionLocker,
        U: UsbStorageExecutor,
        N: NicControlExecutor,
        B: BurningControlExecutor,
    {
        let outcome = self.apply_policy(locker, observed, now)?;
        let EnforcementOutcome::DevicePlans(plans) = outcome else {
            return Ok(outcome);
        };
        let active_policy = self
            .store
            .active_policy()?
            .expect("allowed authorization requires an active policy");
        let policy_version = active_policy.payload.version;
        let allowed_nics: Vec<String> =
            if active_policy.payload.network.policy == ActionPolicy::Allow {
                active_policy
                    .payload
                    .network
                    .allowed
                    .iter()
                    .map(|rule| rule.adapter_id.clone())
                    .collect()
            } else {
                Vec::new()
            };
        let allowed_burn_drives: Vec<String> =
            if active_policy.payload.burning.policy == ActionPolicy::Allow {
                active_policy
                    .payload
                    .burning
                    .allowed
                    .iter()
                    .map(|rule| rule.drive_id.clone())
                    .collect()
            } else {
                Vec::new()
            };

        let mut first_failure = None;

        for plan in &plans.usb {
            if let Err(error) = apply_usb_storage_control(usb_executor, plan.clone()) {
                let audit = self.append_enforcement_audit(
                    EventType::UsbAttach,
                    "apply_usb_control",
                    "failed",
                    Some((&plan.device.instance_id, policy_version)),
                    now,
                );
                remember_execution_failure(
                    &mut first_failure,
                    audit.map_or_else(ExecutionFailure::StatePersistence, |_| {
                        ExecutionFailure::DeviceControl(error)
                    }),
                );
                continue;
            }
            if let Err(error) = self.persist_usb_plan(plan, policy_version, now) {
                remember_execution_failure(
                    &mut first_failure,
                    ExecutionFailure::StatePersistence(error),
                );
            }
        }

        for plan in &plans.adapters {
            if let Err(error) =
                apply_nic_control(nic_executor, &plan.adapter_id, plan.enabled, &allowed_nics)
            {
                let audit = self.append_enforcement_audit(
                    EventType::NicChange,
                    "apply_nic_control",
                    "failed",
                    Some((&plan.adapter_id, policy_version)),
                    now,
                );
                remember_execution_failure(
                    &mut first_failure,
                    audit.map_or_else(ExecutionFailure::StatePersistence, |_| {
                        ExecutionFailure::DeviceControl(error)
                    }),
                );
                continue;
            }
            if let Err(error) = self.persist_nic_plan(plan, policy_version, now) {
                remember_execution_failure(
                    &mut first_failure,
                    ExecutionFailure::StatePersistence(error),
                );
            }
        }

        for plan in &plans.burn_drives {
            if let Err(error) = apply_burning_control(
                burning_executor,
                &plan.drive_id,
                plan.enabled,
                &allowed_burn_drives,
            ) {
                let audit = self.append_enforcement_audit(
                    EventType::BurnTask,
                    "apply_burning_control",
                    "failed",
                    Some((&plan.drive_id, policy_version)),
                    now,
                );
                remember_execution_failure(
                    &mut first_failure,
                    audit.map_or_else(ExecutionFailure::StatePersistence, |_| {
                        ExecutionFailure::DeviceControl(error)
                    }),
                );
                continue;
            }
            if let Err(error) = self.persist_burning_plan(plan, policy_version, now) {
                remember_execution_failure(
                    &mut first_failure,
                    ExecutionFailure::StatePersistence(error),
                );
            }
        }

        if let Some(failure) = first_failure {
            return match self.lock_after_device_control_failure(locker, now) {
                Ok(()) => Err(failure.into_error()),
                Err(EnforcementError::SessionLock(session)) => {
                    Err(failure.with_session_lock_error(session))
                }
                Err(error) => Err(error),
            };
        }

        Ok(EnforcementOutcome::DevicePlans(plans))
    }

    fn lock_denied_session<L>(
        &self,
        locker: &L,
        reason: AuthorizationDenial,
        now: DateTime<Utc>,
    ) -> Result<EnforcementOutcome, EnforcementError>
    where
        L: SessionLocker,
    {
        let lock_result = locker.lock_current_session();
        self.append_enforcement_audit(
            EventType::AuthorizationDenied,
            "authorization",
            authorization_denial_reason(reason),
            None,
            now,
        )?;

        match lock_result {
            Ok(_) => {
                self.append_enforcement_audit(
                    EventType::SessionLocked,
                    "lock_session",
                    "locked",
                    None,
                    now,
                )?;
                Ok(EnforcementOutcome::SessionLocked { reason })
            }
            Err(error) => {
                self.append_enforcement_audit(
                    EventType::SessionAssistantFailed,
                    "lock_session",
                    "failed",
                    None,
                    now,
                )?;
                Err(EnforcementError::SessionLock(error))
            }
        }
    }

    fn plan_allowed_devices(
        &self,
        observed: ObservedDevices,
        _now: DateTime<Utc>,
    ) -> Result<EnforcementOutcome, EnforcementError> {
        let active_policy = self
            .store
            .active_policy()?
            .expect("allowed authorization requires an active policy");
        let policy = &active_policy.payload;
        let mut plans = DevicePlans::default();

        let usb_allowlist: Vec<UsbAllowRule> =
            if policy.usb.read == ActionPolicy::Allow && policy.usb.write == ActionPolicy::Allow {
                policy
                    .usb
                    .allowed
                    .iter()
                    .map(|rule| UsbAllowRule {
                        instance_id: rule.instance_id.clone(),
                        vendor_id: rule.vendor_id.clone(),
                        product_id: rule.product_id.clone(),
                        serial: rule.serial.clone(),
                    })
                    .collect()
            } else {
                Vec::new()
            };
        for device in observed.usb_storage {
            let plan = plan_usb_storage_control(device, &usb_allowlist);
            plans.usb.push(plan);
        }

        for adapter in observed.adapters {
            let enabled = policy.network.policy == ActionPolicy::Allow
                && policy
                    .network
                    .allowed
                    .iter()
                    .any(|rule| rule.adapter_id == adapter.adapter_id);
            let plan = NicDisposition {
                adapter_id: adapter.adapter_id.clone(),
                enabled,
            };
            plans.adapters.push(plan);
        }

        for drive in observed.burn_drives {
            let enabled = policy.burning.policy == ActionPolicy::Allow
                && policy
                    .burning
                    .allowed
                    .iter()
                    .any(|rule| rule.drive_id == drive.drive_id);
            let plan = BurningDisposition {
                drive_id: drive.drive_id.clone(),
                enabled,
            };
            plans.burn_drives.push(plan);
        }

        Ok(EnforcementOutcome::DevicePlans(plans))
    }

    fn persist_usb_plan(
        &self,
        plan: &UsbControlResult,
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let result = format!("{:?}", plan.planned_action).to_lowercase();
        let state = json!({
            "vendor_id": plan.device.vendor_id,
            "product_id": plan.device.product_id,
            "serial": plan.device.serial,
            "matched_rule": plan.matched_rule,
            "planned_action": result,
        });
        self.append_enforcement_audit_and_state(
            EventType::UsbAttach,
            "plan_usb_control",
            &result,
            Some((&plan.device.instance_id, policy_version)),
            DeviceStateUpdate {
                kind: "usb",
                device_id: &plan.device.instance_id,
                state: &state,
            },
            now,
        )
    }

    fn lock_after_device_control_failure<L>(
        &self,
        locker: &L,
        now: DateTime<Utc>,
    ) -> Result<(), EnforcementError>
    where
        L: SessionLocker,
    {
        match locker.lock_current_session() {
            Ok(_) => {
                self.append_enforcement_audit(
                    EventType::SessionLocked,
                    "lock_session",
                    "device_control_failed",
                    None,
                    now,
                )?;
                Ok(())
            }
            Err(error) => {
                self.append_enforcement_audit(
                    EventType::SessionAssistantFailed,
                    "lock_session",
                    "device_control_failed",
                    None,
                    now,
                )?;
                Err(EnforcementError::SessionLock(error))
            }
        }
    }

    fn persist_nic_plan(
        &self,
        plan: &NicDisposition,
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let result = if plan.enabled { "enable" } else { "disable" };
        let state = json!({
            "planned_enabled": plan.enabled,
        });
        self.append_enforcement_audit_and_state(
            EventType::NicChange,
            "plan_nic_control",
            result,
            Some((&plan.adapter_id, policy_version)),
            DeviceStateUpdate {
                kind: "nic",
                device_id: &plan.adapter_id,
                state: &state,
            },
            now,
        )
    }

    fn persist_burning_plan(
        &self,
        plan: &BurningDisposition,
        policy_version: u64,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let result = if plan.enabled { "enable" } else { "disable" };
        let state = json!({
            "planned_enabled": plan.enabled,
        });
        self.append_enforcement_audit_and_state(
            EventType::BurnTask,
            "plan_burning_control",
            result,
            Some((&plan.drive_id, policy_version)),
            DeviceStateUpdate {
                kind: "burning",
                device_id: &plan.drive_id,
                state: &state,
            },
            now,
        )
    }

    fn append_enforcement_audit(
        &self,
        event_type: EventType,
        action: &str,
        result: &str,
        resource_and_policy: Option<(&str, u64)>,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.store.append_audit(self.enforcement_audit_payload(
            event_type,
            action,
            result,
            resource_and_policy,
            now,
        ))
    }

    fn append_enforcement_audit_and_state(
        &self,
        event_type: EventType,
        action: &str,
        result: &str,
        resource_and_policy: Option<(&str, u64)>,
        update: DeviceStateUpdate<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.store.append_audit_and_upsert_device_state(
            self.enforcement_audit_payload(event_type, action, result, resource_and_policy, now),
            update.kind,
            update.device_id,
            update.state,
            now,
        )
    }

    fn enforcement_audit_payload(
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

fn remember_execution_failure(slot: &mut Option<ExecutionFailure>, failure: ExecutionFailure) {
    if slot.is_none() {
        *slot = Some(failure);
    }
}

fn authorization_denial_reason(reason: AuthorizationDenial) -> &'static str {
    match reason {
        AuthorizationDenial::NoActivePolicy => "no_active_policy",
        AuthorizationDenial::DeviceMismatch => "device_mismatch",
        AuthorizationDenial::NotYetEffective => "not_yet_effective",
        AuthorizationDenial::Expired => "expired",
        AuthorizationDenial::TrustedTimeUnavailable => "trusted_time_unavailable",
        AuthorizationDenial::ClockRollback => "clock_rollback",
        AuthorizationDenial::AuditUnhealthy => "audit_unhealthy",
    }
}
