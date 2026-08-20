//! Anchor Guard 核心类型与加密原语。
//!
//! 覆盖四类核心对象中的三类共享部分：策略包（[`policy`]),
//! 审批令牌（[`approval`]) 与审计事件 hash chain（[`audit`])。
//! 签名与哈希算法封装在 [`crypto`]。

pub mod approval;
pub mod audit;
pub mod crypto;
pub mod error;
pub mod policy;

pub use approval::{
    match_approval, resource_matches, ApprovalAction, ApprovalPayload, ApprovalToken,
};
pub use audit::{verify_chain, AuditEvent, AuditPayload, EventType, GENESIS_HASH};
pub use error::CoreError;
pub use policy::{
    is_offline_expired, validate_incoming, ActionPolicy, ApprovalRules, BurningRules, DeviceMode,
    DeviceScope, Disposition, NetworkRules, PolicyPackage, PolicyPayload, PolicyVerdict, ScanRule,
    ScanRuleKind, ScanRules, SelfProtectionRules, UsbRules,
};
