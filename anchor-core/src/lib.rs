//! Anchor Guard 核心类型与加密原语。
//!
//! 覆盖策略包（[`policy`]) 与审计事件 hash chain（[`audit`])。
//! 签名与哈希算法封装在 [`crypto`]。

pub mod audit;
pub mod crypto;
pub mod error;
pub mod policy;

pub use audit::{verify_chain, AuditEvent, AuditPayload, EventType, GENESIS_HASH};
pub use error::CoreError;
pub use policy::{
    decide_import, evaluate_authorization, ActionPolicy, AuthorizationDenial, AuthorizationState,
    BurningAllowRule, BurningRules, ImportDecision, NetworkAllowRule, NetworkRules, PolicyPackage,
    PolicyPayload, ScanRule, ScanRuleKind, ScanRules, UsbAllowRule, UsbRules,
};
