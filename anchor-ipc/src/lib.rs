//! Anchor Guard 服务端、登录组件和桌面端共用的本地 IPC 协议。

mod protocol;

pub use protocol::{
    decode_frame, decode_frame_with_limit, encode_frame, encode_frame_with_limit, AuditFilter,
    AuditPage, AuditViewEvent, AuthorizationResponse, DesktopProtocolError, DesktopRequest,
    DesktopResponse, DesktopStatus, ImportResponse, PolicyInspection, PolicySummary, ProtocolError,
    ServiceRequest, ServiceResponse, MAX_DESKTOP_MESSAGE_BYTES, MAX_MESSAGE_BYTES,
    MAX_POLICY_PACKAGE_BYTES,
};
