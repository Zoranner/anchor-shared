//! 受限 Windows Named Pipe 传输。

use std::time::Duration;

use crate::error::PlatformError;

/// 单条本地控制消息的最大字节数，与服务协议的限制一致。
pub const MAX_PIPE_MESSAGE_BYTES: usize = 64 * 1024;

/// Anchor Guard 服务的固定本地端点。
pub const DEFAULT_CONTROL_PIPE: &str = r"\\.\pipe\AnchorGuard.Control";

const CONTROLLED_CLIENT_SDDL: &str = "D:P(A;;GA;;;SY)";

/// 服务端一次监听的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeServeOutcome {
    /// 在等待窗口内没有受控客户端连接，可继续下一次监听并处理服务控制事件。
    Idle,
    /// 已完成一次受控客户端请求和响应。
    Handled,
}

/// 返回服务端 Named Pipe 使用的访问控制描述符。
///
/// 仅 `SYSTEM`（Credential Provider 所在的 LogonUI）可连接。
#[must_use]
pub const fn controlled_client_sddl() -> &'static str {
    CONTROLLED_CLIENT_SDDL
}

/// 判断字符串是否为 Windows 本地 Named Pipe 路径。
#[must_use]
pub fn is_named_pipe_path(path: &str) -> bool {
    path.starts_with(r"\\.\pipe\") && path.len() > r"\\.\pipe\".len()
}

/// 服务端处理一次本地请求。
///
/// 消息边界由四字节小端长度前缀确定。处理函数只接收 JSON 载荷，业务协议由
/// `anchor-service` 负责。
#[cfg(windows)]
pub fn serve_once<F>(pipe_name: &str, handler: F) -> Result<PipeServeOutcome, PlatformError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
{
    windows::serve_once(pipe_name, handler)
}

/// 非 Windows 平台没有可支持的本地登录管控端点。
#[cfg(not(windows))]
pub fn serve_once<F>(_pipe_name: &str, _handler: F) -> Result<PipeServeOutcome, PlatformError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
{
    Err(PlatformError::Unsupported("Windows Named Pipe"))
}

/// 向本地服务发出一次请求并等待回复。
#[cfg(windows)]
pub fn transact(
    pipe_name: &str,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, PlatformError> {
    windows::transact(pipe_name, request, timeout)
}

/// 非 Windows 平台没有可支持的本地登录管控端点。
#[cfg(not(windows))]
pub fn transact(
    _pipe_name: &str,
    _request: &[u8],
    _timeout: Duration,
) -> Result<Vec<u8>, PlatformError> {
    Err(PlatformError::Unsupported("Windows Named Pipe"))
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        mem::size_of,
        ptr::null,
        time::{Duration, Instant},
    };

    use crate::{
        error::PlatformError,
        pipe::{
            controlled_client_sddl, is_named_pipe_path, PipeServeOutcome, MAX_PIPE_MESSAGE_BYTES,
        },
    };

    const ERROR_IO_PENDING: i32 = 997;
    const ERROR_PIPE_CONNECTED: i32 = 535;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const INVALID_HANDLE_VALUE: isize = -1;
    const OPEN_EXISTING: u32 = 3;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const PIPE_TYPE_BYTE: u32 = 0;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const TOKEN_QUERY: u32 = 0x0008;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const SERVER_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
    const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(2);

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: isize,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConnectionWaitOutcome {
        Connected,
        Idle,
        Failed,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        fn EqualSid(first_sid: *const c_void, second_sid: *const c_void) -> i32;
        fn GetTokenInformation(
            token: isize,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn OpenProcessToken(process: isize, desired_access: u32, token: *mut isize) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CloseHandle(handle: isize) -> i32;
        fn CancelIoEx(file: isize, overlapped: *mut Overlapped) -> i32;
        fn ConnectNamedPipe(named_pipe: isize, overlapped: *mut Overlapped) -> i32;
        fn CreateEventW(
            event_attributes: *const SecurityAttributes,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> isize;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const SecurityAttributes,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: isize,
        ) -> isize;
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer_size: u32,
            in_buffer_size: u32,
            default_timeout: u32,
            security_attributes: *const SecurityAttributes,
        ) -> isize;
        fn DisconnectNamedPipe(named_pipe: isize) -> i32;
        fn GetOverlappedResult(
            file: isize,
            overlapped: *mut Overlapped,
            bytes_transferred: *mut u32,
            wait: i32,
        ) -> i32;
        fn GetNamedPipeServerProcessId(named_pipe: isize, server_process_id: *mut u32) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        fn ReadFile(
            file: isize,
            buffer: *mut c_void,
            bytes_to_read: u32,
            bytes_read: *mut u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
        fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
        fn WriteFile(
            file: isize,
            buffer: *const c_void,
            bytes_to_write: u32,
            bytes_written: *mut u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }

    struct Handle(isize);

    impl Handle {
        fn new(handle: isize) -> Result<Self, PlatformError> {
            if handle == 0 || handle == INVALID_HANDLE_VALUE {
                return Err(last_error("创建 Named Pipe 句柄失败"));
            }
            Ok(Self(handle))
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct SecurityDescriptor(*mut c_void);

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    pub(super) fn serve_once<F>(
        pipe_name: &str,
        handler: F,
    ) -> Result<PipeServeOutcome, PlatformError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
    {
        let name = wide(pipe_name)?;
        let descriptor = security_descriptor()?;
        let attributes = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            security_descriptor: descriptor.0,
            inherit_handle: 0,
        };
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                MAX_PIPE_MESSAGE_BYTES as u32,
                MAX_PIPE_MESSAGE_BYTES as u32,
                0,
                &attributes,
            )
        };
        let pipe = Handle::new(pipe)?;

        if !connect_named_pipe(pipe.0, SERVER_CONNECT_TIMEOUT)? {
            return Ok(PipeServeOutcome::Idle);
        }

        let deadline = Instant::now() + SERVER_IO_TIMEOUT;
        let request = read_message_overlapped(pipe.0, deadline)?;
        let response = handler(&request)?;
        write_message_overlapped(pipe.0, &response, deadline)?;
        unsafe {
            DisconnectNamedPipe(pipe.0);
        }
        Ok(PipeServeOutcome::Handled)
    }

    pub(super) fn transact(
        pipe_name: &str,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, PlatformError> {
        let name = wide(pipe_name)?;
        let deadline = Instant::now() + timeout;
        if unsafe { WaitNamedPipeW(name.as_ptr(), remaining_timeout(deadline)?) } == 0 {
            return Err(last_error("等待 Named Pipe 服务超时或失败"));
        }
        let client = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                0,
            )
        };
        let client = Handle::new(client)?;
        verify_server_is_local_system(client.0)?;

        write_message_overlapped(client.0, request, deadline)?;
        read_message_overlapped(client.0, deadline)
    }

    fn security_descriptor() -> Result<SecurityDescriptor, PlatformError> {
        let sddl = wide(controlled_client_sddl())?;
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_error("创建 Named Pipe 访问控制失败"));
        }
        Ok(SecurityDescriptor(descriptor))
    }

    fn wide(value: &str) -> Result<Vec<u16>, PlatformError> {
        if !is_named_pipe_path(value) {
            return Err(PlatformError::Failed("Named Pipe 路径无效".into()));
        }
        Ok(wide_nul(value))
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn connect_named_pipe(handle: isize, timeout: Duration) -> Result<bool, PlatformError> {
        let event = Handle::new(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: event.0,
        };
        if unsafe { ConnectNamedPipe(handle, &mut overlapped) } != 0 {
            return Ok(true);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_PIPE_CONNECTED) => Ok(true),
            Some(ERROR_IO_PENDING) => {
                match connection_wait_outcome(unsafe {
                    WaitForSingleObject(event.0, timeout_millis(timeout))
                }) {
                    ConnectionWaitOutcome::Connected => {}
                    ConnectionWaitOutcome::Idle => {
                        cancel_and_wait(handle, &mut overlapped);
                        return Ok(false);
                    }
                    ConnectionWaitOutcome::Failed => {
                        cancel_and_wait(handle, &mut overlapped);
                        return Err(last_error("等待 Named Pipe 客户端失败"));
                    }
                }
                let mut bytes = 0;
                if unsafe { GetOverlappedResult(handle, &mut overlapped, &mut bytes, 0) } == 0 {
                    return Err(last_error("确认 Named Pipe 客户端连接失败"));
                }
                Ok(true)
            }
            _ => Err(last_error("等待 Named Pipe 客户端失败")),
        }
    }

    fn verify_server_is_local_system(handle: isize) -> Result<(), PlatformError> {
        let mut process_id = 0;
        if unsafe { GetNamedPipeServerProcessId(handle, &mut process_id) } == 0 || process_id == 0 {
            return Err(last_error("读取 Named Pipe 服务进程失败"));
        }
        let process =
            Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) })?;
        let mut token = 0;
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error("读取 Named Pipe 服务令牌失败"));
        }
        let token = Handle::new(token)?;

        let mut length = 0;
        unsafe {
            GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut length);
        }
        if length < size_of::<TokenUser>() as u32 {
            return Err(last_error("读取 Named Pipe 服务 SID 长度失败"));
        }
        let mut information = vec![0_u8; length as usize];
        if unsafe {
            GetTokenInformation(
                token.0,
                1,
                information.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } == 0
        {
            return Err(last_error("读取 Named Pipe 服务 SID 失败"));
        }
        let token_user = unsafe { &*information.as_ptr().cast::<TokenUser>() };

        let system_sid = wide_nul("S-1-5-18");
        let mut expected_sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(system_sid.as_ptr(), &mut expected_sid) } == 0 {
            return Err(last_error("生成 LocalSystem SID 失败"));
        }
        let expected_sid = SecurityDescriptor(expected_sid);
        if unsafe { EqualSid(token_user.user.sid, expected_sid.0) } == 0 {
            return Err(PlatformError::Failed(
                "拒绝非 LocalSystem 的 Named Pipe 服务端".into(),
            ));
        }
        Ok(())
    }

    fn read_message_overlapped(handle: isize, deadline: Instant) -> Result<Vec<u8>, PlatformError> {
        let mut header = [0_u8; 4];
        read_exact_overlapped(handle, &mut header, deadline)?;
        let length = u32::from_le_bytes(header) as usize;
        let mut payload = vec![0; checked_message_length(length)?];
        read_exact_overlapped(handle, &mut payload, deadline)?;
        Ok(payload)
    }

    fn write_message_overlapped(
        handle: isize,
        message: &[u8],
        deadline: Instant,
    ) -> Result<(), PlatformError> {
        let length = checked_message_length(message.len())? as u32;
        write_all_overlapped(handle, &length.to_le_bytes(), deadline)?;
        write_all_overlapped(handle, message, deadline)
    }

    fn read_exact_overlapped(
        handle: isize,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<(), PlatformError> {
        let mut offset = 0;
        while offset < buffer.len() {
            let read = read_overlapped(handle, &mut buffer[offset..], deadline)?;
            if read == 0 {
                return Err(PlatformError::Failed("Named Pipe 服务已断开".into()));
            }
            offset += read;
        }
        Ok(())
    }

    fn write_all_overlapped(
        handle: isize,
        buffer: &[u8],
        deadline: Instant,
    ) -> Result<(), PlatformError> {
        let mut offset = 0;
        while offset < buffer.len() {
            let written = write_overlapped(handle, &buffer[offset..], deadline)?;
            if written == 0 {
                return Err(PlatformError::Failed("Named Pipe 服务未写入消息".into()));
            }
            offset += written;
        }
        Ok(())
    }

    fn read_overlapped(
        handle: isize,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, PlatformError> {
        let event = Handle::new(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: event.0,
        };
        let mut bytes = 0;
        let started = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut bytes,
                &mut overlapped,
            )
        } != 0;
        completed_bytes(handle, &mut overlapped, bytes, started, deadline)
    }

    fn write_overlapped(
        handle: isize,
        buffer: &[u8],
        deadline: Instant,
    ) -> Result<usize, PlatformError> {
        let event = Handle::new(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: event.0,
        };
        let mut bytes = 0;
        let started = unsafe {
            WriteFile(
                handle,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                &mut bytes,
                &mut overlapped,
            )
        } != 0;
        completed_bytes(handle, &mut overlapped, bytes, started, deadline)
    }

    fn completed_bytes(
        handle: isize,
        overlapped: &mut Overlapped,
        immediate_bytes: u32,
        started: bool,
        deadline: Instant,
    ) -> Result<usize, PlatformError> {
        if started {
            return Ok(immediate_bytes as usize);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING) {
            return Err(last_error("Named Pipe 异步操作失败"));
        }
        let wait_timeout = match remaining_timeout(deadline) {
            Ok(timeout) => timeout,
            Err(error) => {
                cancel_and_wait(handle, overlapped);
                return Err(error);
            }
        };
        if unsafe { WaitForSingleObject(overlapped.event, wait_timeout) } != WAIT_OBJECT_0 {
            cancel_and_wait(handle, overlapped);
            return Err(PlatformError::Failed("Named Pipe 调用超时".into()));
        }
        let mut bytes = 0;
        if unsafe { GetOverlappedResult(handle, overlapped, &mut bytes, 0) } == 0 {
            return Err(last_error("取得 Named Pipe 操作结果失败"));
        }
        Ok(bytes as usize)
    }

    fn cancel_and_wait(handle: isize, overlapped: &mut Overlapped) {
        unsafe {
            CancelIoEx(handle, overlapped);
            GetOverlappedResult(handle, overlapped, std::ptr::null_mut(), 1);
        }
    }

    fn connection_wait_outcome(status: u32) -> ConnectionWaitOutcome {
        match status {
            WAIT_OBJECT_0 => ConnectionWaitOutcome::Connected,
            WAIT_TIMEOUT => ConnectionWaitOutcome::Idle,
            _ => ConnectionWaitOutcome::Failed,
        }
    }

    fn remaining_timeout(deadline: Instant) -> Result<u32, PlatformError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| PlatformError::Failed("Named Pipe 调用超时".into()))?;
        Ok(timeout_millis(remaining))
    }

    fn checked_message_length(length: usize) -> Result<usize, PlatformError> {
        if length > MAX_PIPE_MESSAGE_BYTES {
            return Err(PlatformError::Failed(format!(
                "Named Pipe 消息超过 {MAX_PIPE_MESSAGE_BYTES} 字节上限"
            )));
        }
        Ok(length)
    }

    fn timeout_millis(timeout: Duration) -> u32 {
        timeout.as_millis().min(u128::from(u32::MAX)) as u32
    }

    fn last_error(context: &str) -> PlatformError {
        PlatformError::Failed(format!("{context}: {}", std::io::Error::last_os_error()))
    }

    #[cfg(test)]
    mod tests {
        use super::{connection_wait_outcome, ConnectionWaitOutcome, WAIT_TIMEOUT};

        #[test]
        fn failed_connection_wait_is_not_treated_as_an_idle_listener() {
            assert_eq!(
                connection_wait_outcome(WAIT_TIMEOUT),
                ConnectionWaitOutcome::Idle
            );
            assert_eq!(
                connection_wait_outcome(u32::MAX),
                ConnectionWaitOutcome::Failed
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{controlled_client_sddl, is_named_pipe_path, MAX_PIPE_MESSAGE_BYTES};

    #[test]
    fn control_pipe_accepts_only_the_logonui_system_identity() {
        assert_eq!(controlled_client_sddl(), "D:P(A;;GA;;;SY)");
    }

    #[test]
    fn accepts_only_windows_named_pipe_paths() {
        assert!(is_named_pipe_path(r"\\.\pipe\AnchorGuard.Control"));
        assert!(!is_named_pipe_path(r"C:\\AnchorGuard.Control"));
        assert!(!is_named_pipe_path(""));
    }

    #[test]
    fn control_pipe_message_limit_matches_the_service_protocol_limit() {
        assert_eq!(MAX_PIPE_MESSAGE_BYTES, 64 * 1024);
    }
}
