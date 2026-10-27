//! 受限 Windows Named Pipe 传输。

use std::time::Duration;

use crate::error::PlatformError;

/// 单条本地控制消息的最大字节数，与服务协议的限制一致。
pub const MAX_PIPE_MESSAGE_BYTES: usize = 64 * 1024;
/// 桌面端管道允许的单条消息上限，覆盖策略包和审计页响应。
pub const MAX_DESKTOP_PIPE_MESSAGE_BYTES: usize = 1024 * 1024;

/// Anchor Guard 服务的固定本地端点。
pub const DEFAULT_CONTROL_PIPE: &str = r"\\.\pipe\AnchorGuard.Control";

/// 供当前用户会话查询授权状态的固定本地端点。
pub const SESSION_STATUS_PIPE: &str = r"\\.\pipe\AnchorGuard.SessionStatus";
/// 供已登录用户桌面端查询状态、导入策略和查看审计的固定本地端点。
pub const DESKTOP_PIPE: &str = r"\\.\pipe\AnchorGuard.Desktop";

const CONTROLLED_CLIENT_SDDL: &str = "D:P(A;;GA;;;SY)";
const SESSION_STATUS_CLIENT_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)";
const DESKTOP_CLIENT_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)";

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

/// 返回会话状态端点使用的访问控制描述符。
///
/// 服务自身以 `SYSTEM` 身份拥有完整访问；`Authenticated Users` 仅获得发起请求和
/// 读取响应所需的通用读写权限。调用端仍需验证服务端为 LocalSystem。
#[must_use]
pub const fn session_status_client_sddl() -> &'static str {
    SESSION_STATUS_CLIENT_SDDL
}

/// 返回桌面端端点使用的访问控制描述符。
///
/// 与会话状态端点相同：`SYSTEM` 全权，已认证用户可读写；调用端仍需验证服务端为
/// LocalSystem。
#[must_use]
pub const fn desktop_client_sddl() -> &'static str {
    DESKTOP_CLIENT_SDDL
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
    windows::serve_once(
        pipe_name,
        controlled_client_sddl(),
        MAX_PIPE_MESSAGE_BYTES,
        handler,
    )
}

/// 非 Windows 平台没有可支持的本地登录管控端点。
#[cfg(not(windows))]
pub fn serve_once<F>(_pipe_name: &str, _handler: F) -> Result<PipeServeOutcome, PlatformError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
{
    Err(PlatformError::Unsupported("Windows Named Pipe"))
}

/// 服务端处理一次用户会话的只读授权状态查询。
#[cfg(windows)]
pub fn serve_session_status_once<F>(handler: F) -> Result<PipeServeOutcome, PlatformError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
{
    windows::serve_once(
        SESSION_STATUS_PIPE,
        session_status_client_sddl(),
        MAX_PIPE_MESSAGE_BYTES,
        handler,
    )
}

/// 非 Windows 平台没有可支持的本地会话状态端点。
#[cfg(not(windows))]
pub fn serve_session_status_once<F>(_handler: F) -> Result<PipeServeOutcome, PlatformError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
{
    Err(PlatformError::Unsupported("Windows Named Pipe"))
}

/// 服务端处理一次桌面端请求。
#[cfg(windows)]
pub fn serve_desktop_once<F>(handler: F) -> Result<PipeServeOutcome, PlatformError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
{
    windows::serve_once(
        DESKTOP_PIPE,
        desktop_client_sddl(),
        MAX_DESKTOP_PIPE_MESSAGE_BYTES,
        handler,
    )
}

/// 非 Windows 平台没有可支持的桌面端端点。
#[cfg(not(windows))]
pub fn serve_desktop_once<F>(_handler: F) -> Result<PipeServeOutcome, PlatformError>
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
    windows::transact(pipe_name, request, timeout, MAX_PIPE_MESSAGE_BYTES)
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

/// 向桌面端本地服务发出一次请求并等待回复。
#[cfg(windows)]
pub fn transact_desktop(request: &[u8], timeout: Duration) -> Result<Vec<u8>, PlatformError> {
    windows::transact(
        DESKTOP_PIPE,
        request,
        timeout,
        MAX_DESKTOP_PIPE_MESSAGE_BYTES,
    )
}

/// 非 Windows 平台没有可支持的桌面端端点。
#[cfg(not(windows))]
pub fn transact_desktop(_request: &[u8], _timeout: Duration) -> Result<Vec<u8>, PlatformError> {
    Err(PlatformError::Unsupported("Windows Named Pipe"))
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        mem::size_of,
        ptr::null,
        thread,
        time::{Duration, Instant},
    };

    use crate::{
        error::PlatformError,
        pipe::{is_named_pipe_path, PipeServeOutcome},
    };

    const ERROR_IO_PENDING: i32 = 997;
    const ERROR_PIPE_CONNECTED: i32 = 535;
    const ERROR_OPERATION_ABORTED: i32 = 995;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const SE_KERNEL_OBJECT: i32 = 6;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const INVALID_HANDLE_VALUE: isize = -1;
    const OPEN_EXISTING: u32 = 3;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const PIPE_TYPE_BYTE: u32 = 0;
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConnectionWaitOutcome {
        Connected,
        Idle,
        Failed,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        fn EqualSid(first_sid: *const c_void, second_sid: *const c_void) -> i32;
        fn GetSecurityInfo(
            handle: isize,
            object_type: i32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            security_descriptor: *mut *mut c_void,
        ) -> u32;
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
        fn FlushFileBuffers(file: isize) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
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
        client_sddl: &str,
        max_message_bytes: usize,
        handler: F,
    ) -> Result<PipeServeOutcome, PlatformError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, PlatformError>,
    {
        let name = wide(pipe_name)?;
        let descriptor = security_descriptor(client_sddl)?;
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
                max_message_bytes as u32,
                max_message_bytes as u32,
                0,
                &attributes,
            )
        };
        let pipe = Handle::new(pipe)?;

        if !connect_named_pipe(pipe.0, SERVER_CONNECT_TIMEOUT)? {
            return Ok(PipeServeOutcome::Idle);
        }

        let deadline = Instant::now() + SERVER_IO_TIMEOUT;
        let request = read_message_overlapped(pipe.0, deadline, max_message_bytes)?;
        let response = handler(&request)?;
        write_message_overlapped(pipe.0, &response, deadline, max_message_bytes)?;
        // 客户端可能尚未读完响应；先等待数据被取走，再断开，否则响应会被丢弃。
        unsafe { FlushFileBuffers(pipe.0) };
        unsafe {
            DisconnectNamedPipe(pipe.0);
        }
        Ok(PipeServeOutcome::Handled)
    }

    pub(super) fn transact(
        pipe_name: &str,
        request: &[u8],
        timeout: Duration,
        max_message_bytes: usize,
    ) -> Result<Vec<u8>, PlatformError> {
        let name = wide(pipe_name)?;
        let deadline = Instant::now() + timeout;
        loop {
            if unsafe { WaitNamedPipeW(name.as_ptr(), remaining_timeout(deadline)?) } != 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            // 服务在处理完一个请求后会短暂关闭实例再重建；这段空隙里管道名不存在，
            // WaitNamedPipe 会立即失败。它不代表服务不可用，应在截止时间内重试。
            if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND) {
                return Err(PlatformError::Failed(format!(
                    "等待 Named Pipe 服务超时或失败: {error}"
                )));
            }
            thread::sleep(Duration::from_millis(10));
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

        write_message_overlapped(client.0, request, deadline, max_message_bytes)?;
        read_message_overlapped(client.0, deadline, max_message_bytes)
    }

    fn security_descriptor(client_sddl: &str) -> Result<SecurityDescriptor, PlatformError> {
        let sddl = security_descriptor_wide(client_sddl);
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

    fn security_descriptor_wide(client_sddl: &str) -> Vec<u16> {
        wide_nul(client_sddl)
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
                        // 取消与客户端连接可能同时发生：操作已完成时不能当作空闲关闭，
                        // 否则客户端会拿到一个马上断开的管道。
                        return Ok(finish_cancelled_operation(handle, &mut overlapped)?.is_some());
                    }
                    ConnectionWaitOutcome::Failed => {
                        let _ = finish_cancelled_operation(handle, &mut overlapped);
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
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        // 直接读取管道对象的所有者：普通用户令牌通常无法打开 SYSTEM 服务进程，
        // 用进程令牌校验会把合法客户端误判成拒绝访问。
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(PlatformError::Failed(format!(
                "读取 Named Pipe 所有者失败: {}",
                std::io::Error::from_raw_os_error(result as i32)
            )));
        }
        let _descriptor = SecurityDescriptor(descriptor);
        if owner.is_null() {
            return Err(PlatformError::Failed("Named Pipe 没有所有者".into()));
        }

        if !trusted_server_owner(owner) {
            return Err(PlatformError::Failed(format!(
                "拒绝非系统身份的 Named Pipe 服务端: {}",
                sid_to_string(owner)
            )));
        }
        Ok(())
    }

    fn trusted_server_owner(owner: *mut c_void) -> bool {
        for name in ["S-1-5-18", "S-1-5-32-544"] {
            let name = wide_nul(name);
            let mut expected = std::ptr::null_mut();
            if unsafe { ConvertStringSidToSidW(name.as_ptr(), &mut expected) } == 0 {
                continue;
            }
            let expected = SecurityDescriptor(expected);
            if unsafe { EqualSid(owner, expected.0) } != 0 {
                return true;
            }
        }
        false
    }

    fn sid_to_string(sid: *mut c_void) -> String {
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return "?".into();
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        unsafe {
            LocalFree(text.cast());
        }
        value
    }

    fn read_message_overlapped(
        handle: isize,
        deadline: Instant,
        max_message_bytes: usize,
    ) -> Result<Vec<u8>, PlatformError> {
        let mut header = [0_u8; 4];
        read_exact_overlapped(handle, &mut header, deadline)?;
        let length = u32::from_le_bytes(header) as usize;
        let mut payload = vec![0; checked_message_length(length, max_message_bytes)?];
        read_exact_overlapped(handle, &mut payload, deadline)?;
        Ok(payload)
    }

    fn write_message_overlapped(
        handle: isize,
        message: &[u8],
        deadline: Instant,
        max_message_bytes: usize,
    ) -> Result<(), PlatformError> {
        let length = checked_message_length(message.len(), max_message_bytes)? as u32;
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
                let _ = finish_cancelled_operation(handle, overlapped);
                return Err(error);
            }
        };
        if unsafe { WaitForSingleObject(overlapped.event, wait_timeout) } != WAIT_OBJECT_0 {
            return match finish_cancelled_operation(handle, overlapped)? {
                Some(bytes) => Ok(bytes),
                None => Err(PlatformError::Failed("Named Pipe 调用超时".into())),
            };
        }
        let mut bytes = 0;
        if unsafe { GetOverlappedResult(handle, overlapped, &mut bytes, 0) } == 0 {
            return Err(last_error("取得 Named Pipe 操作结果失败"));
        }
        Ok(bytes as usize)
    }

    fn finish_cancelled_operation(
        handle: isize,
        overlapped: &mut Overlapped,
    ) -> Result<Option<usize>, PlatformError> {
        let mut bytes = 0;
        unsafe { CancelIoEx(handle, overlapped) };
        if unsafe { GetOverlappedResult(handle, overlapped, &mut bytes, 1) } != 0 {
            return Ok(Some(bytes as usize));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED) {
            return Ok(None);
        }
        Err(PlatformError::Failed(format!(
            "取消 Named Pipe 操作失败: {error}"
        )))
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

    fn checked_message_length(
        length: usize,
        max_message_bytes: usize,
    ) -> Result<usize, PlatformError> {
        if length > max_message_bytes {
            return Err(PlatformError::Failed(format!(
                "Named Pipe 消息超过 {max_message_bytes} 字节上限"
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
        use super::{
            connect_named_pipe, connection_wait_outcome, security_descriptor_wide, wide_nul,
            ConnectionWaitOutcome, CreateNamedPipeW, Handle, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE,
            WAIT_TIMEOUT,
        };
        use crate::pipe::session_status_client_sddl;
        use std::time::Duration;

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

        #[test]
        fn security_descriptor_sddl_does_not_require_a_pipe_path() {
            let encoded = security_descriptor_wide(session_status_client_sddl());

            assert_eq!(
                String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
                session_status_client_sddl()
            );
        }

        #[test]
        fn idle_connect_timeout_cancels_without_a_null_byte_count() {
            let name = wide_nul(&format!(
                r"\\.\pipe\AnchorGuard.PipeTest.{}",
                std::process::id()
            ));
            let pipe = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | super::FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE,
                    1,
                    4096,
                    4096,
                    0,
                    std::ptr::null(),
                )
            };
            let pipe = Handle::new(pipe).unwrap();

            let connected = connect_named_pipe(pipe.0, Duration::from_millis(50)).unwrap();

            assert!(!connected);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        controlled_client_sddl, desktop_client_sddl, is_named_pipe_path,
        session_status_client_sddl, DESKTOP_PIPE, MAX_DESKTOP_PIPE_MESSAGE_BYTES,
        MAX_PIPE_MESSAGE_BYTES,
    };

    #[test]
    fn control_pipe_accepts_only_the_logonui_system_identity() {
        assert_eq!(controlled_client_sddl(), "D:P(A;;GA;;;SY)");
    }

    #[test]
    fn session_status_pipe_grants_only_the_service_and_authenticated_users() {
        assert_eq!(
            session_status_client_sddl(),
            "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)"
        );
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

    #[test]
    fn desktop_pipe_is_available_to_authenticated_users_only() {
        assert_eq!(desktop_client_sddl(), "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)");
        assert_eq!(DESKTOP_PIPE, r"\\.\pipe\AnchorGuard.Desktop");
        assert_eq!(MAX_DESKTOP_PIPE_MESSAGE_BYTES, 1024 * 1024);
    }
}
