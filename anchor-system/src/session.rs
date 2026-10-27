//! 当前交互会话锁定适配。
//!
//! Windows 实现调用 `LockWorkStation` 锁定会话，并识别登录界面是否正在显示。策略判断与会话
//! 协作程序的启动由服务层负责，本模块只提供可替换的锁定动作和只读的界面状态。

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crate::error::PlatformError;

/// 登录界面进程名；控制台登录页和锁屏页都由它承载。
#[cfg(windows)]
const LOGON_UI_PROCESS_NAME: &str = "LogonUI.exe";

/// 判断登录界面是否正在显示。
///
/// 登录界面在开机未登录和交互会话锁定时都会出现，因此它为真表示当前没有已解锁的交互会话。
/// 服务据此保留一条只读的本地策略导入通道：登录界面必须能读到介质上的策略文件。
///
/// 检测方式是枚举进程快照。它不依赖 IPC 和会话枚举结果，服务重启后立即可用；代价是远程桌面
/// 会话也会让它为真，远程使用时不作为解锁依据。
#[cfg(windows)]
pub fn logon_ui_active() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(snapshot) => snapshot,
            Err(_) => return false,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..PROCESSENTRY32W::default()
        };
        let mut active = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                if name.eq_ignore_ascii_case(LOGON_UI_PROCESS_NAME) {
                    active = true;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        active
    }
}

/// 非 Windows 平台没有等价的登录界面概念，固定返回假。
#[cfg(not(windows))]
pub fn logon_ui_active() -> bool {
    false
}

/// 可交互登录的 Windows 会话状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractiveSessionState {
    /// 用户正在使用该桌面会话。
    Active,
    /// 用户会话仍可交互，但当前未处于前台。
    Connected,
}

/// 服务应维护协作程序的交互会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractiveSession {
    /// Windows 终端服务会话标识。
    pub id: u32,
    /// 会话当前状态。
    pub state: InteractiveSessionState,
}

impl InteractiveSession {
    /// 创建活动会话。
    pub const fn active(id: u32) -> Self {
        Self {
            id,
            state: InteractiveSessionState::Active,
        }
    }

    /// 创建已连接会话。
    pub const fn connected(id: u32) -> Self {
        Self {
            id,
            state: InteractiveSessionState::Connected,
        }
    }
}

/// 已启动协作程序的后端进程句柄。
///
/// 该值由 [`SessionAssistantLauncherBackend`] 创建和释放，调用方不应将其用于其他
/// Windows API。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionAssistantProcess(pub u64);

/// 用户会话协作程序的系统后端。
///
/// 通过该接口把 Windows 会话枚举、用户令牌与进程 API 隔离在计划器之外，服务测试可
/// 使用内存实现验证启动与重启策略。
pub trait SessionAssistantLauncherBackend {
    /// 返回需要运行协作程序的活动或已连接交互会话。
    fn interactive_sessions(&self) -> Result<Vec<InteractiveSession>, PlatformError>;

    /// 以给定会话对应的当前用户身份启动协作程序。
    fn start_session_assistant(
        &self,
        session_id: u32,
        executable: &Path,
    ) -> Result<SessionAssistantProcess, PlatformError>;

    /// 判断已启动的协作程序是否仍在运行。
    fn is_session_assistant_running(
        &self,
        process: SessionAssistantProcess,
    ) -> Result<bool, PlatformError>;

    /// 释放进程句柄；不会终止用户会话中的协作程序。
    fn release_session_assistant(&self, process: SessionAssistantProcess);

    /// 判断指定会话中是否已有桌面端进程。
    fn desktop_running(
        &self,
        session_id: u32,
        executable_name: &str,
    ) -> Result<bool, PlatformError>;

    /// 以指定会话用户身份启动桌面端；只负责启动，不保存长期句柄。
    fn start_desktop(&self, session_id: u32, executable: &Path) -> Result<(), PlatformError>;
}

/// 一轮协作程序会话协调的结果。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SessionAssistantLaunchReport {
    started: Vec<u32>,
    restarted: Vec<u32>,
    stopped: Vec<u32>,
}

impl SessionAssistantLaunchReport {
    /// 本轮首次启动协作程序的会话。
    pub fn started_sessions(&self) -> &[u32] {
        &self.started
    }

    /// 本轮检测到先前进程已退出并重新启动的会话。
    pub fn restarted_sessions(&self) -> &[u32] {
        &self.restarted
    }

    /// 本轮不再是可交互会话、已停止跟踪的会话。
    pub fn stopped_sessions(&self) -> &[u32] {
        &self.stopped
    }
}

/// 协调每个交互会话中唯一的 `anchor-session.exe` 进程。
///
/// 每次调用 [`Self::reconcile`] 都重新读取会话列表。仍存活的进程不会重复启动；进程
/// 已退出时，计划器会释放旧句柄并为该会话重新启动协作程序。
pub struct SessionAssistantLauncher<B: SessionAssistantLauncherBackend> {
    backend: B,
    executable: PathBuf,
    processes: BTreeMap<u32, SessionAssistantProcess>,
}

impl<B: SessionAssistantLauncherBackend> SessionAssistantLauncher<B> {
    /// 为指定协作程序创建会话协调器。
    pub fn new(backend: B, executable: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            executable: executable.into(),
            processes: BTreeMap::new(),
        }
    }

    /// 执行一轮会话协调。
    pub fn reconcile(&mut self) -> Result<SessionAssistantLaunchReport, PlatformError> {
        let interactive_sessions = self.backend.interactive_sessions()?;
        let session_ids = interactive_sessions
            .into_iter()
            .map(|session| session.id)
            .collect::<BTreeSet<_>>();
        let mut report = SessionAssistantLaunchReport::default();
        let mut restart = BTreeSet::new();

        for (session_id, process) in &self.processes {
            if !session_ids.contains(session_id) {
                report.stopped.push(*session_id);
                continue;
            }

            if !self.backend.is_session_assistant_running(*process)? {
                restart.insert(*session_id);
            }
        }

        for session_id in report.stopped.iter().chain(restart.iter()) {
            if let Some(process) = self.processes.remove(session_id) {
                self.backend.release_session_assistant(process);
            }
        }

        for session_id in session_ids {
            if self.processes.contains_key(&session_id) {
                continue;
            }

            let process = self
                .backend
                .start_session_assistant(session_id, &self.executable)?;
            self.processes.insert(session_id, process);
            if restart.contains(&session_id) {
                report.restarted.push(session_id);
            } else {
                report.started.push(session_id);
            }
        }

        Ok(report)
    }

    /// 读取正在跟踪的进程句柄，仅用于诊断或测试。
    pub fn process_for(&self, session_id: u32) -> Option<SessionAssistantProcess> {
        self.processes.get(&session_id).copied()
    }

    /// 读取底层系统后端。
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// 读取底层系统后端，以便测试模拟会话变化。
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

impl<B: SessionAssistantLauncherBackend> Drop for SessionAssistantLauncher<B> {
    fn drop(&mut self) {
        for process in self.processes.values().copied() {
            self.backend.release_session_assistant(process);
        }
    }
}

/// 协调每个交互会话中唯一的桌面端进程。
pub struct DesktopLauncher<B: SessionAssistantLauncherBackend> {
    backend: B,
    executable: PathBuf,
}

impl<B: SessionAssistantLauncherBackend> DesktopLauncher<B> {
    pub fn new(backend: B, executable: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            executable: executable.into(),
        }
    }

    /// 返回本轮实际启动桌面端的会话。
    pub fn reconcile(&mut self) -> Result<Vec<u32>, PlatformError> {
        let mut started = Vec::new();
        for session in self.backend.interactive_sessions()? {
            if self
                .backend
                .desktop_running(session.id, "anchor-guard.exe")?
            {
                continue;
            }
            self.backend.start_desktop(session.id, &self.executable)?;
            started.push(session.id);
        }
        Ok(started)
    }
}

/// 当前平台的会话枚举与协作程序启动后端。
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalSessionAssistantBackend;

impl SessionAssistantLauncherBackend for LocalSessionAssistantBackend {
    fn interactive_sessions(&self) -> Result<Vec<InteractiveSession>, PlatformError> {
        local_interactive_sessions()
    }

    fn start_session_assistant(
        &self,
        session_id: u32,
        executable: &Path,
    ) -> Result<SessionAssistantProcess, PlatformError> {
        start_local_session_assistant(session_id, executable)
    }

    fn is_session_assistant_running(
        &self,
        process: SessionAssistantProcess,
    ) -> Result<bool, PlatformError> {
        local_session_assistant_running(process)
    }

    fn release_session_assistant(&self, process: SessionAssistantProcess) {
        release_local_session_assistant(process);
    }

    fn desktop_running(
        &self,
        session_id: u32,
        executable_name: &str,
    ) -> Result<bool, PlatformError> {
        desktop_running(session_id, executable_name)
    }

    fn start_desktop(&self, session_id: u32, executable: &Path) -> Result<(), PlatformError> {
        let process = start_local_session_assistant(session_id, executable)?;
        release_local_session_assistant(process);
        Ok(())
    }
}

/// 当前交互会话的锁定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLockResult {
    /// Windows 已接受当前工作站的锁定请求。
    Locked,
}

/// 当前交互会话的锁定能力。
///
/// 服务层在授权拒绝后通过该接口发起锁定，并可在测试中替换实现。
pub trait SessionLocker: Send + Sync {
    /// 锁定当前交互会话。
    fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError>;
}

/// 当前平台的本地会话锁定实现。
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalSessionLocker;

impl SessionLocker for LocalSessionLocker {
    fn lock_current_session(&self) -> Result<SessionLockResult, PlatformError> {
        lock_current_session()
    }
}

#[cfg(windows)]
fn local_interactive_sessions() -> Result<Vec<InteractiveSession>, PlatformError> {
    let mut sessions_ptr = std::ptr::null_mut();
    let mut count = 0;
    let enumerated = unsafe {
        wts_enumerate_sessions_w(std::ptr::null_mut(), 0, 1, &mut sessions_ptr, &mut count)
    };
    if enumerated == 0 {
        return Err(PlatformError::Failed(
            "WTSEnumerateSessionsW 调用失败".into(),
        ));
    }
    if count == 0 {
        if !sessions_ptr.is_null() {
            unsafe { wts_free_memory(sessions_ptr.cast()) };
        }
        return Ok(Vec::new());
    }
    if sessions_ptr.is_null() {
        return Err(PlatformError::Failed(
            "WTSEnumerateSessionsW 返回了空会话列表指针".into(),
        ));
    }

    let sessions = unsafe { std::slice::from_raw_parts(sessions_ptr, count as usize) };
    // 登录界面也会以活动会话存在，但没有登录用户，此时无法取得用户令牌。
    // 协作程序只属于已登录用户，按用户名过滤可避免把登录界面误判为故障。
    let result = sessions
        .iter()
        .filter_map(|session| {
            let state = match session.state {
                WTS_ACTIVE => InteractiveSessionState::Active,
                WTS_CONNECTED => InteractiveSessionState::Connected,
                _ => return None,
            };
            session_user_name(session.session_id)?;
            Some(InteractiveSession {
                id: session.session_id,
                state,
            })
        })
        .collect();
    unsafe { wts_free_memory(sessions_ptr.cast()) };
    Ok(result)
}

#[cfg(not(windows))]
fn local_interactive_sessions() -> Result<Vec<InteractiveSession>, PlatformError> {
    Err(PlatformError::Unsupported(
        "Windows interactive session enumeration",
    ))
}

/// 当前活动会话的操作者：会话标识与登录用户名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOperator {
    pub session_id: u32,
    pub user: String,
}

/// 读取当前活动会话的登录用户名；没有活动会话或查询失败时返回 None。
///
/// 文件写入者无法在用户态可靠归属，因此调用方只应把该结果当作会话级近似。
#[cfg(windows)]
pub fn active_session_operator() -> Option<SessionOperator> {
    let sessions = local_interactive_sessions().ok()?;
    let session = sessions
        .iter()
        .find(|session| session.state == InteractiveSessionState::Active)?;
    let user = session_user_name(session.id)?;
    Some(SessionOperator {
        session_id: session.id,
        user,
    })
}

#[cfg(not(windows))]
pub fn active_session_operator() -> Option<SessionOperator> {
    None
}

/// 读取指定会话的登录用户名。
#[cfg(windows)]
fn session_user_name(session_id: u32) -> Option<String> {
    let mut buffer: *mut u16 = std::ptr::null_mut();
    let mut bytes = 0u32;
    let queried = unsafe {
        wts_query_session_information_w(
            std::ptr::null_mut(),
            session_id,
            WTS_USER_NAME,
            &mut buffer,
            &mut bytes,
        )
    };
    if queried == 0 || buffer.is_null() {
        return None;
    }
    let units = unsafe { std::slice::from_raw_parts(buffer, (bytes / 2) as usize) };
    let name = String::from_utf16_lossy(units)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    unsafe { wts_free_memory(buffer.cast()) };
    (!name.is_empty()).then_some(name)
}

#[cfg(windows)]
fn start_local_session_assistant(
    session_id: u32,
    executable: &Path,
) -> Result<SessionAssistantProcess, PlatformError> {
    use std::os::windows::ffi::OsStrExt;

    let executable = executable
        .canonicalize()
        .map_err(|error| PlatformError::Failed(format!("无法解析协作程序路径: {error}")))?;
    let mut user_token = 0;
    if unsafe { wts_query_user_token(session_id, &mut user_token) } == 0 {
        return Err(PlatformError::Failed(format!(
            "无法获取会话 {session_id} 的用户令牌"
        )));
    }
    let _user_token = HandleGuard(user_token);

    let mut primary_token = 0;
    if unsafe {
        duplicate_token_ex(
            user_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            std::ptr::null(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut primary_token,
        )
    } == 0
    {
        return Err(PlatformError::Failed(format!(
            "无法创建会话 {session_id} 的主令牌"
        )));
    }
    let _primary_token = HandleGuard(primary_token);

    let mut environment = std::ptr::null_mut();
    if unsafe { create_environment_block(&mut environment, primary_token, 0) } == 0 {
        return Err(PlatformError::Failed(format!(
            "无法创建会话 {session_id} 的用户环境"
        )));
    }
    let _environment = EnvironmentBlockGuard(environment);

    let application = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let desktop = "winsta0\\default\0".encode_utf16().collect::<Vec<_>>();
    let current_directory = executable
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut startup = StartupInfoW {
        cb: std::mem::size_of::<StartupInfoW>() as u32,
        desktop: desktop.as_ptr().cast_mut(),
        ..Default::default()
    };
    let mut process = ProcessInformation::default();
    let created = unsafe {
        create_process_as_user_w(
            primary_token,
            application.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment,
            current_directory.as_ptr(),
            &mut startup,
            &mut process,
        )
    };
    if created == 0 {
        return Err(PlatformError::Failed(format!(
            "无法在会话 {session_id} 中启动协作程序"
        )));
    }
    unsafe { close_handle(process.thread) };
    Ok(SessionAssistantProcess(process.process as u64))
}

#[cfg(not(windows))]
fn start_local_session_assistant(
    _session_id: u32,
    _executable: &Path,
) -> Result<SessionAssistantProcess, PlatformError> {
    Err(PlatformError::Unsupported(
        "Windows user session assistant launch",
    ))
}

#[cfg(windows)]
fn local_session_assistant_running(
    process: SessionAssistantProcess,
) -> Result<bool, PlatformError> {
    let mut exit_code = 0;
    if unsafe { get_exit_code_process(process.0 as isize, &mut exit_code) } == 0 {
        return Err(PlatformError::Failed("无法读取会话协作程序进程状态".into()));
    }
    Ok(exit_code == STILL_ACTIVE)
}

#[cfg(windows)]
fn desktop_running(session_id: u32, executable_name: &str) -> Result<bool, PlatformError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|error| PlatformError::Failed(format!("枚举桌面端进程失败: {error}")))?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..PROCESSENTRY32W::default()
        };
        let mut found = false;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                if name.eq_ignore_ascii_case(executable_name) {
                    let mut process_session = 0;
                    if process_id_to_session_id(entry.th32ProcessID, &mut process_session) != 0
                        && process_session == session_id
                    {
                        found = true;
                        break;
                    }
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        Ok(found)
    }
}

#[cfg(not(windows))]
fn desktop_running(_session_id: u32, _executable_name: &str) -> Result<bool, PlatformError> {
    Err(PlatformError::Unsupported("Windows desktop process query"))
}

#[cfg(not(windows))]
fn local_session_assistant_running(
    _process: SessionAssistantProcess,
) -> Result<bool, PlatformError> {
    Err(PlatformError::Unsupported(
        "Windows user session assistant process query",
    ))
}

#[cfg(windows)]
fn release_local_session_assistant(process: SessionAssistantProcess) {
    unsafe { close_handle(process.0 as isize) };
}

#[cfg(not(windows))]
fn release_local_session_assistant(_process: SessionAssistantProcess) {}

#[cfg(windows)]
struct HandleGuard(isize);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { close_handle(self.0) };
    }
}

#[cfg(windows)]
struct EnvironmentBlockGuard(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for EnvironmentBlockGuard {
    fn drop(&mut self) {
        unsafe { destroy_environment_block(self.0) };
    }
}

#[cfg(windows)]
const WTS_ACTIVE: i32 = 0;
/// `WTSQuerySessionInformationW` 的用户名信息类别。
const WTS_USER_NAME: u32 = 5;
#[cfg(windows)]
const WTS_CONNECTED: i32 = 1;
#[cfg(windows)]
const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
#[cfg(windows)]
const TOKEN_DUPLICATE: u32 = 0x0002;
#[cfg(windows)]
const TOKEN_QUERY: u32 = 0x0008;
#[cfg(windows)]
const SECURITY_IMPERSONATION: u32 = 2;
#[cfg(windows)]
const TOKEN_PRIMARY: u32 = 1;
#[cfg(windows)]
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const STILL_ACTIVE: u32 = 259;

#[cfg(windows)]
#[repr(C)]
struct WtsSessionInfoW {
    session_id: u32,
    station_name: *mut u16,
    state: i32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_count: u16,
    reserved2: *mut u8,
    std_input: isize,
    std_output: isize,
    std_error: isize,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct ProcessInformation {
    process: isize,
    thread: isize,
    process_id: u32,
    thread_id: u32,
}

#[cfg(windows)]
#[link(name = "wtsapi32")]
extern "system" {
    #[link_name = "WTSEnumerateSessionsW"]
    fn wts_enumerate_sessions_w(
        server: *mut std::ffi::c_void,
        reserved: u32,
        version: u32,
        sessions: *mut *mut WtsSessionInfoW,
        count: *mut u32,
    ) -> i32;
    #[link_name = "WTSQueryUserToken"]
    fn wts_query_user_token(session_id: u32, token: *mut isize) -> i32;
    #[link_name = "WTSQuerySessionInformationW"]
    fn wts_query_session_information_w(
        server: *mut std::ffi::c_void,
        session_id: u32,
        info_class: u32,
        buffer: *mut *mut u16,
        bytes_returned: *mut u32,
    ) -> i32;
    #[link_name = "WTSFreeMemory"]
    fn wts_free_memory(memory: *mut std::ffi::c_void);
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    #[link_name = "DuplicateTokenEx"]
    fn duplicate_token_ex(
        existing_token: isize,
        desired_access: u32,
        token_attributes: *const std::ffi::c_void,
        impersonation_level: u32,
        token_type: u32,
        new_token: *mut isize,
    ) -> i32;
    #[link_name = "CreateProcessAsUserW"]
    fn create_process_as_user_w(
        token: isize,
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *const std::ffi::c_void,
        thread_attributes: *const std::ffi::c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *mut std::ffi::c_void,
        current_directory: *const u16,
        startup_info: *mut StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "userenv")]
extern "system" {
    #[link_name = "CreateEnvironmentBlock"]
    fn create_environment_block(
        environment: *mut *mut std::ffi::c_void,
        token: isize,
        inherit: i32,
    ) -> i32;
    #[link_name = "DestroyEnvironmentBlock"]
    fn destroy_environment_block(environment: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "CloseHandle"]
    fn close_handle(handle: isize) -> i32;
    #[link_name = "GetExitCodeProcess"]
    fn get_exit_code_process(process: isize, exit_code: *mut u32) -> i32;
    #[link_name = "ProcessIdToSessionId"]
    fn process_id_to_session_id(process_id: u32, session_id: *mut u32) -> i32;
}

#[cfg(windows)]
fn lock_current_session() -> Result<SessionLockResult, PlatformError> {
    if unsafe { lock_work_station() } == 0 {
        return Err(PlatformError::Failed("LockWorkStation 调用失败".into()));
    }
    Ok(SessionLockResult::Locked)
}

#[cfg(not(windows))]
fn lock_current_session() -> Result<SessionLockResult, PlatformError> {
    Err(PlatformError::Unsupported(
        "Windows workstation session lock",
    ))
}

#[cfg(windows)]
#[link(name = "user32")]
extern "system" {
    #[link_name = "LockWorkStation"]
    fn lock_work_station() -> i32;
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeSet, path::Path};

    use super::{
        DesktopLauncher, InteractiveSession, SessionAssistantLauncher,
        SessionAssistantLauncherBackend, SessionAssistantProcess,
    };

    #[derive(Default)]
    struct TestLauncherBackend {
        sessions: Vec<InteractiveSession>,
        next_process: u64,
        running: RefCell<BTreeSet<SessionAssistantProcess>>,
        starts: RefCell<Vec<(u32, String)>>,
        released: RefCell<Vec<SessionAssistantProcess>>,
        desktop_running: RefCell<BTreeSet<u32>>,
        desktop_starts: RefCell<Vec<u32>>,
    }

    impl TestLauncherBackend {
        fn with_sessions(sessions: Vec<InteractiveSession>) -> Self {
            Self {
                sessions,
                next_process: 1,
                ..Self::default()
            }
        }

        fn mark_exited(&self, process: SessionAssistantProcess) {
            self.running.borrow_mut().remove(&process);
        }
    }

    impl SessionAssistantLauncherBackend for TestLauncherBackend {
        fn interactive_sessions(
            &self,
        ) -> Result<Vec<InteractiveSession>, crate::error::PlatformError> {
            Ok(self.sessions.clone())
        }

        fn start_session_assistant(
            &self,
            session_id: u32,
            executable: &Path,
        ) -> Result<SessionAssistantProcess, crate::error::PlatformError> {
            let process =
                SessionAssistantProcess(self.next_process + self.starts.borrow().len() as u64);
            self.starts
                .borrow_mut()
                .push((session_id, executable.display().to_string()));
            self.running.borrow_mut().insert(process);
            Ok(process)
        }

        fn is_session_assistant_running(
            &self,
            process: SessionAssistantProcess,
        ) -> Result<bool, crate::error::PlatformError> {
            Ok(self.running.borrow().contains(&process))
        }

        fn release_session_assistant(&self, process: SessionAssistantProcess) {
            self.released.borrow_mut().push(process);
        }

        fn desktop_running(
            &self,
            session_id: u32,
            _executable_name: &str,
        ) -> Result<bool, crate::error::PlatformError> {
            Ok(self.desktop_running.borrow().contains(&session_id))
        }

        fn start_desktop(
            &self,
            session_id: u32,
            _executable: &Path,
        ) -> Result<(), crate::error::PlatformError> {
            self.desktop_starts.borrow_mut().push(session_id);
            Ok(())
        }
    }

    #[test]
    fn desktop_launcher_starts_only_missing_sessions() {
        let backend = TestLauncherBackend::with_sessions(vec![
            InteractiveSession::active(1),
            InteractiveSession::active(2),
        ]);
        backend.desktop_running.borrow_mut().insert(1);
        let mut launcher = DesktopLauncher::new(backend, "anchor-guard.exe");

        let started = launcher.reconcile().unwrap();

        assert_eq!(started, vec![2]);
        assert_eq!(launcher.backend.desktop_starts.borrow().as_slice(), &[2]);
    }

    #[test]
    fn launcher_starts_an_assistant_once_for_each_interactive_session() {
        let backend = TestLauncherBackend::with_sessions(vec![
            InteractiveSession::active(1),
            InteractiveSession::connected(2),
        ]);
        let mut launcher = SessionAssistantLauncher::new(
            backend,
            "C:\\Program Files\\Anchor Guard\\anchor-session.exe",
        );

        let first = launcher.reconcile().unwrap();
        let second = launcher.reconcile().unwrap();

        assert_eq!(first.started_sessions(), &[1, 2]);
        assert!(second.started_sessions().is_empty());
        assert_eq!(launcher.backend().starts.borrow().len(), 2);
    }

    #[test]
    fn launcher_restarts_an_assistant_after_its_process_exits() {
        let backend = TestLauncherBackend::with_sessions(vec![InteractiveSession::active(7)]);
        let mut launcher = SessionAssistantLauncher::new(backend, "anchor-session.exe");

        launcher.reconcile().unwrap();
        launcher
            .backend()
            .mark_exited(launcher.process_for(7).unwrap());
        let second = launcher.reconcile().unwrap();

        assert_eq!(second.restarted_sessions(), &[7]);
        assert_eq!(launcher.backend().starts.borrow().len(), 2);
        assert_eq!(launcher.backend().released.borrow().len(), 1);
    }

    #[test]
    fn launcher_stops_tracking_sessions_that_are_no_longer_interactive() {
        let backend = TestLauncherBackend::with_sessions(vec![InteractiveSession::active(3)]);
        let mut launcher = SessionAssistantLauncher::new(backend, "anchor-session.exe");
        launcher.reconcile().unwrap();
        let process = launcher.process_for(3).unwrap();
        launcher.backend_mut().sessions.clear();

        let report = launcher.reconcile().unwrap();

        assert_eq!(report.stopped_sessions(), &[3]);
        assert_eq!(launcher.backend().released.borrow().as_slice(), &[process]);
    }

    #[cfg(not(windows))]
    #[test]
    fn local_assistant_launcher_backend_reports_unsupported_outside_windows() {
        assert!(matches!(
            super::LocalSessionAssistantBackend.interactive_sessions(),
            Err(crate::error::PlatformError::Unsupported(
                "Windows interactive session enumeration"
            ))
        ));
    }

    #[test]
    fn session_locker_interface_reports_a_locked_result() {
        struct TestLocker;

        impl super::SessionLocker for TestLocker {
            fn lock_current_session(
                &self,
            ) -> Result<super::SessionLockResult, crate::error::PlatformError> {
                Ok(super::SessionLockResult::Locked)
            }
        }

        let result = super::SessionLocker::lock_current_session(&TestLocker).unwrap();

        assert_eq!(result, super::SessionLockResult::Locked);
    }

    #[cfg(not(windows))]
    #[test]
    fn local_session_locker_reports_unsupported_outside_windows() {
        assert!(matches!(
            super::SessionLocker::lock_current_session(&super::LocalSessionLocker),
            Err(crate::error::PlatformError::Unsupported(
                "Windows workstation session lock"
            ))
        ));
    }
}
