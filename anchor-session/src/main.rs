#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    use anchor_session::{AnchorPipeAuthorizationClient, SessionAssistant};
    use anchor_system::session::LocalSessionLocker;

    let assistant = SessionAssistant::new(AnchorPipeAuthorizationClient, LocalSessionLocker);
    assistant.run_forever();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("anchor-session 仅支持 Windows 用户会话");
    std::process::exit(1);
}
