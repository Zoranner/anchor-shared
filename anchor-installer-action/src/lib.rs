//! 安装期自定义动作：从 MSI 的 CustomActionData 属性读取安装输入并写入服务配置。
//!
//! Windows Installer 只在脚本执行期向延迟自定义动作开放 CustomActionData、ProductCode
//! 和 UserSID 三个属性，因此安装输入必须由前置的 SetProperty 动作合并成一个数据串。
//! 数据串按分号分隔，每项形如 `键=值`，值按原样传递，不做转义，即值中不得出现分号。

use std::path::Path;

use anchor_setup::write_service_config;
use anyhow::{bail, Context, Result};

/// 数据串各项的分隔符。
const ENTRY_SEPARATOR: char = ';';

const KEY_CONFIG: &str = "config";
const KEY_DATABASE: &str = "database";
const KEY_DEVICE_ID: &str = "device_id";
const KEY_VERIFYING_KEY_HEX: &str = "verifying_key_hex";

/// 安装期传入的服务配置输入。
#[derive(Debug, PartialEq, Eq)]
pub struct ActionData<'a> {
    pub config_path: &'a str,
    pub database_path: &'a str,
    pub device_id: Option<&'a str>,
    pub verifying_key_hex: &'a str,
}

/// 解析安装输入数据串。
///
/// 未知键、重复键、缺失的必填项和含分隔符的值都会直接失败，避免按错误输入写入配置。
pub fn parse_action_data(raw: &str) -> Result<ActionData<'_>> {
    let mut config_path = None;
    let mut database_path = None;
    let mut device_id = None;
    let mut verifying_key_hex = None;

    for entry in raw.split(ENTRY_SEPARATOR) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').with_context(|| {
            format!("安装输入项缺少等号，值中不能包含分隔符 {ENTRY_SEPARATOR}: {entry}")
        })?;
        match key.trim() {
            KEY_CONFIG => set_once(&mut config_path, value.trim(), KEY_CONFIG)?,
            KEY_DATABASE => set_once(&mut database_path, value.trim(), KEY_DATABASE)?,
            KEY_DEVICE_ID => set_once(&mut device_id, value.trim(), KEY_DEVICE_ID)?,
            KEY_VERIFYING_KEY_HEX => {
                set_once(&mut verifying_key_hex, value.trim(), KEY_VERIFYING_KEY_HEX)?
            }
            other => {
                bail!("安装输入包含未知键，值中不能包含分隔符 {ENTRY_SEPARATOR}: {other}")
            }
        }
    }

    Ok(ActionData {
        config_path: required(config_path, KEY_CONFIG)?,
        database_path: required(database_path, KEY_DATABASE)?,
        device_id: device_id.filter(|value| !value.is_empty()),
        verifying_key_hex: required(verifying_key_hex, KEY_VERIFYING_KEY_HEX)?,
    })
}

/// 按安装输入写入服务配置；未提供设备标识时沿用已有配置或生成一个本机标识。
pub fn apply_action_data(raw: &str) -> Result<()> {
    let data = parse_action_data(raw)?;
    write_service_config(
        Path::new(data.config_path),
        Path::new(data.database_path),
        data.device_id,
        data.verifying_key_hex,
    )
}

fn set_once<'a>(slot: &mut Option<&'a str>, value: &'a str, key: &str) -> Result<()> {
    if slot.is_some() {
        bail!("安装输入重复包含键: {key}");
    }
    *slot = Some(value);
    Ok(())
}

fn required<'a>(slot: Option<&'a str>, key: &str) -> Result<&'a str> {
    slot.filter(|value| !value.is_empty())
        .with_context(|| format!("安装输入缺少必填项: {key}"))
}

#[cfg(windows)]
mod installer {
    use std::path::PathBuf;

    use anyhow::{bail, Result};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::System::ApplicationInstallationAndServicing::{MsiGetPropertyW, MSIHANDLE};

    use super::apply_action_data;

    /// 延迟自定义动作在执行期唯一能读取的数据属性。
    const ACTION_DATA_PROPERTY: &str = "CustomActionData";
    /// Windows Installer 的缓冲区不足错误码。
    const ERROR_MORE_DATA: u32 = 234;
    /// 安装输入长度上限，避免异常数据无限扩容。
    const MAX_DATA_LENGTH: u32 = 64 * 1024;
    /// Windows Installer 的“安装失败”错误码。
    const ERROR_INSTALL_FAILURE: u32 = 1603;
    /// 失败原因记录文件名，与 `service.toml` 同目录。
    const FAILURE_NOTE: &str = "setup-action-error.log";

    /// MSI 自定义动作入口：写入服务配置，成功返回 0，失败返回 MSI 错误码。
    ///
    /// 这个函数由 msiexec 直接调用，因此不向外抛出 panic，失败原因写在配置目录的
    /// `setup-action-error.log`，便于在 MSI 日志之外定位。
    #[no_mangle]
    pub extern "system" fn AnchorWriteServiceConfig(h_install: MSIHANDLE) -> u32 {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            read_action_data(h_install).and_then(|raw| apply_action_data(&raw))
        }));
        match outcome {
            Ok(Ok(())) => {
                clear_failure_note();
                0
            }
            Ok(Err(error)) => {
                write_failure_note(&format!("{error:#}"));
                ERROR_INSTALL_FAILURE
            }
            Err(_) => {
                write_failure_note("安装动作内部错误");
                ERROR_INSTALL_FAILURE
            }
        }
    }

    fn read_action_data(h_install: MSIHANDLE) -> Result<String> {
        let name: Vec<u16> = ACTION_DATA_PROPERTY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut capacity = 1024u32;
        loop {
            let mut buffer = vec![0u16; capacity as usize];
            let mut length = capacity;
            let status = unsafe {
                MsiGetPropertyW(
                    h_install,
                    PCWSTR(name.as_ptr()),
                    Some(PWSTR(buffer.as_mut_ptr())),
                    Some(&mut length),
                )
            };
            if status == 0 {
                let length = (length as usize).min(buffer.len());
                return Ok(String::from_utf16_lossy(&buffer[..length]));
            }
            if status != ERROR_MORE_DATA {
                bail!("无法读取 {ACTION_DATA_PROPERTY} 属性，Windows Installer 错误码 {status}");
            }
            if length >= MAX_DATA_LENGTH {
                bail!("{ACTION_DATA_PROPERTY} 超过 {MAX_DATA_LENGTH} 个字符");
            }
            capacity = length + 1;
        }
    }

    fn failure_note_path() -> Option<PathBuf> {
        let directory = PathBuf::from(std::env::var_os("ProgramData")?).join("Anchor Guard");
        directory.is_dir().then(|| directory.join(FAILURE_NOTE))
    }

    fn write_failure_note(message: &str) {
        if let Some(path) = failure_note_path() {
            let _ = std::fs::write(path, format!("{message}\r\n"));
        }
    }

    fn clear_failure_note() {
        if let Some(path) = failure_note_path() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(windows)]
pub use installer::AnchorWriteServiceConfig;

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFYING_KEY_HEX: &str =
        "f0951b88b7646461aa6f989d70c323130ddc8f0d1650224650ec906579c0866a";

    fn action_data(device_id: &str) -> String {
        format!(
            "config=C:\\ProgramData\\Anchor Guard\\service.toml;\
             database=C:\\ProgramData\\Anchor Guard\\audit.db;\
             device_id={device_id};verifying_key_hex={VERIFYING_KEY_HEX}"
        )
    }

    #[test]
    fn parses_install_input() {
        let raw = action_data("laptop-1");
        let data = parse_action_data(&raw).unwrap();
        assert_eq!(
            data.config_path,
            "C:\\ProgramData\\Anchor Guard\\service.toml"
        );
        assert_eq!(
            data.database_path,
            "C:\\ProgramData\\Anchor Guard\\audit.db"
        );
        assert_eq!(data.device_id, Some("laptop-1"));
        assert_eq!(data.verifying_key_hex, VERIFYING_KEY_HEX);
    }

    #[test]
    fn treats_empty_device_id_as_absent() {
        let raw = action_data("");
        assert_eq!(parse_action_data(&raw).unwrap().device_id, None);
    }

    #[test]
    fn rejects_missing_required_entry() {
        let raw = action_data("laptop-1")
            .split(';')
            .filter(|entry| !entry.starts_with(KEY_DATABASE))
            .collect::<Vec<_>>()
            .join(";");
        let error = parse_action_data(&raw).unwrap_err();
        assert!(error.to_string().contains(KEY_DATABASE), "{error}");
    }

    #[test]
    fn rejects_value_containing_separator() {
        let error = parse_action_data(&action_data("lap;top")).unwrap_err();
        assert!(error.to_string().contains("分隔符"), "{error}");
    }

    #[test]
    fn rejects_unknown_and_duplicate_entry() {
        let unknown =
            parse_action_data(&format!("{};extra=1", action_data("laptop-1"))).unwrap_err();
        assert!(unknown.to_string().contains("未知键"), "{unknown}");

        let duplicate = parse_action_data(&format!(
            "{};config=D:\\other.toml",
            action_data("laptop-1")
        ))
        .unwrap_err();
        assert!(duplicate.to_string().contains("重复"), "{duplicate}");
    }

    #[test]
    fn applies_install_input_to_config() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("service.toml");
        let database = directory.path().join("audit.db");
        let raw = format!(
            "config={};database={};device_id=;verifying_key_hex={VERIFYING_KEY_HEX}",
            config.display(),
            database.display()
        );

        apply_action_data(&raw).unwrap();

        let content = std::fs::read_to_string(&config).unwrap();
        assert!(content.contains(VERIFYING_KEY_HEX), "{content}");
        assert!(content.contains("device-"), "{content}");
    }
}
