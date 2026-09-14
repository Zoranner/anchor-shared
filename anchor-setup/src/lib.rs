use std::{
    fs::{self, File},
    path::Path,
};

use anyhow::{bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
struct ServiceConfig<'a> {
    database: &'a Path,
    verifying_key_hex: &'a str,
    device_id: &'a str,
}

/// 校验安装输入并原子写入服务配置，私钥不会经过该接口。
///
/// 未提供设备标识时沿用已有配置中的标识；首次安装也没有提供时生成一个本机标识。
pub fn write_service_config(
    config_path: &Path,
    database_path: &Path,
    device_id: Option<&str>,
    verifying_key_hex: &str,
) -> Result<()> {
    validate_verifying_key(verifying_key_hex)?;
    let device_id = resolve_device_id(config_path, device_id)?;
    let parent = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("配置文件路径必须包含父目录"))?;
    fs::create_dir_all(parent).with_context(|| format!("无法创建配置目录 {}", parent.display()))?;

    let content = toml::to_string(&ServiceConfig {
        database: database_path,
        verifying_key_hex,
        device_id: &device_id,
    })?;
    let temporary_path = config_path.with_extension(format!(
        "{}.tmp",
        config_path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
    ));
    fs::write(&temporary_path, content)
        .with_context(|| format!("无法写入临时配置 {}", temporary_path.display()))?;
    File::options()
        .write(true)
        .open(&temporary_path)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("无法同步临时配置 {}", temporary_path.display()))?;
    if let Err(error) = replace_file(&temporary_path, config_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    Ok(())
}

/// 设备标识优先使用显式输入，其次沿用已有配置，最后生成一个本机唯一标识。
fn resolve_device_id(config_path: &Path, requested: Option<&str>) -> Result<String> {
    if let Some(device_id) = requested.map(str::trim).filter(|value| !value.is_empty()) {
        validate_device_id(device_id)?;
        return Ok(device_id.to_string());
    }
    if let Some(existing) = existing_device_id(config_path) {
        return Ok(existing);
    }
    Ok(format!("device-{}", Uuid::new_v4()))
}

fn existing_device_id(config_path: &Path) -> Option<String> {
    let content = fs::read_to_string(config_path).ok()?;
    let parsed: toml::Value = toml::from_str(&content).ok()?;
    let device_id = parsed.get("device_id")?.as_str()?.trim();
    (!device_id.is_empty()).then(|| device_id.to_string())
}

fn validate_device_id(device_id: &str) -> Result<()> {
    if device_id.trim().is_empty() || device_id.contains(['\r', '\n']) {
        bail!("device_id 不能为空且不得包含换行符");
    }
    Ok(())
}

fn validate_verifying_key(verifying_key_hex: &str) -> Result<()> {
    let bytes = hex::decode(verifying_key_hex).context("管理员验证公钥不是十六进制")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("管理员验证公钥必须是 32 字节"))?;
    VerifyingKey::from_bytes(&bytes).context("管理员验证公钥无效")?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temporary_path: &Path, config_path: &Path) -> Result<()> {
    fs::rename(temporary_path, config_path).with_context(|| {
        format!(
            "无法将临时配置 {} 替换为 {}",
            temporary_path.display(),
            config_path.display()
        )
    })
}

#[cfg(windows)]
fn replace_file(temporary_path: &Path, config_path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        },
    };

    let temporary: Vec<u16> = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let config: Vec<u16> = config_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(temporary.as_ptr()),
            PCWSTR(config.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .with_context(|| {
        format!(
            "无法将临时配置 {} 替换为 {}",
            temporary_path.display(),
            config_path.display()
        )
    })
}
