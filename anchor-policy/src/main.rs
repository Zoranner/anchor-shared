use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anchor_core::{
    crypto, ActionPolicy, BurningRules, NetworkRules, PolicyPackage, PolicyPayload, ScanRules,
    UsbAllowRule, UsbRules,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "anchor-policy", about = "Anchor Guard 离线策略签发工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 生成管理员离线保存的 Ed25519 密钥对。
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// 从 TOML 配置签发策略包。
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// 确认这份策略不保留管理介质：设备此后只能离线改盘或重装才能更新。
        #[arg(long)]
        no_admin_media: bool,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    version: u64,
    expires_at: String,
    usb: UsbRules,
    network: NetworkRules,
    burning: BurningRules,
    scan: ScanRules,
}

impl PolicyConfig {
    fn into_payload(self, no_admin_media: bool) -> Result<PolicyPayload> {
        validate_allowed_objects(&self.usb, &self.network, &self.burning)?;
        validate_file_types(&self.scan)?;
        validate_admin_media(&self.usb, &self.burning, no_admin_media)?;

        let expires_at = parse_time(&self.expires_at, "expires_at")?;

        Ok(PolicyPayload {
            version: self.version,
            expires_at,
            usb: self.usb,
            network: self.network,
            burning: self.burning,
            scan: self.scan,
        })
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen { out } => keygen(out),
        Command::Sign {
            key,
            config,
            out,
            no_admin_media,
        } => sign(key, config, out, no_admin_media),
    }
}

fn keygen(out: PathBuf) -> Result<()> {
    fs::create_dir_all(&out).with_context(|| format!("无法创建密钥目录 {}", out.display()))?;
    let signing_path = out.join("signing-key.hex");
    let verifying_path = out.join("verifying-key.hex");
    if signing_path.exists() || verifying_path.exists() {
        bail!("密钥文件已存在，拒绝覆盖");
    }

    let (signing_key, verifying_key) = crypto::generate_keypair();
    fs::write(
        &signing_path,
        format!("{}\n", crypto::signing_key_to_hex(&signing_key)),
    )
    .with_context(|| format!("无法写入 {}", signing_path.display()))?;
    fs::write(
        &verifying_path,
        format!("{}\n", crypto::verifying_key_to_hex(&verifying_key)),
    )
    .with_context(|| format!("无法写入 {}", verifying_path.display()))?;
    Ok(())
}

fn sign(key_path: PathBuf, config_path: PathBuf, out: PathBuf, no_admin_media: bool) -> Result<()> {
    let signing_key = crypto::signing_key_from_hex(
        fs::read_to_string(&key_path)
            .with_context(|| format!("无法读取私钥 {}", key_path.display()))?
            .trim(),
    )?;
    let config: PolicyConfig = toml::from_str(
        &fs::read_to_string(&config_path)
            .with_context(|| format!("无法读取策略配置 {}", config_path.display()))?,
    )
    .with_context(|| format!("策略配置不是有效 TOML: {}", config_path.display()))?;
    let package = PolicyPackage::sign(config.into_payload(no_admin_media)?, &signing_key)?;
    let content = serde_json::to_vec_pretty(&package)?;
    fs::write(&out, content).with_context(|| format!("无法写入策略包 {}", out.display()))?;
    Ok(())
}

fn parse_time(value: &str, field: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{field} 不是 RFC 3339 时间"))?
        .with_timezone(&Utc))
}

/// 文件类型声明只要求非空；大小写与前导点由设备端归一化处理。
fn validate_file_types(scan: &anchor_core::ScanRules) -> Result<()> {
    for (index, file_type) in scan.file_types.iter().enumerate() {
        if file_type.trim().trim_start_matches('.').is_empty() {
            bail!("scan.file_types[{index}] 不能为空");
        }
    }
    Ok(())
}

/// 策略必须保留一条管理员更新通道：放行至少一支管理介质。
///
/// 物理机上没有可挂载的固定卷，内部盘又要进入系统才能写入；一旦把 USB 大容量存储和刻录
/// 全部禁掉，设备就只能靠离线改盘或重装才能拿到新策略。因此签发时要求显式放行一支管理介质
/// （`usb.allowed` 或 `burning.allowed` 非空），确需完全锁死时用 `--no-admin-media` 明确接受。
fn validate_admin_media(
    usb: &UsbRules,
    burning: &BurningRules,
    no_admin_media: bool,
) -> Result<()> {
    if no_admin_media {
        return Ok(());
    }
    if usb.allowed.is_empty() && burning.allowed.is_empty() {
        bail!(
            "策略必须放行至少一支管理介质（usb.allowed 或 burning.allowed 非空），否则设备失去策略更新通道；确需完全锁死时加 --no-admin-media"
        );
    }
    Ok(())
}

fn validate_allowed_objects(
    usb: &UsbRules,
    network: &NetworkRules,
    burning: &BurningRules,
) -> Result<()> {
    if (matches!(usb.read, ActionPolicy::Allow) || matches!(usb.write, ActionPolicy::Allow))
        && usb.allowed.is_empty()
    {
        bail!("usb 允许读取或写入时 usb.allowed 不能为空");
    }
    if matches!(network.policy, ActionPolicy::Allow) && network.allowed.is_empty() {
        bail!("network.policy 为 allow 时 network.allowed 不能为空");
    }
    if matches!(burning.policy, ActionPolicy::Allow) && burning.allowed.is_empty() {
        bail!("burning.policy 为 allow 时 burning.allowed 不能为空");
    }

    for (index, rule) in usb.allowed.iter().enumerate() {
        validate_usb_allow_rule(rule, index)?;
    }
    for (index, rule) in network.allowed.iter().enumerate() {
        if rule.adapter_id.trim().is_empty() {
            bail!("network.allowed[{index}].adapter_id 不能为空");
        }
    }
    for (index, rule) in burning.allowed.iter().enumerate() {
        if rule.drive_id.trim().is_empty() {
            bail!("burning.allowed[{index}].drive_id 不能为空");
        }
    }

    Ok(())
}

fn validate_usb_allow_rule(rule: &UsbAllowRule, index: usize) -> Result<()> {
    let fields = [
        ("instance_id", rule.instance_id.as_deref()),
        ("vendor_id", rule.vendor_id.as_deref()),
        ("product_id", rule.product_id.as_deref()),
        ("serial", rule.serial.as_deref()),
    ];
    if fields.iter().all(|(_, value)| value.is_none()) {
        bail!("usb.allowed[{index}] 至少需要 instance_id、vendor_id、product_id 或 serial 之一");
    }
    for (field, value) in fields {
        if value.is_some_and(|value| value.trim().is_empty()) {
            bail!("usb.allowed[{index}].{field} 不能为空白字符串");
        }
    }

    Ok(())
}
