use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anchor_core::{
    crypto, ActionPolicy, BurningRules, NetworkRules, PolicyPackage, PolicyPayload, ScanRules,
    UsbRules,
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
    },
}

#[derive(Deserialize)]
struct PolicyConfig {
    policy_id: String,
    version: u64,
    device_id: String,
    effective_from: String,
    effective_until: String,
    clock_rollback_tolerance_secs: i64,
    usb: UsbRules,
    network: NetworkRules,
    burning: BurningRules,
    scan: ScanRules,
}

impl PolicyConfig {
    fn into_payload(self) -> Result<PolicyPayload> {
        if self.policy_id.trim().is_empty() {
            bail!("policy_id 不能为空");
        }
        if self.device_id.trim().is_empty() {
            bail!("device_id 不能为空");
        }
        if self.clock_rollback_tolerance_secs < 0 {
            bail!("clock_rollback_tolerance_secs 不能为负数");
        }
        if self.scan.controlled_dirs.is_empty() {
            bail!("scan.controlled_dirs 不能为空");
        }
        if !has_allow_rule(&self.usb, &self.network, &self.burning) {
            bail!("策略至少需要一条明确允许的受控设备规则");
        }

        let effective_from = parse_time(&self.effective_from, "effective_from")?;
        let effective_until = parse_time(&self.effective_until, "effective_until")?;
        if effective_until <= effective_from {
            bail!("effective_until 必须晚于 effective_from");
        }

        Ok(PolicyPayload {
            policy_id: self.policy_id,
            version: self.version,
            device_id: self.device_id,
            effective_from,
            effective_until,
            clock_rollback_tolerance_secs: self.clock_rollback_tolerance_secs as u64,
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
        Command::Sign { key, config, out } => sign(key, config, out),
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

fn sign(key_path: PathBuf, config_path: PathBuf, out: PathBuf) -> Result<()> {
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
    let package = PolicyPackage::sign(config.into_payload()?, &signing_key)?;
    let content = serde_json::to_vec_pretty(&package)?;
    fs::write(&out, content).with_context(|| format!("无法写入策略包 {}", out.display()))?;
    Ok(())
}

fn parse_time(value: &str, field: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{field} 不是 RFC 3339 时间"))?
        .with_timezone(&Utc))
}

fn has_allow_rule(usb: &UsbRules, network: &NetworkRules, burning: &BurningRules) -> bool {
    matches!(usb.read, ActionPolicy::Allow)
        || matches!(usb.write, ActionPolicy::Allow)
        || matches!(network.policy, ActionPolicy::Allow)
        || matches!(burning.policy, ActionPolicy::Allow)
}
