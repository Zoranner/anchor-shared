use std::{path::PathBuf, process::ExitCode};

use anchor_setup::write_service_config;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "anchor-setup", about = "Anchor Guard 安装配置工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 写入 Windows 服务使用的本地配置文件。
    WriteServiceConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        database: PathBuf,
        /// 本机审计用标识；省略时使用已有配置或自动生成。
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        verifying_key_hex: String,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::WriteServiceConfig {
            config,
            database,
            device_id,
            verifying_key_hex,
        } => {
            match write_service_config(&config, &database, device_id.as_deref(), &verifying_key_hex)
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("错误: {error:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
