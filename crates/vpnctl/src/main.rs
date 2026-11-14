//! `vpnctl`: command-line companion of VPN Manager.
//!
//! Everything except `ssh-proxy` is the VPN Web API over the controller's `api.sock`
//! (HTTP/1.1 on a Unix socket that serves only this user): the same operations, validation,
//! idempotency and errors as the web UI. Human output is Traditional Chinese; `--json` prints the
//! API's JSON. Exit codes: 0 done, 1 failed, 2 usage (including a missing confirmation or an
//! ambiguous name), 3 unknown outcome (a change may or may not have happened; it was not sent
//! again).
//!
//! `vpnctl ssh-proxy` is the `ProxyCommand` of SSH hosts routed through a Gateway (see
//! `cmd/ssh.rs`); it does not use the API socket.

// A `pub` item of a program that nothing uses is dead code all the same (off by default).
#![deny(dead_code_pub_in_binary)]

mod client;
mod cmd;
mod output;
mod prompt;
mod resolve;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::cmd::{CmdResult, Ctx, Exit};

#[derive(Parser, Debug)]
#[command(
    name = "vpnctl",
    version,
    about = "VPN Manager 命令列工具（經 controller 的 api.sock）",
    after_help = "結束碼：0 完成、1 失敗、2 用法錯誤（含缺少確認旗標、名稱不唯一）、3 結果未知（沒有重送）"
)]
pub struct Cli {
    /// VPN Manager 的資料目錄（預設：本使用者的安裝；開發環境用 vpnd 的 --state-dir）
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// 輸出 API 的 JSON
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 診斷：版本、程式雜湊、資料庫完整性、金鑰、遺留資源（有失敗項目時結束碼 1）
    Doctor,
    /// 服務與所有連線的狀態
    Status,
    /// 連線：list、inspect、start、stop、restart、clear-emergency
    #[command(subcommand)]
    Instance(cmd::instance::InstanceCmd),
    /// 急停：立即封鎖並停止，之後必須先解除急停才能啟動
    EmergencyStop {
        /// 名稱、ID 或 ID 開頭
        instance: String,
    },
    /// 代理埠
    #[command(subcommand)]
    Gateway(cmd::gateway::GatewayCmd),
    /// 受管 App：list、status、start、stop、restart
    #[command(subcommand)]
    App(cmd::app::AppCmd),
    /// 轉發（經 tunnel 轉入受管 App）：list、status、enable、disable、proxy-protocol、udp-direct
    #[command(subcommand)]
    Forward(cmd::forward::ForwardCmd),
    /// `WireGuard` 設定
    #[command(subcommand)]
    Profile(cmd::profile::ProfileCmd),
    /// 金鑰保管庫（只有中繼資料）
    #[command(subcommand)]
    Secret(cmd::secret::SecretCmd),
    /// 遺留資源的檢查與清理
    #[command(subcommand)]
    Recovery(cmd::recovery::RecoveryCmd),
    /// Provider 出口
    #[command(subcommand)]
    ProviderEgress(cmd::provider::EgressCmd),
    /// 供應商帳號：check、account add、account remove（憑證只從標準輸入讀取）
    #[command(subcommand)]
    Provider(cmd::provider::ProviderCmd),
    /// SSH 設定
    #[command(subcommand)]
    Ssh(cmd::ssh::SshCmd),
    /// SSH 下載：list、clear-log、clear-history、records（是否記錄檔名、紀錄保留天數）
    #[command(subcommand)]
    SshDownload(cmd::ssh_download::SshDownloadCmd),
    /// IP 封鎖清單：list、show、refresh、delete
    #[command(subcommand)]
    Blocklist(cmd::blocklist::BlocklistCmd),
    /// 自動封鎖的來源：list、remove
    #[command(subcommand)]
    Ban(cmd::ban::BanCmd),
    /// 效能統計：被動摘要（summary）
    #[command(subcommand)]
    Performance(cmd::performance::PerformanceCmd),
    /// 傳輸設定（每條連線的緩衝、逾時與健康探測）：list、show、use
    #[command(subcommand)]
    Transport(cmd::transport::TransportCmd),
    /// 經 VPN Manager 代理埠轉送一條 SSH 連線（ssh 的 `ProxyCommand`）
    SshProxy {
        /// 代理埠，一定在 127.0.0.1
        #[arg(long)]
        gateway: SocketAddr,
        /// 安裝的代理埠金鑰（<資料目錄>/gateway.key）
        #[arg(long)]
        key_file: PathBuf,
        /// 目的主機（%h）：不在本機解析，交給 tunnel 內的 DNS
        host: String,
        /// 目的埠（%p）
        port: u16,
    },
}

/// Where the controller's API socket is: the platform paths of the default installation, or of
/// `--state-dir` (the same rules the daemons use).
fn api_socket(state_dir: Option<&PathBuf>) -> Result<PathBuf, cmd::Failure> {
    let paths = match state_dir {
        Some(d) => {
            let abs = std::path::absolute(d)
                .map_err(|e| cmd::Failure::Usage(format!("--state-dir：{e}")))?;
            vpn_platform::paths::Paths::under(&abs)
        }
        None => vpn_platform::paths::Paths::default_for_user()
            .map_err(|e| cmd::Failure::Usage(format!("找不到預設的資料目錄：{e}")))?,
    };
    Ok(paths.api_socket())
}

async fn dispatch(ctx: &Ctx, command: Command) -> CmdResult {
    match command {
        Command::Doctor => cmd::doctor::run(ctx).await,
        Command::Status => cmd::status::run(ctx).await,
        Command::Instance(c) => cmd::instance::run(ctx, c).await,
        Command::EmergencyStop { instance } => cmd::instance::emergency_stop(ctx, &instance).await,
        Command::Gateway(c) => cmd::gateway::run(ctx, c).await,
        Command::App(c) => cmd::app::run(ctx, c).await,
        Command::Forward(c) => cmd::forward::run(ctx, c).await,
        Command::Profile(c) => cmd::profile::run(ctx, c).await,
        Command::Secret(c) => cmd::secret::run(ctx, c).await,
        Command::Recovery(c) => cmd::recovery::run(ctx, c).await,
        Command::ProviderEgress(c) => cmd::provider::run_egress(ctx, c).await,
        Command::Provider(c) => cmd::provider::run_provider(ctx, c).await,
        Command::Ssh(c) => cmd::ssh::run(ctx, c).await,
        Command::SshDownload(c) => cmd::ssh_download::run(ctx, c).await,
        Command::Blocklist(c) => cmd::blocklist::run(ctx, c).await,
        Command::Ban(c) => cmd::ban::run(ctx, c).await,
        Command::Performance(c) => cmd::performance::run(ctx, c).await,
        Command::Transport(c) => cmd::transport::run(ctx, c).await,
        // Handled before a context exists (it never uses the API socket).
        Command::SshProxy { .. } => Ok(Exit::Usage),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            output::stderr_line(&format!("vpnctl: 無法啟動：{e}"));
            return ExitCode::FAILURE;
        }
    };
    if let Command::SshProxy {
        gateway,
        key_file,
        host,
        port,
    } = cli.command
    {
        return rt.block_on(cmd::ssh::proxy(gateway, key_file, host, port));
    }
    let out = output::Out { json: cli.json };
    let result = match api_socket(cli.state_dir.as_ref()) {
        Ok(socket) => {
            let ctx = Ctx {
                client: client::Client::new(socket),
                out,
            };
            rt.block_on(dispatch(&ctx, cli.command))
        }
        Err(e) => Err(e),
    };
    let exit = match result {
        Ok(exit) => exit,
        Err(failure) => {
            if out.json {
                out.json(&failure.to_json());
            } else {
                output::stderr_line(&format!("vpnctl: {}", failure.to_text()));
            }
            failure.exit()
        }
    };
    ExitCode::from(exit as u8)
}
