//! `vpn-installer`: installs, upgrades and removes VPN Manager for the current user. It is not
//! part of the running system: a packaged installer (scripts/package.sh) carries `vpnd` and
//! `vpnctl` inside itself, puts them in place as services of the machine's own supervisor —
//! launchd `LaunchAgents` on macOS, systemd user units on Linux — and keeps a copy of itself next
//! to them for later upgrades, status checks and removal.
//!
//! Everything VPN Manager keeps lives under one directory (macOS `~/Library/Application
//! Support/VPN Manager`, Linux `~/.local/share/vpn-manager`): programs, data, the vault key, logs
//! and this installer's record and backups. Outside it are only the service definitions the
//! supervisor requires.

// A `pub` item of a program that nothing uses is dead code all the same (off by default).
#![deny(dead_code_pub_in_binary)]

/// Progress for the user, one line on stdout ([`output::say`]: a failed write does not stop the
/// steps it describes).
macro_rules! say {
    ($($arg:tt)*) => {
        $crate::output::say(format_args!($($arg)*))
    };
}

mod fsx;
mod health;
mod launchd;
mod layout;
mod notices;
mod ops;
mod output;
mod payload;
mod record;
mod scrub;
mod supervisor;
mod systemd;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::layout::Target;
use crate::ops::{InstallOptions, Mode};
use crate::payload::Payload;

#[derive(Parser)]
#[command(
    name = "vpn-installer",
    version,
    about = "Install, upgrade or remove VPN Manager for this user"
)]
struct Cli {
    /// Directory holding the vpnd and vpnctl to install, instead of the ones built into this
    /// installer (development).
    #[arg(long, global = true)]
    payload: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Install {
    #[command(flatten)]
    target: Target,
    /// Port of the web UI (default: the installed one, else 18765, else the next free one).
    #[arg(long)]
    port: Option<u16>,
    /// Address the web UI listens on (default: the installed one, else 127.0.0.1). Another
    /// address, such as 0.0.0.0, lets other hosts of the --allow-client networks use it: anything
    /// in those networks can then control VPN Manager, starting managed Apps included.
    #[arg(long)]
    listen_address: Option<std::net::IpAddr>,
    /// A network (CIDR) other hosts may use the web UI from; repeatable, required with a
    /// --listen-address that is not loopback (default: the installed ones).
    #[arg(long)]
    allow_client: Vec<ipnetwork::IpNetwork>,
    /// SSH directory the SSH Manager manages (default: `~/.ssh`).
    #[arg(long)]
    ssh_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Install VPN Manager and start it; an existing installation is upgraded.
    Install(Install),
    /// Replace the installed programs with the ones in this installer; the previous version comes
    /// back by itself if the new one does not start.
    Upgrade(Install),
    /// Stop and remove VPN Manager. Data, the vault key and logs stay unless --purge.
    Uninstall {
        #[command(flatten)]
        target: Target,
        /// Also delete all data, the vault key, logs and backups.
        #[arg(long)]
        purge: bool,
    },
    /// Show what is installed and whether it runs.
    Status {
        #[command(flatten)]
        target: Target,
    },
    /// Print the licences of VPN Manager and of the third-party software in its programs.
    Licenses,
}

#[expect(
    unsafe_code,
    reason = "umask at startup so the installer's files are private to this user"
)]
fn main() -> ExitCode {
    // Files the installer creates (records, backups) are private to this user.
    // SAFETY: umask has no preconditions.
    unsafe {
        libc::umask(0o077);
    }
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Install(o) => run_install(o, cli.payload.as_deref(), Mode::Install),
        Command::Upgrade(o) => run_install(o, cli.payload.as_deref(), Mode::Upgrade),
        Command::Uninstall { target, purge } => ops::uninstall(&target, purge).map(|()| true),
        Command::Licenses => Ok(notices::print()),
        Command::Status { target } => {
            let payload = (cli.payload.is_some() || Payload::embedded())
                .then(|| Payload::load(cli.payload.as_deref()).ok())
                .flatten();
            ops::status(&target, payload.as_ref())
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            output::error(format_args!("vpn-installer：{e:#}"));
            ExitCode::FAILURE
        }
    }
}

fn run_install(o: Install, payload: Option<&Path>, mode: Mode) -> anyhow::Result<bool> {
    let payload = Payload::load(payload)?;
    let opts = InstallOptions {
        target: o.target,
        port: o.port,
        listen_address: o.listen_address,
        allow_clients: (!o.allow_client.is_empty()).then_some(o.allow_client),
        ssh_dir: o.ssh_dir,
    };
    ops::install(&opts, &payload, mode).map(|()| true)
}
