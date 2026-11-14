//! `vpnd`: the VPN Manager daemon. One executable, three roles:
//!
//! - `vpnd controller` — Web Provide Service + VPN Web API + providers (stateless, restartable)
//! - `vpnd manager`    — Instance Manager + Store + Platform (the long-lived core)
//! - `vpnd instance`   — one Instance worker; started only by the manager (fd 3 = control)
//!
//! Installing, upgrading and removing it is the separate `vpn-installer`'s job.

// A `pub` item of a program that nothing uses is dead code all the same (off by default).
#![deny(dead_code_pub_in_binary)]
#![expect(unsafe_code, reason = "the umask call at process start-up")]

mod logfile;
mod manager;
mod output;
mod sandbox_exec;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vpnd", version, about = "VPN Manager daemon")]
struct Cli {
    /// Write stderr (logs, panics, the workers' output) to this file, kept below 8 MiB with one
    /// previous file (`<file>.1`).
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// Internal: one Instance worker. Started only by the manager (control socket on fd 3).
    #[command(hide = true)]
    Instance,
    /// Internal: what this build is, as JSON, for the installer to check before installing it.
    #[command(hide = true)]
    BuildInfo,
    /// Internal (Linux strict mode): the holder of one connection's sandbox. Started only by the
    /// manager (control socket on fd 3).
    #[command(hide = true)]
    SandboxHolder,
    /// Diagnostics (Linux strict mode): run a command inside a strict connection's sandbox,
    /// with this terminal as its standard input and output.
    #[command(hide = true)]
    SandboxExec {
        /// Same state directory as the manager.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// The connection's (Instance's) id.
        #[arg(long)]
        instance: String,
        /// Program and arguments (a program name is looked up on PATH).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Run the web UI, the HTTP API and the Provider integrations (stateless).
    Controller {
        /// Port of the web UI and API.
        #[arg(long, default_value_t = 18765)]
        port: u16,
        /// Address the web UI and API listen on. Not loopback (e.g. 0.0.0.0): other hosts of the
        /// --allow-client networks may use them too (this host's programs are still served only
        /// for this user). Anything in those networks can then control VPN Manager.
        #[arg(long, default_value = "127.0.0.1")]
        listen_address: std::net::IpAddr,
        /// A network (CIDR) other hosts may use the web UI and API from; repeatable. Required
        /// with a --listen-address that is not loopback.
        #[arg(long)]
        allow_client: Vec<ipnetwork::IpNetwork>,
        /// Same state directory as the manager (to find its socket).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Extra allowed origin for a frontend dev server, e.g. <http://localhost:5173>.
        #[arg(long)]
        dev_origin: Vec<String>,
    },
    /// Run the Instance Manager, Store and Platform core.
    Manager {
        /// Private state directory (default: per-user application data directory). The vault
        /// key (`vault.key`) lives in it.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// SSH directory the SSH Manager reads and writes (default: `~/.ssh`).
        #[arg(long)]
        ssh_dir: Option<PathBuf>,
        /// Linux: the service manager runs this manager in a unit with `Delegate=yes` (the
        /// installer's systemd unit says so); its workers and managed Apps then get cgroups of
        /// their own below the unit's.
        #[arg(long)]
        delegated_cgroup: bool,
    },
}

pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    #[expect(
        clippy::expect_used,
        reason = "cannot fail: SIGTERM is a catchable signal, and this runs inside the runtime `main` builds with `enable_all` (its signal driver)"
    )]
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn init_tracing() {
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // No colour codes in a log file.
        .with_ansi(std::io::stderr().is_terminal())
        // A line the disk refuses is dropped and counted, never a panic of the thread that
        // logged (with `--log-file`, the oldest lines make room first).
        .with_writer(logfile::Stderr)
        .init();
}

/// Worker threads of a connection's worker: two, or one on a single-core host.
///
/// Every packet passes a chain of tasks (Gateway, netstack or sandbox socket, tunnel), and with
/// a thread per core most hand-overs wake another thread. Measured on a 32-core host
/// (2026-11-11; 1, 4 and 12 downloads at once through a SOCKS5 Gateway from the lab peer, five
/// runs of 8 s): 32 threads carried 80–122 MiB/s at 6.3–8.4 CPU seconds per GiB, two threads
/// 179–217 MiB/s at 3.2–3.9; in strict mode 66–107 MiB/s at 9.7–13.5 against 129–214 at
/// 4.2–4.4. One thread used the least CPU (2.2–2.9 s per GiB) and carried the most with twelve
/// downloads, but a single download in strict mode was slower (93 against 129 MiB/s) and
/// nothing goes on while one task holds the thread.
///
/// The manager and the controller keep a thread per core: with fewer the manager pulled files
/// over SSH no faster and at the same CPU time, and the controller answered a quarter fewer
/// requests per second.
fn instance_worker_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |cores| cores.get().min(2))
}

fn main() -> anyhow::Result<()> {
    // A managed App's launcher into a strict sandbox (started by the manager, control socket on
    // fd 3): before anything else — no option parsing, no logging, no thread.
    // nosemgrep: rust.lang.security.args-os.args-os -- picks the role this process runs as; invoked by hand it gains nothing (it needs the manager's control socket on fd 3)
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(vpn_platform::sandbox::APP_ROLE))
    {
        std::process::exit(vpn_platform::sandbox::run_app());
    }
    // Every file we create (databases, sockets, locks) is private to this user.
    // SAFETY: umask has no preconditions.
    unsafe {
        libc::umask(0o077);
    }
    let cli = Cli::parse();
    if let Some(path) = &cli.log_file {
        logfile::redirect(path)
            .map_err(|e| anyhow::anyhow!("open log file {}: {e}", path.display()))?;
    }
    if matches!(cli.role, Role::BuildInfo) {
        output::stdout_line(format_args!(
            "{{\"version\":\"{}\",\"release\":{},\"web_assets\":{}}}",
            vpn_ipc::identity::VERSION,
            !cfg!(debug_assertions),
            vpn_web_provide::has_assets(),
        ));
        return Ok(());
    }
    init_tracing();
    if matches!(cli.role, Role::SandboxHolder) {
        // Before any thread exists: creating a user namespace requires a single thread.
        std::process::exit(vpn_platform::sandbox::run_holder());
    }
    // Hash our own executable once up front (used in every IPC handshake).
    let _ = vpn_ipc::identity::build_id();
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    if matches!(cli.role, Role::Instance) {
        runtime.worker_threads(instance_worker_threads());
    }
    let rt = runtime.enable_all().thread_name("vpnd").build()?;
    match cli.role {
        Role::Instance => {
            let fd = vpn_platform::process::take_control_fd()?;
            let code = rt.block_on(vpn_instance::controller::run(fd));
            rt.shutdown_timeout(std::time::Duration::from_secs(1));
            std::process::exit(code);
        }
        Role::Controller {
            port,
            listen_address,
            allow_client,
            state_dir,
            dev_origin,
        } => rt.block_on(async move {
            let paths = match &state_dir {
                Some(d) => vpn_platform::paths::Paths::under(d),
                None => vpn_platform::paths::Paths::default_for_user()?,
            };
            paths.ensure()?;
            vpn_controller::run(
                vpn_controller::ControllerConfig {
                    port,
                    exposure: vpn_controller::Exposure {
                        listen: listen_address,
                        allow_clients: allow_client
                            .into_iter()
                            .map(vpn_domain::validation::network_of)
                            .collect(),
                    },
                    manager_socket: paths.manager_socket(),
                    api_socket: Some(paths.api_socket()),
                    dev_origins: dev_origin,
                    gateway_key: Some(paths.gateway_key()),
                    data_dir: Some(paths.state.clone()),
                },
                shutdown_signal(),
            )
            .await
        }),
        Role::Manager {
            state_dir,
            ssh_dir,
            delegated_cgroup,
        } => rt.block_on(manager::run(manager::ManagerArgs {
            state_dir,
            ssh_dir,
            delegated_cgroup,
        })),
        Role::SandboxExec {
            state_dir,
            instance,
            command,
        } => {
            let code = rt.block_on(sandbox_exec::run(state_dir, instance, command))?;
            rt.shutdown_timeout(std::time::Duration::from_secs(1));
            std::process::exit(code);
        }
        Role::BuildInfo | Role::SandboxHolder => Ok(()),
    }
}
