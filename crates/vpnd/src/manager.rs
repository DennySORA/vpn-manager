//! `vpnd manager`: Instance Manager + Store + Platform. The long-lived core.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use tokio::net::UnixListener;
use vpn_instance_manager::Manager;
use vpn_instance_manager::performance::Performance;
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_instance_manager::ssh::SshProjector;
use vpn_instance_manager::watchdog::{self, WatchdogConfig};
use vpn_platform::lock::FileLock;
use vpn_platform::paths::Paths;
use vpn_platform::{capabilities, keystore};
use vpn_store::Store;

pub struct ManagerArgs {
    pub state_dir: Option<PathBuf>,
    pub ssh_dir: Option<PathBuf>,
    /// `--delegated-cgroup`: the unit this manager runs in has `Delegate=yes`.
    pub delegated_cgroup: bool,
}

/// How often the SSH projection is compared with what it should be.
const SSH_RESYNC: std::time::Duration = std::time::Duration::from_secs(15);

/// Keeps the SSH projection current in the background, every [`SSH_RESYNC`].
fn spawn_ssh_resync(ssh: Arc<SshProjector>, store: Arc<Store>) {
    tokio::spawn(async move {
        // Keeps the file current: at start (an upgrade moves vpnctl) and after the user edits
        // ~/.ssh/config (an overlay covers every name of its block, so a name added there must
        // not connect directly for long). Only a file that is verifiably ours is replaced.
        let mut tick = tokio::time::interval(SSH_RESYNC);
        let mut last: Option<vpn_domain::Text> = None;
        loop {
            tick.tick().await;
            if !store
                .list::<vpn_domain::SshHost>()
                .await
                .is_ok_and(|h| !h.is_empty())
            {
                continue;
            }
            let failed = ssh.apply(&store).await.err();
            if let Some(e) = failed.as_ref().filter(|e| last.as_ref() != Some(*e)) {
                tracing::warn!(error = %e.en, "SSH projection not written");
            }
            last = failed;
        }
    });
}

pub async fn run(args: ManagerArgs) -> anyhow::Result<()> {
    let paths = match &args.state_dir {
        Some(d) => Paths::under(d),
        None => Paths::default_for_user()?,
    };
    paths
        .ensure()
        .context("prepare private state directories")?;
    let Ok(_single) = FileLock::try_acquire(&paths.manager_lock()) else {
        bail!(
            "another manager is already running for {}",
            paths.state.display()
        );
    };
    // Resource limits of workers and Apps (Linux: the cgroup systemd delegated to this service;
    // this process moves into its leaf). Before any child is started.
    let resources = Arc::new(vpn_platform::limits::ResourceControl::init(
        args.delegated_cgroup,
    ));

    // The vault key is VPN Manager's own file beside the data; the store refuses one that is
    // not its own.
    let master = keystore::load_or_create_key_file(&paths.vault_key())
        .with_context(|| format!("load vault key {}", paths.vault_key().display()))?;
    let store = Arc::new(Store::open(&paths.state, &master, 1).context("open store")?);
    drop(master);

    // The executable is fixed at start; workers are this exact file (build id checked).
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("resolve own executable")?;
    let vpnctl = exe.with_file_name("vpnctl");
    // Linux strict mode is reported only after a real throw-away sandbox was built here.
    let strict = capabilities::strict_netns(&exe).await;
    let manager = Manager::start_with(store.clone(), exe, paths.clone(), resources.clone()).await?;
    // Subscribed right away: the first worker samples come seconds after the actors start.
    let performance = Performance::start(manager.clone(), store.clone(), manager.subscribe());

    let sock = paths.manager_socket();
    // We hold the manager lock, so any existing socket file is a stale one of ours.
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).context("bind manager socket")?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    // SSH Manager: `vpnctl` ships next to `vpnd`; nothing is written until hosts exist or the
    // user adds the Include line.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let ssh_dir = match (&args.ssh_dir, &home) {
        (Some(d), _) => Some(d.clone()),
        (None, Some(h)) => Some(h.join(".ssh")),
        (None, None) => None,
    };
    // Managed Apps under Seatbelt never read the SSH Manager's directory (besides ~/.ssh and
    // VPN Manager's own data, which they never read either).
    if let Some(dir) = &ssh_dir {
        manager.apps().protect(dir.clone());
    }
    let ssh = ssh_dir.map(|dir| {
        Arc::new(SshProjector::new(
            dir,
            home.as_deref(),
            &vpnctl,
            &paths.gateway_key(),
            &paths.state,
        ))
    });
    if let Some(ssh) = &ssh {
        spawn_ssh_resync(ssh.clone(), store.clone());
    }
    let mut capabilities = capabilities::detect(Some(&strict));
    capabilities.push(strict);
    capabilities.extend(resources.capabilities());
    let facts = SystemFacts {
        capabilities,
        ssh,
        performance: Some(performance),
    };
    tracing::info!(state = %paths.state.display(), "manager ready");
    let server = tokio::spawn(serve(listener, manager.clone(), store.clone(), facts));
    // A manager that stays alive but stops answering must recover by itself: the watchdog (a
    // thread and runtime of its own) checks this socket the way the controller uses it and ends
    // the process after repeated failures, so that launchd or systemd starts it again. Workers
    // fail closed when the manager is gone.
    let stopping = Arc::new(AtomicBool::new(false));
    {
        let stopping = stopping.clone();
        let manager = Arc::downgrade(&manager);
        watchdog::start(
            sock.clone(),
            WatchdogConfig::default(),
            move || {
                stopping.load(Ordering::SeqCst)
                    || manager.upgrade().is_none_or(|m| m.is_closing())
            },
            |why| {
                tracing::error!(%why, "the manager stopped answering on its own socket: exiting so that its supervisor starts it again");
                std::process::exit(EXIT_UNRESPONSIVE);
            },
        )
        .context("start the manager watchdog")?;
    }

    crate::shutdown_signal().await;
    // Stopping from here: calls are refused by design, then nobody serves them.
    stopping.store(true, Ordering::SeqCst);
    tracing::info!("manager stopping (instance intents are kept for the next start)");
    server.abort();
    // Fail closed: every worker is stopped and reaped before anything else happens.
    manager.shutdown().await;
    let _ = std::fs::remove_file(&sock);
    drop(store);
    Ok(())
}

/// Exit code when the watchdog found the manager no longer answering. Not 0, so launchd
/// (`KeepAlive`/`SuccessfulExit` false) and systemd (`Restart=on-failure`) start it again.
const EXIT_UNRESPONSIVE: i32 = 76;
