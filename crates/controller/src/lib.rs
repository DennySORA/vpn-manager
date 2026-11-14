//! VPN Controller (`vpnd controller`): Web Provide Service + VPN Web API + VPN Core + VPN Profile
//! Checker + VPN Platform Controller. It keeps no durable state of its own; restarting it never
//! touches a tunnel.

#![forbid(unsafe_code)]

pub mod api_socket;
pub mod blocklists;
pub mod diagnostics;
pub mod egress;
pub mod guard;
pub mod http;
pub mod hub;
pub mod link;
pub mod provider;
pub mod routes;
pub mod tcp_listener;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::middleware::from_fn_with_state;
use ipnetwork::IpNetwork;

use crate::guard::{GuardConfig, LanHosts, guard};
use crate::hub::Hub;
use crate::link::ManagerLink;
use crate::routes::AppState;

/// Where the web UI and API listen, and which other hosts may use them: installation
/// parameters (`vpn-installer --listen-address`, `--allow-client`), not settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    /// `127.0.0.1` (the default): this host only. Another address: other hosts of `allow_clients`
    /// as well (this host's programs are still checked for being this user's).
    pub listen: IpAddr,
    pub allow_clients: Vec<IpNetwork>,
}

impl Default for Exposure {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_clients: Vec::new(),
        }
    }
}

impl Exposure {
    /// Other hosts may reach the listener.
    #[must_use]
    pub const fn lan(&self) -> bool {
        !self.listen.is_loopback()
    }

    /// What to bind for `port`: the listen address — and loopback too when that is one specific
    /// address of this host, so this host's own programs (and the installer's health check) keep
    /// reaching it at 127.0.0.1.
    #[must_use]
    pub fn bind_addresses(&self, port: u16) -> Vec<SocketAddr> {
        let mut out = vec![SocketAddr::new(self.listen, port)];
        if !self.listen.is_loopback() && !self.listen.is_unspecified() {
            out.insert(0, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        out
    }
}

#[derive(Debug)]
pub struct ControllerConfig {
    /// Port of the web UI and API.
    pub port: u16,
    /// Where it listens, and for whom besides this host's programs.
    pub exposure: Exposure,
    /// The installation's directory (shown to the user; never read here).
    pub data_dir: Option<PathBuf>,
    pub manager_socket: PathBuf,
    /// UDS for `vpnctl` (same API, no browser guard; 0600 in a 0700 directory).
    pub api_socket: Option<PathBuf>,
    /// Extra allowed origins for a local frontend dev server (e.g. `http://localhost:5173`).
    pub dev_origins: Vec<String>,
    /// The Gateway key file shared with the manager.
    pub gateway_key: Option<PathBuf>,
}

/// Router for browser clients (guarded) — also used by tests.
pub fn browser_router(state: AppState, guard_cfg: GuardConfig) -> Router {
    routes::api(state)
        .fallback(vpn_web_provide::serve)
        .layer(from_fn_with_state(Arc::new(guard_cfg), guard))
}

/// How long a stopping controller waits for in-flight requests.
const DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Serve the controller until `shutdown` resolves, then drain in-flight requests.
///
/// # Errors
///
/// When the exposure settings are refused, a listener or the API socket cannot be bound, or
/// serving fails.
pub async fn run(
    cfg: ControllerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let hub = Hub::new();
    let closing_hub = hub.clone();
    let link = ManagerLink::new(cfg.manager_socket.clone(), hub.clone());
    tokio::spawn(link.clone().run());
    // URL blocklists whose automatic refresh is due (downloaded through the Provider egress).
    tokio::spawn(blocklists::auto_refresh(link.clone()));
    vpn_platform::admission::check_exposure(cfg.exposure.listen, &cfg.exposure.allow_clients)
        .map_err(|e| anyhow::Error::msg(e.en.clone()))?;
    let state = AppState {
        link,
        hub,
        port: cfg.port,
        exposure: Arc::new(cfg.exposure.clone()),
        data_dir: cfg.data_dir.as_ref().map(|d| d.to_string_lossy().into()),
        gateway_key: cfg.gateway_key.clone().map(Arc::new),
        providers: provider::Providers::new(),
    };
    // The connection the direct exception built becomes the egress once it is connected (a
    // durable record in the manager: a restart of either process resumes it).
    tokio::spawn(egress::drive(state.providers.clone(), state.link.clone()));

    let mut inners = Vec::new();
    for addr in cfg.exposure.bind_addresses(cfg.port) {
        inners.push(
            tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind {addr}"))?,
        );
    }
    // This host's programs are served only for this user, like on api.sock (another local
    // account could forge every browser header); other hosts only from the allowed networks.
    let me = vpn_platform::process::current_uid();
    let tcp = tcp_listener::SameUserTcpListener::with_policy(
        inners,
        vpn_platform::admission::ClientPolicy {
            uid: me,
            allow: cfg.exposure.allow_clients.clone(),
        },
        Arc::new(vpn_platform::admission::OsHost),
    )
    .context("serve the web UI")?;
    let mut guard_cfg = GuardConfig::loopback(cfg.port, &cfg.dev_origins);
    if cfg.exposure.lan() {
        guard_cfg = guard_cfg.with_lan(LanHosts::of_this_host(cfg.port));
    }
    let browser = browser_router(state.clone(), guard_cfg);
    if !vpn_web_provide::has_assets() {
        tracing::warn!("web assets are not embedded; build the frontend for the full UI");
    }
    if cfg.exposure.lan() {
        let allowed: Vec<String> = cfg
            .exposure
            .allow_clients
            .iter()
            .map(ToString::to_string)
            .collect();
        tracing::warn!(listen = %cfg.exposure.listen, port = cfg.port, allowed = %allowed.join(","), "controller listening for other hosts of the allowed networks too (this host: this user's programs only)");
    } else {
        tracing::info!(addr = %axum::serve::Listener::local_addr(&tcp)?, "controller listening (this user's programs only)");
    }

    let token = tokio_util::sync::CancellationToken::new();
    let mut api_socket = None;
    if let Some(sock) = &cfg.api_socket {
        let bound = api_socket::ApiSocket::bind(sock).await?;
        api_socket = Some((bound.path().to_path_buf(), bound.inode()));
        let listener = api_socket::SameUserListener::new(bound.listener, me);
        let app = routes::api(state.clone());
        let t = token.clone();
        tracing::info!(path = %sock.display(), "API socket listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async move { t.cancelled().await })
                .await
            {
                tracing::warn!(error = %e, "API socket stopped serving");
            }
        });
    }
    let t = token.clone();
    tokio::spawn(async move {
        shutdown.await;
        closing_hub.close();
        t.cancel();
    });
    let graceful = {
        let t = token.clone();
        axum::serve(tcp, browser).with_graceful_shutdown(async move { t.cancelled().await })
    };
    // In-flight requests get a bounded drain; a stuck client never holds the process open.
    tokio::select! {
        r = async move { graceful.await } => r?,
        () = async {
            token.cancelled().await;
            tokio::time::sleep(DRAIN_LIMIT).await;
        } => tracing::warn!("connections still open after the drain limit; exiting"),
    }
    if let Some((path, inode)) = &api_socket {
        api_socket::ApiSocket::remove(path, *inode);
    }
    Ok(())
}
