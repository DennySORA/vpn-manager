//! The strict sandbox of an Instance, as its actor keeps it (Linux strict mode).
//!
//! A strict Instance has its sandbox whether or not it runs (built when its actor starts, or
//! when it becomes strict), so managed Apps can start in it ([`StrictApps`]). It is kept across
//! worker generations: a crash, a Stop or an emergency stop leave it standing and closed — its
//! Apps offline, never routed anywhere else — and the next generation's worker re-attaches to the
//! same TUN device. It is rebuilt only when it cannot be proven intact or no longer fits the
//! profile (tunnel addresses, MTU), and torn down — Apps first — when the Instance is deleted or
//! leaves strict mode. A restarted manager adopts the sandboxes whose identity proves they are
//! its own ([`adopt_all`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vpn_domain::{
    APP_STOP_GRACE_SECS, AppIsolation, AppSpec, InstanceId, InstanceSpec, RuntimeProfile,
    SandboxStatus, Text, tr,
};
use vpn_platform::apps::{IsolationBackend, SandboxProvider};
use vpn_platform::sandbox::{AppEntry, ORPHAN_GRACE, SandboxLease, SandboxSpec};
use vpn_sync::Mutex;

use crate::apps::Apps;
use crate::{Ctx, remove_file_if_present};

/// Managed Apps' way into the strict sandboxes (`AppIsolation::StrictNetns`): what each
/// Instance's sandbox offers them, kept current by the Instance's actor while it holds the
/// sandbox (a strict Instance keeps one even while it does not run, so its Apps can start —
/// offline until it runs).
pub struct StrictApps {
    exe: PathBuf,
    apps: Weak<Apps>,
    entries: Mutex<HashMap<InstanceId, Arc<AppEntry>>>,
    /// Why an Instance has no sandbox for its Apps now.
    problems: Mutex<HashMap<InstanceId, Text>>,
}

impl StrictApps {
    pub(crate) fn new(exe: PathBuf, apps: Weak<Apps>) -> Arc<Self> {
        Arc::new(Self {
            exe,
            apps,
            entries: Mutex::new(HashMap::new()),
            problems: Mutex::new(HashMap::new()),
        })
    }

    /// The actor holds a sandbox for `id` now.
    pub(crate) fn register(&self, ctx: &Ctx, id: InstanceId, lease: &SandboxLease) {
        let (hide, xdg_runtime_dir) = covers(ctx);
        match lease.app_entry(hide, xdg_runtime_dir) {
            Ok(entry) => {
                self.entries.lock().insert(id, Arc::new(entry));
                self.problems.lock().remove(&id);
            }
            Err(e) => {
                self.entries.lock().remove(&id);
                self.problems.lock().insert(id, Text::of_io_error(&e));
            }
        }
    }

    /// The actor no longer holds a sandbox for `id` (Apps that run in it are not affected).
    pub(crate) fn unregister(&self, id: InstanceId) {
        self.entries.lock().remove(&id);
    }

    /// A sandbox for `id` could not be built: what its Apps are told.
    pub(crate) fn failed(&self, id: InstanceId, reason: Text) {
        self.problems.lock().insert(id, reason);
    }

    /// The Instance is gone.
    pub(crate) fn forget(&self, id: InstanceId) {
        self.entries.lock().remove(&id);
        self.problems.lock().remove(&id);
    }
}

impl SandboxProvider for StrictApps {
    fn backend(&self, instance_id: &str) -> Result<Arc<dyn IsolationBackend>, Text> {
        if !cfg!(target_os = "linux") {
            return Err(vpn_platform::sandbox::unsupported());
        }
        let id: InstanceId = instance_id.parse().map_err(|e| {
            tracing::debug!(error = %e, "an app names its connection with a malformed id");
            tr!(
                "This connection was not found",
                "找不到這條連線",
                "この接続が見つかりません"
            )
        })?;
        let entry = self.entries.lock().get(&id).cloned();
        let Some(entry) = entry else {
            return Err(self.problems.lock().get(&id).cloned().unwrap_or_else(|| {
                tr!(
                    "The strict isolation sandbox of this connection is not ready yet (the connection must have strict isolation turned on); try again later",
                    "這條連線的嚴格隔離 sandbox 尚未就緒（連線必須啟用嚴格隔離）；請稍後再試",
                    "この接続の厳格な分離のサンドボックスはまだ準備できていません（接続で厳格な分離を有効にする必要があります）。しばらくしてからもう一度お試しください"
                )
            }));
        };
        // ~/.ssh, the SSH Manager's directory, another VPN Manager's data: covered too.
        let private = self.apps.upgrade().map_or_default(|a| a.private());
        backend(self.exe.clone(), &entry, private)
    }
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the non-Linux variant, which fails"
)]
fn backend(
    exe: PathBuf,
    entry: &Arc<AppEntry>,
    private: Vec<PathBuf>,
) -> Result<Arc<dyn IsolationBackend>, Text> {
    Ok(Arc::new(vpn_platform::sandbox::AppBackend::new(
        exe,
        Arc::downgrade(entry),
        private,
    )))
}

#[cfg(not(target_os = "linux"))]
fn backend(
    _exe: PathBuf,
    _entry: &Arc<AppEntry>,
    _private: Vec<PathBuf>,
) -> Result<Arc<dyn IsolationBackend>, Text> {
    Err(vpn_platform::sandbox::unsupported())
}

/// What a sandbox of this manager covers besides the usual socket directories (its Apps' mount
/// namespaces as well): VPN Manager's own directories, read-only, and the runtime directory.
fn covers(ctx: &Ctx) -> (Vec<PathBuf>, Option<PathBuf>) {
    (
        vec![ctx.paths.state.clone(), ctx.paths.run.clone()],
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
    )
}

/// How long Apps get to exit on SIGTERM before a sandbox is torn down around them, at least.
pub const TEARDOWN_GRACE: Duration = Duration::from_secs(3);

/// How long the Apps in Instance `instance_id`'s sandbox get to exit on SIGTERM before it is torn
/// down around them: the longest stop grace of its strict Apps ([`AppSpec::stop_grace_secs`]),
/// at least [`TEARDOWN_GRACE`].
pub async fn teardown_grace(ctx: &Ctx, instance_id: &str) -> Duration {
    let longest = ctx
        .store
        .list::<AppSpec>()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|a| {
            a.isolation == AppIsolation::StrictNetns && a.instance_id.to_string() == instance_id
        })
        .map(|a| a.stop_grace_secs.min(*APP_STOP_GRACE_SECS.end()))
        .max()
        .unwrap_or(0);
    TEARDOWN_GRACE.max(Duration::from_secs(u64::from(longest)))
}

/// What the sandbox is built for: the first tunnel address of each family (with its prefix)
/// and the MTU.
pub fn plan(profile: &RuntimeProfile) -> (Vec<(IpAddr, u8)>, u16) {
    let mut addresses = Vec::new();
    for family_v6 in [false, true] {
        if let Some(net) = profile
            .interface
            .addresses
            .iter()
            .find(|n| n.is_ipv6() == family_v6)
        {
            addresses.push((net.ip(), net.prefix()));
        }
    }
    (addresses, profile.interface.mtu)
}

/// Whether an existing sandbox serves this profile as it is now.
pub fn fits(lease: &SandboxLease, profile: &RuntimeProfile) -> bool {
    let (addresses, mtu) = plan(profile);
    lease.identity().addresses == addresses && lease.identity().mtu == mtu
}

/// A new epoch: creation time in milliseconds, above any earlier epoch of this Instance.
pub fn next_epoch(previous: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    now.max(previous + 1)
}

pub fn spec(ctx: &Ctx, id: InstanceId, epoch: u64, profile: &RuntimeProfile) -> SandboxSpec {
    let (addresses, mtu) = plan(profile);
    let (hide, xdg_runtime_dir) = covers(ctx);
    SandboxSpec {
        installation_id: ctx.store.installation_id().to_string(),
        instance_id: id.to_string(),
        epoch,
        mtu,
        addresses,
        hide,
        xdg_runtime_dir,
        rendezvous: ctx.paths.sandbox_socket(&id.to_string()),
        orphan_grace: ORPHAN_GRACE,
    }
}

pub fn status(lease: &SandboxLease) -> SandboxStatus {
    let identity = lease.identity();
    SandboxStatus {
        epoch: identity.epoch,
        holder_pid: lease.holder().pid,
        tun_name: identity.tun_name.clone(),
        addresses: identity
            .addresses
            .iter()
            .map(|(ip, prefix)| format!("{ip}/{prefix}"))
            .collect(),
    }
}

/// A SOCKS5 UDP relay socket for a strict worker: bound on the client's loopback address in the
/// host network namespace (the worker's own loopback is the sandbox's).
pub fn relay_socket(client_ip: IpAddr) -> std::io::Result<OwnedFd> {
    let ip = client_ip.to_canonical();
    if !ip.is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "relay sockets are bound on loopback only",
        ));
    }
    Ok(OwnedFd::from(std::net::UdpSocket::bind((ip, 0))?))
}

/// A sandbox of this Instance that nobody holds, still listening at its rendezvous socket (one
/// a previous manager left that could not be adopted at start, or whose teardown did not
/// finish), taken over. A new sandbox would replace its socket file and leave it unreachable
/// until it shuts itself down, so the caller adopts it or tears it down first.
pub async fn leftover(ctx: &Ctx, id: InstanceId) -> Option<SandboxLease> {
    let socket = ctx.paths.sandbox_socket(&id.to_string());
    if vpn_platform::sandbox::listening(&socket) != Some(true) {
        return None;
    }
    match SandboxLease::attach(&socket, &ctx.store.installation_id().to_string()).await {
        Ok(lease) if lease.identity().instance_id == id.to_string() => Some(lease),
        Ok(other) => {
            // Ours but not this Instance's (it cannot be named so): left alone. Its holder now
            // counts this manager as its own and stays while it runs.
            tracing::warn!(
                socket = %socket.display(),
                instance = %other.identity().instance_id,
                "sandbox of another connection at this rendezvous socket"
            );
            None
        }
        Err(e) => {
            tracing::warn!(socket = %socket.display(), error = %e, "sandbox not taken over");
            None
        }
    }
}

/// Find the sandboxes a previous manager of this installation left behind. Those that prove
/// they are ours and belong to a strict Instance that still exists are returned for adoption
/// (the newest per Instance); those that prove they are ours but are no longer wanted are torn
/// down, Apps first. Anything that does not prove it is ours is left alone.
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        clippy::zero_sized_map_values,
        reason = "off Linux a lease is an uninhabited stub and `discover` finds no sandbox: this map, shaped for Linux leases, stays empty"
    )
)]
pub async fn adopt_all(ctx: &Ctx, specs: &[InstanceSpec]) -> HashMap<InstanceId, SandboxLease> {
    let mut adopted: HashMap<InstanceId, SandboxLease> = HashMap::new();
    let installation = ctx.store.installation_id().to_string();
    for socket in vpn_platform::sandbox::discover(&ctx.paths.run) {
        let lease = match SandboxLease::attach(&socket, &installation).await {
            Ok(lease) => lease,
            Err(e) => {
                // Nothing listens: a socket file of ours that its holder could not remove.
                if matches!(&e, vpn_platform::sandbox::SandboxError::Io(io)
                    if io.kind() == std::io::ErrorKind::ConnectionRefused)
                {
                    remove_file_if_present(&socket);
                } else {
                    tracing::warn!(socket = %socket.display(), error = %e, "sandbox not adopted");
                }
                continue;
            }
        };
        let wanted = lease
            .identity()
            .instance_id
            .parse::<InstanceId>()
            .ok()
            .filter(|id| specs.iter().any(|s| s.id == *id && s.strict));
        let grace = teardown_grace(ctx, &lease.identity().instance_id).await;
        let Some(id) = wanted else {
            tracing::info!(
                instance = %lease.identity().instance_id,
                "sandbox of a deleted or non-strict connection: tearing it down"
            );
            lease.teardown(grace).await;
            continue;
        };
        match adopted.remove(&id) {
            Some(other) if other.identity().epoch > lease.identity().epoch => {
                lease.teardown(grace).await;
                adopted.insert(id, other);
            }
            Some(older) => {
                older.teardown(grace).await;
                adopted.insert(id, lease);
            }
            None => {
                adopted.insert(id, lease);
            }
        }
    }
    adopted
}
