//! Process sandbox for Linux strict mode.
//!
//! A [`SandboxLease`] is one connection's rootless sandbox: a holder process in new user (our
//! uid/gid mapped to 0 inside), network, mount and pid namespaces. Inside: `lo`, a TUN device
//! with the tunnel's address(es) and MTU and default routes through it (only for the families the
//! profile has), a DNS listener socket pair on 127.0.0.53:53 for the connection's resolver,
//! private empty tmpfs over the host's socket directories (`/run`, `/var/run`,
//! `$XDG_RUNTIME_DIR`, `/tmp`, `/var/tmp`, `/dev/shm`) and VPN Manager's own directories, a
//! private `resolv.conf` and `/proc`. No veth, no NAT, no root, no change on the host: the only
//! way out of the namespace is the TUN device, which the connection's worker feeds into `GotaTun`.
//!
//! The lease is named by installation + instance + `sandbox_epoch` and outlives worker
//! generations: the manager keeps the namespace and TUN descriptors and hands them to each new
//! worker ([`SandboxLease::worker_entry`], [`SandboxLease::tun`]), so Apps stay in their sandbox,
//! offline, while a worker is replaced. A restarted manager finds sandboxes through their
//! rendezvous sockets ([`discover`]) and adopts only those whose identity proves they are its own
//! ([`SandboxLease::attach`]).
//!
//! Managed Apps start through `AppBackend` (Linux; the App supervisor's `AppIsolation::StrictNetns`
//! backend): the manager's own child, `vpnd sandbox-app`, joins the sandbox's namespaces, makes
//! the App a mount namespace of its own and starts its tree under its own init in a pid
//! namespace nested in the sandbox's — `no_new_privs`, no capabilities, no descriptor but stdio.
//! [`SandboxLease::spawn`] starts a process through the holder instead (diagnostics). Either way
//! a process is named by host pid and start time, and its whole tree is killed by killing that
//! init. Tearing the sandbox down terminates every App first.
//!
//! Only Linux has this; elsewhere every constructor answers [`SandboxError::Unsupported`].

use std::io;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpn_domain::{Text, tr};

#[cfg(target_os = "linux")]
mod linux;

/// Processes are named as everywhere else in VPN Manager: pid, user, OS start time, program.
pub use crate::process::ProcessIdentity;
#[cfg(target_os = "linux")]
pub(crate) use linux::caps_drop_all;
#[cfg(target_os = "linux")]
pub use linux::{
    APP_ROLE, AccessChannel, AppBackend, AppEntry, SandboxClient, SandboxLease, SandboxProcess,
    WorkerEntry, detect, discover, listening, probe, run_app, run_holder, same_process,
    underlay_socket,
};

/// Interface name of the TUN device inside every sandbox.
pub const TUN_NAME: &str = "vpn0";
/// The sandbox's resolver listens on 127.0.0.53 at this port (UDP and TCP).
pub const DNS_PORT: u16 = 53;
/// How long a holder that lost its manager keeps the sandbox for a restarted one.
pub const ORPHAN_GRACE: Duration = Duration::from_mins(10);

/// Who a sandbox belongs to and what it was built as. Reported by the holder itself, so a
/// restarted manager can tell its own sandboxes from anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxIdentity {
    pub installation_id: String,
    pub instance_id: String,
    /// Increases whenever a sandbox of this Instance is built anew.
    pub epoch: u64,
    /// Kernel boot the sandbox belongs to.
    pub boot_id: String,
    /// Start time of the holder process (clock ticks after boot), with its pid the proof that a
    /// pid still names the same process.
    pub holder_start: u64,
    pub tun_name: String,
    pub mtu: u16,
    /// Tunnel addresses with prefix lengths, as configured on the TUN device.
    pub addresses: Vec<(IpAddr, u8)>,
}

/// What to build.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub installation_id: String,
    pub instance_id: String,
    pub epoch: u64,
    pub mtu: u16,
    /// Tunnel addresses with prefix lengths (the first of each family is used).
    pub addresses: Vec<(IpAddr, u8)>,
    /// VPN Manager's own directories (data, runtime): covered with an empty read-only tmpfs.
    pub hide: Vec<PathBuf>,
    /// The App's `$XDG_RUNTIME_DIR` (covered, and recreated empty and private).
    pub xdg_runtime_dir: Option<PathBuf>,
    /// The holder's rendezvous socket (in the manager's private runtime directory).
    pub rendezvous: PathBuf,
    /// How long the holder waits for a manager to re-attach before it shuts the sandbox down.
    pub orphan_grace: Duration,
}

/// What an App's launcher says about a connection of a local access port it was handed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AccessReport {
    /// The App accepted the connection relayed to its `port`.
    Relayed { port: u16 },
    /// The connection for `port` could not be relayed: why.
    Failed { port: u16, message: Text },
}

/// How a sandboxed App ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

/// What to start in a sandbox. No shell is involved: `argv[0]` is an absolute path inside the
/// sandbox's file system view and the environment is exactly `env`.
#[derive(Debug, Default)]
pub struct SpawnSpec {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Working directory (default `/`).
    pub cwd: Option<PathBuf>,
    /// File mode creation mask (typical: `0o022`).
    pub umask: u32,
    /// Standard descriptors; `None` is `/dev/null`.
    pub stdin: Option<OwnedFd>,
    pub stdout: Option<OwnedFd>,
    pub stderr: Option<OwnedFd>,
}

/// Why a sandbox cannot be built or used. Its `Display` is the English (logs); [`Self::text`] is
/// what people are told.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// This operating system has no rootless network namespaces.
    #[error("{}", .0.en)]
    Unsupported(Text),
    /// The host does not allow what the sandbox needs (concrete reason).
    #[error("{}", .0.en)]
    Blocked(Text),
    #[error("{}", .0.en)]
    Failed(Text),
    #[error("{0}")]
    Io(#[from] io::Error),
}

impl SandboxError {
    /// A host restriction that retrying cannot fix.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self, Self::Unsupported(_) | Self::Blocked(_))
    }

    /// What to tell people.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Unsupported(t) | Self::Blocked(t) | Self::Failed(t) => t.clone(),
            Self::Io(e) => Text::of_io_error(e),
        }
    }
}

/// Why this operating system has no strict sandbox, in English (an I/O error's words); people
/// are told [`unsupported`].
pub const UNSUPPORTED: &str = "Strict isolation (rootless network namespace) is available only on Linux; on this operating system, use a Gateway proxy";

/// Why this operating system has no strict sandbox.
#[must_use]
pub fn unsupported() -> Text {
    tr!(
        "Strict isolation (rootless network namespace) is available only on Linux; on this operating system, use a Gateway proxy",
        "嚴格隔離（rootless network namespace）只在 Linux 提供；這個作業系統請使用 Gateway 代理",
        "厳格な分離（rootless network namespace）は Linux でのみ利用できます。この OS ではゲートウェイのプロキシを使ってください"
    )
}

#[cfg(not(target_os = "linux"))]
mod other {
    //! Every operating system but Linux: the types exist, nothing can be built.

    use std::convert::Infallible;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use vpn_domain::Text;

    use super::{
        AccessReport, ExitStatus, ProcessIdentity, SandboxError, SandboxIdentity, SandboxSpec,
        SpawnSpec, UNSUPPORTED, unsupported,
    };

    /// A strict sandbox (never constructed on this operating system).
    #[derive(Debug)]
    pub struct SandboxLease {
        never: Infallible,
    }

    /// A process in a sandbox (never constructed on this operating system).
    #[derive(Debug)]
    pub struct SandboxProcess {
        never: Infallible,
    }

    /// Namespaces a worker joins (never constructed on this operating system).
    #[derive(Debug)]
    pub struct WorkerEntry {
        _never: Infallible,
    }

    /// What managed Apps need to enter a sandbox (never constructed on this operating system).
    #[derive(Debug)]
    pub struct AppEntry {
        never: Infallible,
    }

    /// The manager's end of a sandboxed App's access relay (never constructed on this operating
    /// system).
    #[derive(Debug)]
    pub struct AccessChannel {
        never: Infallible,
    }

    impl AccessChannel {
        /// Hand the App's launcher a connection for `port`.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn send(&self, _port: u16, _conn: OwnedFd) -> io::Result<()> {
            match self.never {}
        }

        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it waits for the launcher's next report"
        )]
        pub async fn report(&self) -> Option<AccessReport> {
            match self.never {}
        }
    }

    impl AppEntry {
        #[must_use]
        pub const fn epoch(&self) -> u64 {
            match self.never {}
        }
    }

    /// The hidden `vpnd` role of a managed App's launcher.
    pub const APP_ROLE: &str = "sandbox-app";

    #[must_use]
    pub const fn run_app() -> i32 {
        2
    }

    /// A non-managing connection to a sandbox (never constructed on this operating system).
    #[derive(Debug)]
    pub struct SandboxClient {
        never: Infallible,
    }

    impl SandboxClient {
        /// Connect to the holder listening on the rendezvous `socket`.
        ///
        /// # Errors
        ///
        /// Always [`SandboxError::Unsupported`]: only Linux has this sandbox.
        #[expect(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "same signature as on Linux, where it talks to the holder"
        )]
        pub async fn connect(_socket: &Path) -> Result<Self, SandboxError> {
            Err(SandboxError::Unsupported(unsupported()))
        }

        #[must_use]
        pub const fn identity(&self) -> &SandboxIdentity {
            match self.never {}
        }

        #[must_use]
        pub const fn holder(&self) -> &ProcessIdentity {
            match self.never {}
        }

        #[must_use]
        pub const fn managed(&self) -> bool {
            match self.never {}
        }

        /// Start a process in the sandbox.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it asks the holder to start the process"
        )]
        pub async fn spawn(&self, _spec: SpawnSpec) -> Result<SandboxProcess, SandboxError> {
            match self.never {}
        }
    }

    #[must_use]
    pub fn same_process(then: &ProcessIdentity, now: &ProcessIdentity) -> bool {
        then.pid == now.pid && then.uid == now.uid && then.start == now.start && !now.zombie
    }

    #[must_use]
    pub const fn listening(_socket: &Path) -> Option<bool> {
        None
    }

    /// Static host checks for the capability list.
    ///
    /// # Errors
    ///
    /// Always: the reason this operating system has no strict sandbox ([`unsupported`]).
    pub fn detect() -> Result<(), Text> {
        Err(unsupported())
    }

    /// Build a throw-away sandbox to find out whether this host allows one.
    ///
    /// # Errors
    ///
    /// Always [`SandboxError::Unsupported`]: only Linux has this sandbox.
    pub async fn probe(_exe: &Path) -> Result<(), SandboxError> {
        Err(SandboxError::Unsupported(unsupported()))
    }

    #[must_use]
    pub const fn discover(_run: &Path) -> Vec<PathBuf> {
        Vec::new()
    }

    #[must_use]
    pub const fn run_holder() -> i32 {
        2
    }

    /// The `WireGuard` underlay socket of a strict worker.
    ///
    /// # Errors
    ///
    /// Always [`io::ErrorKind::Unsupported`]: only Linux has strict workers.
    pub fn underlay_socket(_endpoint: std::net::SocketAddr) -> io::Result<OwnedFd> {
        Err(io::Error::new(io::ErrorKind::Unsupported, UNSUPPORTED))
    }

    impl SandboxLease {
        /// Build a new sandbox.
        ///
        /// # Errors
        ///
        /// Always [`SandboxError::Unsupported`]: only Linux has this sandbox.
        #[expect(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "same signature as on Linux, where it starts the holder and waits for its report"
        )]
        pub async fn create(_exe: &Path, _spec: SandboxSpec) -> Result<Self, SandboxError> {
            Err(SandboxError::Unsupported(unsupported()))
        }

        /// Adopt a sandbox left by a previous manager.
        ///
        /// # Errors
        ///
        /// Always [`SandboxError::Unsupported`]: only Linux has this sandbox.
        #[expect(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "same signature as on Linux, where it asks the holder for its identity"
        )]
        pub async fn attach(_socket: &Path, _installation_id: &str) -> Result<Self, SandboxError> {
            Err(SandboxError::Unsupported(unsupported()))
        }

        #[must_use]
        pub const fn identity(&self) -> &SandboxIdentity {
            match self.never {}
        }

        #[must_use]
        pub const fn holder(&self) -> &ProcessIdentity {
            match self.never {}
        }

        #[must_use]
        pub const fn is_alive(&self) -> bool {
            match self.never {}
        }

        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it waits for the holder to exit"
        )]
        pub async fn holder_gone(&self) {
            match self.never {}
        }

        /// Raise the kernel's TCP buffer limits in the sandbox.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it asks the holder to set the limits"
        )]
        pub async fn raise_tcp_limits(
            &self,
            _receive_max: u64,
            _send_max: u64,
        ) -> Result<Option<(u64, u64)>, SandboxError> {
            match self.never {}
        }

        /// Whether the sandbox is intact.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it asks the holder"
        )]
        pub async fn check(&self) -> Result<(), SandboxError> {
            match self.never {}
        }

        /// The namespaces a worker joins before it starts.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn worker_entry(&self) -> io::Result<WorkerEntry> {
            match self.never {}
        }

        /// The TUN device.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn tun(&self) -> io::Result<OwnedFd> {
            match self.never {}
        }

        /// The resolver's UDP socket inside the sandbox.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn dns_udp(&self) -> io::Result<OwnedFd> {
            match self.never {}
        }

        /// The resolver's TCP listener inside the sandbox.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn dns_tcp(&self) -> io::Result<OwnedFd> {
            match self.never {}
        }

        /// What managed Apps need to start in this sandbox.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn app_entry(
            &self,
            _hide: Vec<PathBuf>,
            _xdg_runtime_dir: Option<PathBuf>,
        ) -> io::Result<AppEntry> {
            match self.never {}
        }

        /// Start a process in the sandbox.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it asks the holder to start the process"
        )]
        pub async fn spawn(&self, _spec: SpawnSpec) -> Result<SandboxProcess, SandboxError> {
            match self.never {}
        }

        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it waits for the holder to leave"
        )]
        pub async fn teardown(self, _grace: Duration) -> bool {
            match self.never {}
        }
    }

    impl SandboxProcess {
        #[must_use]
        pub const fn pid(&self) -> u32 {
            match self.never {}
        }

        #[must_use]
        pub const fn identity(&self) -> Option<&ProcessIdentity> {
            match self.never {}
        }

        #[must_use]
        pub const fn tree_init_pid(&self) -> u32 {
            match self.never {}
        }

        #[must_use]
        pub const fn tree_init(&self) -> Option<&ProcessIdentity> {
            match self.never {}
        }

        /// Send `signal` to every process of the App's tree.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn signal(&self, _signal: i32) -> io::Result<()> {
            match self.never {}
        }

        /// Kill the whole tree at once.
        ///
        /// # Errors
        ///
        /// Never: it cannot be called, as no value of this type exists on this operating system.
        pub const fn kill_tree(&self) -> io::Result<()> {
            match self.never {}
        }

        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it waits until the App's tree has ended"
        )]
        #[expect(
            clippy::needless_pass_by_ref_mut,
            reason = "same signature as on Linux, where it records the App's exit status"
        )]
        pub async fn wait(&mut self) -> Option<ExitStatus> {
            match self.never {}
        }

        #[expect(
            clippy::unused_async,
            reason = "same signature as on Linux, where it signals the tree and waits for its end"
        )]
        pub async fn terminate(self, _grace: Duration) -> Option<ExitStatus> {
            match self.never {}
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use other::{
    APP_ROLE, AccessChannel, AppEntry, SandboxClient, SandboxLease, SandboxProcess, WorkerEntry,
    detect, discover, listening, probe, run_app, run_holder, same_process, underlay_socket,
};
