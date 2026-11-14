//! The sandbox holder: the small process that creates a sandbox and keeps it alive across worker
//! generations (`vpnd sandbox-holder`, started by the manager with its control socket on fd 3).
//!
//! Start-up, single-threaded from the first instruction (`unshare(CLONE_NEWUSER)` requires it):
//! 1. read the [`HolderConfig`]; bind the rendezvous socket in the manager's runtime directory
//!    (still in the host's mount view) so a restarted manager can find and re-attach the sandbox;
//! 2. `unshare(user + net + mount)`, map our uid/gid to 0 inside;
//! 3. `lo` up, the TUN device with the tunnel address(es) and MTU, default routes through it for
//!    the families the profile has; bind the DNS listener sockets on 127.0.0.53:53 (port 53 needs
//!    the namespace's root, which the worker never is);
//! 4. cover the host's socket directories and VPN Manager's directories, private `resolv.conf`;
//! 5. `unshare(pid)` and fork: the child is pid 1 of the sandbox's pid namespace — the holder
//!    proper — and the original process exits. The holder mounts a private `/proc`, becomes
//!    non-dumpable (Apps run with the same uid and must not be able to ptrace it), and reports
//!    `Ready` with the TUN and DNS descriptors and its namespaces.
//!
//! The holder then serves its control connection and rendezvous connections: identify, attach (a
//! restarted manager), check, spawn an App, shut down. Each App is started in its own nested pid
//! namespace under a tiny init (so one App tree can be killed as a whole, and its exit status is
//! reported), with no capabilities, `no_new_privs` and only its stdio descriptors. When the
//! holder exits, the kernel kills everything left in the sandbox's pid namespace; the network and
//! mount namespaces go with their last user.
//!
//! A manager hands the holder a pidfd of its own process with `Setup` and with `Attach`. The
//! sandbox counts as managed while a manager's connection manages it *or* that manager process
//! lives: a manager that is alive never has its sandbox (and the Apps in it) shut down under it,
//! even when its connection went away — it adopts the sandbox again through the rendezvous
//! socket. Only once no manager connection is left and that process has exited does the orphan
//! grace run.
#![expect(
    unsafe_code,
    reason = "this module owns the sandbox holder: unshare, fork/execve, signals, sockets and fd handling via libc"
)]

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vpn_domain::APP_STOP_GRACE_SECS;

use super::{caps, mounts, net, wire};
use crate::sandbox::{DNS_PORT, SandboxIdentity};

/// What the manager (or a re-attaching manager) asks of a holder.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// First message on the control socket: build the sandbox. Descriptor (optional): a pidfd
    /// of the manager's process.
    Setup(Box<HolderConfig>),
    Identify,
    /// Become the managing connection (a restarted manager); answered with the descriptors.
    /// Descriptor (optional): a pidfd of the attaching manager's process.
    Attach,
    /// Verify the sandbox is intact.
    Check,
    Spawn(Box<SpawnRequest>),
    /// Raise the kernel's limit on the receive and the send buffer of one TCP socket in the
    /// sandbox's network namespace to at least these, in bytes. Never lowers one. Only a holder
    /// that says so in its identity (`tunes`) knows this request.
    Tune {
        receive_max: u64,
        send_max: u64,
    },
    /// Terminate every process in the sandbox (SIGTERM, then SIGKILL after the grace period)
    /// and exit.
    Shutdown {
        grace_ms: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Reply {
    /// Set up; descriptors: TUN, DNS UDP, DNS TCP.
    Ready {
        identity: Box<SandboxIdentity>,
    },
    Failed {
        stage: String,
        errno: Option<i32>,
        message: String,
    },
    Identity {
        identity: Box<SandboxIdentity>,
        /// A manager manages the sandbox right now — its connection, or its process that is
        /// still alive (it is not a leftover).
        #[serde(default)]
        managed: bool,
        /// This holder answers `Tune` (one of an earlier build does not know the request).
        #[serde(default)]
        tunes: bool,
    },
    /// The kernel's limits on one TCP socket's buffers now, in bytes.
    Tuned {
        receive_max: u64,
        send_max: u64,
    },
    /// Attached as the managing connection; descriptors: TUN, DNS UDP, DNS TCP.
    Attached,
    /// Another live connection manages this sandbox.
    Busy,
    Checked {
        problem: Option<String>,
    },
    Spawned,
    SpawnFailed {
        message: String,
    },
    ShuttingDown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderConfig {
    pub installation_id: String,
    pub instance_id: String,
    pub epoch: u64,
    pub tun_name: String,
    pub mtu: u16,
    /// Tunnel addresses with prefix lengths; the first of each family is used.
    pub addresses: Vec<(IpAddr, u8)>,
    /// Directories to cover with an empty read-only tmpfs (VPN Manager's own).
    pub hide: Vec<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
    /// Rendezvous socket path; `None` for a probe.
    pub rendezvous: Option<PathBuf>,
    /// How long the holder waits for a manager to (re-)attach before it shuts the sandbox down.
    pub orphan_grace_secs: u64,
    /// Capability probe: set everything up, report, exit.
    pub probe: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpawnRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub umask: u32,
    /// Which standard descriptors follow the report socket, in order.
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

/// Messages on a spawned App's report socket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Report {
    /// From the App tree's init (its credentials carry the init's pid).
    Init,
    /// From the App process right before `exec` (its credentials carry the App's pid).
    App,
    /// `exec` result: 0 on success.
    Exec { errno: i32 },
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

/// Most rendezvous connections served at once.
const MAX_CONNECTIONS: usize = 8;
/// How long the sandbox's processes get after SIGTERM when the holder ends the sandbox on its
/// own (asked by a signal, or no manager left): as long as any App may take to save
/// ([`vpn_domain::APP_STOP_GRACE_SECS`]) — it ends as soon as they are gone.
const SIGNAL_GRACE: Duration = Duration::from_secs(*APP_STOP_GRACE_SECS.end() as u64);
/// A manager's teardown asks for its Apps' longest grace; never more than this.
const MAX_SHUTDOWN_GRACE: Duration = Duration::from_secs(*APP_STOP_GRACE_SECS.end() as u64 + 5);

pub fn errno_of(e: &io::Error) -> Option<i32> {
    e.raw_os_error()
}

pub fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// `starttime` (clock ticks after boot) of a process, from `/proc/<pid>/stat`.
pub fn start_time(pid: &str) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The command name may contain spaces and parentheses: fields restart after the last ')'.
    let rest = stat
        .rsplit_once(')')
        .map(|(_, r)| r)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad stat"))?;
    rest.split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad stat"))
}

pub fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

fn sockaddr_un(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: zeroed sockaddr_un is valid; we fill family and path.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "AF_UNIX (1) fits sa_family_t"
    )]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "a path byte reinterpreted as c_char, whose signedness depends on the target"
        )]
        {
            *dst = *src as libc::c_char;
        }
    }
    let len = size_of::<libc::sa_family_t>() + bytes.len() + 1;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by sun_path's length (108) above"
    )]
    let len = len as libc::socklen_t;
    Ok((addr, len))
}

fn seqpacket_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket call; the result is checked.
    let fd = check(unsafe {
        libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
    })?;
    // SAFETY: fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The holder's rendezvous socket. Its directory is hidden inside the sandbox, so the holder
/// keeps a descriptor of it to remove the socket file when it leaves — only the file it created
/// (a newer holder may have replaced it).
struct Rendezvous {
    listener: OwnedFd,
    dir: OwnedFd,
    name: CString,
    inode: (u64, u64),
}

impl Rendezvous {
    /// Listen at `path` (0600; a stale file is replaced).
    fn listen(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no directory"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
        let dir = CString::new(parent.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: open with a valid C string; the result is checked.
        let dir = check(unsafe {
            libc::open(
                dir.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: a fresh descriptor we own.
        let dir = unsafe { OwnedFd::from_raw_fd(dir) };
        // A stale socket file is replaced (binding over one that stays fails below).
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(error = %e, "stale rendezvous socket not removed");
        }
        let listener = seqpacket_socket()?;
        let (addr, len) = sockaddr_un(path)?;
        // SAFETY: bind/listen with a valid sockaddr_un of the given length.
        unsafe {
            check(libc::bind(
                listener.as_raw_fd(),
                (&raw const addr).cast(),
                len,
            ))?;
        }
        std::fs::set_permissions(
            path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )?;
        let meta = std::fs::symlink_metadata(path)?;
        // SAFETY: listen on a bound socket we own.
        unsafe {
            check(libc::listen(listener.as_raw_fd(), 4))?;
        }
        Ok(Self {
            listener,
            dir,
            name: CString::new(name.as_bytes()).map_err(io::Error::other)?,
            inode: (meta.dev(), meta.ino()),
        })
    }

    /// Remove the socket file, if it is still the one this holder created.
    fn remove(&self) {
        // SAFETY: an all-zero stat is a valid buffer for fstatat to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstatat relative to a directory descriptor we own, with a valid C string and a
        // pointer to the local stat buffer.
        let found = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                &raw mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        if found && (st.st_dev, st.st_ino) == self.inode {
            // SAFETY: unlinkat relative to a directory descriptor we own, with a valid C string.
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

/// Try to connect without waiting (a full backlog answers EAGAIN instead of blocking).
pub fn connect_nonblocking(path: &Path) -> io::Result<OwnedFd> {
    // SAFETY: plain socket call; the result is checked.
    let fd = check(unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    })?;
    // SAFETY: fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let (addr, len) = sockaddr_un(path)?;
    // SAFETY: connect with a valid sockaddr_un of the given length.
    unsafe {
        check(libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len))?;
    }
    Ok(fd)
}

/// Connect to a holder's rendezvous socket. Bounded: while the holder's backlog is full the
/// connect gives up (EAGAIN) after the send timeout; a queued connection the holder never
/// serves fails on the caller's receive timeout.
pub fn connect_to(path: &Path) -> io::Result<OwnedFd> {
    let fd = seqpacket_socket()?;
    bound_sends(fd.as_raw_fd());
    let (addr, len) = sockaddr_un(path)?;
    // SAFETY: connect with a valid sockaddr_un of the given length.
    unsafe {
        check(libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len))?;
    }
    Ok(fd)
}

fn write_file(path: &str, data: &str) -> io::Result<()> {
    std::fs::write(path, data)
}

/// Close every descriptor from 3 up except those in `keep`.
fn close_all_except(keep: &[RawFd]) {
    let mut keep: Vec<RawFd> = keep.iter().copied().filter(|fd| *fd >= 3).collect();
    keep.sort_unstable();
    let mut next = 3u32;
    let close_range = |first: u32, last: u32| {
        // SAFETY: closing descriptor ranges of this (single-threaded) process.
        unsafe {
            libc::syscall(libc::SYS_close_range, first, last, 0u32);
        }
    };
    for fd in keep {
        let fd = fd.cast_unsigned();
        if fd > next {
            close_range(next, fd - 1);
        }
        next = next.max(fd + 1);
    }
    close_range(next, u32::MAX);
}

/// Block the signals the process handles through a signalfd and return that descriptor.
pub fn signal_fd(signals: &[libc::c_int]) -> io::Result<OwnedFd> {
    // SAFETY: an all-zero sigset_t is a valid value for sigemptyset to initialize.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: sigemptyset initializes the local set.
    unsafe { libc::sigemptyset(&raw mut set) };
    for s in signals {
        // SAFETY: sigaddset on the initialized local set.
        unsafe { libc::sigaddset(&raw mut set, *s) };
    }
    // SAFETY: sigprocmask with a pointer to the local set and no buffer for the old one.
    check(unsafe { libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) })?;
    // SAFETY: signalfd making a new descriptor (-1) for the local set.
    let fd = check(unsafe { libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC) })?;
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Read pending signals from a signalfd (non-blocking after poll said readable).
/// One pending signal: its number, and whether it came from outside this pid namespace (the
/// sender's pid is then invisible here and reads 0).
pub struct Signal {
    pub(crate) number: u32,
    pub(crate) from_outside: bool,
}

pub fn read_signals(fd: RawFd) -> Vec<Signal> {
    let mut out = Vec::new();
    // SAFETY: an all-zero signalfd_siginfo is a valid value.
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    // SAFETY: read at most the size of the local `info` into it.
    let n = unsafe {
        libc::read(
            fd,
            (&raw mut info).cast(),
            size_of::<libc::signalfd_siginfo>(),
        )
    };
    if n == size_of::<libc::signalfd_siginfo>().cast_signed() {
        out.push(Signal {
            number: info.ssi_signo,
            from_outside: info.ssi_pid == 0,
        });
    }
    out
}

/// Bound blocking sends on a socket, so a peer that stops reading cannot stall the holder.
pub fn bound_sends(fd: RawFd) {
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "size_of::<timeval>() is 16, which socklen_t holds"
    )]
    let len = size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: setsockopt with a pointer to a live timeval of the size we pass.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&raw const tv).cast(),
            len,
        )
    };
}

/// Entry point of `vpnd sandbox-holder`. Must run before any thread exists.
#[must_use]
pub fn run_holder() -> i32 {
    let Ok(control) = crate::process::take_control_fd() else {
        return 2;
    };
    let ctl = control.as_raw_fd();
    let (config, manager) = match wire::recv_json::<Request>(ctl) {
        Ok(Some((Request::Setup(c), fds, _))) => (*c, fds.into_iter().next()),
        _ => return 2,
    };
    let fail = |stage: &str, e: &io::Error| -> i32 { set_up_failed(ctl, stage, e) };
    match build(&config) {
        Ok(Built::Exit) => 0,
        Ok(Built::Holder(parts)) => holder(config, control, *parts, manager),
        Err((stage, e)) => fail(stage, &e),
    }
}

/// Tell the manager on `ctl` why the sandbox could not be built; the holder's exit code.
fn set_up_failed(ctl: RawFd, stage: &str, e: &io::Error) -> i32 {
    let reply = Reply::Failed {
        stage: stage.into(),
        errno: errno_of(e),
        message: e.to_string(),
    };
    if let Err(unsent) = wire::send_json(ctl, &reply, &[]) {
        tracing::warn!(
            stage,
            error = %e,
            %unsent,
            "sandbox set-up failed and the manager was not told why"
        );
    }
    1
}

struct Parts {
    tun: OwnedFd,
    dns_udp: OwnedFd,
    dns_tcp: OwnedFd,
    /// The sandbox's user and network namespaces, for the workers. (The holder is not dumpable,
    /// so nobody can open its `/proc/<pid>/ns/*` but itself.)
    userns: OwnedFd,
    netns: OwnedFd,
    /// The sandbox's pid namespace (opened by the holder, its init); managed Apps start in it.
    pidns: Option<OwnedFd>,
    rendezvous: Option<Rendezvous>,
    boot_id: String,
}

fn open_namespace(kind: &str) -> io::Result<OwnedFd> {
    Ok(OwnedFd::from(std::fs::File::open(format!(
        "/proc/self/ns/{kind}"
    ))?))
}

enum Built {
    /// The process that forked the holder.
    Exit,
    /// The holder (pid 1 of the sandbox's pid namespace).
    Holder(Box<Parts>),
}

type Stage = (&'static str, io::Error);

fn build(config: &HolderConfig) -> Result<Built, Stage> {
    let at = |stage: &'static str| move |e: io::Error| (stage, e);
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getgid has no preconditions.
    let gid = unsafe { libc::getgid() };
    let boot_id = boot_id().map_err(at("boot_id"))?;
    let rendezvous = match &config.rendezvous {
        Some(path) => Some(Rendezvous::listen(path).map_err(at("rendezvous"))?),
        None => None,
    };

    // SAFETY: unshare with constant flags in a single-threaded process.
    check(unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) })
        .map_err(at("userns"))?;
    write_file("/proc/self/setgroups", "deny").map_err(at("setgroups"))?;
    write_file("/proc/self/uid_map", &format!("0 {uid} 1")).map_err(at("uid_map"))?;
    write_file("/proc/self/gid_map", &format!("0 {gid} 1")).map_err(at("gid_map"))?;
    let userns = open_namespace("user").map_err(at("namespaces"))?;
    let netns = open_namespace("net").map_err(at("namespaces"))?;

    // Network: lo, TUN, addresses, routes, DNS listener sockets.
    let mut nl = net::Netlink::open().map_err(at("netlink"))?;
    let lo = net::if_index("lo").map_err(at("lo"))?;
    nl.link_up(lo, None).map_err(at("lo"))?;
    let tun = net::create_tun(&config.tun_name).map_err(at("tun"))?;
    let index = net::if_index(&config.tun_name).map_err(at("tun"))?;
    let (v4, v6) = net::first_per_family(&config.addresses);
    if v6.is_none() {
        // Without IPv6 on the device nothing IPv6 can leave through it. A kernel without IPv6
        // has no such switch, and needs none.
        if let Err(e) = net::disable_ipv6(&config.tun_name) {
            tracing::debug!(error = %e, "IPv6 not switched off on the tunnel device");
        }
    }
    nl.link_up(index, Some(u32::from(config.mtu)))
        .map_err(at("tun_up"))?;
    if let Some((a, prefix)) = v4 {
        nl.add_address(index, a.into(), prefix)
            .map_err(at("address"))?;
        nl.add_default_route(index, false).map_err(at("route"))?;
    }
    if let Some((a, prefix)) = v6 {
        nl.add_address(index, a.into(), prefix)
            .map_err(at("address"))?;
        nl.add_default_route(index, true).map_err(at("route"))?;
    }
    drop(nl);
    let dns = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 53), DNS_PORT));
    let dns_udp = OwnedFd::from(std::net::UdpSocket::bind(dns).map_err(at("dns"))?);
    let dns_tcp = OwnedFd::from(std::net::TcpListener::bind(dns).map_err(at("dns"))?);

    mounts::setup(config.xdg_runtime_dir.as_deref(), &config.hide).map_err(at("mounts"))?;

    // SAFETY: unshare with a constant flag in a single-threaded process.
    check(unsafe { libc::unshare(libc::CLONE_NEWPID) }).map_err(at("pidns"))?;
    // SAFETY: fork in a single-threaded process.
    match check(unsafe { libc::fork() }).map_err(at("fork"))? {
        0 => Ok(Built::Holder(Box::new(Parts {
            tun,
            dns_udp,
            dns_tcp,
            userns,
            netns,
            pidns: None,
            rendezvous,
            boot_id,
        }))),
        _ => Ok(Built::Exit),
    }
}

/// What `Ready` and `Attached` carry, in this order: TUN, DNS UDP, DNS TCP, user, network and
/// pid namespaces. (A holder of an earlier build sends the first five.)
pub const DESCRIPTORS: usize = 6;

fn descriptors(parts: &Parts) -> Vec<RawFd> {
    let mut fds = vec![
        parts.tun.as_raw_fd(),
        parts.dns_udp.as_raw_fd(),
        parts.dns_tcp.as_raw_fd(),
        parts.userns.as_raw_fd(),
        parts.netns.as_raw_fd(),
    ];
    fds.extend(parts.pidns.as_ref().map(AsRawFd::as_raw_fd));
    fds
}

struct Conn {
    fd: OwnedFd,
    managing: bool,
}

struct State {
    config: HolderConfig,
    identity: SandboxIdentity,
    parts: Parts,
    conns: Vec<Conn>,
    cap_last: u32,
    /// A pidfd of the process of the manager that set the sandbox up or attached last (`None`
    /// from a manager of an earlier build).
    manager: Option<OwnedFd>,
    lost_manager_at: Option<Instant>,
    shutdown_by: Option<Instant>,
}

/// Whether the process behind a pidfd has exited (no waiting; a failed poll says no).
fn process_exited(pidfd: &OwnedFd) -> bool {
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll one pollfd we own, no wait.
    unsafe { libc::poll(&raw mut p, 1, 0) > 0 }
}

/// The holder proper: pid 1 of the sandbox's pid namespace.
fn holder(
    config: HolderConfig,
    control: OwnedFd,
    mut parts: Parts,
    manager: Option<OwnedFd>,
) -> i32 {
    let ctl = control.as_raw_fd();
    let fail = |stage: &str, e: &io::Error| -> i32 { set_up_failed(ctl, stage, e) };
    if let Err(e) = mounts::private_proc() {
        return fail("proc", &e);
    }
    // Our own pid namespace (with the private /proc, "self" is us, pid 1).
    match open_namespace("pid") {
        Ok(fd) => parts.pidns = Some(fd),
        Err(e) => return fail("namespaces", &e),
    }
    // Apps run with our uid; a non-dumpable process cannot be ptraced by them.
    // SAFETY: prctl with constant arguments.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // SAFETY: ignoring SIGPIPE, with constant arguments.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let sigfd = match signal_fd(&[
        libc::SIGCHLD,
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGQUIT,
    ]) {
        Ok(fd) => fd,
        Err(e) => return fail("signals", &e),
    };
    let holder_start = match start_time("self") {
        Ok(t) => t,
        Err(e) => return fail("identity", &e),
    };
    let identity = SandboxIdentity {
        installation_id: config.installation_id.clone(),
        instance_id: config.instance_id.clone(),
        epoch: config.epoch,
        boot_id: parts.boot_id.clone(),
        holder_start,
        tun_name: config.tun_name.clone(),
        mtu: config.mtu,
        addresses: config.addresses.clone(),
    };
    let fds = descriptors(&parts);
    let ready = Reply::Ready {
        identity: Box::new(identity.clone()),
    };
    if wire::send_json(ctl, &ready, &fds).is_err() {
        return 1;
    }
    if config.probe {
        return 0;
    }
    bound_sends(control.as_raw_fd());
    let mut state = State {
        cap_last: caps::last_capability(),
        config,
        identity,
        parts,
        conns: vec![Conn {
            fd: control,
            managing: true,
        }],
        manager,
        lost_manager_at: None,
        shutdown_by: None,
    };
    state.serve(sigfd)
}

impl State {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "serving owns the signalfd for the rest of the holder's life"
    )]
    fn serve(&mut self, sigfd: OwnedFd) -> i32 {
        loop {
            let now = Instant::now();
            if let Some(by) = self.shutdown_by
                && (now >= by || !Self::reap())
            {
                return self.exit();
            }
            if self.managed() {
                self.lost_manager_at = None;
            } else {
                let lost = *self.lost_manager_at.get_or_insert(now);
                let grace = Duration::from_secs(self.config.orphan_grace_secs);
                if self.shutdown_by.is_none() && now.duration_since(lost) >= grace {
                    tracing::warn!(
                        instance = %self.config.instance_id,
                        "no manager for the sandbox; shutting it down"
                    );
                    self.begin_shutdown(SIGNAL_GRACE);
                }
            }
            let mut pollfds = vec![libc::pollfd {
                fd: sigfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let listening = self.shutdown_by.is_none() && self.conns.len() < MAX_CONNECTIONS;
            if let (true, Some(r)) = (listening, &self.parts.rendezvous) {
                pollfds.push(libc::pollfd {
                    fd: r.listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            let first_conn = pollfds.len();
            for c in &self.conns {
                pollfds.push(libc::pollfd {
                    fd: c.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // SAFETY: poll on an array of pollfd we own.
            let r =
                unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 1000) };
            if r < 0 {
                continue;
            }
            if pollfds[0].revents != 0 {
                for sig in read_signals(sigfd.as_raw_fd()) {
                    match sig.number.cast_signed() {
                        libc::SIGCHLD => {
                            Self::reap();
                        }
                        // Only from outside (the manager, the service manager, the user): an App
                        // inside must not be able to end the sandbox around its siblings.
                        _ if sig.from_outside && self.shutdown_by.is_none() => {
                            self.begin_shutdown(SIGNAL_GRACE);
                        }
                        _ => {}
                    }
                }
            }
            if first_conn == 2 && pollfds[1].revents != 0 {
                self.accept();
            }
            // Handle connections back to front so removals keep earlier indices valid.
            let ready = pollfds[first_conn..]
                .iter()
                .enumerate()
                .filter(|(_, p)| p.revents != 0)
                .map(|(i, p)| (i, p.revents));
            for (i, revents) in ready.rev() {
                if i >= self.conns.len() {
                    continue;
                }
                if revents & libc::POLLIN != 0 {
                    if !self.handle(i) {
                        self.conns.remove(i);
                    }
                } else {
                    self.conns.remove(i);
                }
            }
        }
    }

    /// A manager manages the sandbox: its connection does, or its process still lives (it went
    /// on without the connection and adopts the sandbox again). A pidfd that cannot be polled
    /// counts as alive: never shut down on a guess.
    fn managed(&self) -> bool {
        self.conns.iter().any(|c| c.managing)
            || self.manager.as_ref().is_some_and(|m| !process_exited(m))
    }

    /// Reap exited children; `false` once there are none left.
    fn reap() -> bool {
        loop {
            let mut status = 0;
            // SAFETY: waitpid with a pointer to a local.
            let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
            match pid {
                0 => return true,
                p if p > 0 => {}
                _ => return false,
            }
        }
    }

    fn accept(&mut self) {
        let Some(r) = &self.parts.rendezvous else {
            return;
        };
        // SAFETY: accept4 on a listening socket we own; the result is checked.
        let fd = unsafe {
            libc::accept4(
                r.listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return;
        }
        // SAFETY: fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Only our own user (uid 0 here, the manager's uid outside) may talk to the holder.
        let mut cred: libc::ucred = libc::ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "size_of::<ucred>() is 12, which socklen_t holds"
        )]
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt with a pointer to a live ucred and its size.
        let ok = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &raw mut len,
            ) == 0
        } && cred.uid == unsafe { libc::getuid() };
        if ok {
            bound_sends(fd.as_raw_fd());
            self.conns.push(Conn {
                fd,
                managing: false,
            });
        }
    }

    /// Serve one message; `false` when the connection is done.
    fn handle(&mut self, i: usize) -> bool {
        let fd = self.conns[i].fd.as_raw_fd();
        let Ok(Some((request, fds, _))) = wire::recv_json::<Request>(fd) else {
            return false;
        };
        let reply = |r: &Reply, fds: &[RawFd]| wire::send_json(fd, r, fds).is_ok();
        match request {
            Request::Identify => reply(
                &Reply::Identity {
                    identity: Box::new(self.identity.clone()),
                    managed: self.managed(),
                    tunes: true,
                },
                &[],
            ),
            Request::Tune {
                receive_max,
                send_max,
            } => match net::raise_tcp_limits(receive_max, send_max) {
                Ok((receive_max, send_max)) => reply(
                    &Reply::Tuned {
                        receive_max,
                        send_max,
                    },
                    &[],
                ),
                Err(e) => reply(
                    &Reply::Failed {
                        stage: "tune".into(),
                        errno: errno_of(&e),
                        message: e.to_string(),
                    },
                    &[],
                ),
            },
            Request::Attach => {
                if self
                    .conns
                    .iter()
                    .enumerate()
                    .any(|(j, c)| j != i && c.managing)
                {
                    return reply(&Reply::Busy, &[]);
                }
                self.conns[i].managing = true;
                // From now on this manager's process is the one that counts.
                self.manager = fds.into_iter().next();
                reply(&Reply::Attached, &descriptors(&self.parts))
            }
            Request::Check => reply(
                &Reply::Checked {
                    problem: self.self_check(),
                },
                &[],
            ),
            Request::Spawn(req) => match self.spawn(&req, fds) {
                Ok(()) => reply(&Reply::Spawned, &[]),
                Err(message) => reply(&Reply::SpawnFailed { message }, &[]),
            },
            Request::Shutdown { grace_ms } => {
                let ok = reply(&Reply::ShuttingDown, &[]);
                self.begin_shutdown(Duration::from_millis(grace_ms).min(MAX_SHUTDOWN_GRACE));
                ok
            }
            Request::Setup(_) => false,
        }
    }

    /// Whether the sandbox still is what it was built as.
    fn self_check(&self) -> Option<String> {
        let names = match net::interfaces() {
            Ok(n) => n,
            Err(e) => return Some(format!("cannot list interfaces: {e}")),
        };
        let tun = &self.config.tun_name;
        if names.iter().any(|n| n != "lo" && n != tun) || !names.iter().any(|n| n == tun) {
            return Some(format!("unexpected interfaces {names:?}"));
        }
        match net::tun_name(self.parts.tun.as_raw_fd()) {
            Ok(n) if &n == tun => None,
            Ok(n) => Some(format!("TUN descriptor belongs to {n:?}")),
            Err(e) => Some(format!("TUN descriptor unusable: {e}")),
        }
    }

    fn begin_shutdown(&mut self, grace: Duration) {
        // SAFETY: kill(-1) from the namespace's init signals every other process in it.
        unsafe {
            libc::kill(-1, libc::SIGTERM);
        }
        self.shutdown_by = Some(Instant::now() + grace);
        // Nobody can find or adopt the sandbox any more.
        if let Some(r) = self.parts.rendezvous.take() {
            r.remove();
        }
    }

    /// Leave: the kernel kills whatever is left in the sandbox's pid namespace.
    fn exit(&self) -> i32 {
        if let Some(r) = &self.parts.rendezvous {
            r.remove();
        }
        0
    }

    fn spawn(&self, req: &SpawnRequest, mut fds: Vec<OwnedFd>) -> Result<(), String> {
        let wanted = 1 + usize::from(req.stdin) + usize::from(req.stdout) + usize::from(req.stderr);
        if fds.len() != wanted {
            return Err("descriptor count does not match the request".into());
        }
        if self.shutdown_by.is_some() {
            return Err("sandbox is shutting down".into());
        }
        let cwd = match &req.cwd {
            Some(p) => CString::new(p.as_os_str().as_bytes())
                .map_err(|_nul| "NUL in working directory".to_owned())?,
            None => CString::from(c"/"),
        };
        let launch = Launch::new(&req.argv, &req.env, cwd, req.umask, self.cap_last)?;
        let report = fds.remove(0);
        let mut stdio: [Option<OwnedFd>; 3] = [None, None, None];
        for (slot, wanted) in [req.stdin, req.stdout, req.stderr].into_iter().enumerate() {
            if wanted {
                stdio[slot] = Some(fds.remove(0));
            }
        }
        start_tree(report, stdio, &launch, TreeInit::default())
            .map(|_| ())
            .map_err(|e| format!("cannot start the App's init: {e}"))
    }
}

/// Everything the App process needs, prepared before forking (nothing is allocated after).
pub struct Launch {
    path: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
    cwd: CString,
    umask: u32,
    cap_last: u32,
    /// A Landlock ruleset the App restricts itself to before `exec` (where it may write).
    landlock: Option<OwnedFd>,
}

impl Launch {
    /// `argv[0]` is the program (an absolute path); `env` is the whole environment.
    pub(crate) fn new(
        argv: &[String],
        env: &[(String, String)],
        cwd: CString,
        umask: u32,
        cap_last: u32,
    ) -> Result<Self, String> {
        let program = argv.first().ok_or("empty command")?;
        if !program.starts_with('/') {
            return Err("the program must be an absolute path".into());
        }
        // The error would carry the argument or variable itself, which may be a secret.
        let cstr =
            |s: &str| CString::new(s).map_err(|_nul| "NUL in command or environment".to_owned());
        let path = cstr(program)?;
        let argv: Vec<CString> = argv.iter().map(|a| cstr(a)).collect::<Result<_, _>>()?;
        let envp: Vec<CString> = env
            .iter()
            .map(|(k, v)| {
                if k.is_empty() || k.contains('=') {
                    return Err("bad environment variable name".to_owned());
                }
                cstr(&format!("{k}={v}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            path,
            argv,
            envp,
            cwd,
            umask: umask & 0o777,
            cap_last,
            landlock: None,
        })
    }

    /// The App restricts itself to `ruleset` before `exec` ([`super::landlock::ruleset`]).
    pub(crate) fn confine_writes(&mut self, ruleset: OwnedFd) {
        self.landlock = Some(ruleset);
    }
}

/// How an App tree's init behaves beyond the basics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeInit {
    /// Mount a `/proc` of the tree's own pid namespace first (the tree has a mount namespace of
    /// its own).
    pub mount_proc: bool,
    /// When the App process exits, end the rest of its tree too (SIGTERM, SIGKILL after
    /// [`END_GRACE`]), so the tree lives exactly as long as the App.
    pub end_with_app: bool,
}

/// How long the rest of a tree gets after its App process exited (`end_with_app`).
const END_GRACE: Duration = Duration::from_secs(5);

/// Start an App tree: a fork whose child is pid 1 of a new pid namespace nested in the caller's
/// (the tree's init), which starts the App. Returns the init's pid in the caller's namespace.
/// Single-threaded callers only.
pub fn start_tree(
    report: OwnedFd,
    stdio: [Option<OwnedFd>; 3],
    launch: &Launch,
    tree: TreeInit,
) -> io::Result<libc::pid_t> {
    // SAFETY: raw clone used like fork (no new stack, SIGCHLD to us) in a single-threaded
    // process.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            (libc::CLONE_NEWPID | libc::SIGCHLD) as libc::c_ulong,
            0usize,
            0usize,
            0usize,
            0usize,
        )
    };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        app_init(report, stdio, launch, tree);
    }
    Ok(pid as libc::pid_t)
}

/// Report on `rep`, from an App tree's init or the App. Best effort: a reader that is gone or
/// stopped reading only misses the report, and the tree goes on the same way.
fn tell(rep: RawFd, report: &Report) {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a report nobody reads changes nothing for the tree, which goes on the same way"
    )]
    let _ = wire::send_json(rep, report, &[]);
}

/// The App tree's init (pid 1 of its own pid namespace): starts the App, forwards termination
/// signals to every process of the tree, reaps, reports the App's exit and leaves when the
/// tree is empty (its leaving kills whatever might remain). It holds no capability and cannot
/// be ptraced by the App.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the init owns the report socket until it exits"
)]
fn app_init(report: OwnedFd, stdio: [Option<OwnedFd>; 3], launch: &Launch, tree: TreeInit) -> ! {
    let mut keep = vec![report.as_raw_fd()];
    keep.extend(stdio.iter().flatten().map(AsRawFd::as_raw_fd));
    // The App's Landlock ruleset, for it to restrict itself with (close-on-exec).
    keep.extend(launch.landlock.as_ref().map(AsRawFd::as_raw_fd));
    close_all_except(&keep);
    let rep = report.as_raw_fd();
    let Ok(sigfd) = signal_fd(&[
        libc::SIGCHLD,
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGQUIT,
    ]) else {
        // SAFETY: _exit is always safe.
        unsafe { libc::_exit(126) }
    };
    tell(rep, &Report::Init);
    let refuse = |e: io::Error| -> ! {
        let errno = e.raw_os_error().unwrap_or(libc::EIO);
        tell(rep, &Report::Exec { errno });
        // SAFETY: _exit is always safe.
        unsafe { libc::_exit(127) }
    };
    if tree.mount_proc
        && let Err(e) = mounts::private_proc()
    {
        refuse(e);
    }
    // SAFETY: prctl with constant arguments.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    if let Err(e) = caps::drop_all(launch.cap_last) {
        refuse(e);
    }
    let (app, errno) = fork_app(rep, stdio, launch);
    tell(rep, &Report::Exec { errno });
    let mut app_code: Option<i32> = None;
    // `end_with_app`: when the rest of the tree gets SIGKILL.
    let mut kill_at: Option<Instant> = None;
    loop {
        if let Some(at) = kill_at {
            let left = at.saturating_duration_since(Instant::now());
            if left.is_zero() {
                // SAFETY: kill(-1) from this namespace's init reaches the whole App tree.
                unsafe {
                    libc::kill(-1, libc::SIGKILL);
                }
                kill_at = None;
            } else {
                let mut p = libc::pollfd {
                    fd: sigfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ms = libc::c_int::try_from(left.as_millis().clamp(1, i32::MAX as u128))
                    .unwrap_or(libc::c_int::MAX);
                // SAFETY: poll one pollfd we own.
                if unsafe { libc::poll(&raw mut p, 1, ms) } <= 0 {
                    continue;
                }
            }
        }
        // Blocking read: the signals are queued on the signalfd while we work.
        for sig in read_signals(sigfd.as_raw_fd()) {
            match sig.number.cast_signed() {
                libc::SIGCHLD => reap_tree(rep, app, tree, &mut app_code, &mut kill_at),
                sig => {
                    // SAFETY: kill(-1) from this namespace's init reaches the whole App tree.
                    unsafe {
                        libc::kill(-1, sig);
                    }
                }
            }
        }
    }
}

/// Fork the App (see [`app_exec`]) and learn whether its `exec` worked: its pid and `0`, or the
/// `errno` of the failed fork or `exec`. Leaves (127) when the exec pipe cannot be made.
fn fork_app(rep: RawFd, stdio: [Option<OwnedFd>; 3], launch: &Launch) -> (libc::pid_t, i32) {
    let mut pipe = [0; 2];
    // SAFETY: pipe2 writes two descriptors into the array.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        tell(
            rep,
            &Report::Exec {
                errno: io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            },
        );
        // SAFETY: _exit is always safe.
        unsafe { libc::_exit(127) };
    }
    // SAFETY: pipe2 succeeded: a fresh descriptor we own.
    let exec_r = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: the same for the write end.
    let exec_w = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    // SAFETY: fork in this single-threaded process.
    let app = unsafe { libc::fork() };
    if app == 0 {
        drop(exec_r);
        app_exec(rep, exec_w.as_raw_fd(), &stdio, launch);
    }
    drop(exec_w);
    drop(stdio);
    let errno = if app < 0 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    } else {
        let mut buf = [0u8; 4];
        // SAFETY: read into a local buffer; EOF (0) means exec succeeded.
        let n = unsafe { libc::read(exec_r.as_raw_fd(), buf.as_mut_ptr().cast(), 4) };
        if n == 4 { i32::from_ne_bytes(buf) } else { 0 }
    };
    drop(exec_r);
    (app, errno)
}

/// `SIGCHLD` in the tree's init: reap every exited child; report the App's end (and with
/// `end_with_app` end the rest of the tree); leave once the tree is empty.
fn reap_tree(
    rep: RawFd,
    app: libc::pid_t,
    tree: TreeInit,
    app_code: &mut Option<i32>,
    kill_at: &mut Option<Instant>,
) {
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a pointer to a local.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if pid == 0 {
            break;
        }
        if pid < 0 {
            // The tree is empty.
            // SAFETY: _exit is always safe.
            unsafe { libc::_exit(app_code.unwrap_or(0)) };
        }
        if pid == app {
            let (code, signal) = if libc::WIFEXITED(status) {
                (Some(libc::WEXITSTATUS(status)), None)
            } else if libc::WIFSIGNALED(status) {
                (None, Some(libc::WTERMSIG(status)))
            } else {
                (None, None)
            };
            *app_code = Some(code.unwrap_or_else(|| 128 + signal.unwrap_or(0)));
            tell(rep, &Report::Exited { code, signal });
            if tree.end_with_app {
                // SAFETY: kill(-1) from this namespace's init reaches the rest of
                // the tree.
                unsafe {
                    libc::kill(-1, libc::SIGTERM);
                }
                *kill_at = Some(Instant::now() + END_GRACE);
            }
        }
    }
}

/// The App process: reset what the holder changed, enter its own session, take its stdio, shed
/// every privilege, close everything else and `exec`. Reports `exec` failure through `exec_w`.
fn app_exec(report: RawFd, exec_w: RawFd, stdio: &[Option<OwnedFd>; 3], launch: &Launch) -> ! {
    let fail = |errno: i32| -> ! {
        let bytes = errno.to_ne_bytes();
        // SAFETY: write a local buffer of 4 bytes to the exec pipe.
        unsafe { libc::write(exec_w, bytes.as_ptr().cast(), 4) };
        // SAFETY: leave without running any destructor; _exit is always safe.
        unsafe { libc::_exit(127) }
    };
    let last_errno = || {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    };
    // SAFETY: an all-zero sigset_t is a valid value for sigemptyset to initialize.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: sigemptyset initializes the local set.
    unsafe { libc::sigemptyset(&raw mut set) };
    // SAFETY: sigprocmask with a pointer to the local (empty) set: no signal stays blocked.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut()) };
    // SAFETY: SIGPIPE's default disposition back, with constant arguments.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    // SAFETY: setsid on this process has no preconditions.
    unsafe { libc::setsid() };
    tell(report, &Report::App);
    for (target, source) in stdio.iter().enumerate() {
        let fd = source.as_ref().map_or_else(
            || {
                // SAFETY: open with a constant C string.
                let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
                if null < 0 {
                    fail(last_errno());
                }
                null
            },
            AsRawFd::as_raw_fd,
        );
        // SAFETY: dup2 onto a standard descriptor number.
        if unsafe { libc::dup2(fd, target as RawFd) } < 0 {
            fail(last_errno());
        }
    }
    // SAFETY: umask has no preconditions.
    unsafe { libc::umask(launch.umask as libc::mode_t) };
    // SAFETY: chdir with a valid C string.
    if unsafe { libc::chdir(launch.cwd.as_ptr()) } < 0 {
        fail(last_errno());
    }
    if let Err(e) = caps::drop_all(launch.cap_last) {
        fail(e.raw_os_error().unwrap_or(libc::EPERM));
    }
    // After no_new_privs (drop_all): from here on the App writes only where its ruleset allows.
    if let Some(ruleset) = &launch.landlock
        && let Err(e) = super::landlock::restrict_self(ruleset.as_raw_fd())
    {
        fail(e.raw_os_error().unwrap_or(libc::EPERM));
    }
    let mut argv: Vec<*const libc::c_char> = launch.argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = launch.envp.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    // SAFETY: marks every inherited descriptor above stdio close-on-exec (constant arguments).
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    // SAFETY: exec with null-terminated arrays of valid C strings, alive across the call.
    unsafe { libc::execve(launch.path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    fail(last_errno())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_time_survives_odd_command_names() {
        let t = start_time("self").unwrap();
        assert!(t > 0);
    }
}
