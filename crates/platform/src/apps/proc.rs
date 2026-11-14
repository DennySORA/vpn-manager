//! This user's processes as the OS reports them.
//!
//! Identity (pid + start time, never the pid alone), parent, process group, CPU time, resident
//! memory, TCP sockets (listening, connected or neither) and bound UDP sockets. macOS uses libproc
//! (no `ps`/`lsof` child processes); Linux reads `/proc`.
//!
//! A table that cannot be read is an error, never an empty table: "no process found" is only
//! ever concluded from a successful read.
#![expect(
    unsafe_code,
    reason = "process table scans and signalling call kill/killpg, clock_gettime, sysconf and libproc via libc"
)]

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;

/// A process as it was started: a pid is reused, a pid with its start time is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Start time in microseconds, on a clock no step of the wall clock moves. macOS: since the
    /// Unix epoch, as the kernel recorded it at fork. Linux: since boot (the start ticks of
    /// `/proc/<pid>/stat`, so tick resolution); the boot time `/proc/stat` derives is "now minus
    /// uptime" and moves with every clock step. It names a process only within one boot: a run
    /// is recorded with its [`boot_id`].
    pub started_us: u64,
}

/// This boot's id (`None`: the OS did not say).
#[must_use]
pub fn boot_id() -> Option<String> {
    crate::resources::host_boot_id()
}

/// A start time as [`ProcessIdentity::started_us`] counts it, for a process starting now (when
/// its own could not be read).
#[must_use]
pub fn now_start_us() -> u64 {
    sys::now_start_us()
}

/// A root start time from a run record written before records carried their boot.
///
/// On Linux those counted from the boot time, so they are moved onto the since-boot clock (exact
/// unless the clock was stepped since; a since-boot time is never larger than the uptime).
/// Unchanged on macOS.
#[must_use]
pub fn legacy_start_us(started_us: u64) -> u64 {
    sys::legacy_start_us(started_us)
}

/// When a process started, Unix milliseconds, for display only (Linux: from the boot time,
/// which a clock step moves).
#[must_use]
pub fn started_unix_ms(started_us: u64) -> Option<i64> {
    i64::try_from(sys::started_unix_us(started_us)? / 1000).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub started_us: u64,
    /// Exited but not reaped yet: not alive, but its pid is not free either.
    pub zombie: bool,
    /// Executable name as the OS reports it (macOS truncates to 32 bytes, Linux to 15).
    pub name: String,
}

impl ProcInfo {
    #[must_use]
    pub const fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            started_us: self.started_us,
        }
    }
}

/// This user's processes by pid.
pub type ProcTable = HashMap<u32, ProcInfo>;

/// CPU time and resident memory of one process; `None` where the OS did not say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub cpu_ns: Option<u64>,
    pub rss_bytes: Option<u64>,
}

/// Every process of this user. Errs when the list cannot be read.
///
/// # Errors
///
/// Fails when the list of this user's processes cannot be read.
pub fn snapshot() -> io::Result<ProcTable> {
    let mut table = ProcTable::new();
    for pid in sys::own_pids()? {
        if let Some(info) = sys::info(pid) {
            table.insert(pid, info);
        }
    }
    Ok(table)
}

/// One process of this user (`None`: gone, or not ours).
#[must_use]
pub fn info(pid: u32) -> Option<ProcInfo> {
    if pid == 0 {
        return None;
    }
    sys::info(pid)
}

/// The identity of a process of this user, zombies included (its pid is not free yet).
#[must_use]
pub fn identity(pid: u32) -> Option<ProcessIdentity> {
    info(pid).map(|i| i.identity())
}

/// Whether `id` still names the process it named (alive, not a zombie).
#[must_use]
pub fn is_alive(id: ProcessIdentity) -> bool {
    info(id.pid).is_some_and(|i| i.started_us == id.started_us && !i.zombie)
}

#[must_use]
pub fn usage(pid: u32) -> Usage {
    sys::usage(pid)
}

/// The file a process of this user runs (`None`: gone, not ours, or not readable). For a script
/// this is its interpreter.
#[must_use]
pub fn executable(pid: u32) -> Option<std::path::PathBuf> {
    if pid == 0 {
        return None;
    }
    sys::executable(pid)
}

/// One TCP socket of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSocket {
    pub local: SocketAddr,
    /// The peer; `None` while not connected (a listener, or a socket not connected yet).
    pub remote: Option<SocketAddr>,
    pub listening: bool,
}

impl TcpSocket {
    /// A connection that reached the process over a network interface: its local address is a
    /// specific one that is not loopback. A socket that is only bound (0.0.0.0, `::`) is not.
    #[must_use]
    pub const fn is_from_network(&self) -> bool {
        let ip = self.local.ip().to_canonical();
        !self.listening && !ip.is_loopback() && !ip.is_unspecified()
    }
}

/// The sockets of one process, read in one pass over its descriptors: every TCP socket
/// (listening, connected or neither) and every UDP socket with a local port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessSockets {
    pub tcp: Vec<TcpSocket>,
    /// UDP sockets with a local port, as bound (a client socket bound to `0.0.0.0:<ephemeral>`
    /// is one too).
    pub udp: Vec<SocketAddr>,
}

impl ProcessSockets {
    /// The ones that receive connections or datagrams.
    #[must_use]
    pub fn receiving(&self) -> Sockets {
        Sockets {
            tcp_listen: self
                .tcp
                .iter()
                .filter(|s| s.listening)
                .map(|s| s.local)
                .collect(),
            udp: self.udp.clone(),
        }
    }
}

/// Every TCP and bound UDP socket of one process (one pass over its descriptors); `None` when
/// they could not be read.
#[must_use]
pub fn all_sockets(pid: u32) -> Option<ProcessSockets> {
    sys::sockets(pid)
}

/// Every TCP socket of one process (listening, connected or neither); `None` when they could not
/// be read.
#[must_use]
pub fn tcp_sockets(pid: u32) -> Option<Vec<TcpSocket>> {
    sys::sockets(pid).map(|s| s.tcp)
}

/// The sockets of one process that receive connections or datagrams.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sockets {
    /// Listening TCP sockets, as bound.
    pub tcp_listen: Vec<SocketAddr>,
    /// UDP sockets with a local port, as bound (a client socket bound to `0.0.0.0:<ephemeral>`
    /// is one too).
    pub udp: Vec<SocketAddr>,
}

/// Listening TCP and bound UDP sockets of one process (one pass over its descriptors); `None`
/// when they could not be read.
#[must_use]
pub fn sockets(pid: u32) -> Option<Sockets> {
    sys::sockets(pid).map(|s| s.receiving())
}

/// One of this user's processes holding a port (a listening TCP socket, or a bound UDP socket),
/// and the address it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    pub name: String,
    pub address: SocketAddr,
    /// Its network namespace ([`net_namespace`]): an address is only the same address in the
    /// same namespace.
    pub netns: Option<u64>,
}

/// The network namespace of a process (Linux: the inode of `/proc/<pid>/ns/net`); `None` where
/// there are none, or when it cannot be read.
#[must_use]
pub fn net_namespace(pid: u32) -> Option<u64> {
    sys::net_namespace(pid)
}

/// Every process of this user holding each of `ports` — `(port, udp)`: TCP listening, or UDP
/// with `udp` — as one list per port, in the order asked.
///
/// `None` when the process list cannot be read; a process that cannot be read is skipped (it may
/// hold a port unseen, as may other users' processes, which are never visible here). The process
/// list is read once for all the ports, and on Linux the socket tables of each network namespace
/// once for the whole scan, not once per process (generating them is what costs: ~0.6 s of
/// kernel time for 130 processes; one scan took 26 ms with 790 processes on the owner's PC).
#[must_use]
pub fn holders(ports: &[(u16, bool)]) -> Option<Vec<Vec<Holder>>> {
    let table = snapshot().ok()?;
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            clippy::default_constructed_unit_structs,
            reason = "one constructor for every system: only the Linux scan keeps state"
        )
    )]
    let mut scan = sys::Scan::default();
    let mut out: Vec<Vec<Holder>> = ports.iter().map(|_| Vec::new()).collect();
    for info in table.values().filter(|i| !i.zombie) {
        let netns = sys::net_namespace(info.pid);
        let Some(s) = scan.sockets(info.pid, netns).map(|s| s.receiving()) else {
            continue;
        };
        for (found, (port, udp)) in out.iter_mut().zip(ports) {
            let held = if *udp { &s.udp } else { &s.tcp_listen };
            found.extend(
                held.iter()
                    .filter(|a| a.port() == *port)
                    .map(|address| Holder {
                        pid: info.pid,
                        name: info.name.clone(),
                        address: *address,
                        netns,
                    }),
            );
        }
    }
    for found in &mut out {
        found.sort_by_key(|h| (h.pid, h.address));
        found.dedup();
    }
    Some(out)
}

/// Processes of an App's tree seen so far, by pid with their start time.
pub type Tree = BTreeMap<u32, u64>;

/// Most processes one tree tracks; beyond it new ones are not added (and reported truncated).
pub const MAX_TREE: usize = 4096;

/// Bring `tree` up to date with `table`.
///
/// Drop processes that are gone (or whose pid now names another process), add every descendant of a
/// tracked process and every member of the root's process group started after the root. A pid is
/// only ever trusted with its start time, so a reused pid never adopts its new children into the
/// tree. Returns whether processes were left out because the tree is full.
pub fn track(tree: &mut Tree, root: ProcessIdentity, table: &ProcTable) -> bool {
    tree.retain(|pid, started| {
        table
            .get(pid)
            .is_some_and(|i| i.started_us == *started && !i.zombie)
    });
    let mut children: HashMap<u32, Vec<&ProcInfo>> = HashMap::new();
    for info in table.values() {
        children.entry(info.ppid).or_default().push(info);
    }
    let mut todo: Vec<u32> = tree.keys().copied().collect();
    let mut truncated = false;
    // The root itself while it lives, and group members that were orphaned before we saw them
    // (the group was created by the root, so its members started after it). The kernel never
    // hands out a pid that is an active group id: if the root's pid now names another process,
    // our group was empty at that moment, and a group with that id now is someone else's.
    let group_is_ours = table
        .get(&root.pid)
        .is_none_or(|i| i.started_us == root.started_us);
    for info in table.values() {
        let in_group = group_is_ours && info.pgid == root.pid && info.started_us >= root.started_us;
        let is_root = info.pid == root.pid && info.started_us == root.started_us;
        if (in_group || is_root) && !info.zombie && !tree.contains_key(&info.pid) {
            if tree.len() >= MAX_TREE {
                truncated = true;
                break;
            }
            tree.insert(info.pid, info.started_us);
            todo.push(info.pid);
        }
    }
    while let Some(pid) = todo.pop() {
        let Some(parent_started) = tree.get(&pid).copied() else {
            continue;
        };
        for child in children.get(&pid).into_iter().flatten() {
            // A child starts after its parent; anything else is a reused pid.
            if child.zombie || child.started_us < parent_started || tree.contains_key(&child.pid) {
                continue;
            }
            if tree.len() >= MAX_TREE {
                truncated = true;
                break;
            }
            tree.insert(child.pid, child.started_us);
            todo.push(child.pid);
        }
    }
    truncated
}

/// The environment variable every App process starts with: `VPNM_RUN=<run id>`.
pub const RUN_ENV: &str = "VPNM_RUN";

/// Processes examined and found unmarked that one marker remembers at most (beyond it they are
/// examined again: a cost, never a miss).
const MAX_EXAMINED: usize = 16_384;

/// How the processes of one run are found when they left its tree.
///
/// A process that forks, `setsid`s and loses its parent between two passes (`ssh -f`, `aria2c
/// --daemon`) is no one's descendant and in no group of ours.
/// - Seatbelt runs: the run's profile denies reading one file in the App's own directory and
///   allows its sibling ([`super::seatbelt::marker_paths`]); `sandbox_check` finds every process
///   under that profile (an unsandboxed process may read both, other sandboxes deny both). A
///   sandbox is inherited and cannot be left: authoritative. Both files must exist (the check
///   takes a missing path for denied), so the profile forbids writing them, and the marker is
///   only used while they exist and this process itself does not read as marked.
/// - Other runs: `VPNM_RUN=<run id>` in the environment a process started with (Linux
///   `/proc/<pid>/environ`). Inherited, but a program can be started with a cleared environment:
///   not authoritative. macOS shows no other process's environment: no marker there.
#[derive(Debug)]
pub struct RunMarker {
    env: Vec<u8>,
    /// The paths the run's profile denies and allows.
    sandbox: Option<(std::path::PathBuf, std::ffi::CString, std::ffi::CString)>,
    /// Processes examined and found unmarked, by pid with their start time.
    examined: HashMap<u32, u64>,
}

impl RunMarker {
    /// `sandbox_dir`: for a Seatbelt run, the directory of its marker paths (the App's own,
    /// real path).
    #[must_use]
    pub fn new(run_id: &str, sandbox_dir: Option<&std::path::Path>) -> Self {
        let sandbox = sandbox_dir.and_then(|dir| {
            let (denied, open) = super::seatbelt::marker_paths(dir, run_id);
            Some((
                denied.clone(),
                std::ffi::CString::new(denied.as_os_str().as_bytes()).ok()?,
                std::ffi::CString::new(open.as_os_str().as_bytes()).ok()?,
            ))
        });
        Self {
            env: format!("{RUN_ENV}={run_id}").into_bytes(),
            sandbox,
            examined: HashMap::new(),
        }
    }

    /// Whether every process of the run carries the marker, whatever it does: under Seatbelt.
    /// Otherwise a process that cleared its environment, or any process on macOS, is not found.
    #[must_use]
    pub const fn authoritative(&self) -> bool {
        self.sandbox.is_some()
    }

    /// Whether `pid` carries the run's marker (`None`: could not be told).
    #[must_use]
    pub fn carries(&self, pid: u32) -> Option<bool> {
        match &self.sandbox {
            Some((_, denied, open)) => {
                match (
                    sys::sandbox_denies(pid, denied)?,
                    sys::sandbox_denies(pid, open)?,
                ) {
                    (true, false) => Some(true),
                    _ => Some(false),
                }
            }
            None => sys::environ_has(pid, &self.env),
        }
    }

    /// Whether the marker tells anything now. A Seatbelt marker needs both of its files (a
    /// missing one reads as denied to everyone) and must not mark this process (not under the
    /// run's profile): otherwise every process could look marked.
    fn usable(&self) -> bool {
        match &self.sandbox {
            Some((denied, _, open)) => {
                let open = std::path::Path::new(std::ffi::OsStr::from_bytes(open.as_bytes()));
                denied.is_file()
                    && open.is_file()
                    && self.carries(std::process::id()) == Some(false)
            }
            None => true,
        }
    }

    /// Add to `tree` every process of `table` started since the root that carries the run's
    /// marker; [`track`] then follows their descendants. Each process is examined once; a pid is
    /// trusted only while it still names the process the table listed. Returns whether
    /// processes were left out because the tree is full.
    pub fn adopt(&mut self, tree: &mut Tree, root: ProcessIdentity, table: &ProcTable) -> bool {
        self.examined
            .retain(|pid, started| table.get(pid).is_some_and(|i| i.started_us == *started));
        if self.examined.len() >= MAX_EXAMINED {
            self.examined.clear();
        }
        if !self.usable() {
            return false;
        }
        let me = std::process::id();
        for info in table.values() {
            if info.zombie
                || info.pid == me
                || info.started_us < root.started_us
                || tree.contains_key(&info.pid)
                || self.examined.get(&info.pid) == Some(&info.started_us)
            {
                continue;
            }
            let marked = self.carries(info.pid);
            if sys::info(info.pid).is_none_or(|now| now.started_us != info.started_us) {
                // Gone, or the pid names another process now: nothing learnt.
                continue;
            }
            if marked == Some(true) {
                if tree.len() >= MAX_TREE {
                    return true;
                }
                tree.insert(info.pid, info.started_us);
            } else {
                self.examined.insert(info.pid, info.started_us);
            }
        }
        false
    }
}

/// Tracked processes that are still the ones we saw.
#[must_use]
pub fn alive(tree: &Tree, table: &ProcTable) -> Vec<ProcessIdentity> {
    tree.iter()
        .filter(|(pid, started)| {
            table
                .get(pid)
                .is_some_and(|i| i.started_us == **started && !i.zombie)
        })
        .map(|(pid, started)| ProcessIdentity {
            pid: *pid,
            started_us: *started,
        })
        .collect()
}

/// Send `SIGTERM` (or `SIGKILL` with `force`) to the root's process group and to every tracked
/// process, each only after re-checking its identity.
///
/// The group is signalled only while its leader is still the process we started (alive or a
/// zombie): a group id can be taken by a new leader once the old group is gone. Members that left
/// the group are reached individually.
pub fn signal_tree(root: ProcessIdentity, tracked: &[ProcessIdentity], force: bool) {
    let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
    if info(root.pid).is_some_and(|i| i.started_us == root.started_us) {
        // SAFETY: killpg with a concrete group id and signal.
        unsafe {
            libc::killpg(root.pid as libc::pid_t, sig);
        }
    }
    for id in tracked {
        // One that is gone, or whose pid now names another process, is left alone.
        if !signal(*id, sig) {
            tracing::trace!(
                pid = id.pid,
                "tracked process not signalled: gone or replaced"
            );
        }
    }
}

/// Signal one process if it is still `id`. Returns whether a signal was sent.
#[must_use]
pub fn signal(id: ProcessIdentity, sig: i32) -> bool {
    if id.pid == 0 || !is_alive(id) {
        return false;
    }
    // SAFETY: kill with a concrete pid (identity just checked) and signal.
    unsafe { libc::kill(id.pid as libc::pid_t, sig) == 0 }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

#[cfg(target_os = "macos")]
mod sys {
    #[expect(
        clippy::missing_const_for_fn,
        reason = "its caller is shared with Linux, where this reads `/proc` and cannot be `const`"
    )]
    pub fn net_namespace(_pid: u32) -> Option<u64> {
        None
    }

    pub fn executable(pid: u32) -> Option<std::path::PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let pid = libc::c_int::try_from(pid).ok()?;
        let path_max = libc::PROC_PIDPATHINFO_MAXSIZE.cast_unsigned();
        let mut buf = vec![0u8; path_max as usize];
        // SAFETY: the buffer and its size are passed together; the kernel writes at most that.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), path_max) };
        buf.truncate(positive(n)?);
        Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
    }

    use std::ffi::c_void;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::OnceLock;

    use super::{ProcInfo, ProcessSockets, TcpSocket, Usage};

    /// `proc_listpids` type: processes of one effective uid (libproc.h).
    const PROC_UID_ONLY: u32 = 4;
    /// `proc_pidfdinfo` flavor (`sys/proc_info.h`).
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    /// `struct socket_fdinfo` and the offsets this module reads (`sys/proc_info.h`, checked
    /// against the SDK of macOS 26 with `offsetof`). The kernel returns the size it wrote: any
    /// other size means a layout this code does not know, and nothing is parsed.
    const SOCKET_FDINFO_SIZE: libc::c_int = 792;
    /// The same size, as a buffer length.
    const SOCKET_FDINFO_LEN: usize = SOCKET_FDINFO_SIZE as usize;
    const PSI: usize = 24;
    const SOI_PROTOCOL: usize = PSI + 156;
    const SOI_FAMILY: usize = PSI + 160;
    const SOI_KIND: usize = PSI + 232;
    const SOI_PROTO: usize = PSI + 240;
    const INSI_FPORT: usize = SOI_PROTO;
    const INSI_LPORT: usize = SOI_PROTO + 4;
    const INSI_FADDR: usize = SOI_PROTO + 32;
    const INSI_LADDR: usize = SOI_PROTO + 48;
    const TCPSI_STATE: usize = SOI_PROTO + 80;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;
    const TSI_S_LISTEN: i32 = 1;
    const IPPROTO_UDP: i32 = 17;
    const AF_INET6: i32 = 30;

    #[repr(C, align(8))]
    struct SocketFdInfo([u8; SOCKET_FDINFO_LEN]);

    fn i32_at(b: &[u8], at: usize) -> Option<i32> {
        Some(i32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
    }

    /// A size libproc returned, when it is one (`None`: nothing, or the call failed).
    fn positive(n: libc::c_int) -> Option<usize> {
        usize::try_from(n).ok().filter(|n| *n > 0)
    }

    pub fn now_start_us() -> u64 {
        super::now_us()
    }

    #[expect(
        clippy::missing_const_for_fn,
        reason = "its caller is shared with Linux, where this reads the clock and cannot be `const`"
    )]
    pub fn legacy_start_us(started_us: u64) -> u64 {
        started_us
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "same signature as on Linux, where the boot time may be unreadable"
    )]
    pub const fn started_unix_us(started_us: u64) -> Option<u64> {
        Some(started_us)
    }

    /// `SANDBOX_FILTER_PATH` (sandbox.h).
    const SANDBOX_FILTER_PATH: libc::c_int = 1;

    unsafe extern "C" {
        /// `libsystem_sandbox`: 0 when `pid` may perform `operation` on the filter argument, 1
        /// when its sandbox denies it, -1 on error.
        fn sandbox_check(
            pid: libc::pid_t,
            operation: *const libc::c_char,
            filter: libc::c_int,
            ...
        ) -> libc::c_int;
        /// Or'ed into the filter type: the check itself is not reported as a denial.
        static SANDBOX_CHECK_NO_REPORT: libc::c_int;
    }

    /// Whether `pid`'s sandbox denies reading `path` (`None`: could not be told).
    pub fn sandbox_denies(pid: u32, path: &std::ffi::CStr) -> Option<bool> {
        let pid = libc::pid_t::try_from(pid).ok().filter(|p| *p > 0)?;
        // SAFETY: a constant exported by libsystem_sandbox.
        let no_report = unsafe { SANDBOX_CHECK_NO_REPORT };
        // SAFETY: both strings are NUL-terminated and outlive the call; the filter type takes
        // exactly one path argument.
        let r = unsafe {
            sandbox_check(
                pid,
                c"file-read-data".as_ptr(),
                SANDBOX_FILTER_PATH | no_report,
                path.as_ptr(),
            )
        };
        match r {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// Not readable here: macOS withholds the environment of every other process from
    /// `KERN_PROCARGS2` (`ps -E` shows none either; measured on macOS 26.6), so an environment
    /// marker cannot be told.
    pub const fn environ_has(_pid: u32, _entry: &[u8]) -> Option<bool> {
        None
    }

    pub fn own_pids() -> io::Result<Vec<u32>> {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        // SAFETY: a null buffer asks for the size needed (bytes).
        let needed = unsafe { libc::proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0) };
        let Ok(needed) = usize::try_from(needed) else {
            return Err(io::Error::last_os_error());
        };
        // Room for processes started between the two calls.
        let cap = needed / size_of::<libc::c_int>() + 256;
        let mut buf = vec![0 as libc::c_int; cap];
        let bytes = libc::c_int::try_from(cap * size_of::<libc::c_int>())
            .map_err(|_too_large| io::Error::other("the process list is too large"))?;
        // SAFETY: the buffer holds `cap` ints and its size in bytes is passed.
        let got = unsafe {
            libc::proc_listpids(PROC_UID_ONLY, uid, buf.as_mut_ptr().cast::<c_void>(), bytes)
        };
        let Ok(got) = usize::try_from(got) else {
            return Err(io::Error::last_os_error());
        };
        buf.truncate(got / size_of::<libc::c_int>());
        Ok(buf
            .into_iter()
            .filter(|p| *p > 0)
            .map(libc::c_int::cast_unsigned)
            .collect())
    }

    fn c_string(chars: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = chars
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| c.cast_unsigned())
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn info(pid: u32) -> Option<ProcInfo> {
        let raw = libc::c_int::try_from(pid).ok()?;
        // SAFETY: proc_pidinfo fills the zeroed struct whose size we pass.
        let mut bsd: libc::proc_bsdinfo = unsafe { zeroed() };
        let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: pointer and size describe `bsd`.
        let n = unsafe {
            libc::proc_pidinfo(
                raw,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut bsd).cast::<c_void>(),
                size,
            )
        };
        if n != size {
            return None;
        }
        // SAFETY: getuid has no preconditions.
        if bsd.pbi_uid != unsafe { libc::getuid() } {
            return None;
        }
        let mut name = c_string(&bsd.pbi_name);
        if name.is_empty() {
            name = c_string(&bsd.pbi_comm);
        }
        Some(ProcInfo {
            pid,
            ppid: bsd.pbi_ppid,
            pgid: bsd.pbi_pgid,
            started_us: bsd.pbi_start_tvsec * 1_000_000 + bsd.pbi_start_tvusec,
            zombie: bsd.pbi_status == libc::SZOMB,
            name,
        })
    }

    /// `mach_timebase_info_data_t` (`mach/mach_time.h`); declared here rather than through the
    /// deprecated libc item or a new crate for one stable libSystem call.
    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    unsafe extern "C" {
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }

    /// Mach absolute-time units per nanosecond (Apple silicon reports task times in ticks).
    fn timebase() -> (u64, u64) {
        static TB: OnceLock<(u64, u64)> = OnceLock::new();
        *TB.get_or_init(|| {
            let mut tb = MachTimebaseInfo { numer: 0, denom: 0 };
            // SAFETY: fills the struct we pass.
            let r = unsafe { mach_timebase_info(&raw mut tb) };
            if r != 0 || tb.denom == 0 {
                (1, 1)
            } else {
                (u64::from(tb.numer), u64::from(tb.denom))
            }
        })
    }

    pub fn usage(pid: u32) -> Usage {
        let (Ok(raw), Ok(size)) = (
            libc::c_int::try_from(pid),
            libc::c_int::try_from(size_of::<libc::proc_taskinfo>()),
        ) else {
            return Usage::default();
        };
        // SAFETY: proc_pidinfo fills the zeroed struct whose size we pass.
        let mut task: libc::proc_taskinfo = unsafe { zeroed() };
        // SAFETY: pointer and size describe `task`.
        let n = unsafe {
            libc::proc_pidinfo(
                raw,
                libc::PROC_PIDTASKINFO,
                0,
                (&raw mut task).cast::<c_void>(),
                size,
            )
        };
        if n != size {
            return Usage::default();
        }
        let (numer, denom) = timebase();
        let ticks = task.pti_total_user.saturating_add(task.pti_total_system);
        Usage {
            cpu_ns: Some(
                u64::try_from(u128::from(ticks) * u128::from(numer) / u128::from(denom))
                    .unwrap_or(u64::MAX),
            ),
            rss_bytes: Some(task.pti_resident_size),
        }
    }

    /// The address at `port_at` / `addr_at` of a `struct in_sockinfo`.
    fn address(b: &[u8], v6: bool, port_at: usize, addr_at: usize) -> Option<SocketAddr> {
        // The port is the network-order 16-bit value in the low half of an `int`.
        let port = u16::from_be((i32_at(b, port_at)?.cast_unsigned() & 0xffff) as u16);
        let raw = b.get(addr_at..addr_at + 16)?;
        let ip = if v6 {
            let octets: [u8; 16] = raw.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            // `struct in4in6_addr`: 12 bytes of padding, then the IPv4 address.
            let octets: [u8; 4] = raw.get(12..16)?.try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        };
        Some(SocketAddr::new(ip, port))
    }

    /// One pass over many processes: each process's sockets are read for it alone.
    #[derive(Default)]
    pub struct Scan;

    impl Scan {
        #[expect(
            clippy::unused_self,
            clippy::needless_pass_by_ref_mut,
            reason = "same signature as on Linux, where the scan caches each namespace's socket tables"
        )]
        pub fn sockets(&mut self, pid: u32, _netns: Option<u64>) -> Option<ProcessSockets> {
            sockets(pid)
        }
    }

    pub fn sockets(pid: u32) -> Option<ProcessSockets> {
        let raw = libc::c_int::try_from(pid).ok()?;
        let fd_size = size_of::<libc::proc_fdinfo>();
        // SAFETY: a null buffer asks for the size needed (bytes).
        let needed =
            unsafe { libc::proc_pidinfo(raw, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        let cap = positive(needed)? / fd_size + 32;
        // SAFETY: proc_fdinfo is plain data; zeroed values are valid.
        let mut fds: Vec<libc::proc_fdinfo> = vec![unsafe { zeroed() }; cap];
        let bytes = libc::c_int::try_from(cap * fd_size).ok()?;
        // SAFETY: the buffer holds `cap` entries and its size in bytes is passed.
        let got = unsafe {
            libc::proc_pidinfo(
                raw,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast::<c_void>(),
                bytes,
            )
        };
        fds.truncate(positive(got)? / fd_size);
        let mut out = ProcessSockets::default();
        for fd in fds
            .iter()
            .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
        {
            let mut buf = SocketFdInfo([0; SOCKET_FDINFO_LEN]);
            // SAFETY: the buffer is SOCKET_FDINFO_SIZE bytes, 8-aligned, and that size is passed.
            let n = unsafe {
                libc::proc_pidfdinfo(
                    raw,
                    fd.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    buf.0.as_mut_ptr().cast::<c_void>(),
                    SOCKET_FDINFO_SIZE,
                )
            };
            if n <= 0 {
                // Closed meanwhile.
                continue;
            }
            if n != SOCKET_FDINFO_SIZE {
                // A layout this build does not know: report "unknown", never a wrong address.
                return None;
            }
            let b = &buf.0;
            let kind = i32_at(b, SOI_KIND)?;
            let udp = kind == SOCKINFO_IN && i32_at(b, SOI_PROTOCOL)? == IPPROTO_UDP;
            if kind != SOCKINFO_TCP && !udp {
                continue;
            }
            let v6 = i32_at(b, SOI_FAMILY)? == AF_INET6;
            let local = address(b, v6, INSI_LPORT, INSI_LADDR)?;
            if udp {
                // A UDP socket that never bound or sent has no local port yet.
                if local.port() != 0 {
                    out.udp.push(local);
                }
                continue;
            }
            let remote = address(b, v6, INSI_FPORT, INSI_FADDR)?;
            out.tcp.push(TcpSocket {
                local,
                remote: (remote.port() != 0).then_some(remote),
                listening: i32_at(b, TCPSI_STATE)? == TSI_S_LISTEN,
            });
        }
        Some(out)
    }
}

#[cfg(target_os = "linux")]
mod sys {
    pub fn executable(pid: u32) -> Option<std::path::PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    /// `net:[4026531840]` → 4026531840.
    pub fn net_namespace(pid: u32) -> Option<u64> {
        std::fs::read_link(format!("/proc/{pid}/ns/net"))
            .ok()?
            .to_str()?
            .strip_prefix("net:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::fs::MetadataExt;

    use super::{ProcInfo, ProcessSockets, TcpSocket, Usage};

    fn clk_tck() -> u64 {
        // SAFETY: sysconf with a constant name.
        let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if t > 0 { t.cast_unsigned() } else { 100 }
    }

    /// Boot time, seconds since the epoch (`/proc/stat`): now minus the uptime, so it moves when
    /// the clock is stepped. Display and old run records only, never an identity.
    fn btime() -> Option<u64> {
        std::fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()
    }

    /// Microseconds since boot, suspended time included: the clock `starttime` counts on.
    pub fn now_start_us() -> u64 {
        // SAFETY: clock_gettime fills the zeroed timespec we pass.
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: a valid clock id and pointer.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) } != 0 {
            return 0;
        }
        ts.tv_sec.cast_unsigned() * 1_000_000 + ts.tv_nsec.cast_unsigned() / 1_000
    }

    pub fn legacy_start_us(started_us: u64) -> u64 {
        if started_us <= now_start_us() {
            return started_us;
        }
        btime().map_or(started_us, |b| started_us.saturating_sub(b * 1_000_000))
    }

    /// Seatbelt is macOS-only.
    pub const fn sandbox_denies(_pid: u32, _path: &std::ffi::CStr) -> Option<bool> {
        None
    }

    /// Whether the environment `pid` started with holds exactly `entry` (`/proc/<pid>/environ`,
    /// readable for this user's processes that are not setuid).
    pub fn environ_has(pid: u32, entry: &[u8]) -> Option<bool> {
        use std::io::Read;
        let mut env = Vec::new();
        std::fs::File::open(format!("/proc/{pid}/environ"))
            .ok()?
            .take(8 << 20)
            .read_to_end(&mut env)
            .ok()?;
        Some(env.split(|b| *b == 0).any(|s| s == entry))
    }

    pub fn started_unix_us(started_us: u64) -> Option<u64> {
        // Display only: read once (a listing asks for every process).
        static BTIME: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
        Some((*BTIME.get_or_init(btime))? * 1_000_000 + started_us)
    }

    pub fn own_pids() -> io::Result<Vec<u32>> {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let mut out = Vec::new();
        for entry in std::fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            if entry.metadata().is_ok_and(|m| m.uid() == uid) {
                out.push(pid);
            }
        }
        Ok(out)
    }

    /// `(name, fields after the name)` of `/proc/<pid>/stat`; the name may hold spaces and
    /// parentheses, so it ends at the last `)`.
    fn stat(pid: u32) -> Option<(String, Vec<String>)> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let open = text.find('(')?;
        let close = text.rfind(')')?;
        let name = text.get(open + 1..close)?.to_string();
        let rest = text.get(close + 1..)?;
        Some((name, rest.split_whitespace().map(str::to_string).collect()))
    }

    pub fn info(pid: u32) -> Option<ProcInfo> {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        if std::fs::metadata(format!("/proc/{pid}")).ok()?.uid() != uid {
            return None;
        }
        let (name, f) = stat(pid)?;
        // Fields after the name: state(3) ppid(4) pgrp(5) ... starttime(22).
        let state = f.first()?;
        let parent = f.get(1)?.parse().ok()?;
        let group = f.get(2)?.parse().ok()?;
        let start_ticks: u64 = f.get(19)?.parse().ok()?;
        let started_us = start_ticks * 1_000_000 / clk_tck();
        Some(ProcInfo {
            pid,
            ppid: parent,
            pgid: group,
            started_us,
            zombie: state == "Z" || state == "X",
            name,
        })
    }

    pub fn usage(pid: u32) -> Usage {
        let Some((_, f)) = stat(pid) else {
            return Usage::default();
        };
        let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
        // utime(14) stime(15) rss(24, pages).
        let cpu_ns = match (ticks(11), ticks(12)) {
            (Some(u), Some(s)) => Some((u + s) * 1_000_000_000 / clk_tck()),
            _ => None,
        };
        // SAFETY: sysconf with a constant name.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
            .max(0)
            .cast_unsigned();
        Usage {
            cpu_ns,
            rss_bytes: ticks(21).map(|pages| pages * page),
        }
    }

    /// `0100007F:1F90` (v4) or 32 hex digits (v6), as `/proc/net/tcp*` print them: each 32-bit
    /// word in host (little-endian) order.
    fn parse_addr(s: &str) -> Option<SocketAddr> {
        let (addr, port) = s.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let words: Option<Vec<u32>> = (0..addr.len() / 8)
            .map(|i| u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok())
            .collect();
        let words = words?;
        let ip = match words.as_slice() {
            [word] => IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())),
            quad @ [_, _, _, _] => {
                let mut octets = [0u8; 16];
                for (chunk, word) in octets.as_chunks_mut::<4>().0.iter_mut().zip(quad) {
                    *chunk = word.to_le_bytes();
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// The socket inodes of one process's descriptors; `None` when they cannot be read.
    fn socket_inodes(pid: u32) -> Option<HashSet<u64>> {
        let mut inodes = HashSet::new();
        for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path())
                && let Some(inode) = target
                    .to_str()
                    .and_then(|t| t.strip_prefix("socket:["))
                    .and_then(|t| t.strip_suffix(']'))
                    .and_then(|t| t.parse::<u64>().ok())
            {
                inodes.insert(inode);
            }
        }
        Some(inodes)
    }

    /// The TCP and UDP sockets of one network namespace by inode, as `/proc/<pid>/net/*` lists
    /// them for the namespace `pid` is in (UDP: only those with a local port).
    #[derive(Default)]
    pub struct NetTables {
        tcp: HashMap<u64, TcpSocket>,
        udp: HashMap<u64, SocketAddr>,
    }

    impl NetTables {
        fn read(pid: u32) -> Self {
            let mut out = Self::default();
            for (table, udp) in [
                ("tcp", false),
                ("tcp6", false),
                ("udp", true),
                ("udp6", true),
            ] {
                let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
                    continue;
                };
                for line in text.lines().skip(1) {
                    let f: Vec<&str> = line.split_whitespace().collect();
                    // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
                    let Some(inode) = f.get(9).and_then(|i| i.parse::<u64>().ok()) else {
                        continue;
                    };
                    let Some(local) = f.get(1).and_then(|a| parse_addr(a)) else {
                        continue;
                    };
                    if !udp {
                        let remote = f.get(2).and_then(|a| parse_addr(a));
                        out.tcp.insert(
                            inode,
                            TcpSocket {
                                local,
                                remote: remote.filter(|r| r.port() != 0),
                                listening: f.get(3) == Some(&"0A"),
                            },
                        );
                    } else if local.port() != 0 {
                        out.udp.insert(inode, local);
                    }
                }
            }
            out
        }

        fn of(&self, inodes: &HashSet<u64>) -> ProcessSockets {
            let mut out = ProcessSockets::default();
            for inode in inodes {
                if let Some(t) = self.tcp.get(inode) {
                    out.tcp.push(*t);
                }
                if let Some(u) = self.udp.get(inode) {
                    out.udp.push(*u);
                }
            }
            out
        }
    }

    pub fn sockets(pid: u32) -> Option<ProcessSockets> {
        let inodes = socket_inodes(pid)?;
        if inodes.is_empty() {
            return Some(ProcessSockets::default());
        }
        Some(NetTables::read(pid).of(&inodes))
    }

    /// One pass over many processes: each network namespace's tables are read once.
    #[derive(Default)]
    pub struct Scan {
        pub(super) tables: HashMap<u64, NetTables>,
    }

    impl Scan {
        /// The sockets of `pid`, in network namespace `netns` (`None`: unknown, read for it
        /// alone).
        pub fn sockets(&mut self, pid: u32, netns: Option<u64>) -> Option<ProcessSockets> {
            let inodes = socket_inodes(pid)?;
            if inodes.is_empty() {
                return Some(ProcessSockets::default());
            }
            Some(match netns {
                Some(ns) => self
                    .tables
                    .entry(ns)
                    .or_insert_with(|| NetTables::read(pid))
                    .of(&inodes),
                None => NetTables::read(pid).of(&inodes),
            })
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod sys {
    use std::io;
    use std::net::SocketAddr;

    use super::{ProcInfo, ProcessSockets, Usage};

    pub fn own_pids() -> io::Result<Vec<u32>> {
        Err(io::Error::other("process table not supported on this OS"))
    }
    pub fn now_start_us() -> u64 {
        super::now_us()
    }
    pub fn legacy_start_us(started_us: u64) -> u64 {
        started_us
    }
    pub fn started_unix_us(_started_us: u64) -> Option<u64> {
        None
    }
    pub fn sandbox_denies(_pid: u32, _path: &std::ffi::CStr) -> Option<bool> {
        None
    }
    pub fn environ_has(_pid: u32, _entry: &[u8]) -> Option<bool> {
        None
    }
    pub fn info(_pid: u32) -> Option<ProcInfo> {
        None
    }
    pub fn usage(_pid: u32) -> Usage {
        Usage::default()
    }
    /// One pass over many processes: each process's sockets are read for it alone.
    #[derive(Default)]
    pub struct Scan;

    impl Scan {
        pub fn sockets(&mut self, pid: u32, _netns: Option<u64>) -> Option<ProcessSockets> {
            sockets(pid)
        }
    }

    pub fn sockets(_pid: u32) -> Option<ProcessSockets> {
        None
    }
    pub fn net_namespace(_pid: u32) -> Option<u64> {
        None
    }
    pub fn executable(_pid: u32) -> Option<std::path::PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, parent: u32, group: u32, started_us: u64) -> ProcInfo {
        ProcInfo {
            pid,
            ppid: parent,
            pgid: group,
            started_us,
            zombie: false,
            name: format!("p{pid}"),
        }
    }

    fn table(rows: &[ProcInfo]) -> ProcTable {
        rows.iter().map(|r| (r.pid, r.clone())).collect()
    }

    #[test]
    fn the_tree_follows_parents_groups_and_never_a_reused_pid() {
        let root = ProcessIdentity {
            pid: 100,
            started_us: 1_000,
        };
        let t = table(&[
            p(100, 1, 100, 1_000),
            p(101, 100, 100, 1_100),
            // Left the group (setsid) but is a child of a tracked process.
            p(102, 101, 102, 1_200),
            // Orphaned before we looked (parent gone, re-parented to launchd), still in the group.
            p(103, 1, 100, 1_300),
            // Another user's process tree is not in a table of ours; an unrelated process whose
            // parent pid happens to be ours but started before the root is a reused pid.
            p(104, 100, 104, 900),
            p(200, 1, 200, 500),
        ]);
        let mut tree = Tree::new();
        assert!(!track(&mut tree, root, &t));
        let pids: Vec<u32> = tree.keys().copied().collect();
        assert_eq!(pids, vec![100, 101, 102, 103]);

        // The root exits and its pid is reused by an unrelated process: the reused pid is
        // dropped, its children are not adopted, the rest of the tree is still tracked.
        let t = table(&[
            p(100, 1, 100, 5_000),
            p(105, 100, 100, 5_100),
            p(102, 1, 102, 1_200),
            p(103, 1, 100, 1_300),
        ]);
        track(&mut tree, root, &t);
        let pids: Vec<u32> = tree.keys().copied().collect();
        assert_eq!(pids, vec![102, 103]);
        let alive: Vec<u32> = alive(&tree, &t).iter().map(|i| i.pid).collect();
        assert_eq!(alive, vec![102, 103]);
    }
}
