//! Process Manager: spawning Instance workers, watching parent liveness, and identifying a
//! process beyond its pid (OS start time and program) so a leftover worker can be proven ours.
//!
//! A worker gets exactly one inherited descriptor besides stdio: its private control socket as
//! fd 3. Every other descriptor is closed in the child before `exec`, so no listener, database,
//! lock or socket of the manager leaks into the worker.
#![allow(
    unsafe_code,
    reason = "this module owns process spawn: pre-exec fd setup, setns, signals and process lookups via libc"
)]

use std::ffi::OsStr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::{Child, Command};

/// The descriptor number the worker finds its control socket on.
pub const CONTROL_FD: i32 = 3;

/// Spawn `exe <args>` with `control` as fd 3 and every other descriptor closed at exec. A failed
/// exec (missing or non-executable binary) is reported by this call, not by a later timeout.
///
/// # Errors
///
/// Fails when the process cannot be spawned or `exec` fails (missing or non-executable binary).
pub fn spawn_with_control_fd<I, S>(exe: &Path, args: I, control: OwnedFd) -> std::io::Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    spawn(exe, args, control, None, None)
}

/// [`spawn_with_control_fd`], optionally into the worker's cgroup.
///
/// With `cgroup_procs` (the open `cgroup.procs` of the worker's cgroup, see
/// [`crate::limits::Leaf::procs_fd`]) the child moves itself into that cgroup before `exec`: none
/// of its code runs outside it. The caller confirms the move afterwards.
///
/// # Errors
///
/// Fails when the process cannot be spawned, joining the cgroup fails, or `exec` fails.
pub fn spawn_worker<I, S>(
    exe: &Path,
    args: I,
    control: OwnedFd,
    cgroup_procs: Option<std::os::fd::RawFd>,
) -> std::io::Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    spawn(exe, args, control, None, cgroup_procs)
}

/// Like [`spawn_with_control_fd`], for the worker of a strict Instance.
///
/// Before `exec` the child joins the sandbox's user namespace, then its network namespace (it is
/// root in neither the host nor, after this, anywhere: every capability is dropped and
/// `no_new_privs` set). Its kernel sockets can then only reach the sandbox's TUN device;
/// descriptors it is handed (the Gateway listeners, the `WireGuard` underlay socket) stay in the
/// host's namespace. With `cgroup_procs` it joins its cgroup first, before any namespace changes
/// (see [`spawn_worker`]).
///
/// # Errors
///
/// Fails when the process cannot be spawned, joining the cgroup or a namespace or dropping
/// capabilities fails, or `exec` fails.
#[cfg(target_os = "linux")]
pub fn spawn_with_control_fd_in<I, S>(
    exe: &Path,
    args: I,
    control: OwnedFd,
    sandbox: &crate::sandbox::WorkerEntry,
    cgroup_procs: Option<std::os::fd::RawFd>,
) -> std::io::Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    spawn(exe, args, control, Some(sandbox), cgroup_procs)
}

#[cfg(target_os = "linux")]
type Entry<'a> = Option<&'a crate::sandbox::WorkerEntry>;
/// Only Linux has a sandbox to join: elsewhere no entry can be named, by value, so nothing ever
/// refers to an uninhabited type (the lifetime only matches the Linux alias).
#[cfg(not(target_os = "linux"))]
type Entry<'a> = Option<std::convert::Infallible>;

fn spawn<I, S>(
    exe: &Path,
    args: I,
    control: OwnedFd,
    entry: Entry<'_>,
    cgroup_procs: Option<std::os::fd::RawFd>,
) -> std::io::Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    #[cfg(target_os = "linux")]
    let entry = entry.map(|e| (e.user.as_raw_fd(), e.net.as_raw_fd(), e.cap_last));
    #[cfg(not(target_os = "linux"))]
    let entry: Option<(i32, i32, u32)> = entry.map(|never| match never {});
    let raw = control.as_raw_fd();
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env_clear()
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        .kill_on_drop(true);
    // SAFETY: the closure runs in the forked child before exec and only calls
    // async-signal-safe functions (dup2, fcntl, write, close_range, getdtablesize, setns, prctl,
    // capset).
    unsafe {
        cmd.pre_exec(move || {
            if raw == CONTROL_FD {
                // Already at fd 3: just clear close-on-exec.
                let flags = libc::fcntl(CONTROL_FD, libc::F_GETFD);
                libc::fcntl(CONTROL_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            } else if libc::dup2(raw, CONTROL_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(fd) = cgroup_procs {
                // "0" moves the writing process, before any namespace changes. A failure is
                // seen by the caller's check.
                libc::write(fd, b"0".as_ptr().cast(), 1);
            }
            cloexec_from(CONTROL_FD + 1);
            #[cfg(target_os = "linux")]
            if let Some((user, net, cap_last)) = entry {
                // The user namespace first: it grants the right to join its network namespace.
                if libc::setns(user, libc::CLONE_NEWUSER) < 0
                    || libc::setns(net, libc::CLONE_NEWNET) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                crate::sandbox::caps_drop_all(cap_last)?;
            }
            #[cfg(not(target_os = "linux"))]
            let _ = entry;
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(control);
    Ok(child)
}

/// Mark every descriptor >= `first` close-on-exec (async-signal-safe). Closing them here instead
/// would also close the standard library's exec-error pipe: a failed exec would then go
/// unreported and `spawn()` would return a child that never runs.
pub(crate) fn cloexec_from(first: i32) {
    #[cfg(target_os = "linux")]
    {
        /// `CLOSE_RANGE_CLOEXEC` (Linux 5.11+): set the flag instead of closing.
        const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
        // SAFETY: raw syscall with constant arguments; failure falls through to the loop.
        let r = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first.cast_unsigned(),
                u32::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if r == 0 {
            return;
        }
    }
    // SAFETY: getdtablesize/fcntl are async-signal-safe and have no memory preconditions.
    let max = unsafe { libc::getdtablesize() }.max(first);
    for fd in first..max {
        // SAFETY: fcntl on a possibly-unused descriptor number only fails with EBADF.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

/// Take the control socket a worker inherited on fd 3.
///
/// # Errors
///
/// Fails when fd 3 is not open.
pub fn take_control_fd() -> std::io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: fcntl on a constant fd number only queries its flags.
    let flags = unsafe { libc::fcntl(CONTROL_FD, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::other(
            "no control socket on fd 3 (workers are started by the manager only)",
        ));
    }
    // SAFETY: fd 3 is open (checked above) and owned by nobody else in this process.
    let fd = unsafe { OwnedFd::from_raw_fd(CONTROL_FD) };
    // SAFETY: set close-on-exec on an fd we now own.
    unsafe {
        libc::fcntl(CONTROL_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }
    Ok(fd)
}

/// Whether our parent died (we were re-parented to init/launchd).
#[must_use]
pub fn orphaned() -> bool {
    // SAFETY: getppid has no preconditions.
    unsafe { libc::getppid() == 1 }
}

/// This process's user id.
#[must_use]
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// What identifies one process for its whole life. A pid alone is reused by the OS; a pid with
/// the OS's record of when that process started is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub uid: u32,
    /// Opaque start token: macOS `<seconds>.<microseconds>` since the epoch; Linux
    /// `<boot id>:<clock ticks since boot>`. Equal tokens mean the same process.
    pub start: String,
    /// Start time in Unix milliseconds (display only); None when the OS does not say.
    pub started_at_ms: Option<i64>,
    /// The program it runs; None when the OS does not tell us.
    pub exe: Option<PathBuf>,
    /// Exited, waiting to be reaped by its parent: no longer runs anything.
    pub zombie: bool,
}

impl ProcessIdentity {
    /// Whether `now` (observed at this moment) is provably the process `self` recorded: same
    /// pid, user, start time and program. An unknown program never counts as the same.
    #[must_use]
    pub fn is_same_process(&self, now: &Self) -> bool {
        self.pid == now.pid
            && self.uid == now.uid
            && self.start == now.start
            && matches!((&self.exe, &now.exe), (Some(a), Some(b)) if a == b)
    }
}

/// The identity of `pid` right now; None when there is no such process (or the OS will not
/// tell us about it).
#[cfg(target_os = "macos")]
#[must_use]
pub fn identity(pid: u32) -> Option<ProcessIdentity> {
    use std::os::unix::ffi::OsStrExt;
    let raw = libc::pid_t::try_from(pid).ok().filter(|p| *p > 0)?;
    // SAFETY: proc_pidinfo fills a zeroed proc_bsdinfo of the size we pass.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: pointer and size describe `info`.
    let n = unsafe {
        libc::proc_pidinfo(
            raw,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast::<libc::c_void>(),
            size,
        )
    };
    if n != size {
        return None;
    }
    let path_max = libc::PROC_PIDPATHINFO_MAXSIZE.cast_unsigned();
    let mut buf = vec![0u8; path_max as usize];
    // SAFETY: the buffer is PROC_PIDPATHINFO_MAXSIZE bytes long, as the call requires.
    let len = unsafe { libc::proc_pidpath(raw, buf.as_mut_ptr().cast::<libc::c_void>(), path_max) };
    let exe = usize::try_from(len)
        .ok()
        .filter(|l| *l > 0 && *l <= buf.len())
        .map(|l| PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..l])));
    let secs = info.pbi_start_tvsec;
    let micros = info.pbi_start_tvusec;
    Some(ProcessIdentity {
        pid,
        uid: info.pbi_uid,
        start: format!("{secs}.{micros:06}"),
        started_at_ms: i64::try_from(secs)
            .ok()
            .map(|s| s * 1000 + (micros / 1000).cast_signed()),
        exe,
        zombie: info.pbi_status == libc::SZOMB,
    })
}

/// The identity of `pid` right now; None when there is no such process (or the OS will not
/// tell us about it).
#[cfg(target_os = "linux")]
#[must_use]
pub fn identity(pid: u32) -> Option<ProcessIdentity> {
    use std::os::unix::fs::MetadataExt;
    if pid == 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` may contain spaces and parentheses: the fields that follow start after the last ')'.
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] is field 3 (state); starttime is field 22.
    let zombie = fields.first().is_some_and(|s| *s == "Z" || *s == "X");
    let ticks: u64 = fields.get(19)?.parse().ok()?;
    let uid = std::fs::metadata(format!("/proc/{pid}")).ok()?.uid();
    // The link reads "<path> (deleted)" once the file was replaced; the process still runs that
    // program.
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| {
            p.to_str()
                .and_then(|s| s.strip_suffix(" (deleted)"))
                .map_or_else(|| p.clone(), PathBuf::from)
        });
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_or_default(|s| s.trim().to_string());
    Some(ProcessIdentity {
        pid,
        uid,
        start: format!("{boot_id}:{ticks}"),
        started_at_ms: linux_boot_ms()
            .map(|boot| boot + (ticks * 1000 / clock_ticks()).cast_signed()),
        exe,
        zombie,
    })
}

#[cfg(target_os = "linux")]
fn clock_ticks() -> u64 {
    // SAFETY: sysconf with a constant name.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(t).ok().filter(|t| *t > 0).unwrap_or(100)
}

/// Boot time in Unix milliseconds (`btime` of /proc/stat).
#[cfg(target_os = "linux")]
fn linux_boot_ms() -> Option<i64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let secs: i64 = stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(secs * 1000)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn identity(_pid: u32) -> Option<ProcessIdentity> {
    None
}

/// What [`kill_verified`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    /// SIGKILL was sent to exactly the recorded process.
    Killed,
    /// No such process any more (or only its zombie): nothing to do.
    Gone,
    /// The pid now belongs to another process: left alone.
    NotOurs,
}

/// SIGKILL the process `expected` describes, and only that process: its identity is checked
/// right before the signal.
///
/// On Linux the check and the signal go through a pidfd, which pins the process, so a pid reused in
/// between cannot be hit. macOS has no pidfd: the check and the `kill` are microseconds apart,
/// while the OS reuses a pid only after cycling through the others.
///
/// # Errors
///
/// Fails when opening the pidfd or sending the signal fails for a reason other than the process
/// being gone.
pub fn kill_verified(expected: &ProcessIdentity) -> std::io::Result<KillOutcome> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: plain syscall with a pid and no flags; the descriptor is closed below.
        let fd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, libc::c_long::from(expected.pid), 0) };
        if fd >= 0 {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "pidfd_open returns a descriptor number, which fits c_int"
            )]
            let fd = fd as libc::c_int;
            let outcome = match identity(expected.pid) {
                Some(now) if now.zombie => Ok(KillOutcome::Gone),
                Some(now) if expected.is_same_process(&now) => {
                    // SAFETY: signal through the pidfd opened above; no siginfo, no flags.
                    let r = unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            fd,
                            libc::SIGKILL,
                            std::ptr::null::<libc::c_void>(),
                            0,
                        )
                    };
                    if r == 0 {
                        Ok(KillOutcome::Killed)
                    } else {
                        let e = std::io::Error::last_os_error();
                        if e.raw_os_error() == Some(libc::ESRCH) {
                            Ok(KillOutcome::Gone)
                        } else {
                            Err(e)
                        }
                    }
                }
                Some(_) => Ok(KillOutcome::NotOurs),
                None => Ok(KillOutcome::Gone),
            };
            // SAFETY: closing the pidfd we own.
            unsafe { libc::close(fd) };
            return outcome;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            return Ok(KillOutcome::Gone);
        }
        if e.raw_os_error() != Some(libc::ENOSYS) {
            return Err(e);
        }
        // No pidfd (kernel < 5.3): check, then signal, as on macOS.
    }
    match identity(expected.pid) {
        Some(now) if now.zombie => Ok(KillOutcome::Gone),
        Some(now) if expected.is_same_process(&now) => {
            // SAFETY: kill with a concrete pid and signal.
            if unsafe { libc::kill(expected.pid as libc::pid_t, libc::SIGKILL) } == 0 {
                Ok(KillOutcome::Killed)
            } else {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ESRCH) {
                    Ok(KillOutcome::Gone)
                } else {
                    Err(e)
                }
            }
        }
        Some(_) => Ok(KillOutcome::NotOurs),
        None => Ok(KillOutcome::Gone),
    }
}

/// Whether the process `expected` describes has ended (no process, a zombie, or the pid now
/// belongs to someone else).
#[must_use]
pub fn ended(expected: &ProcessIdentity) -> bool {
    match identity(expected.pid) {
        Some(now) => now.zombie || !expected.is_same_process(&now),
        None => true,
    }
}
