//! Resource sampling: CPU time, resident memory and open descriptors of VPN Manager's own
//! processes.
//!
//! A process reports itself with [`sample_self`] (no privileges needed). The manager also samples
//! processes it did not start itself but serves — the controller on its socket — by pid with
//! [`sample_process`]. A pid alone never identifies a process: pids are reused, so every sample
//! carries a [`ProcessIdentity`] of pid **and start time**, and callers never difference counters
//! across two identities (a restarted process starts new counters).
//!
//! Supported on macOS (`proc_pidinfo`) and Linux (`/proc`). Elsewhere the by-pid calls return
//! `Unsupported` and `sample_self` reports CPU time only.
#![allow(
    unsafe_code,
    reason = "resource sampling calls getrusage/sysconf (Linux) and proc_pidinfo/sysctlbyname/mach_timebase_info (macOS) via libc"
)]

use std::io;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelfSample {
    /// User + system CPU time consumed so far, nanoseconds.
    pub cpu_ns: u64,
    /// Current resident set size, bytes (None if the OS did not tell us).
    pub rss_bytes: Option<u64>,
}

#[must_use]
pub fn sample_self() -> SelfSample {
    SelfSample {
        cpu_ns: cpu_ns(),
        rss_bytes: rss_bytes(),
    }
}

fn cpu_ns() -> u64 {
    // SAFETY: getrusage writes into the zeroed struct we pass.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointer to a rusage.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut ru) } != 0 {
        return 0;
    }
    #[expect(
        clippy::cast_sign_loss,
        reason = "getrusage reports non-negative CPU times"
    )]
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1_000;
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

#[cfg(target_os = "macos")]
fn rss_bytes() -> Option<u64> {
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    macos::task_info(pid).ok().map(|t| t.pti_resident_size)
}

#[cfg(target_os = "linux")]
fn rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * linux::page_size())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rss_bytes() -> Option<u64> {
    None
}

/// What a long-running VPN Manager process reports about itself (diagnostics): its own OS
/// start time, memory and CPU time.
pub fn process_report(
    role: &str,
    version: &str,
    build_id: &str,
    git_rev: &str,
    binary: vpn_domain::BinaryDigest,
) -> vpn_domain::ProcessReport {
    let pid = std::process::id();
    let started_ms = crate::process::identity(pid).and_then(|i| i.started_at_ms);
    let now_ms = vpn_domain::Timestamp::now().unix_millis();
    let sample = sample_self();
    vpn_domain::ProcessReport {
        role: role.into(),
        pid,
        version: version.into(),
        build_id: build_id.into(),
        git_rev: git_rev.into(),
        binary,
        started_at: started_ms.and_then(vpn_domain::Timestamp::from_unix_millis),
        uptime_secs: started_ms
            .filter(|s| *s <= now_ms)
            .map(|s| ((now_ms - s) / 1000).cast_unsigned()),
        rss_bytes: sample.rss_bytes,
        cpu_ms: sample.cpu_ns / 1_000_000,
    }
}

/// Number of logical CPUs (for host-percentage conversions).
#[must_use]
pub fn logical_cpus() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX))
}

/// A process told apart from any later process that reuses its pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// When the process started, microseconds since the Unix epoch.
    pub start_unix_us: u64,
}

impl ProcessIdentity {
    /// Stable text form `pid:<pid>/start:<µs>`, used as the identity in samples and reports.
    #[must_use]
    pub fn key(&self) -> String {
        format!("pid:{}/start:{}", self.pid, self.start_unix_us)
    }
}

/// One by-pid observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSample {
    pub identity: ProcessIdentity,
    /// User + system CPU time consumed so far, nanoseconds.
    pub cpu_ns: u64,
    pub rss_bytes: Option<u64>,
    /// Open file descriptors (None if the OS did not tell us).
    pub fd_count: Option<u32>,
}

/// Identity of the calling process.
///
/// # Errors
///
/// Fails as [`process_identity`] does.
pub fn self_identity() -> io::Result<ProcessIdentity> {
    process_identity(std::process::id())
}

/// Identity (pid + start time) of a process of this user.
///
/// # Errors
///
/// Fails when the process does not exist or cannot be inspected; always on unsupported systems.
pub fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    #[cfg(target_os = "macos")]
    {
        macos::identity(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::identity(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err(unsupported())
    }
}

/// CPU time, resident memory and descriptors of a process of this user, with its identity.
///
/// The caller compares the identity with the one it expects: a different start time is another
/// process that reused the pid.
///
/// # Errors
///
/// Fails when the process does not exist or cannot be inspected; always on unsupported systems.
pub fn sample_process(pid: u32) -> io::Result<ProcessSample> {
    #[cfg(target_os = "macos")]
    {
        macos::sample(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::sample(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err(unsupported())
    }
}

/// Open descriptors of the calling process.
#[must_use]
pub fn fd_count_self() -> Option<u32> {
    sample_process(std::process::id())
        .ok()
        .and_then(|s| s.fd_count)
}

/// The boot session of this host as a lowercase UUID: samples and leases from another boot are
/// never compared with this one. macOS `kern.bootsessionuuid`, Linux `boot_id`.
#[must_use]
pub fn host_boot_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    let raw = macos::sysctl_string("kern.bootsessionuuid");
    #[cfg(target_os = "linux")]
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let raw: Option<String> = None;
    raw.map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "process sampling is implemented for macOS and Linux only",
    )
}

#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use std::io;
    use std::sync::OnceLock;

    use super::{ProcessIdentity, ProcessSample};

    fn pidinfo<T>(pid: i32, flavor: i32, arg: u64) -> io::Result<T> {
        // SAFETY: an all-zero bit pattern is valid for the plain C structs used here.
        let mut out: T = unsafe { std::mem::zeroed() };
        let size = i32::try_from(std::mem::size_of::<T>())
            .map_err(|_| io::Error::other("proc_pidinfo struct out of range"))?;
        // SAFETY: pointer and size describe `out`.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                flavor,
                arg,
                (&raw mut out).cast::<libc::c_void>(),
                size,
            )
        };
        if n == size {
            Ok(out)
        } else if n <= 0 {
            Err(io::Error::last_os_error())
        } else {
            Err(io::Error::other("proc_pidinfo returned a short answer"))
        }
    }

    pub fn task_info(pid: i32) -> io::Result<libc::proc_taskinfo> {
        pidinfo(pid, libc::PROC_PIDTASKINFO, 0)
    }

    fn bsd_info(pid: i32) -> io::Result<libc::proc_bsdinfo> {
        pidinfo(pid, libc::PROC_PIDTBSDINFO, 0)
    }

    pub fn identity(pid: u32) -> io::Result<ProcessIdentity> {
        let pid_i = i32::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
        let b = bsd_info(pid_i)?;
        Ok(ProcessIdentity {
            pid,
            start_unix_us: b
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(b.pbi_start_tvusec),
        })
    }

    /// `proc_taskinfo` CPU times are Mach absolute time units (equal to nanoseconds on Intel,
    /// 125/3 ns per unit on Apple silicon). libc marks the timebase call deprecated in favour of
    /// the `mach2` crate; it is the same stable libSystem function, so no extra dependency.
    #[allow(
        deprecated,
        reason = "libc points to the `mach2` crate for the same stable libSystem call"
    )]
    fn mach_to_ns(units: u64) -> u64 {
        static TIMEBASE: OnceLock<(u64, u64)> = OnceLock::new();
        let (numer, denom) = *TIMEBASE.get_or_init(|| {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: writes into the struct we pass.
            let r = unsafe { libc::mach_timebase_info(&raw mut info) };
            if r == 0 && info.numer > 0 && info.denom > 0 {
                (u64::from(info.numer), u64::from(info.denom))
            } else {
                (1, 1)
            }
        });
        u64::try_from((u128::from(units) * u128::from(numer)) / u128::from(denom))
            .unwrap_or(u64::MAX)
    }

    fn fd_count(pid: i32, hint: u32) -> Option<u32> {
        let entry = std::mem::size_of::<libc::proc_fdinfo>();
        // Room for the count the kernel reported plus a margin for descriptors opened since.
        let slots = (hint as usize).saturating_add(64).min(1 << 20);
        let mut buf: Vec<libc::proc_fdinfo> = Vec::with_capacity(slots);
        let bytes = i32::try_from(slots * entry).ok()?;
        // SAFETY: the buffer has room for `slots` entries; the kernel writes at most `bytes`.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                bytes,
            )
        };
        let written = usize::try_from(n).ok()?;
        u32::try_from(written / entry).ok()
    }

    pub fn sample(pid: u32) -> io::Result<ProcessSample> {
        let pid_i = i32::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
        let b = bsd_info(pid_i)?;
        let t = task_info(pid_i)?;
        // The identity is read before and after: a pid that changed hands in between is refused.
        let after = identity(pid)?;
        let identity = ProcessIdentity {
            pid,
            start_unix_us: b
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(b.pbi_start_tvusec),
        };
        if after != identity {
            return Err(io::Error::other("the process changed while it was sampled"));
        }
        Ok(ProcessSample {
            identity,
            cpu_ns: mach_to_ns(t.pti_total_user.saturating_add(t.pti_total_system)),
            rss_bytes: Some(t.pti_resident_size),
            fd_count: fd_count(pid_i, b.pbi_nfiles),
        })
    }

    pub fn sysctl_string(name: &str) -> Option<String> {
        let cname = std::ffi::CString::new(name).ok()?;
        let mut len: libc::size_t = 0;
        // SAFETY: a size query with a null buffer.
        let r = unsafe {
            libc::sysctlbyname(
                cname.as_ptr(),
                std::ptr::null_mut(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 || len == 0 || len > 4096 {
            return None;
        }
        let mut buf = vec![0u8; len];
        // SAFETY: the buffer holds `len` bytes.
        let r = unsafe {
            libc::sysctlbyname(
                cname.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return None;
        }
        buf.truncate(len);
        while buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).ok()
    }

    pub fn sysctl_u64(name: &str) -> Option<u64> {
        let cname = std::ffi::CString::new(name).ok()?;
        let mut v: u64 = 0;
        let mut len: libc::size_t = std::mem::size_of::<u64>();
        // SAFETY: `v` holds `len` bytes.
        let r = unsafe {
            libc::sysctlbyname(
                cname.as_ptr(),
                (&raw mut v).cast::<libc::c_void>(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (r == 0 && len == std::mem::size_of::<u64>()).then_some(v)
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::io;
    use std::sync::OnceLock;

    use super::{ProcessIdentity, ProcessSample};

    pub fn page_size() -> u64 {
        // SAFETY: sysconf with a constant name.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        page.max(0).cast_unsigned()
    }

    fn clock_ticks() -> u64 {
        // SAFETY: sysconf with a constant name.
        let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if t > 0 { t.cast_unsigned() } else { 100 }
    }

    /// Boot time (Unix seconds) from `/proc/stat`: start times are ticks since boot.
    fn boot_time() -> io::Result<u64> {
        static BTIME: OnceLock<Option<u64>> = OnceLock::new();
        BTIME
            .get_or_init(|| {
                let stat = std::fs::read_to_string("/proc/stat").ok()?;
                stat.lines()
                    .find_map(|l| l.strip_prefix("btime "))
                    .and_then(|v| v.trim().parse().ok())
            })
            .ok_or_else(|| io::Error::other("btime missing from /proc/stat"))
    }

    /// `utime`, `stime` and `starttime` (clock ticks) from `/proc/<pid>/stat`. The command name
    /// may contain spaces and parentheses: fields are counted after its last `)`.
    pub fn parse_stat(stat: &str) -> Option<(u64, u64, u64)> {
        let rest = &stat[stat.rfind(')')? + 1..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        // rest[0] is field 3 (state): utime is field 14, stime 15, starttime 22.
        Some((
            f.get(11)?.parse().ok()?,
            f.get(12)?.parse().ok()?,
            f.get(19)?.parse().ok()?,
        ))
    }

    fn read_stat(pid: u32) -> io::Result<(u64, u64, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        parse_stat(&stat).ok_or_else(|| io::Error::other("unexpected /proc/<pid>/stat format"))
    }

    fn identity_from(pid: u32, start_ticks: u64) -> io::Result<ProcessIdentity> {
        let hz = clock_ticks();
        Ok(ProcessIdentity {
            pid,
            start_unix_us: boot_time()?
                .saturating_mul(1_000_000)
                .saturating_add(start_ticks.saturating_mul(1_000_000) / hz),
        })
    }

    pub fn identity(pid: u32) -> io::Result<ProcessIdentity> {
        let (_, _, start) = read_stat(pid)?;
        identity_from(pid, start)
    }

    pub fn sample(pid: u32) -> io::Result<ProcessSample> {
        let (utime, stime, start) = read_stat(pid)?;
        let identity = identity_from(pid, start)?;
        let rss = std::fs::read_to_string(format!("/proc/{pid}/statm"))
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .map(|pages| pages * page_size());
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()
            .map(|d| u32::try_from(d.count()).unwrap_or(u32::MAX));
        // Read the identity again: a pid that changed hands in between is refused.
        if self::identity(pid)? != identity {
            return Err(io::Error::other("the process changed while it was sampled"));
        }
        let hz = clock_ticks();
        Ok(ProcessSample {
            identity,
            cpu_ns: utime.saturating_add(stime).saturating_mul(1_000_000_000) / hz,
            rss_bytes: rss,
            fd_count: fds,
        })
    }
}
