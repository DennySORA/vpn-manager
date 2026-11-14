//! Shedding privileges before `exec`. A process that joined (or created) the sandbox's user
//! namespace is root there with every capability; neither an App nor the worker needs any. The
//! functions here only make system calls (no allocation, no locks), so they are safe between
//! `fork` and `exec` of a multi-threaded parent.
#![allow(
    unsafe_code,
    reason = "this module owns capability dropping via capset and prctl"
)]

use std::io;

/// `_LINUX_CAPABILITY_VERSION_3`
const CAP_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Highest capability number this kernel knows (read before forking; needs the filesystem).
pub fn last_capability() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(63)
}

/// Whether this process holds no capability at all (none permitted, none effective).
fn holds_none() -> bool {
    let header = CapHeader {
        version: CAP_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capget with a live header and a two-element array, as version 3 requires.
    let r = unsafe { libc::syscall(libc::SYS_capget, &raw const header, data.as_mut_ptr()) };
    r == 0
        && data
            .iter()
            .all(|d| d.permitted == 0 && d.effective == 0 && d.inheritable == 0)
}

/// Drop every capability for good — bounding set, ambient, inheritable, permitted, effective —
/// lock root's special treatment off (so `exec` as uid 0 in the namespace grants nothing back)
/// and set `no_new_privs`. Async-signal-safe. A process that already holds none (an App tree's
/// init shed them before it started the App) only makes sure of `no_new_privs`: what it lacks
/// it can never get back.
pub fn drop_all(last_cap: u32) -> io::Result<()> {
    if holds_none() {
        // SAFETY: prctl with constant arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }
    // SAFETY: prctl and capset with constant arguments and pointers to live locals.
    unsafe {
        for cap in 0..=last_cap {
            if libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) < 0 {
                let e = io::Error::last_os_error();
                // Unknown to this kernel: nothing to drop.
                if e.raw_os_error() != Some(libc::EINVAL) {
                    return Err(e);
                }
            }
        }
        // Old kernels without ambient capabilities answer EINVAL: nothing to clear.
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        );
        let bits = libc::SECBIT_KEEP_CAPS_LOCKED
            | libc::SECBIT_NO_SETUID_FIXUP
            | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
            | libc::SECBIT_NOROOT
            | libc::SECBIT_NOROOT_LOCKED;
        if libc::prctl(
            libc::PR_SET_SECUREBITS,
            libc::c_ulong::from(bits.cast_unsigned()),
            0,
            0,
            0,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        let header = CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
