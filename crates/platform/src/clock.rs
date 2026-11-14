//! Whether this host's clock is synchronized (NTP or the like), as the kernel reports it.
//!
//! Linux: `adjtimex` asking for no change (read-only, needs no privilege). The clock counts as
//! synchronized while the maximum error the kernel keeps for it is below 16 s, systemd's rule (what
//! `timedatectl` shows as "System clock synchronized"): an NTP client (systemd-timesyncd, chrony,
//! ntpd) keeps it small; without one it grows by 0.5 ms a second, and the kernel marks the clock
//! unsynchronized at 16 s, where it also starts at boot. Elsewhere it cannot be told.
#![allow(
    unsafe_code,
    reason = "reading the kernel's clock discipline calls adjtimex via libc"
)]

/// The kernel's ceiling for the clock's maximum error (`NTP_PHASE_LIMIT`, in µs): there the clock
/// is unsynchronized.
#[cfg(target_os = "linux")]
const UNSYNCHRONIZED_US: libc::c_long = 16_000_000;

/// `Some(true)` while something keeps this host's clock synchronized, `Some(false)` while nothing
/// does, `None` when it cannot be told.
#[cfg(target_os = "linux")]
#[must_use]
pub fn synchronized() -> Option<bool> {
    // SAFETY: an all-zero timex is a valid one; its `modes` 0 asks adjtimex to change nothing.
    let mut t: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: adjtimex fills in the timex we own and pass exclusively.
    if unsafe { libc::adjtimex(&raw mut t) } < 0 {
        return None;
    }
    Some(t.maxerror < UNSYNCHRONIZED_US)
}

/// `None`: only Linux tells.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub const fn synchronized() -> Option<bool> {
    None
}
