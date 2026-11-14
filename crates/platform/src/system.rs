//! What this host is, as far as the passive performance analysis needs it: the installed memory
//! (with the logical CPU count, whether this host is the spec's reference environment).
//!
//! A value that cannot be read is `None`, never guessed. Read-only: `/proc` (Linux) and `sysctl`
//! (macOS).

/// Installed memory in bytes.
#[cfg(target_os = "macos")]
#[must_use]
pub fn ram_bytes() -> Option<u64> {
    crate::resources::macos::sysctl_u64("hw.memsize")
}

/// Installed memory in bytes.
#[cfg(target_os = "linux")]
#[must_use]
pub fn ram_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kib * 1024)
}

/// Installed memory in bytes.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn ram_bytes() -> Option<u64> {
    None
}
