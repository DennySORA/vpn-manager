//! The metric formulas of `PERFORMANCE_MANAGER.md` §4 the passive analysis uses.
//!
//! Every function returns `None` where the spec says the value is unknown (no elapsed time, a
//! counter that went backwards): unknown is never turned into zero.

/// Longest interval one rate may span: `max(5 s, 2.5 × sample interval)`.
#[must_use]
pub const fn max_gap_ms(sample_interval_ms: u64) -> u64 {
    let scaled = sample_interval_ms * 5 / 2;
    if scaled > 5_000 { scaled } else { 5_000 }
}

/// `new − old` of a cumulative counter; `None` when it went backwards (a reset is unknown, not 0).
#[must_use]
pub const fn delta(new: u64, old: u64) -> Option<u64> {
    new.checked_sub(old)
}

/// `100 × Δcpu_ns / (Δms × 1,000,000)`: percent of one logical CPU (100 = one core fully used;
/// may exceed 100).
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "a percentage of counters; f64's 52-bit mantissa is far finer than the result needs"
)]
pub fn cpu_core_pct(cpu_delta_ns: u64, elapsed_ms: u64) -> Option<f64> {
    (elapsed_ms > 0).then(|| 100.0 * cpu_delta_ns as f64 / (elapsed_ms as f64 * 1_000_000.0))
}

/// `cpu_core_pct / logical CPUs`: share of the whole host (not a power percentage).
#[must_use]
pub fn cpu_host_pct(cpu_core_pct: f64, logical_cpus: u32) -> Option<f64> {
    (logical_cpus > 0).then(|| cpu_core_pct / f64::from(logical_cpus))
}

/// `8 × Δbytes / Δt_seconds`, bits per second.
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "a rate of counters; f64's 52-bit mantissa is far finer than the result needs"
)]
pub fn rate_bps(delta_bytes: u64, elapsed_ms: u64) -> Option<f64> {
    (elapsed_ms > 0).then(|| delta_bytes as f64 * 8_000.0 / elapsed_ms as f64)
}

/// `(observed / requested, requested − observed)`, the ratio capped at 1.
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "a ratio of durations in ms; f64's 52-bit mantissa is far finer than the result needs"
)]
pub fn coverage(observed_ms: u64, requested_ms: u64) -> (f64, u64) {
    if requested_ms == 0 {
        return (0.0, 0);
    }
    let observed = observed_ms.min(requested_ms);
    (
        observed as f64 / requested_ms as f64,
        requested_ms - observed,
    )
}

/// Round to `digits` decimals for display-stable numbers.
#[must_use]
pub fn round(v: f64, digits: i32) -> f64 {
    let m = 10f64.powi(digits);
    (v * m).round() / m
}
