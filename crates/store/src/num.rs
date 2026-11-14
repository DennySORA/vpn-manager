//! Numeric conversions of metric arithmetic that may round.

/// `v` as `f64`, for rates, means and gauges.
///
/// Counters, byte counts and durations in ms stay far below 2^53, where the conversion is
/// exact; beyond it rounds to the nearest `f64`, as `as` does.
#[expect(
    clippy::cast_precision_loss,
    reason = "metric values are far below 2^53; rounding beyond is the intended float conversion"
)]
pub const fn u64_to_f64(v: u64) -> f64 {
    v as f64
}

/// [`u64_to_f64`] for a signed value (a time or a signed delta in ms).
#[expect(
    clippy::cast_precision_loss,
    reason = "metric values are far below 2^53; rounding beyond is the intended float conversion"
)]
pub const fn i64_to_f64(v: i64) -> f64 {
    v as f64
}
