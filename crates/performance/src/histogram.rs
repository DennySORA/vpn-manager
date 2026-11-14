//! Fixed-bucket latency histograms (`PERFORMANCE_MANAGER.md` §4 and §9).
//!
//! Counters are cumulative since the owner's epoch (a worker's generation), so a window is the
//! *difference* of two readings of the same epoch; windows are merged by adding bucket counts,
//! never by averaging per-interval quantiles. A quantile is the upper bound of the first bucket
//! whose cumulative count reaches `ceil(q × count)`, with that bucket's lower bound beside it; in
//! the +∞ bucket there is no upper bound. Timeouts are counted apart and are never a latency.

use vpn_domain::{Counter, LATENCY_HISTOGRAM_VERSION, LatencyKind, LatencySummary};

/// One histogram reading. `bounds[i]` is the inclusive upper bound (µs) of bucket `i`;
/// `u64::MAX` marks the +∞ bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    pub bounds: &'static [u64],
    /// Per-bucket counts (not cumulative).
    pub buckets: Vec<u64>,
    pub sum_us: u64,
    pub timeouts: u64,
}

/// A quantile from bucket counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantile {
    NoSamples,
    /// The true value is in `(lower_us, upper_us]`; `upper_us` is `None` in the +∞ bucket.
    InBucket {
        lower_us: u64,
        upper_us: Option<u64>,
    },
}

impl Histogram {
    #[must_use]
    pub fn empty(bounds: &'static [u64]) -> Self {
        Self {
            bounds,
            buckets: vec![0; bounds.len()],
            sum_us: 0,
            timeouts: 0,
        }
    }

    /// A reading from per-bucket counts; `None` when the bucket count does not match the bounds.
    #[must_use]
    pub fn from_buckets(
        bounds: &'static [u64],
        buckets: &[u64],
        sum_us: u64,
        timeouts: u64,
    ) -> Option<Self> {
        (buckets.len() == bounds.len()).then(|| Self {
            bounds,
            buckets: buckets.to_vec(),
            sum_us,
            timeouts,
        })
    }

    /// Observations in buckets (timeouts excluded).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.buckets.iter().fold(0u64, |a, b| a.saturating_add(*b))
    }

    pub fn record(&mut self, us: u64) {
        let i = self
            .bounds
            .iter()
            .position(|&b| us <= b)
            .unwrap_or_else(|| self.bounds.len().saturating_sub(1));
        if let Some(b) = self.buckets.get_mut(i) {
            *b = b.saturating_add(1);
        }
        self.sum_us = self.sum_us.saturating_add(us);
    }

    pub const fn record_timeout(&mut self) {
        self.timeouts = self.timeouts.saturating_add(1);
    }

    /// `self − earlier` of two cumulative readings of the same epoch; `None` when any counter went
    /// backwards (a reset: the window across it is unknown).
    #[must_use]
    pub fn delta(&self, earlier: &Self) -> Option<Self> {
        if self.bounds != earlier.bounds || self.buckets.len() != earlier.buckets.len() {
            return None;
        }
        let buckets = self
            .buckets
            .iter()
            .zip(&earlier.buckets)
            .map(|(a, b)| a.checked_sub(*b))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            bounds: self.bounds,
            buckets,
            sum_us: self.sum_us.checked_sub(earlier.sum_us)?,
            timeouts: self.timeouts.checked_sub(earlier.timeouts)?,
        })
    }

    /// Add another window of the same bucket version.
    pub fn merge(&mut self, other: &Self) {
        if self.bounds != other.bounds {
            return;
        }
        for (a, b) in self.buckets.iter_mut().zip(&other.buckets) {
            *a = a.saturating_add(*b);
        }
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        self.timeouts = self.timeouts.saturating_add(other.timeouts);
    }

    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the rank `ceil(q × count)` with q in [0, 1] lies in [0, count], so it fits u64"
    )]
    pub fn quantile(&self, q: f64) -> Quantile {
        let count = self.count();
        if count == 0 || !(0.0..=1.0).contains(&q) {
            return Quantile::NoSamples;
        }
        let rank = ((q * count as f64).ceil() as u64).max(1);
        let mut cumulative = 0u64;
        for (i, n) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(*n);
            if cumulative >= rank {
                let lower_us = if i == 0 { 0 } else { self.bounds[i - 1] };
                let upper = self.bounds[i];
                return Quantile::InBucket {
                    lower_us,
                    upper_us: (upper != u64::MAX).then_some(upper),
                };
            }
        }
        Quantile::NoSamples
    }

    /// Observations in the +∞ bucket.
    #[must_use]
    pub fn overflow_count(&self) -> u64 {
        match self.bounds.last() {
            Some(&u64::MAX) => self.buckets.last().copied().unwrap_or(0),
            _ => 0,
        }
    }

    /// Upper bound of the highest non-empty bucket; `None` if empty or in the +∞ bucket.
    #[must_use]
    pub fn max_bucket_upper_us(&self) -> Option<u64> {
        let i = self.buckets.iter().rposition(|&n| n > 0)?;
        let upper = self.bounds[i];
        (upper != u64::MAX).then_some(upper)
    }

    /// The window summary. `coverage` is the share of the window covered by continuous readings.
    pub fn summary(&self, kind: LatencyKind, coverage: f64) -> LatencySummary {
        let q = |p: f64| match self.quantile(p) {
            Quantile::NoSamples => (None, None),
            Quantile::InBucket { lower_us, upper_us } => {
                (upper_us.map(Counter), Some(Counter(lower_us)))
            }
        };
        let (p50, p50_lower) = q(0.50);
        let (p95, p95_lower) = q(0.95);
        let (p99, p99_lower) = q(0.99);
        let count = self.count();
        let reason = if count == 0 {
            Some(vpn_domain::reason::NO_LATENCY_SAMPLES.to_string())
        } else if p99.is_none() {
            Some(vpn_domain::reason::OVERFLOW_BUCKET.to_string())
        } else {
            None
        };
        LatencySummary {
            kind,
            histogram_version: LATENCY_HISTOGRAM_VERSION.to_string(),
            quantile_method: "bucket_upper_bound".into(),
            count: Counter(count),
            timeout_count: Counter(self.timeouts),
            overflow_count: Counter(self.overflow_count()),
            p50_us: p50,
            p95_us: p95,
            p99_us: p99,
            p50_lower_us: p50_lower,
            p95_lower_us: p95_lower,
            p99_lower_us: p99_lower,
            max_bucket_upper_us: self.max_bucket_upper_us().map(Counter),
            coverage_ratio: coverage.clamp(0.0, 1.0),
            reason_code: reason,
        }
    }
}
