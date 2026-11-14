//! Latency histograms (`latency-us-v1`) as the collector takes them and the Store keeps them:
//! per-bucket counts, the summed microseconds and the timeouts beside them. A raw sample holds
//! the readings since its generation started; a rollup bucket holds the differences over its
//! continuous intervals. Quantiles are computed only from merged differences of one version
//! (`PERFORMANCE_MANAGER` §4): the upper bound of the first bucket whose cumulative count reaches
//! `ceil(q × count)`, `None` for the +∞ bucket or an empty window.

use vpn_domain::{LATENCY_BUCKET_COUNT, LATENCY_BUCKETS_US};

/// First byte of a stored histogram: its encoding (LEB128 fields of `latency-us-v1`).
const ENCODING_V1: u8 = 1;
/// sum, timeouts, then one count per bucket.
const FIELDS: usize = 2 + LATENCY_BUCKET_COUNT;

/// One latency histogram of [`vpn_domain::LATENCY_HISTOGRAM_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hist {
    /// Observations per bucket (not cumulative across buckets).
    pub buckets: [u64; LATENCY_BUCKET_COUNT],
    pub sum_us: u64,
    /// Attempts that ran out of time: counted beside the buckets, never a latency.
    pub timeouts: u64,
}

/// A quantile the API reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantile {
    P50,
    P95,
    P99,
}

impl Quantile {
    /// `ceil(q × count)` in integers (at least 1 for a non-empty histogram).
    fn rank(self, count: u64) -> u64 {
        let percent: u128 = match self {
            Self::P50 => 50,
            Self::P95 => 95,
            Self::P99 => 99,
        };
        // At most `count`, so it always fits.
        u64::try_from((u128::from(count) * percent).div_ceil(100)).unwrap_or(u64::MAX)
    }
}

impl Hist {
    /// A worker's reading; `None` unless it has exactly one count per bucket (a reading of
    /// another bucket layout is never reinterpreted).
    #[must_use]
    pub fn from_wire(buckets: &[u64], sum_us: u64, timeouts: u64) -> Option<Self> {
        Some(Self {
            buckets: buckets.try_into().ok()?,
            sum_us,
            timeouts,
        })
    }

    /// Observations (the buckets' total; a separately read count may disagree by a moment).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0u64, |total, n| total.saturating_add(*n))
    }

    /// What happened since `older` (an earlier reading of the same lineage), or `None` when
    /// any field went backwards: a reset is unknown, never clipped to zero.
    #[must_use]
    pub fn since(&self, older: &Self) -> Option<Self> {
        let mut out = Self {
            sum_us: self.sum_us.checked_sub(older.sum_us)?,
            timeouts: self.timeouts.checked_sub(older.timeouts)?,
            ..Self::default()
        };
        for (i, d) in out.buckets.iter_mut().enumerate() {
            *d = self.buckets[i].checked_sub(older.buckets[i])?;
        }
        Some(out)
    }

    /// Merge another window's differences into this one.
    pub fn add(&mut self, other: &Self) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets) {
            *a = a.saturating_add(b);
        }
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        self.timeouts = self.timeouts.saturating_add(other.timeouts);
    }

    /// The quantile as the upper bound (µs) of the bucket holding it; `None` without
    /// observations or when it lies in the +∞ bucket.
    #[must_use]
    pub fn quantile(&self, q: Quantile) -> Option<u64> {
        let count = self.count();
        if count == 0 {
            return None;
        }
        let rank = q.rank(count);
        let mut cumulative = 0u64;
        for (i, n) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(*n);
            if cumulative >= rank {
                return (i + 1 < LATENCY_BUCKET_COUNT).then_some(LATENCY_BUCKETS_US[i]);
            }
        }
        None
    }

    /// Stored form: an encoding byte, then every field as an unsigned LEB128 (mostly-empty
    /// histograms take about 20 bytes).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + FIELDS * 2);
        out.push(ENCODING_V1);
        for v in [self.sum_us, self.timeouts]
            .into_iter()
            .chain(self.buckets.iter().copied())
        {
            let mut v = v;
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
        }
        out
    }

    /// The stored form back; `None` for another encoding, a truncated or overlong field or
    /// trailing bytes (a damaged value is unknown; it never fails the whole read).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&version, mut rest) = bytes.split_first()?;
        if version != ENCODING_V1 {
            return None;
        }
        let mut fields = [0u64; FIELDS];
        for field in &mut fields {
            let mut value = 0u64;
            let mut shift = 0u32;
            loop {
                let (&byte, tail) = rest.split_first()?;
                rest = tail;
                let part = u64::from(byte & 0x7f);
                // The tenth byte may only carry the top bit of a u64.
                if shift == 63 && part > 1 {
                    return None;
                }
                value |= part << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
                if shift > 63 {
                    return None;
                }
            }
            *field = value;
        }
        if !rest.is_empty() {
            return None;
        }
        let mut hist = Self {
            sum_us: fields[0],
            timeouts: fields[1],
            ..Self::default()
        };
        hist.buckets.copy_from_slice(&fields[2..]);
        Some(hist)
    }
}
