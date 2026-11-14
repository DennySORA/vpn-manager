//! Metrics persistence against a real metrics.sqlite: append and dedupe, rates and gaps on the
//! series grid, Instance and Gateway rollups, a strict sandbox's App traffic, `scope=all` sums,
//! latency quantiles, retention per tier, the disk quota, the raw-row bound and the status
//! summary.

// Test fixtures: a failed setup step should panic right there.
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use vpn_domain::*;
use vpn_store::{
    ConnectCounters, GatewaySample, Hist, MetricSample, MetricsPolicy, SshBytes, Store,
};
use zeroize::Zeroizing;

/// A fixed "now": on the hour plus 30 s, so the current minute is half full.
const NOW: i64 = 1_800_000_000_000 + 30_000;
const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;
const DAY: i64 = 24 * HOUR;

fn open() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &Zeroizing::new([7u8; 32]), 1).unwrap();
    (dir, store)
}

/// The one Gateway each test Instance has.
const fn gateway_of(id: InstanceId) -> GatewayId {
    GatewayId(id.0)
}

/// One sample per second of `generation`, `secs` worker-clock seconds in, arriving at `at_ms`;
/// payload grows 1,000 B/s (all through the one Gateway) and `WireGuard` 2,000 B/s.
fn sample(id: InstanceId, at_ms: i64, generation: u64, secs: u64) -> MetricSample {
    MetricSample {
        instance_id: id,
        at_ms,
        generation,
        epoch: 0,
        mono_ms: secs * 1_000,
        payload_rx: secs * 1_000,
        payload_tx: secs * 500,
        wg_rx: secs * 2_000,
        wg_tx: secs * 1_500,
        tunnel_rx: secs * 1_800,
        tunnel_tx: secs * 1_300,
        dns_queries: secs,
        dns_failures: 0,
        dns_cache_hits: secs / 2,
        active_tcp: 3,
        active_udp: 1,
        cpu_ns: Some(secs * 5_000_000),
        rss_bytes: Some(32 << 20),
        gate_open: Some(true),
        connect: Some(ConnectCounters::default()),
        dns_latency: Some(Hist::default()),
        gateways: vec![GatewaySample {
            gateway_id: gateway_of(id),
            epoch: 1,
            payload_rx: secs * 1_000,
            payload_tx: secs * 500,
            active_tcp: 3,
            active_udp: 1,
            serving: true,
            connect: Some(ConnectCounters::default()),
            ssh: Some(ssh_after(secs)),
        }],
        sandbox_rx: None,
        sandbox_tx: None,
        ssh: Some(ssh_after(secs)),
    }
}

/// Of the payload, SSH sessions 200 B/s down and 100 B/s up, SSH downloads 300 B/s down and
/// 10 B/s up.
const fn ssh_after(secs: u64) -> SshBytes {
    SshBytes {
        rx: secs * 200,
        tx: secs * 100,
        pull_rx: secs * 300,
        pull_tx: secs * 10,
    }
}

/// `n` consecutive samples of one generation, the last one arriving at `end_ms`.
fn run(id: InstanceId, end_ms: i64, generation: u64, n: u64) -> Vec<MetricSample> {
    (0..n)
        .map(|i| {
            sample(
                id,
                end_ms - (n - 1 - i).cast_signed() * 1_000,
                generation,
                i,
            )
        })
        .collect()
}

async fn append_all(store: &Store, samples: Vec<MetricSample>) {
    for chunk in samples.chunks(256) {
        store.metrics_append(chunk.to_vec(), vec![]).await.unwrap();
    }
}

async fn roll_until_caught_up(store: &Store, now: i64) {
    for _ in 0..1_000 {
        if store.metrics_rollup(now).await.unwrap().until_ms > now {
            return;
        }
    }
    panic!("rollup never caught up");
}

async fn series(
    store: &Store,
    scope: MetricsScope,
    range: MetricsRange,
    now: i64,
) -> MetricsSeries {
    store.metrics_series(scope, range, now, DAY).await.unwrap()
}

/// The index of the point whose window starts at `t`.
fn at(s: &MetricsSeries, t: i64) -> usize {
    s.timestamps
        .iter()
        .position(|x| *x == t)
        .unwrap_or_else(|| panic!("no point at {t}"))
}

#[tokio::test]
async fn retention_deletes_each_tier_after_its_period() {
    let (_dir, store) = open();
    let id = InstanceId::new();
    // Old data: 40 days ago (beyond the minute tier) and 30 hours ago (beyond raw).
    let mut samples = run(id, NOW - 40 * DAY, 1, 120);
    samples.extend(run(id, NOW - 30 * HOUR, 2, 120));
    samples.extend(run(id, NOW, 3, 120));
    append_all(&store, samples).await;
    roll_until_caught_up(&store, NOW).await;

    let report = store
        .metrics_retain(MetricsPolicy::default(), NOW)
        .await
        .unwrap();
    // Instance and Gateway rows go together.
    assert_eq!(
        report.raw_deleted,
        2 * 240,
        "raw older than 24 h: {report:?}"
    );
    assert_eq!(
        report.buckets_deleted,
        2 * 3,
        "the three minute buckets 40 days old"
    );
    assert!(!report.over_quota);
    // The last minutes are untouched (a query a second later includes the sample at NOW).
    let s = series(
        &store,
        MetricsScope::Instance(id),
        MetricsRange::Last15m,
        NOW + 1_000,
    )
    .await;
    assert_eq!(s.totals.payload_rx_bytes, Some(119_000));
    // Its SSH parts are read back as they were written, apart from each other.
    assert_eq!(s.totals.ssh_rx_bytes, Some(119 * 200));
    assert_eq!(s.totals.ssh_pull_rx_bytes, Some(119 * 300));
    assert_eq!(s.totals.ssh_pull_tx_bytes, Some(119 * 10));

    // 150 days later only hour buckets not older than 180 days remain, a year later none.
    let later = NOW + 150 * DAY;
    roll_until_caught_up(&store, later).await;
    let report = store
        .metrics_retain(MetricsPolicy::default(), later)
        .await
        .unwrap();
    assert_eq!(report.raw_deleted, 2 * 120);
    assert_eq!(
        report.buckets_deleted,
        2 * (6 + 2),
        "every minute bucket, the oldest hours"
    );
    let report = store
        .metrics_retain(MetricsPolicy::default(), NOW + 365 * DAY)
        .await
        .unwrap();
    assert!(report.buckets_deleted > 0);
    let s = series(&store, MetricsScope::All, MetricsRange::Last30d, NOW).await;
    assert!(s.payload_rx_bps.iter().all(Option::is_none));
    assert!(s.instances.is_empty() && s.gateways.is_empty());
}

#[tokio::test]
async fn the_quota_prunes_the_oldest_raw_samples_and_says_so() {
    let (_dir, store) = open();
    let id = InstanceId::new();
    // Two hours of samples ending now.
    append_all(&store, run(id, NOW, 1, 7_200)).await;
    roll_until_caught_up(&store, NOW).await;
    let before = store
        .metrics_retain(MetricsPolicy::default(), NOW)
        .await
        .unwrap();
    assert_eq!(before.quota_deleted, 0);

    let quota = before.used_bytes * 3 / 10;
    let after = store
        .metrics_retain(
            MetricsPolicy {
                raw_retention_ms: DAY,
                quota_bytes: quota,
            },
            NOW,
        )
        .await
        .unwrap();
    assert!(after.quota_deleted > 0, "{after:?}");
    assert!(after.used_bytes <= quota, "{after:?} quota {quota}");
    assert!(!after.over_quota);

    // The newest samples are intact; the pruned span is a `quota` gap, not zeros.
    let now = NOW + 1_000;
    for scope in [
        MetricsScope::Instance(id),
        MetricsScope::Gateway(gateway_of(id)),
    ] {
        let s = series(&store, scope, MetricsRange::Last1h, now).await;
        assert_eq!(s.resolution_secs, 5);
        let newest = at(&s, NOW - 30_000);
        assert_eq!(s.payload_rx_bps[newest], Some(8_000.0), "{scope}");
        assert_eq!(
            s.gaps[0].reason,
            MetricsGapReason::Quota,
            "{scope}: {:?}",
            s.gaps
        );
        assert_eq!(s.gaps[0].from_ms, s.from_ms);
        assert_eq!(s.payload_rx_bps[0], None);
    }
    // The minute rollups still cover the pruned time.
    let s = series(
        &store,
        MetricsScope::Instance(id),
        MetricsRange::Last6h,
        NOW,
    )
    .await;
    let covered = s.payload_rx_bps.iter().filter(|v| v.is_some()).count();
    assert!(covered >= 119, "{covered}");

    let status = store.metrics_status(NOW).await.unwrap();
    let cut = status.pruned_before.raw_ms.unwrap();
    assert!(cut > NOW - 2 * HOUR && cut < NOW, "{status:?}");
    assert!(status.oldest.raw_ms.unwrap() >= cut);
    assert!(status.oldest.minute_ms.unwrap() <= NOW - 2 * HOUR + MIN);
    let quota_gap = status
        .gaps_24h
        .iter()
        .find(|g| g.reason == MetricsGapReason::Quota)
        .unwrap();
    assert_eq!(quota_gap.duration_ms, Some(cut - (NOW - DAY)));
}
