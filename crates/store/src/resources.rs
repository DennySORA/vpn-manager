//! Process resource samples (Performance Manager): CPU time, resident memory and open
//! descriptors of the manager, the controllers and every worker. Independent of the Instance
//! metrics, so it works with zero Instances.
//!
//! Raw samples (every 5 s, one row per process per sampler tick) are kept 24 h; 1-minute rollups
//! per role 30 days; all inside the metrics database's disk quota (oldest first, each pruned span
//! recorded as a `quota` gap). A sample identifies its process by role and `pid + start time`
//! (plus generation for workers), never by pid alone.
//!
//! Every process is sampled at the same ticks, so a role's CPU at a tick is the sum of its
//! processes' CPU-time deltas since the previous tick. A tick at which any process of the role
//! has no continuous predecessor (it just started, a counter went backwards, the interval was
//! longer than `max(5 s, 2.5 × interval)`) has no CPU value for the role: a partial sum is never
//! shown as the role's usage.

use std::collections::{BTreeMap, HashMap};

use rusqlite::{Connection, OptionalExtension, params};
use vpn_domain::{InstanceId, ProcessRole};

use crate::Store;
use crate::error::StoreError;
use crate::num::{i64_to_f64, u64_to_f64};

/// Metrics-database migration step of this module (v4): the process resource tables, and the
/// measurement points of the removed benchmarks (metrics v6 drops them, with the rows of the
/// benchmark tools' roles). Kept as written so an older database still migrates one step at a
/// time; `local` is always 1 now.
pub const METRICS_STEP: &str = r"
CREATE TABLE resource_series (
    id               INTEGER PRIMARY KEY,
    role             TEXT    NOT NULL CHECK (role IN ('manager', 'controller', 'worker', 'runner', 'peer')),
    process_identity TEXT    NOT NULL,
    instance_id      TEXT,
    generation       INTEGER,
    host_boot_id     TEXT,
    counter_epoch    TEXT    NOT NULL,
    local            INTEGER NOT NULL CHECK (local IN (0, 1)),
    UNIQUE (role, process_identity, generation)
);

-- One row per process per sampler tick. Counters stored bit for bit (u64 through i64); every
-- difference happens in Rust.
CREATE TABLE resource_samples (
    series    INTEGER NOT NULL,
    at_ms     INTEGER NOT NULL,
    mono_ms   INTEGER NOT NULL,
    cpu_ns    INTEGER,
    rss_bytes INTEGER,
    fd_count  INTEGER,
    PRIMARY KEY (series, at_ms)
) WITHOUT ROWID;
CREATE INDEX resource_samples_at ON resource_samples (at_ms);

-- 1-minute rollups per role: the role's CPU-time delta over the tick time it covers; memory (the
-- role's summed RSS per tick) as min, max and Σ value × ms over ms.
CREATE TABLE resource_buckets (
    role      TEXT    NOT NULL,
    bucket_ms INTEGER NOT NULL,
    ticks     INTEGER NOT NULL,
    processes INTEGER NOT NULL,
    cpu_ns    INTEGER NOT NULL,
    cpu_ms    INTEGER NOT NULL,
    rss_min   REAL,
    rss_max   REAL,
    rss_sum   REAL    NOT NULL,
    rss_ms    INTEGER NOT NULL,
    PRIMARY KEY (role, bucket_ms)
) WITHOUT ROWID;

-- What the resource data cannot show: samples never stored ('dropped') or a tier pruned for the
-- quota ('raw', 'minute').
CREATE TABLE resource_gaps (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scope    TEXT    NOT NULL CHECK (scope IN ('dropped', 'raw', 'minute')),
    start_ms INTEGER NOT NULL,
    end_ms   INTEGER NOT NULL
);

-- Measurement points of benchmark runs (cumulative counters, at most one per second), from which
-- the report of a run is built — also after a manager restart interrupted it.
CREATE TABLE benchmark_measurements (
    run_id TEXT    NOT NULL,
    at_ms  INTEGER NOT NULL,
    body   TEXT    NOT NULL CHECK (json_valid(body)),
    PRIMARY KEY (run_id, at_ms)
) WITHOUT ROWID;
";

pub const RESOURCE_SAMPLE_INTERVAL_MS: u64 = 5_000;
/// Longest interval one CPU rate may span: `max(5 s, 2.5 × 5 s)`.
pub const RESOURCE_MAX_GAP_MS: u64 = 12_500;
pub const RESOURCE_RAW_RETENTION_MS: i64 = 24 * HOUR_MS;
pub const RESOURCE_MINUTE_RETENTION_MS: i64 = 30 * 24 * HOUR_MS;
const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
/// Recent minutes recomputed by every rollup run (absorbs samples stored late).
const LOOKBACK_MS: i64 = 10 * MINUTE_MS;
/// Most raw time one rollup run folds while catching up.
const MAX_SPAN_MS: i64 = 6 * HOUR_MS;
/// Minute buckets of the last hours are never pruned for the quota.
const QUOTA_PROTECT_MS: i64 = 2 * HOUR_MS;
const QUOTA_STEPS: usize = 16;
const ROLLUP_KEY: &str = "resource_rollup_until_ms";

/// Who a sample belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceIdentity {
    pub role: ProcessRole,
    /// `pid:<pid>/start:<µs>`.
    pub process_identity: String,
    pub instance_id: Option<InstanceId>,
    pub generation: Option<u64>,
    pub host_boot_id: Option<String>,
    /// Random per identity: counters are only comparable within one epoch.
    pub counter_epoch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSample {
    pub identity: ResourceIdentity,
    /// Manager wall clock of the sampler tick (unix ms); equal for every process of one tick.
    pub at_ms: i64,
    /// The process's own clock (or the sampler's for processes sampled by pid).
    pub mono_ms: u64,
    pub cpu_ns: Option<u64>,
    pub rss_bytes: Option<u64>,
    pub fd_count: Option<u32>,
}

/// A span the sampler knows is missing because its queue dropped samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceDropped {
    pub from_ms: i64,
    pub to_ms: i64,
}

/// One process sample as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRawRow {
    pub series: i64,
    pub at_ms: i64,
    pub mono_ms: u64,
    pub cpu_ns: Option<u64>,
    pub rss_bytes: Option<u64>,
    pub fd_count: Option<u32>,
}

/// A role at one sampler tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleTick {
    pub at_ms: i64,
    /// Processes of the role sampled at this tick.
    pub processes: u32,
    /// The role's CPU-time delta since the previous tick and the wall time it covers; `None` when
    /// some process of the role has no continuous predecessor.
    pub cpu: Option<(u64, u64)>,
    /// Summed resident memory (`None` when no process reported it).
    pub rss_bytes: Option<u64>,
}

/// A role's 1-minute rollup bucket.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RoleBucket {
    pub bucket_ms: i64,
    pub ticks: u64,
    pub processes: u32,
    pub cpu_ns: u64,
    pub cpu_ms: u64,
    pub rss_min: Option<f64>,
    pub rss_max: Option<f64>,
    pub rss_sum: f64,
    pub rss_ms: u64,
}

impl RoleBucket {
    fn observe_rss(&mut self, v: f64, weight_ms: u64) {
        self.rss_min = Some(self.rss_min.map_or(v, |m| m.min(v)));
        self.rss_max = Some(self.rss_max.map_or(v, |m| m.max(v)));
        self.rss_sum = v.mul_add(u64_to_f64(weight_ms), self.rss_sum);
        self.rss_ms += weight_ms;
    }

    /// Add another bucket of the same role (minute → coarser).
    pub fn merge(&mut self, o: &Self) {
        self.ticks += o.ticks;
        self.processes = self.processes.max(o.processes);
        self.cpu_ns = self.cpu_ns.saturating_add(o.cpu_ns);
        self.cpu_ms += o.cpu_ms;
        self.rss_min = match (self.rss_min, o.rss_min) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.rss_max = match (self.rss_max, o.rss_max) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        self.rss_sum += o.rss_sum;
        self.rss_ms += o.rss_ms;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceGapKind {
    Dropped,
    Quota,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceGap {
    pub from_ms: i64,
    pub to_ms: i64,
    pub kind: ResourceGapKind,
}

/// Role data over a range: per-tick values (raw) or minute buckets.
#[derive(Debug, Clone, PartialEq)]
pub enum RoleData {
    Ticks(BTreeMap<ProcessRole, Vec<RoleTick>>),
    Minutes(BTreeMap<ProcessRole, Vec<RoleBucket>>),
}

/// Answer of [`Store::resources_query`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceQuery {
    pub data: RoleData,
    pub gaps: Vec<ResourceGap>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceRetention {
    pub raw_deleted: usize,
    pub buckets_deleted: usize,
    pub quota_deleted: usize,
    pub used_bytes: u64,
}

const fn enc(v: u64) -> i64 {
    v.cast_signed()
}

const fn dec(v: i64) -> u64 {
    v.cast_unsigned()
}

const fn floor_to(t: i64, step: i64) -> i64 {
    t.div_euclid(step) * step
}

/// Per-tick role values from per-process rows (time-ordered within each series). Rows before
/// `from` only serve as predecessors.
pub fn role_ticks(
    rows: &[(ProcessRole, ResourceRawRow)],
    from: i64,
) -> BTreeMap<ProcessRole, Vec<RoleTick>> {
    let mut by_role: BTreeMap<ProcessRole, BTreeMap<i64, Vec<ResourceRawRow>>> = BTreeMap::new();
    for (role, r) in rows {
        by_role
            .entry(*role)
            .or_default()
            .entry(r.at_ms)
            .or_default()
            .push(*r);
    }
    let mut out = BTreeMap::new();
    for (role, ticks) in by_role {
        let mut last: HashMap<i64, ResourceRawRow> = HashMap::new();
        let mut prev_at: Option<i64> = None;
        let mut role_ticks = Vec::new();
        for (at, rows) in ticks {
            let mut delta = 0u64;
            let mut ok = true;
            let mut rss: Option<u64> = None;
            for r in &rows {
                match last.get(&r.series) {
                    Some(p)
                        if r.mono_ms > p.mono_ms
                            && r.mono_ms - p.mono_ms <= RESOURCE_MAX_GAP_MS =>
                    {
                        match (r.cpu_ns, p.cpu_ns) {
                            (Some(a), Some(b)) if a >= b => delta = delta.saturating_add(a - b),
                            _ => ok = false,
                        }
                    }
                    _ => ok = false,
                }
                if let Some(v) = r.rss_bytes {
                    rss = Some(rss.unwrap_or(0).saturating_add(v));
                }
            }
            for r in &rows {
                last.insert(r.series, *r);
            }
            let dt = prev_at.map(|p| at - p);
            prev_at = Some(at);
            if at < from {
                continue;
            }
            let cpu = match dt {
                Some(dt) if ok && dt > 0 && dt.cast_unsigned() <= RESOURCE_MAX_GAP_MS => {
                    Some((delta, dt.cast_unsigned()))
                }
                _ => None,
            };
            role_ticks.push(RoleTick {
                at_ms: at,
                processes: u32::try_from(rows.len()).unwrap_or(u32::MAX),
                cpu,
                rss_bytes: rss,
            });
        }
        out.insert(role, role_ticks);
    }
    out
}

/// Fold a role's ticks in `[lo, hi)` into minute buckets.
pub fn fold_minutes(ticks: &[RoleTick], lo: i64, hi: i64) -> Vec<RoleBucket> {
    let mut out: Vec<RoleBucket> = Vec::new();
    for t in ticks.iter().filter(|t| (lo..hi).contains(&t.at_ms)) {
        let start = floor_to(t.at_ms, MINUTE_MS);
        if out.last().is_none_or(|b| b.bucket_ms != start) {
            out.push(RoleBucket {
                bucket_ms: start,
                ..Default::default()
            });
        }
        if let Some(b) = out.last_mut() {
            b.ticks += 1;
            b.processes = b.processes.max(t.processes);
            let weight = match t.cpu {
                Some((d, dt)) => {
                    b.cpu_ns = b.cpu_ns.saturating_add(d);
                    b.cpu_ms += dt;
                    dt
                }
                None => RESOURCE_SAMPLE_INTERVAL_MS,
            };
            if let Some(r) = t.rss_bytes {
                b.observe_rss(u64_to_f64(r), weight);
            }
        }
    }
    out
}

fn ensure_series(c: &Connection, id: &ResourceIdentity) -> Result<i64, StoreError> {
    c.execute(
        "INSERT OR IGNORE INTO resource_series
            (role, process_identity, instance_id, generation, host_boot_id, counter_epoch, local)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![
            id.role.as_str(),
            id.process_identity,
            id.instance_id.map(|i| i.to_string()),
            id.generation.map(enc),
            id.host_boot_id,
            id.counter_epoch
        ],
    )?;
    Ok(c.query_row(
        "SELECT id FROM resource_series
          WHERE role = ?1 AND process_identity = ?2 AND generation IS ?3",
        params![
            id.role.as_str(),
            id.process_identity,
            id.generation.map(enc)
        ],
        |r| r.get(0),
    )?)
}

fn meta_i64(c: &Connection, key: &str) -> Result<Option<i64>, StoreError> {
    let v: Option<String> = c
        .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(v.and_then(|v| v.parse().ok()))
}

fn set_meta_i64(c: &Connection, key: &str, v: i64) -> Result<(), StoreError> {
    c.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, v.to_string()],
    )?;
    Ok(())
}

/// Every process row with its role in `[from, to)`, ordered by series and time.
fn load_raw(
    c: &Connection,
    from: i64,
    to: i64,
) -> Result<Vec<(ProcessRole, ResourceRawRow)>, StoreError> {
    let mut stmt = c.prepare_cached(
        "SELECT r.role, s.series, s.at_ms, s.mono_ms, s.cpu_ns, s.rss_bytes, s.fd_count
           FROM resource_samples s JOIN resource_series r ON r.id = s.series
          WHERE s.at_ms >= ?1 AND s.at_ms < ?2
          ORDER BY s.series, s.at_ms",
    )?;
    let rows = stmt.query_map(params![from, to], |r| {
        Ok((
            r.get::<_, String>(0)?,
            ResourceRawRow {
                series: r.get(1)?,
                at_ms: r.get(2)?,
                mono_ms: dec(r.get(3)?),
                cpu_ns: r.get::<_, Option<i64>>(4)?.map(dec),
                rss_bytes: r.get::<_, Option<i64>>(5)?.map(dec),
                fd_count: r
                    .get::<_, Option<i64>>(6)?
                    .map(|v| u32::try_from(v.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX)),
            },
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (role, raw) = row?;
        // A row written by something else than this module is left alone.
        if let Some(role) = ProcessRole::parse(&role) {
            out.push((role, raw));
        }
    }
    Ok(out)
}

const BUCKET_COLUMNS: &str =
    "bucket_ms, ticks, processes, cpu_ns, cpu_ms, rss_min, rss_max, rss_sum, rss_ms";

fn put_bucket(c: &Connection, role: ProcessRole, b: &RoleBucket) -> Result<(), StoreError> {
    c.prepare_cached(&format!(
        "INSERT OR REPLACE INTO resource_buckets (role, {BUCKET_COLUMNS})
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
    ))?
    .execute(params![
        role.as_str(),
        b.bucket_ms,
        enc(b.ticks),
        b.processes,
        enc(b.cpu_ns),
        enc(b.cpu_ms),
        b.rss_min,
        b.rss_max,
        b.rss_sum,
        enc(b.rss_ms),
    ])?;
    Ok(())
}

fn append(
    c: &mut Connection,
    samples: &[ResourceSample],
    dropped: &[ResourceDropped],
) -> Result<(), StoreError> {
    let tx = c.transaction()?;
    {
        let mut ids: HashMap<ResourceIdentity, i64> = HashMap::new();
        let mut insert = tx.prepare_cached(
            "INSERT OR IGNORE INTO resource_samples
                (series, at_ms, mono_ms, cpu_ns, rss_bytes, fd_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for s in samples {
            let series = if let Some(id) = ids.get(&s.identity) {
                *id
            } else {
                let id = ensure_series(&tx, &s.identity)?;
                ids.insert(s.identity.clone(), id);
                id
            };
            insert.execute(params![
                series,
                s.at_ms,
                enc(s.mono_ms),
                s.cpu_ns.map(enc),
                s.rss_bytes.map(enc),
                s.fd_count.map(i64::from),
            ])?;
        }
        for d in dropped {
            record_gap(&tx, "dropped", d.from_ms, d.to_ms)?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn record_gap(c: &Connection, scope: &str, from: i64, to: i64) -> Result<(), StoreError> {
    // Contiguous drops, and successive quota cuts of a tier, extend one span.
    let last: Option<(i64, i64)> = c
        .query_row(
            "SELECT id, end_ms FROM resource_gaps WHERE scope = ?1 ORDER BY end_ms DESC LIMIT 1",
            params![scope],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match last {
        Some((id, end))
            if scope != "dropped" || from <= end + RESOURCE_MAX_GAP_MS.cast_signed() =>
        {
            c.execute(
                "UPDATE resource_gaps SET start_ms = min(start_ms, ?2), end_ms = max(end_ms, ?3)
                  WHERE id = ?1",
                params![id, from, to],
            )?;
        }
        _ => {
            c.execute(
                "INSERT INTO resource_gaps (scope, start_ms, end_ms) VALUES (?1, ?2, ?3)",
                params![scope, from, to],
            )?;
        }
    }
    Ok(())
}

fn rollup(c: &mut Connection, now_ms: i64) -> Result<usize, StoreError> {
    let tx = c.transaction()?;
    let recent = floor_to(now_ms, MINUTE_MS) - LOOKBACK_MS;
    let lo = match meta_i64(&tx, ROLLUP_KEY)? {
        Some(w) if w >= recent => recent,
        watermark => {
            // Catching up: continue at the oldest sample not folded yet.
            let base = watermark.unwrap_or(i64::MIN);
            let first: Option<i64> = tx.query_row(
                "SELECT min(at_ms) FROM resource_samples WHERE at_ms >= ?1",
                params![base],
                |r| r.get(0),
            )?;
            first.map_or(recent, |t| floor_to(t, MINUTE_MS).min(recent))
        }
    };
    let hi = (lo + MAX_SPAN_MS).min(floor_to(now_ms, MINUTE_MS) + MINUTE_MS);
    let raw = load_raw(&tx, lo - RESOURCE_MAX_GAP_MS.cast_signed(), hi)?;
    let mut buckets = 0;
    for (role, ticks) in role_ticks(&raw, lo) {
        for b in fold_minutes(&ticks, lo, hi) {
            put_bucket(&tx, role, &b)?;
            buckets += 1;
        }
    }
    set_meta_i64(&tx, ROLLUP_KEY, hi)?;
    tx.commit()?;
    Ok(buckets)
}

/// (file bytes, bytes in use) of the database.
fn page_bytes(c: &Connection) -> Result<(u64, u64), StoreError> {
    let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok((
        (pages.max(0) * size.max(0)).cast_unsigned(),
        ((pages - free).max(0) * size.max(0)).cast_unsigned(),
    ))
}

fn retain(
    c: &mut Connection,
    quota_bytes: u64,
    now_ms: i64,
) -> Result<ResourceRetention, StoreError> {
    let mut report = ResourceRetention::default();
    // Raw samples may go only once folded into minutes that are not recomputed any more.
    let rolled = meta_i64(c, ROLLUP_KEY)?.map(|w| w - LOOKBACK_MS - 2 * MINUTE_MS);
    {
        let tx = c.transaction()?;
        if let Some(rolled) = rolled {
            let cut = (now_ms - RESOURCE_RAW_RETENTION_MS).min(rolled);
            report.raw_deleted = tx.execute(
                "DELETE FROM resource_samples WHERE at_ms < ?1",
                params![cut],
            )?;
        }
        report.buckets_deleted = tx.execute(
            "DELETE FROM resource_buckets WHERE bucket_ms < ?1",
            params![now_ms - RESOURCE_MINUTE_RETENTION_MS],
        )?;
        tx.execute(
            "DELETE FROM resource_gaps WHERE end_ms < ?1",
            params![now_ms - RESOURCE_MINUTE_RETENTION_MS],
        )?;
        tx.execute(
            "DELETE FROM resource_series
              WHERE NOT EXISTS (SELECT 1 FROM resource_samples s WHERE s.series = resource_series.id)",
            [],
        )?;
        tx.commit()?;
    }
    report.quota_deleted = prune_oldest(c, quota_bytes, now_ms)?;
    report.used_bytes = page_bytes(c)?.1;
    Ok(report)
}

/// Until the database's pages in use fit `quota_bytes` (the quota, or the room the metrics need
/// while space is low): delete the oldest raw samples already in the rollups, then the oldest
/// minutes (never those of the last hours), each pruned span a gap of its tier. Returns the rows
/// deleted.
pub fn prune_oldest(
    c: &mut Connection,
    quota_bytes: u64,
    now_ms: i64,
) -> Result<usize, StoreError> {
    let rolled = meta_i64(c, ROLLUP_KEY)?.map(|w| w - LOOKBACK_MS - 2 * MINUTE_MS);
    let mut deleted = 0;
    for (scope, protect) in [
        ("raw", rolled.unwrap_or(i64::MIN)),
        ("minute", now_ms - QUOTA_PROTECT_MS),
    ] {
        let (table, col) = if scope == "raw" {
            ("resource_samples", "at_ms")
        } else {
            ("resource_buckets", "bucket_ms")
        };
        for _ in 0..QUOTA_STEPS {
            let used = page_bytes(c)?.1;
            if used <= quota_bytes {
                break;
            }
            let span: (Option<i64>, Option<i64>) = c.query_row(
                &format!("SELECT min({col}), max({col}) FROM {table} WHERE {col} < ?1"),
                params![protect],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let (Some(oldest), Some(newest)) = span else {
                break;
            };
            let excess = u64_to_f64(used - quota_bytes) / u64_to_f64(used);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a share (at most 1) of a time span in ms, rounded up: within i64"
            )]
            let step = (i64_to_f64(newest - oldest) * excess).ceil() as i64;
            let cut = (oldest + step.max(MINUTE_MS)).min(protect);
            let tx = c.transaction()?;
            record_gap(&tx, scope, oldest, cut)?;
            deleted += tx.execute(
                &format!("DELETE FROM {table} WHERE {col} < ?1"),
                params![cut],
            )?;
            tx.commit()?;
        }
    }
    Ok(deleted)
}

fn query(c: &Connection, from: i64, to: i64, minute: bool) -> Result<ResourceQuery, StoreError> {
    let data = if minute {
        let mut stmt = c.prepare(&format!(
            "SELECT role, {BUCKET_COLUMNS} FROM resource_buckets
              WHERE bucket_ms >= ?1 AND bucket_ms < ?2 ORDER BY role, bucket_ms"
        ))?;
        let rows = stmt.query_map(params![floor_to(from, MINUTE_MS), to], |r| {
            Ok((
                r.get::<_, String>(0)?,
                RoleBucket {
                    bucket_ms: r.get(1)?,
                    ticks: dec(r.get(2)?),
                    processes: r.get(3)?,
                    cpu_ns: dec(r.get(4)?),
                    cpu_ms: dec(r.get(5)?),
                    rss_min: r.get(6)?,
                    rss_max: r.get(7)?,
                    rss_sum: r.get(8)?,
                    rss_ms: dec(r.get(9)?),
                },
            ))
        })?;
        let mut out: BTreeMap<ProcessRole, Vec<RoleBucket>> = BTreeMap::new();
        for row in rows {
            let (role, b) = row?;
            if let Some(role) = ProcessRole::parse(&role) {
                out.entry(role).or_default().push(b);
            }
        }
        RoleData::Minutes(out)
    } else {
        // Rows of one interval before `from` give the first tick its rate.
        let raw = load_raw(c, from - RESOURCE_MAX_GAP_MS.cast_signed(), to)?;
        RoleData::Ticks(role_ticks(&raw, from))
    };
    let tier = if minute { "minute" } else { "raw" };
    let mut stmt = c.prepare(
        "SELECT scope, start_ms, end_ms FROM resource_gaps
          WHERE end_ms >= ?1 AND start_ms <= ?2 AND scope IN ('dropped', ?3) ORDER BY start_ms",
    )?;
    let gaps = stmt
        .query_map(params![from, to, tier], |r| {
            Ok(ResourceGap {
                kind: if r.get::<_, String>(0)? == "dropped" {
                    ResourceGapKind::Dropped
                } else {
                    ResourceGapKind::Quota
                },
                from_ms: r.get(1)?,
                to_ms: r.get(2)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(ResourceQuery { data, gaps })
}

impl Store {
    /// Store sampler ticks and the spans the sampler dropped, in one transaction. Fails fast with
    /// `Busy` when the metrics write queue is full (the caller keeps its batch).
    ///
    /// While the data directory's volume is low on space the oldest metrics make room first (the
    /// file does not grow); when the disk is full even then, only the batch's span is recorded (a
    /// `dropped` gap) and the batch counts as handled.
    ///
    /// # Errors
    ///
    /// `Busy` when the metrics write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn resources_append(
        &self,
        samples: Vec<ResourceSample>,
        dropped: Vec<ResourceDropped>,
    ) -> Result<(), StoreError> {
        if samples.is_empty() && dropped.is_empty() {
            return Ok(());
        }
        let span = samples
            .iter()
            .map(|s| s.at_ms)
            .min()
            .zip(samples.iter().map(|s| s.at_ms).max())
            .map(|(from_ms, to_ms)| ResourceDropped { from_ms, to_ms });
        let mut gaps = dropped.clone();
        gaps.extend(span);
        match self
            .ring_write(move |c| append(c, &samples, &dropped))
            .await
        {
            Err(e) if e.is_disk_full() => {}
            other => return other,
        }
        match self.metrics.write(move |c| append(c, &[], &gaps)).await {
            // Not even the gap fits: the span stays unknown, and is not kept to grow a queue.
            Err(e) if e.is_disk_full() => Ok(()),
            other => other,
        }
    }

    /// Fold raw resource samples into per-role 1-minute buckets (recent minutes recomputed).
    ///
    /// # Errors
    ///
    /// `Busy` when the metrics write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn resources_rollup(&self, now_ms: i64) -> Result<usize, StoreError> {
        self.ring_write(move |c| rollup(c, now_ms)).await
    }

    /// Apply retention (raw 24 h, minutes 30 days) and the metrics disk quota to the resource
    /// tables, oldest first, recording each pruned span.
    ///
    /// # Errors
    ///
    /// `Busy` when the metrics write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn resources_retain(
        &self,
        quota_bytes: u64,
        now_ms: i64,
    ) -> Result<ResourceRetention, StoreError> {
        self.metrics
            .write(move |c| retain(c, quota_bytes, now_ms))
            .await
    }

    /// Per-role resource data over `[from, to)`: per-tick values, or minute buckets when
    /// `minute`.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the metrics read
    /// fails.
    pub async fn resources_query(
        &self,
        from_ms: i64,
        to_ms: i64,
        minute: bool,
    ) -> Result<ResourceQuery, StoreError> {
        self.metrics
            .read(move |c| query(c, from_ms, to_ms, minute))
            .await
    }
}
