//! Free space of the data directory, and how the databases keep working when it runs out.
//!
//! - Metrics never stop: below `min(512 MiB, 5 %)` of the volume free (read at most every few
//!   seconds, and at once when a metrics write fails with `SQLITE_FULL`) the metrics database
//!   stops growing and overwrites its oldest data instead — before a write it keeps a few hundred
//!   free pages in its file by deleting the oldest rows (raw samples already rolled up first, then
//!   minute and hour buckets), each pruned span a `disk_low` gap of its tier, and it gives no page
//!   back to the volume. New rows reuse those pages, so its writes (and its WAL, which is bounded
//!   and keeps its blocks, `db.rs`) need no new disk space. It may grow again once the volume has
//!   room (a quarter above the threshold, so it does not flap). Nothing of this waits on, or
//!   blocks, the data path: the collector's queue stays bounded.
//! - Two reserve files are preallocated in the data directory and given back to the volume when a
//!   write finds the disk full: [`RESERVE_FILE`] for control writes (the write then runs once
//!   more, in the room it left), [`METRICS_RESERVE_FILE`] for the metrics database (room for its
//!   WAL and a checkpoint, and a ring of a few megabytes when its file is still small; also given
//!   back before the databases open on a full volume). Both are allocated again once there is room.
//!   Control data and secrets are never deleted for space.

#![allow(
    unsafe_code,
    reason = "this module owns the statvfs, fallocate and F_PREALLOCATE calls through libc"
)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vpn_domain::{DiskReport, DiskSpaceState, ReserveState, Text, Timestamp, tr};
use vpn_sync::Mutex;

const MIB: u64 = 1024 * 1024;
/// Metrics stop growing below `min(LOW_SPACE_CAP, LOW_SPACE_PERCENT % of the volume)` free.
pub const LOW_SPACE_CAP: u64 = 512 * MIB;
pub const LOW_SPACE_PERCENT: u64 = 5;
/// The control database's reserve, in the data directory.
pub const RESERVE_FILE: &str = "control.reserve";
/// The metrics database's reserve, in the data directory.
pub const METRICS_RESERVE_FILE: &str = "metrics.reserve";
/// Size of each reserve.
pub const RESERVE_BYTES: u64 = 8 * MIB;
/// Free space the databases need to open (their WAL and shared-memory files).
const OPEN_ROOM: u64 = MIB;
/// How often the free space is read (at most).
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// After a metrics write found the disk full, how long the metrics database stays at its size
/// whatever the free space reads (a full volume can read as having room: reserved blocks,
/// quotas).
const FULL_HOLD: Duration = Duration::from_secs(60);

/// Free and total bytes of a volume, as this user may use them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// Reads a volume's free space (`statvfs`; a stand-in in tests).
pub trait SpaceProbe: Send + Sync {
    /// Free and total space of the volume holding `dir`.
    ///
    /// # Errors
    ///
    /// The `statvfs` error, or a path that holds a NUL byte.
    fn space(&self, dir: &Path) -> io::Result<Space>;
}

/// `statvfs(2)`: blocks available to this (unprivileged) user.
pub struct Statvfs;

impl SpaceProbe for Statvfs {
    fn space(&self, dir: &Path) -> io::Result<Space> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
        // SAFETY: statvfs is plain data that the call fills in.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a struct of the right type.
        if unsafe { libc::statvfs(path.as_ptr(), &raw mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[allow(
            clippy::useless_conversion,
            reason = "the field widths differ between OSes"
        )]
        let unit = u64::from(if st.f_frsize > 0 {
            st.f_frsize
        } else {
            st.f_bsize
        });
        #[allow(
            clippy::useless_conversion,
            reason = "the field widths differ between OSes"
        )]
        let (avail, blocks) = (u64::from(st.f_bavail), u64::from(st.f_blocks));
        Ok(Space {
            free_bytes: avail.saturating_mul(unit),
            total_bytes: blocks.saturating_mul(unit),
        })
    }
}

/// Below this much free space metrics stop growing: `min(512 MiB, 5 %)` of the volume.
#[must_use]
pub fn low_threshold(total_bytes: u64) -> u64 {
    (total_bytes / 100)
        .saturating_mul(LOW_SPACE_PERCENT)
        .min(LOW_SPACE_CAP)
}

/// From this much free space on, the metrics database may grow again: a quarter above the
/// threshold.
#[must_use]
pub fn resume_threshold(total_bytes: u64) -> u64 {
    let low = low_threshold(total_bytes);
    low.saturating_add(low / 4)
}

/// One reserve file.
#[derive(Default)]
struct Reserve {
    held: bool,
    released_at: Option<Timestamp>,
    error: Option<Text>,
}

impl Reserve {
    const fn state(&self) -> ReserveState {
        if self.held {
            ReserveState::Held
        } else if self.released_at.is_some() {
            ReserveState::Released
        } else {
            ReserveState::Missing
        }
    }
}

#[derive(Default)]
struct State {
    low: bool,
    low_since: Option<Timestamp>,
    space: Option<Space>,
    error: Option<Text>,
    checked: Option<Instant>,
    /// A metrics write found the disk full (holds the database at its size for [`FULL_HOLD`]).
    full: Option<(Instant, Timestamp)>,
    /// Samples not stored at all (not even room made by overwriting was enough), and rows
    /// deleted early to make room, since the manager started.
    samples_skipped: u64,
    rows_pruned: u64,
    /// The same since space last ran low.
    low_skipped: u64,
    low_pruned: u64,
    control: Reserve,
    metrics: Reserve,
}

impl State {
    /// From this much free space on the metrics database may grow again: the resume threshold,
    /// plus room for every reserve not held now (they are allocated first).
    fn resume_bytes(&self, total_bytes: u64) -> u64 {
        let missing = u64::from(!self.control.held) + u64::from(!self.metrics.held);
        resume_threshold(total_bytes).saturating_add(missing * RESERVE_BYTES)
    }

    fn enter_low(&mut self) {
        self.low = true;
        self.low_since = Some(Timestamp::now());
        self.low_skipped = 0;
        self.low_pruned = 0;
    }
}

/// The data directory's space and the reserves (one per Store).
pub struct Disk {
    dir: PathBuf,
    probe: Arc<dyn SpaceProbe>,
    state: Mutex<State>,
}

/// What the metrics database does with the space it has now ([`Disk::metrics`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSpace {
    /// Space is low: the database stays at its size and overwrites its oldest data.
    pub low: bool,
    pub since: Option<Timestamp>,
    pub free_bytes: Option<u64>,
    /// The free space at which the database may grow again.
    pub resume_bytes: Option<u64>,
    /// Rows deleted early (overwritten), and samples not stored at all, since space ran low.
    pub pruned_rows: u64,
    pub skipped_samples: u64,
}

impl Disk {
    pub(crate) fn new(dir: &Path, probe: Arc<dyn SpaceProbe>) -> Arc<Self> {
        let disk = Arc::new(Self {
            dir: dir.to_path_buf(),
            probe,
            state: Mutex::new(State::default()),
        });
        {
            let mut s = disk.state.lock();
            s.control.held = dir.join(RESERVE_FILE).is_file();
            s.metrics.held = dir.join(METRICS_RESERVE_FILE).is_file();
        }
        // A volume too full for the databases' WAL and shared-memory files: the metrics reserve
        // makes their room — or, spent already, the control reserve (a reserve is of no use to a
        // manager that cannot open its databases).
        if let Ok(space) = disk.probe.space(dir)
            && space.free_bytes < RESERVE_BYTES
            && !disk.release_metrics_reserve()
            && space.free_bytes < OPEN_ROOM
        {
            disk.release_reserve();
        }
        disk.refresh(true);
        disk
    }

    /// Whether the metrics database must stay at its size now (free space read again when due,
    /// or when `force`).
    pub(crate) fn low(&self, force: bool) -> bool {
        self.refresh(force)
    }

    fn refresh(&self, force: bool) -> bool {
        {
            let s = self.state.lock();
            if !force && s.checked.is_some_and(|t| t.elapsed() < CHECK_EVERY) {
                return s.low;
            }
        }
        let read = self.probe.space(&self.dir);
        let mut s = self.state.lock();
        s.checked = Some(Instant::now());
        let held_full = s.full.is_some_and(|(at, _)| at.elapsed() < FULL_HOLD);
        let space = match read {
            Ok(space) => {
                s.space = Some(space);
                s.error = None;
                space
            }
            Err(e) => {
                // Unknown: whatever was concluded last stands (never "fine" on a guess).
                s.error = Some(tr!(
                    "Cannot read the free space of the data directory: {e}",
                    "無法讀取資料目錄的可用空間：{e}",
                    "データディレクトリの空き容量を読み取れません：{e}"
                ));
                return s.low;
            }
        };
        let threshold = low_threshold(space.total_bytes);
        let resume = resume_threshold(space.total_bytes);
        // Room means room for the reserves too: a released reserve's blocks are no reason to grow.
        let room = space.free_bytes >= s.resume_bytes(space.total_bytes);
        let low = if held_full {
            true
        } else if s.low {
            !room
        } else {
            space.free_bytes < threshold
        };
        if low != s.low {
            if low {
                tracing::warn!(
                    free_bytes = space.free_bytes,
                    threshold_bytes = threshold,
                    "disk space low: the metrics database stops growing and overwrites its oldest data"
                );
                s.enter_low();
            } else {
                tracing::info!(
                    free_bytes = space.free_bytes,
                    "disk space recovered: the metrics database may grow again"
                );
                s.low = false;
                s.low_since = None;
                s.full = None;
            }
        }
        // Room again: the reserves come back (each is spent only on its own database's writes).
        let mut free = space.free_bytes;
        let st = &mut *s;
        let low = st.low;
        for (reserve, file) in [
            (&mut st.control, RESERVE_FILE),
            (&mut st.metrics, METRICS_RESERVE_FILE),
        ] {
            if low || reserve.held || free < resume.saturating_add(RESERVE_BYTES) {
                continue;
            }
            match allocate(&self.dir.join(file), RESERVE_BYTES) {
                Ok(()) => {
                    reserve.held = true;
                    reserve.error = None;
                    free -= RESERVE_BYTES;
                }
                Err(e) => {
                    reserve.error = Some(tr!(
                        "Cannot allocate the reserved space {file}: {e}",
                        "無法配置保留空間 {file}：{e}",
                        "予約領域 {file} を確保できません：{e}"
                    ));
                }
            }
        }
        s.low
    }

    /// A metrics write found the disk full: the metrics database stays at its size from now on
    /// (for [`FULL_HOLD`] at least).
    pub(crate) fn metrics_full(&self) {
        let mut s = self.state.lock();
        s.full = Some((Instant::now(), Timestamp::now()));
        if !s.low {
            tracing::warn!(
                "a metrics write found the disk full: the metrics database stops growing and overwrites its oldest data"
            );
            s.enter_low();
        }
    }

    /// The metrics database could not store `samples` at all.
    pub(crate) fn skipped(&self, samples: u64) {
        let mut s = self.state.lock();
        s.samples_skipped += samples;
        s.low_skipped += samples;
    }

    /// `rows` were deleted early to make room for new ones.
    pub(crate) fn pruned(&self, rows: u64) {
        let mut s = self.state.lock();
        s.rows_pruned += rows;
        s.low_pruned += rows;
    }

    /// Whether the volume is low on space, and what the metrics database did about it.
    pub(crate) fn metrics(&self) -> MetricsSpace {
        let low = self.refresh(false);
        let s = self.state.lock();
        MetricsSpace {
            low,
            since: s.low_since,
            free_bytes: s.space.map(|x| x.free_bytes),
            resume_bytes: s.space.map(|x| s.resume_bytes(x.total_bytes)),
            pruned_rows: s.low_pruned,
            skipped_samples: s.low_skipped,
        }
    }

    /// Give a reserve file back to the volume. True when there was one to give.
    fn release(&self, s: &mut State, file: &str, metrics: bool) -> bool {
        let reserve = if metrics {
            &mut s.metrics
        } else {
            &mut s.control
        };
        if !reserve.held {
            return false;
        }
        let path = self.dir.join(file);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                reserve.held = false;
                reserve.released_at = Some(Timestamp::now());
                true
            }
            Err(e) => {
                reserve.held = path.is_file();
                reserve.error = Some(tr!(
                    "Cannot release the reserved space {file}: {e}",
                    "無法釋放保留空間 {file}：{e}",
                    "予約領域 {file} を解放できません：{e}"
                ));
                false
            }
        }
    }

    /// A control write found the disk full (or the databases cannot open): give the control
    /// reserve back to the volume. True when there was one to give (the write is worth running
    /// again).
    pub(crate) fn release_reserve(&self) -> bool {
        let mut s = self.state.lock();
        if !self.release(&mut s, RESERVE_FILE, false) {
            return false;
        }
        tracing::warn!(
            "the disk is full: released the control reserve for the control database's writes"
        );
        // Space is short whatever the last reading said: the metrics database stays at its size.
        s.full = Some((Instant::now(), Timestamp::now()));
        if !s.low {
            s.enter_low();
        }
        true
    }

    /// The metrics database found the disk full (or cannot open): give its reserve back to the
    /// volume. True when there was one to give.
    pub(crate) fn release_metrics_reserve(&self) -> bool {
        let released = self.release(&mut self.state.lock(), METRICS_RESERVE_FILE, true);
        if released {
            tracing::warn!(
                "the disk is full: released the metrics reserve for the metrics database's own writes"
            );
        }
        released
    }

    /// The state for the diagnostics report.
    pub(crate) fn report(&self) -> DiskReport {
        self.refresh(false);
        let s = self.state.lock();
        DiskReport {
            path: self.dir.display().to_string(),
            state: match (&s.space, s.low) {
                (_, true) => DiskSpaceState::Low,
                (Some(_), false) => DiskSpaceState::Normal,
                (None, false) => DiskSpaceState::Unknown,
            },
            free_bytes: s.space.map(|x| x.free_bytes),
            total_bytes: s.space.map(|x| x.total_bytes),
            low_threshold_bytes: s.space.map(|x| low_threshold(x.total_bytes)),
            low_since: s.low_since,
            metrics_full_at: s.full.map(|(_, at)| at),
            samples_skipped: s.samples_skipped,
            rows_pruned: s.rows_pruned,
            reserve: s.control.state(),
            reserve_bytes: RESERVE_BYTES,
            reserve_released_at: s.control.released_at,
            metrics_reserve: s.metrics.state(),
            metrics_reserve_released_at: s.metrics.released_at,
            error: s
                .error
                .clone()
                .or_else(|| s.control.error.clone())
                .or_else(|| s.metrics.error.clone()),
        }
    }
}

/// Allocate `len` bytes to a new file at `path` (blocks, not a sparse file): the room a control
/// write gets back when the disk is full.
fn allocate(path: &Path, len: u64) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("reserve.part");
    let _ = std::fs::remove_file(&tmp);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let done = preallocate(&file, len).and_then(|()| file.sync_all());
    drop(file);
    match done {
        Ok(()) => std::fs::rename(&tmp, path),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(target_os = "linux")]
fn preallocate(file: &std::fs::File, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let len = libc::off_t::try_from(len).map_err(|_| io::Error::other("reserve too large"))?;
    // SAFETY: a file descriptor we own, offset 0, a positive length.
    let r = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, len) };
    if r == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
        return write_zeros(file, len.cast_unsigned());
    }
    Err(e)
}

#[cfg(target_os = "macos")]
fn preallocate(file: &std::fs::File, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let length = libc::off_t::try_from(len).map_err(|_| io::Error::other("reserve too large"))?;
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: length,
        fst_bytesalloc: 0,
    };
    // SAFETY: a file descriptor we own and a filled-in fstore_t.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) } == -1 {
        return write_zeros(file, len);
    }
    file.set_len(len)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn preallocate(file: &std::fs::File, len: u64) -> io::Result<()> {
    write_zeros(file, len)
}

/// The portable way: real zeros, so the blocks are the file's.
fn write_zeros(mut file: &std::fs::File, len: u64) -> io::Result<()> {
    use std::io::Write;
    let chunk = vec![0u8; 1024 * 1024];
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).map_or(chunk.len(), |l| l.min(chunk.len()));
        file.write_all(&chunk[..n])?;
        left -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A volume of `total` bytes whose free space the test sets.
    pub struct FakeSpace {
        pub free: AtomicU64,
        pub total: u64,
    }

    impl FakeSpace {
        pub fn new(free: u64, total: u64) -> Arc<Self> {
            Arc::new(Self {
                free: AtomicU64::new(free),
                total,
            })
        }

        pub fn set_free(&self, free: u64) {
            self.free.store(free, Ordering::Relaxed);
        }
    }

    impl SpaceProbe for FakeSpace {
        fn space(&self, _dir: &Path) -> io::Result<Space> {
            Ok(Space {
                free_bytes: self.free.load(Ordering::Relaxed),
                total_bytes: self.total,
            })
        }
    }

    const GIB: u64 = 1024 * MIB;

    // --- Through the Store ---------------------------------------------------------------------

    use rusqlite::Connection;
    use vpn_domain::{GatewayId, InstanceId, MetricsGapReason, ProcessRole};
    use zeroize::Zeroizing;

    use crate::{
        Appended, ConnectCounters, GatewaySample, Hist, MetricSample, ResourceIdentity,
        ResourceSample, Store,
    };

    const HOUR_MS: i64 = 3_600_000;

    fn store_with(space: Arc<FakeSpace>) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::open_with_space(dir.path(), &Zeroizing::new([3u8; 32]), 1, space).unwrap();
        (dir, store)
    }

    fn sample(instance: InstanceId, at_ms: i64) -> MetricSample {
        MetricSample {
            instance_id: instance,
            at_ms,
            generation: 1,
            epoch: 0,
            mono_ms: (at_ms % 1_000_000_000).cast_unsigned(),
            payload_rx: 0,
            payload_tx: 0,
            wg_rx: 0,
            wg_tx: 0,
            tunnel_rx: 0,
            tunnel_tx: 0,
            dns_queries: 0,
            dns_failures: 0,
            dns_cache_hits: 0,
            active_tcp: 0,
            active_udp: 0,
            cpu_ns: Some(0),
            rss_bytes: Some(1 << 20),
            gate_open: Some(true),
            connect: Some(ConnectCounters::default()),
            dns_latency: Some(Hist::default()),
            gateways: vec![GatewaySample {
                gateway_id: GatewayId::new(),
                epoch: 0,
                payload_rx: 0,
                payload_tx: 0,
                active_tcp: 0,
                active_udp: 0,
                serving: true,
                connect: Some(ConnectCounters::default()),
                ssh: None,
            }],
            sandbox_rx: None,
            sandbox_tx: None,
            ssh: None,
        }
    }

    /// One number from the metrics database.
    async fn metric(store: &Store, sql: String) -> i64 {
        store
            .metrics_read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?))
            .await
            .unwrap()
    }

    /// The database may not grow beyond its pages now (what a full volume does to SQLite).
    fn no_more_pages(c: &Connection) -> Result<(), crate::StoreError> {
        let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        c.pragma_update(None, "max_page_count", pages)?;
        Ok(())
    }

    fn resource(at_ms: i64) -> ResourceSample {
        ResourceSample {
            identity: ResourceIdentity {
                role: ProcessRole::Manager,
                process_identity: "pid:1/start:1".into(),
                instance_id: None,
                generation: None,
                host_boot_id: None,
                counter_epoch: "e".into(),
            },
            at_ms,
            mono_ms: at_ms.cast_unsigned(),
            cpu_ns: Some(1),
            rss_bytes: Some(1),
            fd_count: Some(1),
        }
    }

    /// Two hours of samples six hours ago, rolled up: raw data that may be overwritten.
    async fn history(store: &Store, id: InstanceId, now: i64) {
        history_of(store, id, now, 2).await;
    }

    /// `hours` of samples that end four hours ago, rolled up.
    async fn history_of(store: &Store, id: InstanceId, now: i64, hours: i64) {
        let old = now - (4 + hours) * HOUR_MS;
        let history: Vec<MetricSample> = (0..hours * 3_600)
            .map(|i| sample(id, old + i * 1_000))
            .collect();
        for chunk in history.chunks(256) {
            let stored = store.metrics_append(chunk.to_vec(), vec![]).await.unwrap();
            assert_eq!(stored, Appended::Stored);
        }
        for _ in 0..4 {
            if store.metrics_rollup(now).await.unwrap().until_ms > now {
                break;
            }
        }
    }

    /// A kind of metrics write.
    enum Write {
        Samples,
        Processes,
        Rollup,
    }

    /// AC-48 (ring): with the volume low and the metrics file unable to grow by a single page, every
    /// kind of metrics write still lands — the oldest metrics make room (`disk_low` gaps), never
    /// control data or secrets — and the database stays whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_disk_overwrites_the_oldest_metrics_and_keeps_recording() {
        let space = FakeSpace::new(10 * GIB, 100 * GIB);
        let (_dir, store) = store_with(space.clone());
        let id = InstanceId::new();
        let now = Timestamp::now().unix_millis();
        history(&store, id, now).await;
        let secret = store
            .put_secret("key".into(), None, Zeroizing::new(vec![7; 32]), None)
            .await
            .unwrap();

        // The volume runs low, and the file may not take one page more.
        space.set_free(100 * MIB);
        assert!(store.metrics_space());
        store.metrics.write(|c| no_more_pages(c)).await.unwrap();
        let pages = "SELECT * FROM pragma_page_count()".to_string();
        let limit = metric(&store, pages.clone()).await;
        let raw = "SELECT count(*) FROM metric_samples".to_string();
        let before = metric(&store, raw.clone()).await;

        let mut at = now;
        let hour = now - now % HOUR_MS;
        let cases = [
            (
                "Instance samples",
                Write::Samples,
                format!("SELECT count(*) FROM metric_samples WHERE at_ms >= {now}"),
            ),
            (
                "process samples",
                Write::Processes,
                format!("SELECT count(*) FROM resource_samples WHERE at_ms >= {now}"),
            ),
            (
                "rollups",
                Write::Rollup,
                format!("SELECT count(*) FROM metric_buckets WHERE bucket_ms >= {hour}"),
            ),
        ];
        for (case, write, newest) in cases {
            // Far more new rows than the file has free pages.
            match write {
                Write::Samples => {
                    for _ in 0..12 {
                        let batch: Vec<MetricSample> =
                            (0..256).map(|i| sample(id, at + i * 1_000)).collect();
                        at += 256 * 1_000;
                        let stored = store.metrics_append(batch, vec![]).await.unwrap();
                        assert_eq!(stored, Appended::Stored, "{case}");
                    }
                }
                Write::Processes => {
                    let batch: Vec<ResourceSample> =
                        (0..2_000).map(|i| resource(now + i)).collect();
                    store.resources_append(batch, vec![]).await.unwrap();
                }
                Write::Rollup => {
                    store.metrics_rollup(at).await.unwrap();
                }
            }
            assert!(
                metric(&store, newest).await > 0,
                "{case}: the newest rows are stored"
            );
            assert!(
                metric(&store, pages.clone()).await <= limit,
                "{case}: the file grew"
            );
        }
        // The oldest metrics made the room, and say so; nothing was lost besides them.
        assert!(metric(&store, raw).await < before + 12 * 256);
        let overwritten =
            "SELECT count(*) FROM metric_gaps WHERE reason = 'disk_low' AND scope = 'raw'";
        assert_eq!(metric(&store, overwritten.into()).await, 1);
        let lost = "SELECT count(*) FROM metric_gaps WHERE scope = 'samples'";
        assert_eq!(metric(&store, lost.into()).await, 0);
        let check = "SELECT count(*) FROM pragma_integrity_check() WHERE integrity_check != 'ok'";
        assert_eq!(metric(&store, check.into()).await, 0);
        let status = store.metrics_status(at).await.unwrap();
        assert!(
            status
                .gaps_24h
                .iter()
                .any(|g| g.reason == MetricsGapReason::DiskLow),
            "{:?}",
            status.gaps_24h
        );
        let report = store.disk_report();
        assert_eq!(report.state, DiskSpaceState::Low);
        assert_eq!(report.samples_skipped, 0);
        assert!(report.rows_pruned > 0);
        // Control data and secrets are never taken for space.
        assert_eq!(
            store
                .open_secret(secret.secret_ref)
                .await
                .unwrap()
                .as_slice(),
            &[7; 32]
        );

        room_again(&store, &space, report.metrics_full_at.is_some());
    }

    /// Room again: the database may grow again — unless a write found the file full on the way
    /// (`found_full`; the rollup does when it needs more pages than the ring had left, which depends
    /// on how many hour buckets the time of day leaves it): then the database stays at its size for
    /// `FULL_HOLD` more, whatever the free space reads.
    fn room_again(store: &Store, space: &FakeSpace, found_full: bool) {
        space.set_free(10 * GIB);
        assert_eq!(store.metrics_space(), found_full);
        let state = if found_full {
            DiskSpaceState::Low
        } else {
            DiskSpaceState::Normal
        };
        assert_eq!(store.disk_report().state, state);
    }

    /// AC-48 (ring): a metrics write that finds the file full although the ring is not short — more
    /// pages are free than the ring is content with, fewer than the write needs — gets the whole
    /// ring before it runs once more, from the oldest metrics, and never more than a ring.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_that_finds_the_file_full_gets_the_whole_ring() {
        use crate::metrics::{RING_FREE_PAGES, RING_MIN_FREE, ring_room, ring_room_when_full};

        let space = FakeSpace::new(10 * GIB, 100 * GIB);
        let (_dir, store) = store_with(space.clone());
        let id = InstanceId::new();
        let now = Timestamp::now().unix_millis();
        // Enough old data for two rings.
        history_of(&store, id, now, 5).await;
        space.set_free(100 * MIB);
        assert!(store.metrics_space());
        store.metrics.write(|c| no_more_pages(c)).await.unwrap();
        let pages = "SELECT * FROM pragma_page_count()".to_string();
        let limit = metric(&store, pages.clone()).await;
        let free = "SELECT * FROM pragma_freelist_count()".to_string();

        // New samples use the ring up: it is no longer whole, and not short either.
        let mut at = now;
        for _ in 0..64 {
            let batch: Vec<MetricSample> = (0..64).map(|i| sample(id, at + i * 1_000)).collect();
            at += 64 * 1_000;
            let stored = store.metrics_append(batch, vec![]).await.unwrap();
            assert_eq!(stored, Appended::Stored);
            if metric(&store, free.clone()).await < RING_FREE_PAGES - 128 {
                break;
            }
        }
        let partly = metric(&store, free.clone()).await;
        assert!(
            (RING_MIN_FREE..RING_FREE_PAGES - 128).contains(&partly),
            "{partly} free pages"
        );
        let rows = "SELECT count(*) FROM metric_samples".to_string();
        let before = metric(&store, rows.clone()).await;

        // Before a write nothing is deleted for it; after the file was found full the ring is made.
        let (content, made, again) = store
            .metrics
            .write(|c| {
                let now = Timestamp::now().unix_millis();
                Ok((
                    ring_room(c, now)?,
                    ring_room_when_full(c, now)?,
                    ring_room_when_full(c, now)?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(content, 0, "the ring was not short");
        assert!(made > 0, "the oldest metrics make the room");
        assert_eq!(again, 0, "a whole ring is all a full file gets");
        let whole = metric(&store, free).await;
        assert!(whole >= RING_FREE_PAGES, "{partly} then {whole} free pages");
        assert!(metric(&store, rows).await < before);
        assert!(metric(&store, pages).await <= limit, "the file grew");
        // What was deleted says so, and the newest samples are still there.
        let overwritten = "SELECT count(*) FROM metric_gaps WHERE reason = 'disk_low'";
        assert!(metric(&store, overwritten.into()).await > 0);
        let newest = format!("SELECT count(*) FROM metric_samples WHERE at_ms >= {now}");
        assert!(metric(&store, newest).await > 0);
        let check = "SELECT count(*) FROM pragma_integrity_check() WHERE integrity_check != 'ok'";
        assert_eq!(metric(&store, check.into()).await, 0);
    }

    /// AC-48: a control write that finds the disk full gets the reserve and succeeds; without a
    /// reserve left it fails saying so, and nothing stored is lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_control_write_that_finds_the_disk_full_gets_the_reserve() {
        let (dir, mut store) = store_with(FakeSpace::new(10 * GIB, 100 * GIB));
        let reserve = dir.path().join(RESERVE_FILE);
        assert!(reserve.is_file());
        let first = store
            .put_secret("key".into(), None, Zeroizing::new(vec![5; 32]), None)
            .await
            .unwrap();
        // What the released reserve gives back to the volume is room to grow: here, the page
        // limit the write runs into.
        let disk = store.disk.clone();
        store
            .control
            .retry_when_full(Arc::new(move |c: &mut Connection| {
                let released = disk.release_reserve();
                if released {
                    let _ = c.pragma_update(None, "max_page_count", 1_000_000);
                }
                released
            }));
        store.control.write(|c| no_more_pages(c)).await.unwrap();
        let big = Zeroizing::new(vec![9; 256 * 1024]);
        let written = store
            .put_secret("big".into(), None, big.clone(), None)
            .await
            .unwrap();
        assert!(!reserve.exists(), "the reserve was given back");
        assert_eq!(
            store.open_secret(written.secret_ref).await.unwrap().len(),
            256 * 1024
        );
        let report = store.disk_report();
        assert_eq!(report.reserve, ReserveState::Released);
        assert!(report.reserve_released_at.is_some());
        // Space is short: the metrics database stays at its size meanwhile.
        assert_eq!(report.state, DiskSpaceState::Low);

        // Full again, nothing left to release: the write fails and says why.
        store.control.write(|c| no_more_pages(c)).await.unwrap();
        let err = store
            .put_secret("big".into(), None, big, None)
            .await
            .unwrap_err();
        assert!(err.is_disk_full(), "{err}");
        assert!(err.to_api().message.zh_tw.contains("磁碟已滿"), "{err:?}");
        // Nothing stored was given up for it.
        assert_eq!(
            store
                .open_secret(first.secret_ref)
                .await
                .unwrap()
                .as_slice(),
            &[5; 32]
        );
        assert_eq!(store.secrets().await.unwrap().len(), 2);
    }

    /// The control database fills up while the last part of a write runs: there is room for a
    /// small write, but `trigger` makes that part need megabytes. The released reserve gives the
    /// room back (the page limit is lifted), and the write runs once more.
    async fn fills_up_on(store: &mut Store, trigger: &'static str) {
        let disk = store.disk.clone();
        store
            .control
            .retry_when_full(Arc::new(move |c: &mut Connection| {
                let released = disk.release_reserve();
                if released {
                    let _ = c.pragma_update(None, "max_page_count", 1_000_000);
                }
                released
            }));
        store
            .control
            .write(move |c| {
                c.execute_batch("CREATE TABLE test_filler (b BLOB);")?;
                c.execute_batch(trigger)?;
                let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
                c.pragma_update(None, "max_page_count", pages + 64)?;
                Ok(())
            })
            .await
            .unwrap();
    }

    /// An Instance (not stored yet) of a stored profile.
    async fn unsaved_instance(store: &Store) -> vpn_domain::InstanceSpec {
        use vpn_domain::*;
        let key = store
            .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
            .await
            .unwrap();
        let wg: WgKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
            .parse()
            .unwrap();
        let meta = EntityMeta {
            revision: 1,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };
        let profile = store
            .create(RuntimeProfile {
                id: ProfileId::new(),
                meta: meta.clone(),
                name: "p".into(),
                provider: ProviderKind::Generic,
                source: ProfileSource::Imported,
                interface: InterfaceSpec {
                    private_key: key.secret_ref,
                    public_key: wg,
                    addresses: vec!["10.99.0.2/32".parse().unwrap()],
                    dns: vec![],
                    mtu: 1420,
                },
                peer: PeerSpec {
                    public_key: wg,
                    preshared_key: None,
                    endpoint: "198.51.100.7:51820".parse().unwrap(),
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive: None,
                },
                location: None,
                expires_at: None,
            })
            .await
            .unwrap();
        InstanceSpec {
            id: InstanceId::new(),
            meta,
            name: "i".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: vpn_domain::TransportRef::default(),
        }
    }

    // AC-48: a write that finds the disk full half-way runs again as a whole — what its first part
    // wrote went back with it. The retry does not trip over its own Instance or App (「已存在相同
    // id 的資料」, hiding the full disk) and leave it without its intent, nor append an event twice.

    /// An Instance: its entity, then its intent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_instance_written_again_on_a_full_disk_is_whole() {
        use vpn_domain::DesiredState;
        let (_dir, mut store) = store_with(FakeSpace::new(10 * GIB, 100 * GIB));
        let spec = unsaved_instance(&store).await;
        fills_up_on(
            &mut store,
            "CREATE TRIGGER test_fill AFTER INSERT ON instance_intents
             BEGIN INSERT INTO test_filler VALUES (zeroblob(4194304)); END;",
        )
        .await;
        let created = store.create_instance(spec).await.unwrap();
        assert_eq!(
            store.intent(created.id).await.unwrap().desired,
            DesiredState::Stopped
        );
        let all: Vec<vpn_domain::InstanceSpec> = store.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(store.disk_report().reserve, ReserveState::Released);
    }

    /// An App: its entity, then its intent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_app_written_again_on_a_full_disk_is_whole() {
        use vpn_domain::{AppId, AppIsolation, AppLimits, AppSpec, EntityMeta};
        let (_dir, mut store) = store_with(FakeSpace::new(10 * GIB, 100 * GIB));
        let instance = store
            .create_instance(unsaved_instance(&store).await)
            .await
            .unwrap();
        fills_up_on(
            &mut store,
            "CREATE TRIGGER test_fill AFTER INSERT ON app_intents
             BEGIN INSERT INTO test_filler VALUES (zeroblob(4194304)); END;",
        )
        .await;
        let app = store
            .create_app(AppSpec {
                id: AppId::new(),
                meta: EntityMeta {
                    revision: 1,
                    created_at: Timestamp::now(),
                    updated_at: Timestamp::now(),
                },
                instance_id: instance.id,
                name: "a".into(),
                executable: "/bin/sh".into(),
                args: vec![],
                working_dir: None,
                env: vec![],
                isolation: AppIsolation::StrictNetns,
                gateway_id: None,
                restart_on_recovery: true,
                writable_paths: vec![],
                confine_writes: false,
                stop_grace_secs: 10,
                approval: None,
                limits: AppLimits::default(),
                access_ports: Vec::new(),
            })
            .await
            .unwrap();
        let rows = store.app_intents().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].app_id, app.id);
        assert_eq!(store.disk_report().reserve, ReserveState::Released);
    }

    /// An event, once the table is full: appended, then the oldest one goes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_event_appended_again_on_a_full_disk_is_there_once() {
        let (_dir, mut store) = store_with(FakeSpace::new(10 * GIB, 100 * GIB));
        let max = crate::MAX_EVENTS;
        store
            .control
            .write(move |c| {
                c.execute(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
                     INSERT INTO events (at, kind, entity_id, body)
                     SELECT '2026-01-01T00:00:00Z', 'old', NULL, '{}' FROM n",
                    [max],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        fills_up_on(
            &mut store,
            "CREATE TRIGGER test_fill BEFORE DELETE ON events
             BEGIN INSERT INTO test_filler VALUES (zeroblob(4194304)); END;",
        )
        .await;
        store
            .append_event("test.once".into(), None, serde_json::json!({}))
            .await
            .unwrap();
        let count = |sql: &'static str| {
            store
                .control
                .read(move |c| Ok(c.query_row(sql, [], |r| r.get::<_, i64>(0))?))
        };
        assert_eq!(
            count("SELECT count(*) FROM events WHERE kind = 'test.once'")
                .await
                .unwrap(),
            1
        );
        assert_eq!(count("SELECT count(*) FROM events").await.unwrap(), max);
        assert_eq!(store.disk_report().reserve, ReserveState::Released);
    }
}
