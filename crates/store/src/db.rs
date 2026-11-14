//! One SQLite database: a single writer thread fed by a bounded queue plus an unqueued priority
//! lane, and a small pool of read connections. No SQL runs on async executor threads, and no
//! transaction waits for network or OS work.
//!
//! One job never takes the database down with it: a job that panics, or leaves its transaction
//! open, is rolled back (nothing of it committed) and fails alone; the writer and every pooled
//! connection go on with the next one.

use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded, select_biased};
use parking::Pool;
use rusqlite::{Connection, OpenFlags};
use tokio::sync::{Semaphore, oneshot};
use vpn_domain::QueueHealth;

use crate::error::StoreError;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// Called (on the writer's connection) when a write found the disk full; true when it made room
/// (the write runs once more).
pub type OnFull = std::sync::Arc<dyn Fn(&mut Connection) -> bool + Send + Sync>;

/// Durability profile of a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// `synchronous=FULL` (+ `fullfsync` on macOS): control data, intents, latches.
    Full,
    /// `synchronous=NORMAL`: telemetry, where losing the last second is acceptable.
    Normal,
}

pub struct Db {
    // `Option` so `Drop` can close the lanes before joining the writer.
    normal: Option<Sender<Job>>,
    priority: Option<Sender<Job>>,
    writer: Option<std::thread::JoinHandle<()>>,
    readers: Arc<Pool>,
    read_permits: Arc<Semaphore>,
    /// Normal writes refused with `STORE_BUSY` (queue full) since the database was opened.
    busy_refusals: AtomicU64,
    /// Makes room when a write finds the disk full (the control database's reserve).
    on_full: Option<OnFull>,
}

impl Drop for Db {
    /// Close the write lanes and wait until the writer finished its queue and checkpoint, so a
    /// reopen (or process exit) never races a half-closed writer.
    fn drop(&mut self) {
        self.normal.take();
        self.priority.take();
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
    }
}

/// Queue depth of normal writes; beyond it callers get `STORE_BUSY` immediately.
pub const WRITE_QUEUE: usize = 256;

/// Pages the WAL holds before a checkpoint copies them into the database (1 MiB of 4 KiB pages).
const WAL_CHECKPOINT_PAGES: i64 = 256;
/// After a checkpoint emptied it, the WAL file is cut back to at most this size and keeps the
/// rest of its blocks: the next writes reuse them from the start, needing no new disk space.
const WAL_KEEP_BYTES: i64 = 4 * 1024 * 1024;

fn configure(conn: &Connection, durability: Durability) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(
        None,
        "synchronous",
        match durability {
            Durability::Full => "FULL",
            Durability::Normal => "NORMAL",
        },
    )?;
    if durability == Durability::Full && cfg!(target_os = "macos") {
        // macOS fsync() does not flush the drive cache; fullfsync does.
        conn.pragma_update(None, "fullfsync", "ON")?;
        conn.pragma_update(None, "checkpoint_fullfsync", "ON")?;
    }
    // A bounded WAL that keeps its blocks, and no temporary files: on a full disk a write still
    // fits in the space the database already has (`disk.rs`).
    conn.pragma_update(None, "wal_autocheckpoint", WAL_CHECKPOINT_PAGES)?;
    conn.pragma_update(None, "journal_size_limit", WAL_KEEP_BYTES)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.busy_timeout(std::time::Duration::from_millis(100))?;
    Ok(())
}

/// Run one job on `conn` so that it fails alone: a panic becomes its error, and a transaction it
/// left open (a panic half-way, a COMMIT and ROLLBACK that both failed) is rolled back, so that
/// nothing of it is committed and the next job can begin its own.
fn contained<T>(
    conn: &mut Connection,
    f: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| f(&mut *conn)))
        .unwrap_or(Err(StoreError::Aborted("the job panicked")));
    if conn.is_autocommit() {
        return result;
    }
    let _ = conn.execute_batch("ROLLBACK");
    tracing::error!("a store job left its transaction open: rolled back");
    match result {
        Ok(_) => Err(StoreError::Aborted("the job left its transaction open")),
        failed => failed,
    }
}

impl Db {
    /// Open (creating if needed) and run `migrate` on the writer connection before serving.
    pub fn open(
        path: &Path,
        durability: Durability,
        readers: usize,
        migrate: impl FnOnce(&mut Connection) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut writer = Connection::open_with_flags(path, flags)?;
        configure(&writer, durability)?;
        migrate(&mut writer)?;
        let check: String = writer.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(StoreError::Corrupt(check));
        }

        let mut pool = Vec::with_capacity(readers);
        for _ in 0..readers.max(1) {
            let c = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            c.busy_timeout(std::time::Duration::from_millis(250))?;
            c.pragma_update(None, "query_only", "ON")?;
            c.pragma_update(None, "temp_store", "MEMORY")?;
            pool.push(c);
        }

        let (normal_tx, normal_rx) = bounded::<Job>(WRITE_QUEUE);
        let (prio_tx, prio_rx) = bounded::<Job>(64);
        let writer = std::thread::Builder::new()
            .name(format!(
                "store-writer-{}",
                path.file_stem().and_then(|s| s.to_str()).unwrap_or("db")
            ))
            .spawn(move || writer_loop(writer, normal_rx, prio_rx))
            .map_err(|e| StoreError::Io(e.to_string()))?;

        let n = pool.len();
        Ok(Self {
            normal: Some(normal_tx),
            priority: Some(prio_tx),
            writer: Some(writer),
            readers: Arc::new(Pool::new(pool)),
            read_permits: Arc::new(Semaphore::new(n)),
            busy_refusals: AtomicU64::new(0),
            on_full: None,
        })
    }

    /// A write that finds the disk full calls `f`; when it made room, the write runs once more
    /// (on a copy of it taken before the first try).
    pub(crate) fn retry_when_full(&mut self, f: OnFull) {
        self.on_full = Some(f);
    }

    /// Depth of both write lanes and how often the normal one was full.
    pub fn queue_health(&self) -> QueueHealth {
        let depth = |lane: &Option<Sender<Job>>| {
            lane.as_ref()
                .map_or(0, |l| u32::try_from(l.len()).unwrap_or(u32::MAX))
        };
        QueueHealth {
            depth: depth(&self.normal),
            capacity: u32::try_from(WRITE_QUEUE).unwrap_or(u32::MAX),
            priority_depth: depth(&self.priority),
            busy_refusals: self.busy_refusals.load(Ordering::Relaxed),
        }
    }

    /// Run a write transaction-capable closure on the writer thread. Fails fast with
    /// `StoreBusy` when the queue is full. The closure is cloned before it runs where a full
    /// disk can be made room for ([`Self::retry_when_full`]).
    pub async fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Clone + Send + 'static,
    ) -> Result<T, StoreError> {
        let lane = self.normal.as_ref().ok_or(StoreError::Closed)?;
        self.submit(lane, f, true).await
    }

    /// Same as [`Self::write`] but on the priority lane: never rejected for queue depth by
    /// normal traffic. Used for stop/emergency latches.
    pub async fn write_priority<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Clone + Send + 'static,
    ) -> Result<T, StoreError> {
        let lane = self.priority.as_ref().ok_or(StoreError::Closed)?;
        self.submit(lane, f, false).await
    }

    async fn submit<T: Send + 'static>(
        &self,
        lane: &Sender<Job>,
        f: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Clone + Send + 'static,
        fail_fast: bool,
    ) -> Result<T, StoreError> {
        let (tx, rx) = oneshot::channel();
        let on_full = self.on_full.clone();
        let job: Job = Box::new(move |conn| {
            let result = contained(conn, |conn| {
                // The failed transaction was rolled back; its copy runs in the room just made.
                let again = on_full.as_ref().map(|_| f.clone());
                let result = f(conn);
                if result.as_ref().is_err_and(StoreError::is_disk_full)
                    && let (Some(again), Some(make_room)) = (again, on_full.as_ref())
                    && make_room(conn)
                {
                    return again(conn);
                }
                result
            });
            let _ = tx.send(result);
        });
        if fail_fast {
            match lane.try_send(job) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.busy_refusals.fetch_add(1, Ordering::Relaxed);
                    return Err(StoreError::Busy);
                }
                Err(TrySendError::Disconnected(_)) => return Err(StoreError::Closed),
            }
        } else {
            let lane = lane.clone();
            tokio::task::spawn_blocking(move || lane.send(job))
                .await
                .map_err(|_| StoreError::Closed)?
                .map_err(|_| StoreError::Closed)?;
        }
        rx.await.map_err(|_| StoreError::Closed)?
    }

    /// Run a read-only closure on a pooled connection (blocking thread).
    pub async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let permit = self
            .read_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| StoreError::Closed)?;
        let pool = self.readers.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.take();
            // Given back also after a panic: the pool never runs short of what the permits
            // promise.
            let result = contained(&mut conn, |c| f(c));
            pool.give(conn);
            drop(permit);
            result
        })
        .await
        .map_err(|_| StoreError::Closed)?
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the writer thread owns its lanes: they close when the loop ends"
)]
fn writer_loop(mut conn: Connection, normal: Receiver<Job>, priority: Receiver<Job>) {
    loop {
        // Drain the priority lane first, then wait on both with priority bias.
        while let Ok(job) = priority.try_recv() {
            job(&mut conn);
        }
        select_biased! {
            recv(priority) -> job => match job {
                Ok(job) => job(&mut conn),
                Err(_) => break,
            },
            recv(normal) -> job => match job {
                Ok(job) => job(&mut conn),
                Err(_) => break,
            },
        }
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

/// Minimal blocking pool: the semaphore guarantees a connection is available when `take` runs.
mod parking {
    use rusqlite::Connection;
    use vpn_sync::Mutex;

    pub struct Pool(Mutex<Vec<Connection>>);

    impl Pool {
        pub const fn new(v: Vec<Connection>) -> Self {
            Self(Mutex::new(v))
        }

        pub fn take(&self) -> Connection {
            self.0
                .lock()
                .pop()
                .expect("read semaphore guarantees an idle connection")
        }

        pub fn give(&self, c: Connection) {
            self.0.lock().push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Write = fn(&mut Connection) -> Result<(), StoreError>;
    type FailedAs = fn(&StoreError) -> bool;

    /// A write that fails half-way — the disk fills up, the job panics, or it leaves its
    /// transaction open — leaves nothing of itself behind, and the writer takes the next one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_that_fails_half_way_leaves_nothing_and_the_next_one_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.sqlite"), Durability::Normal, 1, |c| {
            c.execute_batch("CREATE TABLE t (x INTEGER NOT NULL); CREATE TABLE filler (b BLOB);")?;
            Ok(())
        })
        .unwrap();
        let cases: [(&str, Write, FailedAs); 3] = [
            (
                "the disk fills up",
                |c| {
                    let tx = c.transaction()?;
                    tx.execute("INSERT INTO t VALUES (1)", [])?;
                    let pages: i64 = tx.query_row("PRAGMA page_count", [], |r| r.get(0))?;
                    tx.pragma_update(None, "max_page_count", pages)?;
                    tx.execute("INSERT INTO filler VALUES (zeroblob(1048576))", [])?;
                    tx.commit()?;
                    Ok(())
                },
                StoreError::is_disk_full,
            ),
            (
                "the job panics",
                |c| {
                    let tx = c.transaction()?;
                    tx.execute("INSERT INTO t VALUES (1)", [])?;
                    panic!("a bug half-way through a transaction");
                },
                |e| matches!(e, StoreError::Aborted(_)),
            ),
            (
                "the job leaves its transaction open",
                |c| {
                    c.execute_batch("BEGIN; INSERT INTO t VALUES (1);")?;
                    Ok(())
                },
                |e| matches!(e, StoreError::Aborted(_)),
            ),
        ];
        for (n, (case, write, failed_as)) in cases.into_iter().enumerate() {
            let err = db.write(write).await.unwrap_err();
            assert!(failed_as(&err), "{case}: {err}");
            db.write(|c| {
                c.pragma_update(None, "max_page_count", 1_000_000)?;
                c.execute("INSERT INTO t VALUES (2)", [])?;
                Ok(())
            })
            .await
            .unwrap();
            let rows: Vec<i64> = db
                .read(|c| {
                    let mut stmt = c.prepare("SELECT x FROM t")?;
                    let rows = stmt.query_map([], |r| r.get(0))?;
                    Ok(rows.collect::<Result<_, _>>()?)
                })
                .await
                .unwrap();
            assert_eq!(
                rows,
                vec![2; n + 1],
                "{case}: only what was committed is there"
            );
        }
        let check: String = db
            .read(|c| Ok(c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(check, "ok");
    }
}
