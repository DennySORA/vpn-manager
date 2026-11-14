//! SSH download: the component's own tables. The job itself is a revisioned entity (kind
//! `ssh_download_job`); here are its runtime state (the user's pause and the trusted host key),
//! the record of every file it took — the truth a restarted manager resumes from — and its log.
//!
//! A record is written before the step it describes, so whatever a crash interrupts, the next
//! start knows where the file is: claimed into the working folder or not, partial or complete,
//! finished locally with the remote copy still to delete, or on its way to the failed folder.

use rusqlite::{Connection, OptionalExtension, params};
use vpn_domain::{
    SSH_DOWNLOAD_MAX_JOBS, SshDownloadJob, SshDownloadJobId, SshDownloadLogEntry,
    SshDownloadLogLevel, SshDownloadTransferState, Text, Timestamp, tr,
};

use crate::Store;
use crate::entities;
use crate::error::StoreError;
use crate::scrub::truncate_wal;

/// v12: the runtime state, file records and log of SSH download jobs.
pub const CONTROL_STEP: &str = r"
-- One row per job, created and deleted with it: the user's pause, the host key trusted on first
-- use (for the target it was seen on), and a different key the server offered since (the job
-- stops until the user trusts it).
CREATE TABLE ssh_download_state (
    job_id              TEXT PRIMARY KEY,
    paused              INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
    key_target          TEXT,
    key_algorithm       TEXT,
    key_fingerprint     TEXT,
    key_public          TEXT,
    key_seen_ms         INTEGER,
    offered_target      TEXT,
    offered_algorithm   TEXT,
    offered_fingerprint TEXT,
    offered_public      TEXT,
    offered_seen_ms     INTEGER,
    updated_ms          INTEGER NOT NULL,
    CHECK ((key_fingerprint IS NULL) = (key_public IS NULL)),
    CHECK ((offered_fingerprint IS NULL) = (offered_public IS NULL))
) WITHOUT ROWID;

-- One row per file a job took from its source folder, written before each step: claim (source
-- to working folder under the row's id), download into `<local_dir>/.vpn-manager-partial/<id>.part`,
-- finalize (the chosen local name is recorded before the rename), delete the remote copy — or move
-- it to the failed folder. Finished rows are the job's history (the newest 1,000 per job); a job
-- that does not record names keeps them without the name and paths (`source_path` empty).
CREATE TABLE ssh_download_transfers (
    id          TEXT PRIMARY KEY,
    job_id      TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('claiming', 'downloading', 'finalizing',
                    'local_done', 'failing', 'completed', 'failed')),
    source_path TEXT    NOT NULL,
    work_path   TEXT    NOT NULL,
    local_dir   TEXT    NOT NULL,
    final_path  TEXT,
    failed_path TEXT,
    size        INTEGER CHECK (size IS NULL OR size >= 0),
    bytes_done  INTEGER CHECK (bytes_done IS NULL OR bytes_done >= 0),
    attempts    INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error       TEXT,
    created_ms  INTEGER NOT NULL,
    started_ms  INTEGER,
    finished_ms INTEGER,
    updated_ms  INTEGER NOT NULL,
    CHECK ((finished_ms IS NULL) = (state NOT IN ('completed', 'failed')))
) WITHOUT ROWID;
CREATE INDEX ssh_download_transfers_open ON ssh_download_transfers (job_id, created_ms)
    WHERE finished_ms IS NULL;
CREATE INDEX ssh_download_transfers_done ON ssh_download_transfers (job_id, finished_ms, id)
    WHERE finished_ms IS NOT NULL;

-- A job's log: public facts only (names, sizes, reasons; never a secret). Newest 500 per job.
CREATE TABLE ssh_download_log (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id  TEXT    NOT NULL,
    at_ms   INTEGER NOT NULL,
    level   TEXT    NOT NULL CHECK (level IN ('info', 'warning', 'error')),
    code    TEXT    NOT NULL,
    message TEXT    NOT NULL,
    file    TEXT
);
CREATE INDEX ssh_download_log_job ON ssh_download_log (job_id, seq);
";

/// Finished transfers kept per job.
pub const SSH_DOWNLOAD_HISTORY_KEPT: i64 = 1_000;
/// Log lines kept per job.
pub const SSH_DOWNLOAD_LOG_KEPT: i64 = 500;

/// A host key as stored: the target (`host:port`) it was seen on, its algorithm, its SHA-256
/// fingerprint and the key itself (OpenSSH public key line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHostKey {
    pub target: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
    pub seen_ms: i64,
}

/// The runtime state of one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDownloadStateRow {
    pub job_id: SshDownloadJobId,
    pub paused: bool,
    pub host_key: Option<StoredHostKey>,
    pub offered_host_key: Option<StoredHostKey>,
}

/// The record of one file a job took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDownloadTransferRow {
    pub id: String,
    pub job_id: SshDownloadJobId,
    pub name: String,
    pub state: SshDownloadTransferState,
    /// Where it was in the source folder.
    pub source_path: String,
    /// Where it is in the working folder (named by `id`).
    pub work_path: String,
    /// The local folder it downloads into (the job's when it was taken).
    pub local_dir: String,
    /// The local name chosen at finalize (recorded before the rename).
    pub final_path: Option<String>,
    /// Where it was moved in the failed folder.
    pub failed_path: Option<String>,
    pub size: Option<u64>,
    pub bytes_done: Option<u64>,
    /// Attempts without progress so far.
    pub attempts: u32,
    pub error: Option<Text>,
    pub created_ms: i64,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
}

const fn state_word(s: SshDownloadTransferState) -> &'static str {
    use SshDownloadTransferState::{
        Claiming, Completed, Downloading, Failed, Failing, Finalizing, LocalDone,
    };
    match s {
        Claiming => "claiming",
        Downloading => "downloading",
        Finalizing => "finalizing",
        LocalDone => "local_done",
        Failing => "failing",
        Completed => "completed",
        Failed => "failed",
    }
}

fn state_of(w: &str) -> Option<SshDownloadTransferState> {
    use SshDownloadTransferState::{
        Claiming, Completed, Downloading, Failed, Failing, Finalizing, LocalDone,
    };
    Some(match w {
        "claiming" => Claiming,
        "downloading" => Downloading,
        "finalizing" => Finalizing,
        "local_done" => LocalDone,
        "failing" => Failing,
        "completed" => Completed,
        "failed" => Failed,
        _ => return None,
    })
}

const fn level_word(l: SshDownloadLogLevel) -> &'static str {
    match l {
        SshDownloadLogLevel::Info => "info",
        SshDownloadLogLevel::Warning => "warning",
        SshDownloadLogLevel::Error => "error",
    }
}

fn now_ms() -> i64 {
    Timestamp::now().unix_millis()
}

const STATE_COLUMNS: &str = "job_id, paused, key_target, key_algorithm, key_fingerprint, key_public, key_seen_ms, offered_target, offered_algorithm, offered_fingerprint, offered_public, offered_seen_ms";

fn key_at(r: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<Option<StoredHostKey>> {
    let fingerprint: Option<String> = r.get(at + 2)?;
    let public_key: Option<String> = r.get(at + 3)?;
    Ok(match (fingerprint, public_key) {
        (Some(fingerprint), Some(public_key)) => Some(StoredHostKey {
            target: r.get::<_, Option<String>>(at)?.unwrap_or_default(),
            algorithm: r.get::<_, Option<String>>(at + 1)?.unwrap_or_default(),
            fingerprint,
            public_key,
            seen_ms: r.get::<_, Option<i64>>(at + 4)?.unwrap_or_default(),
        }),
        _ => None,
    })
}

fn state_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SshDownloadStateRow> {
    let id: String = r.get(0)?;
    Ok(SshDownloadStateRow {
        job_id: id.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        paused: r.get::<_, i64>(1)? != 0,
        host_key: key_at(r, 2)?,
        offered_host_key: key_at(r, 7)?,
    })
}

fn read_state(c: &Connection, id: SshDownloadJobId) -> Result<SshDownloadStateRow, StoreError> {
    c.query_row(
        &format!("SELECT {STATE_COLUMNS} FROM ssh_download_state WHERE job_id = ?1"),
        params![id.to_string()],
        state_row,
    )
    .optional()?
    .ok_or(StoreError::NotFound)
}

const TRANSFER_COLUMNS: &str = "id, job_id, name, state, source_path, work_path, local_dir, final_path, failed_path, size, bytes_done, attempts, error, created_ms, started_ms, finished_ms";

fn transfer_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SshDownloadTransferRow> {
    let bad = |c: &str| rusqlite::Error::InvalidColumnName(c.into());
    let job: String = r.get(1)?;
    let state: String = r.get(3)?;
    let size: Option<i64> = r.get(9)?;
    let done: Option<i64> = r.get(10)?;
    Ok(SshDownloadTransferRow {
        id: r.get(0)?,
        job_id: job.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?,
        name: r.get(2)?,
        state: state_of(&state).ok_or_else(|| bad("state"))?,
        source_path: r.get(4)?,
        work_path: r.get(5)?,
        local_dir: r.get(6)?,
        final_path: r.get(7)?,
        failed_path: r.get(8)?,
        size: size.map(i64::cast_unsigned),
        bytes_done: done.map(i64::cast_unsigned),
        attempts: u32::try_from(r.get::<_, i64>(11)?.clamp(0, i64::from(u32::MAX)))
            .unwrap_or(u32::MAX),
        error: r
            .get::<_, Option<String>>(12)?
            .map(crate::text_column::from_column),
        created_ms: r.get(13)?,
        started_ms: r.get(14)?,
        finished_ms: r.get(15)?,
    })
}

fn job_exists(c: &Connection, id: SshDownloadJobId) -> Result<bool, StoreError> {
    Ok(entities::head_revision(c, "ssh_download_job", &id.to_string())?.is_some())
}

/// Keep the newest `SSH_DOWNLOAD_HISTORY_KEPT` finished transfers of `job`.
fn prune_history(c: &Connection, job: &str) -> Result<(), StoreError> {
    c.execute(
        "DELETE FROM ssh_download_transfers WHERE job_id = ?1 AND finished_ms IS NOT NULL
           AND id NOT IN (SELECT id FROM ssh_download_transfers
                           WHERE job_id = ?1 AND finished_ms IS NOT NULL
                           ORDER BY finished_ms DESC, id DESC LIMIT ?2)",
        params![job, SSH_DOWNLOAD_HISTORY_KEPT],
    )?;
    Ok(())
}

impl Store {
    /// Create a job and its state row in one transaction. Refused beyond
    /// `SSH_DOWNLOAD_MAX_JOBS` jobs.
    ///
    /// # Errors
    ///
    /// `InvalidState` beyond `SSH_DOWNLOAD_MAX_JOBS` jobs, when the id exists already or a
    /// referenced entity is missing; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn create_ssh_download(
        &self,
        job: SshDownloadJob,
        paused: bool,
    ) -> Result<SshDownloadJob, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let n: i64 = tx.query_row(
                    "SELECT count(*) FROM entity_heads WHERE kind = 'ssh_download_job'",
                    [],
                    |r| r.get(0),
                )?;
                if usize::try_from(n).unwrap_or(usize::MAX) >= SSH_DOWNLOAD_MAX_JOBS {
                    return Err(StoreError::InvalidState(tr!(
                        "At most {SSH_DOWNLOAD_MAX_JOBS} SSH download jobs",
                        "最多 {SSH_DOWNLOAD_MAX_JOBS} 個 SSH 下載工作",
                        "SSH ダウンロードジョブは最大 {SSH_DOWNLOAD_MAX_JOBS} 件です"
                    )));
                }
                let id = job.id.to_string();
                let job = entities::insert_in(&tx, job)?;
                tx.execute(
                    "INSERT INTO ssh_download_state (job_id, paused, updated_ms) VALUES (?1, ?2, ?3)
                     ON CONFLICT (job_id) DO NOTHING",
                    params![id, i64::from(paused), now_ms()],
                )?;
                tx.commit()?;
                Ok(job)
            })
            .await
    }

    /// Replace a job, compare-and-set on `expected_revision`.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job, `RevisionConflict` when `expected_revision` is stale,
    /// `InvalidState` when a referenced entity is missing; `Busy` when the write queue is full,
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn update_ssh_download(
        &self,
        job: SshDownloadJob,
        expected_revision: u64,
    ) -> Result<SshDownloadJob, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let job = entities::update_in(&tx, job, expected_revision)?;
                tx.commit()?;
                Ok(job)
            })
            .await
    }

    /// Delete a job with its state, its file records and its log, in one transaction; returns
    /// the job as it was (its secrets are the caller's to delete). Nothing of them is left in the
    /// database or its WAL (`scrub`).
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job, `RevisionConflict` when `expected_revision` is stale, `InUse`
    /// while something references it; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn delete_ssh_download(
        &self,
        id: SshDownloadJobId,
        expected_revision: u64,
    ) -> Result<SshDownloadJob, StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let tx = c.transaction()?;
                let job: SshDownloadJob = entities::get(&tx, &ids)?.ok_or(StoreError::NotFound)?;
                entities::delete_in::<SshDownloadJob>(&tx, &ids, expected_revision)?;
                for table in [
                    "ssh_download_state",
                    "ssh_download_transfers",
                    "ssh_download_log",
                ] {
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE job_id = ?1"),
                        params![ids],
                    )?;
                }
                tx.commit()?;
                truncate_wal(c);
                Ok(job)
            })
            .await
    }

    /// The state row of every job.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn ssh_download_states(&self) -> Result<Vec<SshDownloadStateRow>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt =
                    c.prepare(&format!("SELECT {STATE_COLUMNS} FROM ssh_download_state"))?;
                let rows = stmt.query_map([], state_row)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            })
            .await
    }

    /// The state row of job `id`.
    ///
    /// # Errors
    ///
    /// `NotFound` for a job without a state row; `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the read or a row's decoding fails.
    pub async fn ssh_download_state(
        &self,
        id: SshDownloadJobId,
    ) -> Result<SshDownloadStateRow, StoreError> {
        self.control.read(move |c| read_state(c, id)).await
    }

    /// Record the user's pause or resume.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn set_ssh_download_paused(
        &self,
        id: SshDownloadJobId,
        paused: bool,
    ) -> Result<SshDownloadStateRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if !job_exists(&tx, id)? {
                    return Err(StoreError::NotFound);
                }
                tx.execute(
                    "INSERT INTO ssh_download_state (job_id, paused, updated_ms) VALUES (?1, ?2, ?3)
                     ON CONFLICT (job_id) DO UPDATE SET paused = excluded.paused,
                        updated_ms = excluded.updated_ms",
                    params![id.to_string(), i64::from(paused), now_ms()],
                )?;
                let row = read_state(&tx, id)?;
                tx.commit()?;
                Ok(row)
            })
            .await
    }

    /// Trust on first use: `key` becomes the job's host key unless one is recorded for the same
    /// target already (a key of another target — the job's host or port changed — is replaced).
    /// Returns the state as stored: the caller compares its key with the one it saw.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn record_ssh_download_host_key(
        &self,
        id: SshDownloadJobId,
        key: StoredHostKey,
    ) -> Result<SshDownloadStateRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if !job_exists(&tx, id)? {
                    return Err(StoreError::NotFound);
                }
                tx.execute(
                    "UPDATE ssh_download_state SET key_target = ?2, key_algorithm = ?3,
                        key_fingerprint = ?4, key_public = ?5, key_seen_ms = ?6,
                        offered_target = NULL, offered_algorithm = NULL, offered_fingerprint = NULL,
                        offered_public = NULL, offered_seen_ms = NULL, updated_ms = ?7
                      WHERE job_id = ?1 AND (key_fingerprint IS NULL OR key_target IS NOT ?2)",
                    params![
                        id.to_string(),
                        key.target,
                        key.algorithm,
                        key.fingerprint,
                        key.public_key,
                        key.seen_ms,
                        now_ms()
                    ],
                )?;
                let row = read_state(&tx, id)?;
                tx.commit()?;
                Ok(row)
            })
            .await
    }

    /// The server offered `key` instead of the trusted one: kept for the user to look at and
    /// trust (the job stops meanwhile).
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn offer_ssh_download_host_key(
        &self,
        id: SshDownloadJobId,
        key: StoredHostKey,
    ) -> Result<SshDownloadStateRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if !job_exists(&tx, id)? {
                    return Err(StoreError::NotFound);
                }
                tx.execute(
                    "UPDATE ssh_download_state SET offered_target = ?2, offered_algorithm = ?3,
                        offered_fingerprint = ?4, offered_public = ?5, offered_seen_ms = ?6,
                        updated_ms = ?7
                      WHERE job_id = ?1",
                    params![
                        id.to_string(),
                        key.target,
                        key.algorithm,
                        key.fingerprint,
                        key.public_key,
                        key.seen_ms,
                        now_ms()
                    ],
                )?;
                let row = read_state(&tx, id)?;
                tx.commit()?;
                Ok(row)
            })
            .await
    }

    /// The user trusts the offered key whose fingerprint they saw: it replaces the recorded one.
    /// Refused when no key is offered, or another one is now.
    ///
    /// # Errors
    ///
    /// `InvalidState` when no key is offered or another one is offered now, `NotFound` for a job
    /// without a state row; `Busy` when the write queue is full, `Closed` once the store has shut
    /// down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn trust_ssh_download_host_key(
        &self,
        id: SshDownloadJobId,
        fingerprint: String,
    ) -> Result<SshDownloadStateRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = read_state(&tx, id)?;
                match &row.offered_host_key {
                    Some(k) if k.fingerprint == fingerprint => {}
                    Some(_) => {
                        return Err(StoreError::InvalidState(tr!(
                            "The server now offers a different key; check the fingerprint again and retry",
                            "伺服器現在提供的是另一把金鑰；請重新核對指紋後再試",
                            "サーバーが現在提示しているのは別の鍵です。フィンガープリントをもう一度確認してから再試行してください"
                        )));
                    }
                    None => {
                        return Err(StoreError::InvalidState(tr!(
                            "No host key is waiting for confirmation",
                            "沒有等待確認的主機金鑰",
                            "確認待ちのホスト鍵はありません"
                        )));
                    }
                }
                tx.execute(
                    "UPDATE ssh_download_state SET key_target = offered_target,
                        key_algorithm = offered_algorithm, key_fingerprint = offered_fingerprint,
                        key_public = offered_public, key_seen_ms = offered_seen_ms,
                        offered_target = NULL, offered_algorithm = NULL, offered_fingerprint = NULL,
                        offered_public = NULL, offered_seen_ms = NULL, updated_ms = ?2
                      WHERE job_id = ?1",
                    params![id.to_string(), now_ms()],
                )?;
                let row = read_state(&tx, id)?;
                tx.commit()?;
                Ok(row)
            })
            .await
    }

    /// Write a new transfer record (before the claim it describes).
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn insert_ssh_download_transfer(
        &self,
        row: SshDownloadTransferRow,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if !job_exists(&tx, row.job_id)? {
                    return Err(StoreError::NotFound);
                }
                tx.execute(
                    &format!(
                        "INSERT INTO ssh_download_transfers ({TRANSFER_COLUMNS}, updated_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
                    ),
                    params![
                        row.id,
                        row.job_id.to_string(),
                        row.name,
                        state_word(row.state),
                        row.source_path,
                        row.work_path,
                        row.local_dir,
                        row.final_path,
                        row.failed_path,
                        row.size.map(u64::cast_signed),
                        row.bytes_done.map(u64::cast_signed),
                        i64::from(row.attempts),
                        row.error.as_ref().map(crate::text_column::to_column),
                        row.created_ms,
                        row.started_ms,
                        row.finished_ms,
                        now_ms()
                    ],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Write a transfer record as it is now (its next step is recorded before it is taken). A
    /// finished one joins the history, which keeps the newest per job.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown record; `Busy` when the write queue is full, `Closed` once the
    /// store has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn update_ssh_download_transfer(
        &self,
        row: SshDownloadTransferRow,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let n = tx.execute(
                    "UPDATE ssh_download_transfers SET state = ?2, final_path = ?3, failed_path = ?4,
                        size = ?5, bytes_done = ?6, attempts = ?7, error = ?8, started_ms = ?9,
                        finished_ms = ?10, local_dir = ?11, updated_ms = ?12, name = ?13,
                        source_path = ?14
                      WHERE id = ?1",
                    params![
                        row.id,
                        state_word(row.state),
                        row.final_path,
                        row.failed_path,
                        row.size.map(u64::cast_signed),
                        row.bytes_done.map(u64::cast_signed),
                        i64::from(row.attempts),
                        row.error.as_ref().map(crate::text_column::to_column),
                        row.started_ms,
                        row.finished_ms,
                        row.local_dir,
                        now_ms(),
                        row.name,
                        row.source_path
                    ],
                )?;
                if n == 0 {
                    return Err(StoreError::NotFound);
                }
                if row.finished_ms.is_some() {
                    prune_history(&tx, &row.job_id.to_string())?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Delete every line of a job's log; how many went. Nothing of them is left in the database
    /// or its WAL (`scrub`).
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn clear_ssh_download_log(&self, job: SshDownloadJobId) -> Result<u64, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if !job_exists(&tx, job)? {
                    return Err(StoreError::NotFound);
                }
                let n = tx.execute(
                    "DELETE FROM ssh_download_log WHERE job_id = ?1",
                    params![job.to_string()],
                )?;
                tx.commit()?;
                truncate_wal(c);
                Ok(n as u64)
            })
            .await
    }

    /// Delete a job's finished records (its history); how many went. Unfinished ones stay: they
    /// are what an interrupted file resumes from. Nothing of the deleted ones is left in the
    /// database or its WAL (`scrub`).
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn clear_ssh_download_history(
        &self,
        job: SshDownloadJobId,
    ) -> Result<u64, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if !job_exists(&tx, job)? {
                    return Err(StoreError::NotFound);
                }
                let n = tx.execute(
                    "DELETE FROM ssh_download_transfers
                      WHERE job_id = ?1 AND finished_ms IS NOT NULL",
                    params![job.to_string()],
                )?;
                tx.commit()?;
                truncate_wal(c);
                Ok(n as u64)
            })
            .await
    }

    /// Delete a job's log lines and finished records from before `before_ms` (its own keep
    /// period); how many went. Unfinished records stay.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn purge_ssh_download(
        &self,
        job: SshDownloadJobId,
        before_ms: i64,
    ) -> Result<u64, StoreError> {
        self.control
            .write(move |c| {
                let job = job.to_string();
                let tx = c.transaction()?;
                let lines = tx.execute(
                    "DELETE FROM ssh_download_log WHERE job_id = ?1 AND at_ms < ?2",
                    params![job, before_ms],
                )?;
                let records = tx.execute(
                    "DELETE FROM ssh_download_transfers
                      WHERE job_id = ?1 AND finished_ms IS NOT NULL AND finished_ms < ?2",
                    params![job, before_ms],
                )?;
                tx.commit()?;
                let n = (lines + records) as u64;
                if n > 0 {
                    truncate_wal(c);
                }
                Ok(n)
            })
            .await
    }

    /// Checkpoint the control database's WAL and cut it to nothing: no earlier image of a page —
    /// with rows deleted since in it — is left there (`scrub`). `true` when done (readers can
    /// hold it up; it is tried again next time).
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down.
    pub async fn scrub_control_wal(&self) -> Result<bool, StoreError> {
        self.control.write(|c| Ok(truncate_wal(c))).await
    }

    /// Forget a record whose claim never happened (the file is still, or no longer, in the
    /// source folder).
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn delete_ssh_download_transfer(&self, id: String) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                c.execute(
                    "DELETE FROM ssh_download_transfers WHERE id = ?1 AND finished_ms IS NULL",
                    params![id],
                )?;
                Ok(())
            })
            .await
    }

    /// The unfinished records of a job, oldest first.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn ssh_download_open_transfers(
        &self,
        job: SshDownloadJobId,
    ) -> Result<Vec<SshDownloadTransferRow>, StoreError> {
        self.control
            .read(move |c| {
                let mut stmt = c.prepare(&format!(
                    "SELECT {TRANSFER_COLUMNS} FROM ssh_download_transfers
                      WHERE job_id = ?1 AND finished_ms IS NULL ORDER BY created_ms, id"
                ))?;
                let rows = stmt.query_map(params![job.to_string()], transfer_row)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            })
            .await
    }

    /// One page of a job's records, newest first: the unfinished ones (`finished: false`), or
    /// the finished ones before the cursor `(finished_ms, id)`.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn ssh_download_transfers(
        &self,
        job: SshDownloadJobId,
        finished: bool,
        before: Option<(i64, String)>,
        limit: usize,
    ) -> Result<Vec<SshDownloadTransferRow>, StoreError> {
        self.control
            .read(move |c| {
                let job = job.to_string();
                let limit = i64::try_from(limit).unwrap_or(i64::MAX);
                let rows = if finished {
                    let (at, id) = before.unwrap_or((i64::MAX, String::new()));
                    let mut stmt = c.prepare(&format!(
                        "SELECT {TRANSFER_COLUMNS} FROM ssh_download_transfers
                          WHERE job_id = ?1 AND finished_ms IS NOT NULL
                            AND (finished_ms < ?2 OR (finished_ms = ?2 AND (?3 = '' OR id < ?3)))
                          ORDER BY finished_ms DESC, id DESC LIMIT ?4"
                    ))?;
                    stmt.query_map(params![job, at, id, limit], transfer_row)?
                        .collect::<Result<Vec<_>, _>>()?
                } else {
                    let mut stmt = c.prepare(&format!(
                        "SELECT {TRANSFER_COLUMNS} FROM ssh_download_transfers
                          WHERE job_id = ?1 AND finished_ms IS NULL
                          ORDER BY created_ms DESC, id DESC LIMIT ?2"
                    ))?;
                    stmt.query_map(params![job, limit], transfer_row)?
                        .collect::<Result<Vec<_>, _>>()?
                };
                Ok(rows)
            })
            .await
    }

    /// Add a line to a job's log (the newest `SSH_DOWNLOAD_LOG_KEPT` are kept).
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn append_ssh_download_log(
        &self,
        job: SshDownloadJobId,
        level: SshDownloadLogLevel,
        code: String,
        message: Text,
        file: Option<String>,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let job = job.to_string();
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO ssh_download_log (job_id, at_ms, level, code, message, file)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        job,
                        now_ms(),
                        level_word(level),
                        code,
                        crate::text_column::to_column(&message),
                        file
                    ],
                )?;
                tx.execute(
                    "DELETE FROM ssh_download_log WHERE job_id = ?1 AND seq <= (
                        SELECT seq FROM ssh_download_log WHERE job_id = ?1
                         ORDER BY seq DESC LIMIT 1 OFFSET ?2)",
                    params![job, SSH_DOWNLOAD_LOG_KEPT],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// The newest `limit` lines of a job's log, newest first.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn ssh_download_log(
        &self,
        job: SshDownloadJobId,
        limit: usize,
    ) -> Result<Vec<SshDownloadLogEntry>, StoreError> {
        self.control
            .read(move |c| {
                let mut stmt = c.prepare(
                    "SELECT seq, at_ms, level, code, message, file FROM ssh_download_log
                      WHERE job_id = ?1 ORDER BY seq DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(
                    params![job.to_string(), i64::try_from(limit).unwrap_or(i64::MAX)],
                    |r| {
                        let level: String = r.get(2)?;
                        Ok(SshDownloadLogEntry {
                            seq: r.get(0)?,
                            at: Timestamp::from_unix_millis(r.get(1)?)
                                .unwrap_or_else(Timestamp::now),
                            level: match level.as_str() {
                                "error" => SshDownloadLogLevel::Error,
                                "warning" => SshDownloadLogLevel::Warning,
                                _ => SshDownloadLogLevel::Info,
                            },
                            code: r.get(3)?,
                            message: crate::text_column::from_column(r.get(4)?),
                            file: r.get(5)?,
                        })
                    },
                )?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use vpn_domain::{
        EntityMeta, GatewayId, GatewayKind, GatewaySpec, InstanceId, InstanceLimits,
        InstancePurpose, InstanceSpec, InterfaceSpec, PeerSpec, ProfileId, ProfileSource,
        ProviderKind, RuntimeProfile, SecretId, SecretRef, SshDownloadNameFilter,
    };

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &Zeroizing::new([5u8; 32]), 1).unwrap();
        (dir, store)
    }

    async fn gateway(store: &Store) -> GatewayId {
        let now = Timestamp::now();
        let meta = EntityMeta {
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        let profile = store
            .create(RuntimeProfile {
                id: ProfileId::new(),
                meta: meta.clone(),
                name: "p".into(),
                source: ProfileSource::Imported,
                provider: ProviderKind::Generic,
                location: None,
                interface: InterfaceSpec {
                    private_key: SecretRef(SecretId::new()),
                    public_key: "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhISE="
                        .parse()
                        .unwrap(),
                    addresses: vec!["10.0.0.2/32".parse().unwrap()],
                    dns: vec![],
                    mtu: 1420,
                },
                peer: PeerSpec {
                    public_key: "9JX1xdTTVPl2UuWZPh5Q7K/PbsyHy0I0BWF0tsnmtv8="
                        .parse()
                        .unwrap(),
                    preshared_key: None,
                    endpoint: "203.0.113.1:51820".parse().unwrap(),
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive: None,
                },
                expires_at: None,
            })
            .await
            .unwrap();
        let instance = store
            .create_instance(InstanceSpec {
                id: InstanceId::new(),
                meta: meta.clone(),
                name: "i".into(),
                profile_id: profile.id,
                dns_profile_id: None,
                security_profile_id: None,
                purpose: InstancePurpose::General,
                limits: InstanceLimits::default(),
                strict: false,
                transport: vpn_domain::TransportRef::default(),
            })
            .await
            .unwrap();
        store
            .create(GatewaySpec {
                id: GatewayId::new(),
                meta,
                instance_id: instance.id,
                name: "g".into(),
                kind: GatewayKind::Socks5,
                port: 1080,
                enabled: true,
                udp: false,
                max_connections: 64,
            })
            .await
            .unwrap()
            .id
    }

    fn job(gateway_id: GatewayId) -> SshDownloadJob {
        let now = Timestamp::now();
        SshDownloadJob {
            id: SshDownloadJobId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: now,
                updated_at: now,
            },
            name: "下載".into(),
            gateway_id,
            host: "files.example.net".into(),
            port: 22,
            user: "u".into(),
            identity_file: Some("/k".into()),
            key_passphrase: None,
            password: None,
            source_dir: "/todo".into(),
            work_dir: "/doing".into(),
            failed_dir: "/failed".into(),
            local_dir: "/tmp/in".into(),
            connections: 3,
            retries: 3,
            retry_backoff_secs: 5,
            scan_interval_secs: 60,
            name_filter: SshDownloadNameFilter::All,
            skip_hidden: true,
            record_names: true,
            history_days: None,
        }
    }

    fn key(target: &str, fp: &str) -> StoredHostKey {
        StoredHostKey {
            target: target.into(),
            algorithm: "ssh-ed25519".into(),
            fingerprint: fp.into(),
            public_key: format!("ssh-ed25519 {fp}"),
            seen_ms: 1,
        }
    }

    #[tokio::test]
    async fn the_first_key_is_trusted_a_different_one_waits_for_the_user() {
        let (_d, store) = store();
        let g = gateway(&store).await;
        let j = store.create_ssh_download(job(g), false).await.unwrap();
        let s = store
            .record_ssh_download_host_key(j.id, key("h:22", "SHA256:a"))
            .await
            .unwrap();
        assert_eq!(s.host_key.unwrap().fingerprint, "SHA256:a");
        // A second "first" key for the same target does not replace it.
        let s = store
            .record_ssh_download_host_key(j.id, key("h:22", "SHA256:b"))
            .await
            .unwrap();
        assert_eq!(s.host_key.as_ref().unwrap().fingerprint, "SHA256:a");
        let s = store
            .offer_ssh_download_host_key(j.id, key("h:22", "SHA256:b"))
            .await
            .unwrap();
        assert_eq!(s.offered_host_key.unwrap().fingerprint, "SHA256:b");
        assert!(
            store
                .trust_ssh_download_host_key(j.id, "SHA256:c".into())
                .await
                .is_err(),
            "only the key the user saw"
        );
        let s = store
            .trust_ssh_download_host_key(j.id, "SHA256:b".into())
            .await
            .unwrap();
        assert_eq!(s.host_key.unwrap().fingerprint, "SHA256:b");
        assert!(s.offered_host_key.is_none());
        // Another target (the job's host changed): its first key is trusted.
        let s = store
            .record_ssh_download_host_key(j.id, key("other:22", "SHA256:d"))
            .await
            .unwrap();
        assert_eq!(s.host_key.unwrap().fingerprint, "SHA256:d");
    }
}
