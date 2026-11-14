//! The worker processes this manager started, in memory and on disk.
//!
//! In memory: every child not reaped yet (pid → Instance, generation, key lock, connector), from
//! right after the fork until after the reap. A recovery therefore never mistakes one of our own
//! workers — starting, running or stopping — for a leftover, and needs no answer from a busy
//! actor to know it.
//!
//! On disk (`<run>/workers/<instance>-<generation>.json`, 0600): the same plus the child's OS
//! identity (pid, user, start time, program), removed once it is reaped. After a manager crash
//! these files are what proves that a leftover process is ours; without one, nothing is ever
//! proven ours.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vpn_domain::{InstanceId, Text, Timestamp, tr};
use vpn_platform::process::ProcessIdentity;
use vpn_sync::Mutex;

/// Most record files looked at.
const RECORDS_MAX: usize = 4096;
const RECORD_FORMAT: u32 = 1;
const RECORD_MAX_BYTES: u64 = 16 * 1024;

/// One of our workers that has not been reaped yet.
#[derive(Debug, Clone)]
pub struct LiveWorker {
    pub instance_id: InstanceId,
    pub generation: u64,
    pub key_lock: String,
    pub connector: Option<String>,
    pub process_started_at_ms: Option<i64>,
}

/// What the manager writes down about a worker it started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRecord {
    pub format: u32,
    pub instance_id: InstanceId,
    pub generation: u64,
    pub pid: u32,
    pub uid: u32,
    /// OS start token (see [`ProcessIdentity::start`]).
    pub start: String,
    pub started_at_ms: Option<i64>,
    pub exe: Option<String>,
    pub key_lock: String,
    pub connector: Option<String>,
    pub manager_pid: u32,
    pub recorded_at: Timestamp,
}

impl WorkerRecord {
    /// The process this record describes.
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            uid: self.uid,
            start: self.start.clone(),
            started_at_ms: self.started_at_ms,
            exe: self.exe.as_ref().map(PathBuf::from),
            zombie: false,
        }
    }
}

/// A record file found on disk.
pub struct RecordFile {
    pub path: PathBuf,
    pub record: Result<WorkerRecord, Text>,
}

pub struct Inventory {
    dir: PathBuf,
    live: Mutex<HashMap<u32, LiveWorker>>,
}

impl Inventory {
    #[must_use]
    pub fn new(dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            dir,
            live: Mutex::new(HashMap::new()),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A worker was just forked: remember it, in memory first, then on disk. The returned
    /// ticket forgets it when dropped — after the child was reaped.
    pub fn spawned(
        self: &Arc<Self>,
        pid: u32,
        instance_id: InstanceId,
        generation: u64,
        key_lock: String,
        connector: Option<String>,
    ) -> WorkerTicket {
        let identity = vpn_platform::process::identity(pid);
        self.live.lock().insert(
            pid,
            LiveWorker {
                instance_id,
                generation,
                key_lock: key_lock.clone(),
                connector: connector.clone(),
                process_started_at_ms: identity.as_ref().and_then(|i| i.started_at_ms),
            },
        );
        let path = self.dir.join(format!("{instance_id}-{generation}.json"));
        let record = identity.map(|i| WorkerRecord {
            format: RECORD_FORMAT,
            instance_id,
            generation,
            pid,
            uid: i.uid,
            start: i.start,
            started_at_ms: i.started_at_ms,
            exe: i.exe.map(|p| p.to_string_lossy().into_owned()),
            key_lock,
            connector,
            manager_pid: std::process::id(),
            recorded_at: Timestamp::now(),
        });
        if let Some(r) = record {
            if let Err(e) = self.write(&path, &r) {
                // The worker still runs; only a later recovery could not prove it ours.
                tracing::warn!(error = %e, pid, "worker record not written");
            }
        } else {
            tracing::warn!(pid, "worker identity unknown; no record written");
        }
        WorkerTicket {
            inventory: self.clone(),
            pid,
            path,
        }
    }

    fn write(&self, path: &Path, record: &WorkerRecord) -> std::io::Result<()> {
        vpn_platform::paths::ensure_private_dir(&self.dir)?;
        let tmp = self
            .dir
            .join(format!(".record.tmp-{}-{}", std::process::id(), record.pid));
        let _ = fs::remove_file(&tmp);
        let text = serde_json::to_vec(record).map_err(std::io::Error::other)?;
        let written = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)?;
            f.write_all(&text)?;
            f.sync_all()?;
            fs::rename(&tmp, path)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }

    /// Workers of this manager not reaped yet, by pid.
    pub fn live(&self) -> Vec<(u32, LiveWorker)> {
        self.live
            .lock()
            .iter()
            .map(|(pid, w)| (*pid, w.clone()))
            .collect()
    }

    /// Record files on disk (at most [`RECORDS_MAX`]): ours of live workers, and leftovers.
    /// Every record file; an error when the directory cannot be read (a missing one has none).
    ///
    /// # Errors
    ///
    /// The OS error when the records directory exists but cannot be read.
    pub fn records(&self) -> std::io::Result<Vec<RecordFile>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        Ok(entries
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name().to_str().is_some_and(|n| {
                    // Not hidden: a `.json` extension is the same as ending in ".json".
                    !n.starts_with('.') && Path::new(n).extension().is_some_and(|x| x == "json")
                })
            })
            .take(RECORDS_MAX)
            .map(|e| {
                let path = e.path();
                let record = read_record(&path);
                RecordFile { path, record }
            })
            .collect())
    }
}

fn read_record(path: &Path) -> Result<WorkerRecord, Text> {
    if vpn_platform::probe::entry(path) != Some(vpn_platform::probe::Entry::File) {
        return Err(tr!(
            "not a regular file of this user",
            "不是這個使用者的一般檔案",
            "このユーザーの通常のファイルではありません"
        ));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Text::verbatim(e.to_string()))?;
    let mut text = String::new();
    f.take(RECORD_MAX_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| Text::verbatim(e.to_string()))?;
    let r: WorkerRecord = serde_json::from_str(&text).map_err(|e| Text::verbatim(e.to_string()))?;
    if r.format != RECORD_FORMAT {
        let format = r.format;
        return Err(tr!(
            "unsupported record format {format}",
            "不支援的紀錄格式 {format}",
            "未対応の記録形式 {format}"
        ));
    }
    Ok(r)
}

/// Keeps a worker in the inventory; dropping it (after the reap) forgets the worker.
pub struct WorkerTicket {
    inventory: Arc<Inventory>,
    pid: u32,
    path: PathBuf,
}

impl Drop for WorkerTicket {
    fn drop(&mut self) {
        self.inventory.live.lock().remove(&self.pid);
        let _ = fs::remove_file(&self.path);
    }
}
