//! Pending stops: evidence, outside SQLite, of a user's Stop or emergency stop whose latch is not
//! on disk (yet).
//!
//! The in-memory hold ([`crate::hold`]) closes an Instance at once, but it lives only as long as
//! this process. Should the manager die — or exit normally — before the stop latch reached the
//! Store (a failing disk, a stuck writer, a crash in between), its next start would read the old
//! `running` intent and connect again: the stop would be lost. So every stop that is not durable
//! is mirrored by one small file, `<state>/pending-stops/<instance id>` (mode 0600; written to a
//! temporary file that is flushed and renamed into place, then the directory is flushed), which
//! is removed only once the latch, or a later intent write, is on disk. The state directory is
//! the persistent one on both platforms (Linux's runtime directory would not survive a reboot).
//!
//! A manager start looks for this evidence before any actor runs: a marker; a temporary marker a
//! crash left behind (a marker was being written, so a stop had been asked for); or a stop the
//! Store recorded as an operation after the Instance's last intent write, whose effect that
//! intent does not show ([`Store::unconfirmed_stops`]). Such an Instance is not started from its
//! old intent: it is held closed as an unconfirmed stop, in `recovery_required`, until the user
//! decides. Its marker stays until that decision is on disk (one is written where the evidence
//! was only an operation record, which pruning would delete one day).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vpn_domain::{DesiredState, InstanceId, Timestamp};
use vpn_platform::probe::{self, Entry};
use vpn_store::{IntentRow, Store, StoreError};

use crate::hold::Hold;

/// Format of a marker file.
const FORMAT: u32 = 1;
/// Largest marker file read (one is about 200 bytes).
const MAX_BYTES: u64 = 4096;
/// The markers' directory, below the state directory.
pub const DIR: &str = "pending-stops";

/// What a marker file holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub format: u32,
    pub instance_id: InstanceId,
    /// The stop is, or includes, an emergency stop.
    pub emergency: bool,
    pub written_at: Timestamp,
    /// The manager process that wrote it.
    pub manager_pid: u32,
}

/// A stop asked for before this manager started that nothing on disk confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carried {
    /// An emergency stop was (or may have been) among it.
    pub emergency: bool,
}

/// The markers of one installation.
pub struct PendingStops {
    dir: PathBuf,
    /// Serialises writes and removals. Each one reads the hold while holding it, so whichever
    /// runs last leaves the file matching the hold's latest state.
    serial: vpn_sync::Mutex<()>,
}

impl PendingStops {
    pub fn new(state: &Path) -> Self {
        Self {
            dir: state.join(DIR),
            serial: vpn_sync::Mutex::new(()),
        }
    }

    fn path(&self, id: InstanceId) -> PathBuf {
        self.dir.join(id.to_string())
    }

    fn tmp(&self, id: InstanceId) -> PathBuf {
        self.dir.join(format!(".{id}.tmp"))
    }

    /// Make the marker of `id` match `hold`: present while the hold has a stop that is not on
    /// disk, absent otherwise. Blocking: it flushes to disk.
    pub fn sync(&self, id: InstanceId, hold: &Hold) -> std::io::Result<()> {
        let _serial = self.serial.lock();
        let s = hold.get();
        if !s.pending() {
            return self.remove_files(id);
        }
        if matches!(read_marker(&self.path(id), id), Some(Ok(m)) if m.emergency == s.emergency) {
            return Ok(());
        }
        self.write(&Marker {
            format: FORMAT,
            instance_id: id,
            emergency: s.emergency,
            written_at: Timestamp::now(),
            manager_pid: std::process::id(),
        })
    }

    /// The Instance is gone: so is its marker.
    pub fn forget(&self, id: InstanceId) -> std::io::Result<()> {
        let _serial = self.serial.lock();
        self.remove_files(id)
    }

    /// Whether a marker (or a half-written one) of `id` is on disk.
    #[cfg(test)]
    pub fn exists(&self, id: InstanceId) -> bool {
        probe::entry(&self.path(id)).is_some() || probe::entry(&self.tmp(id)).is_some()
    }

    fn write(&self, m: &Marker) -> std::io::Result<()> {
        vpn_platform::paths::ensure_private_dir(&self.dir)?;
        let text = serde_json::to_vec(m).map_err(std::io::Error::other)?;
        let tmp = self.tmp(m.instance_id);
        // A temporary file a failed write left: replaced by this write.
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        // Should writing fail half-way (a full disk), the temporary file stays: it still says a
        // stop was asked for, and a start reads it as such.
        f.write_all(&text)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, self.path(m.instance_id))?;
        sync_dir(&self.dir)
    }

    fn remove_files(&self, id: InstanceId) -> std::io::Result<()> {
        let mut removed = false;
        for path in [self.path(id), self.tmp(id)] {
            match fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if removed {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// Every marker on disk, half-written ones included: by Instance, the kind of stop each
    /// says (`None`: it cannot be read, so its kind is unknown). Entries that are not ours (a
    /// symlink, another user's file) are left alone.
    pub fn scan(&self) -> std::io::Result<Vec<(InstanceId, Option<bool>)>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(it) => it,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let base = name
                .strip_prefix('.')
                .and_then(|n| n.strip_suffix(".tmp"))
                .unwrap_or(name);
            let Ok(id) = base.parse::<InstanceId>() else {
                tracing::warn!(file = name, "not a pending-stop marker; left alone");
                continue;
            };
            let path = entry.path();
            if probe::entry(&path) != Some(Entry::File) {
                tracing::warn!(
                    file = name,
                    "pending-stop marker is not a file of this user; left alone"
                );
                continue;
            }
            let kind = match read_marker(&path, id) {
                Some(Ok(m)) => Some(m.emergency),
                Some(Err(e)) => {
                    tracing::warn!(instance = %id, file = name, error = %e, "pending-stop marker unreadable: taken as an emergency stop");
                    None
                }
                None => continue,
            };
            out.push((id, kind));
        }
        Ok(out)
    }
}

/// The marker at `path` (None: there is none). Why it cannot be read is logged, in English.
fn read_marker(path: &Path, id: InstanceId) -> Option<Result<Marker, String>> {
    match probe::entry(path)? {
        Entry::File => {}
        _ => return Some(Err("not a regular file of this user".into())),
    }
    let read = || -> Result<Marker, String> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        let mut text = Vec::new();
        f.take(MAX_BYTES)
            .read_to_end(&mut text)
            .map_err(|e| e.to_string())?;
        let m: Marker = serde_json::from_slice(&text).map_err(|e| e.to_string())?;
        if m.format != FORMAT {
            return Err(format!("unsupported format {}", m.format));
        }
        if m.instance_id != id {
            return Err("the file name and the content name different connections".into());
        }
        Ok(m)
    };
    Some(read())
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Mirror `hold` in the marker of `id`, off the async threads. False when the file could not be
/// brought up to date (logged).
pub async fn mirror(stops: Arc<PendingStops>, id: InstanceId, hold: Arc<Hold>) -> bool {
    match tokio::task::spawn_blocking(move || stops.sync(id, &hold)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::error!(instance = %id, error = %e, "pending-stop marker not brought up to date");
            false
        }
        Err(_) => false,
    }
}

/// Whether the stored intent already shows a stop (an emergency stop with `emergency`).
fn shows(row: &IntentRow, emergency: bool) -> bool {
    row.desired == DesiredState::Stopped && row.manual_stop && (row.emergency_latched || !emergency)
}

/// The stops a manager start must not override with the stored intents (see the module
/// documentation), by Instance. Markers the intent shows (their latch did reach the disk) and
/// markers of Instances that are gone are removed here. Run before any actor exists.
pub async fn carried_over(
    store: &Store,
    stops: &Arc<PendingStops>,
) -> Result<HashMap<InstanceId, Carried>, StoreError> {
    let intents: HashMap<InstanceId, IntentRow> = store
        .intents()
        .await?
        .into_iter()
        .map(|r| (r.instance_id, r))
        .collect();
    let scanned = {
        let stops = stops.clone();
        tokio::task::spawn_blocking(move || stops.scan())
            .await
            .map_err(|e| StoreError::Io(e.to_string()))?
            .map_err(|e| StoreError::Io(format!("reading the stop records ({DIR}) failed: {e}")))?
    };
    let mut out: HashMap<InstanceId, Carried> = HashMap::new();
    for (id, kind) in scanned {
        // A marker that cannot be read may stand for an emergency stop.
        let emergency = kind.unwrap_or(true);
        let shown = intents.get(&id).map(|row| shows(row, emergency));
        if shown != Some(false) {
            // The Instance is gone, or its latch did reach the disk.
            let stops = stops.clone();
            if matches!(
                tokio::task::spawn_blocking(move || stops.forget(id)).await,
                Ok(Ok(()))
            ) {
            } else {
                tracing::warn!(instance = %id, "pending-stop marker not removed");
            }
            continue;
        }
        out.entry(id)
            .or_insert(Carried { emergency: false })
            .emergency |= emergency;
    }
    for s in store.unconfirmed_stops().await? {
        tracing::warn!(instance = %s.instance_id, operation = %s.operation_id, requested_at = %s.requested_at, emergency = s.emergency, "a stop recorded before this start is not shown by the stored intent");
        out.entry(s.instance_id)
            .or_insert(Carried { emergency: false })
            .emergency |= s.emergency;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_mirrors_the_hold_and_survives_only_while_the_stop_is_not_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let stops = PendingStops::new(dir.path());
        let id = InstanceId::new();
        let hold = Hold::default();
        // Nothing held: nothing written (not even the directory).
        stops.sync(id, &hold).unwrap();
        assert!(!dir.path().join(DIR).exists());

        let epoch = hold.stop(false);
        stops.sync(id, &hold).unwrap();
        let path = stops.path(id);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(stops.scan().unwrap(), [(id, Some(false))]);
        // An emergency on top: the marker says so.
        hold.stop(true);
        stops.sync(id, &hold).unwrap();
        assert_eq!(stops.scan().unwrap(), [(id, Some(true))]);
        // The first latch is overtaken by the second stop: still pending.
        hold.latched(epoch);
        stops.sync(id, &hold).unwrap();
        assert!(stops.exists(id));
        hold.latched(hold.get().epoch);
        stops.sync(id, &hold).unwrap();
        assert!(!stops.exists(id));
        assert_eq!(stops.scan().unwrap(), []);
    }

    #[test]
    fn half_written_and_unreadable_markers_count_as_emergency_stops() {
        let dir = tempfile::tempdir().unwrap();
        let stops = PendingStops::new(dir.path());
        vpn_platform::paths::ensure_private_dir(&dir.path().join(DIR)).unwrap();
        let (torn, garbage, moved, other) = (
            InstanceId::new(),
            InstanceId::new(),
            InstanceId::new(),
            InstanceId::new(),
        );
        std::fs::write(stops.tmp(torn), b"{\"format\":1,\"instance_").unwrap();
        std::fs::write(stops.path(garbage), b"\x00\x01").unwrap();
        // A marker whose content names another Instance than its file name: not trusted.
        let hold = Hold::default();
        hold.stop(false);
        stops.sync(other, &hold).unwrap();
        std::fs::rename(stops.path(other), stops.path(moved)).unwrap();
        // Not a marker at all.
        std::fs::write(dir.path().join(DIR).join("notes.txt"), b"x").unwrap();
        let mut found = stops.scan().unwrap();
        found.sort();
        let mut want = vec![(torn, None), (garbage, None), (moved, None)];
        want.sort();
        assert_eq!(found, want);
        // Forgetting removes the half-written file too.
        stops.forget(torn).unwrap();
        assert!(!stops.exists(torn));
    }
}
