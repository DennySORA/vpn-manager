//! An upgrade's backup keeps no SSH download log or history: its copy of the control database
//! loses every SSH download job's log lines and finished records — they name remote files, which
//! the user may have cleared since or keep out of the log on purpose — and is rebuilt, so nothing
//! of them stays in its free pages or its WAL. Unfinished records stay: after a rollback their
//! files resume from them.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

/// The control database's file name in the backup.
const CONTROL: &str = "control.sqlite";

/// Scrub the copy of the control database in `dir`. `Ok(false)`: there is nothing to scrub (no
/// copy, or a database from before SSH download).
pub fn backup(dir: &Path) -> rusqlite::Result<bool> {
    let path = dir.join(CONTROL);
    if !path.exists() {
        return Ok(false);
    }
    let c = Connection::open(&path)?;
    c.busy_timeout(Duration::from_secs(5))?;
    c.pragma_update(None, "secure_delete", "ON")?;
    let tables: Option<String> = c
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ssh_download_log'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if tables.is_none() {
        return Ok(false);
    }
    c.execute_batch(
        "BEGIN IMMEDIATE;
         DELETE FROM ssh_download_log;
         DELETE FROM ssh_download_transfers WHERE finished_ms IS NOT NULL;
         COMMIT;
         VACUUM;",
    )?;
    // The WAL goes too (the copy is closed right after: its last connection removes it).
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_keeps_unfinished_records_and_nothing_of_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONTROL);
        {
            let c = Connection::open(&path).unwrap();
            c.pragma_update(None, "journal_mode", "WAL").unwrap();
            c.execute_batch(
                "CREATE TABLE ssh_download_log (seq INTEGER PRIMARY KEY, job_id TEXT, message TEXT, file TEXT);
                 CREATE TABLE ssh_download_transfers (id TEXT PRIMARY KEY, job_id TEXT, name TEXT, finished_ms INTEGER);
                 INSERT INTO ssh_download_log (job_id, message, file) VALUES ('j', 'done', 'cleared-name-1.bin');
                 INSERT INTO ssh_download_transfers VALUES ('a', 'j', 'cleared-name-2.bin', 5);
                 INSERT INTO ssh_download_transfers VALUES ('b', 'j', 'resumes-later.bin', NULL);",
            )
            .unwrap();
        }
        assert!(backup(dir.path()).unwrap());
        let c = Connection::open(&path).unwrap();
        let left: Vec<String> = c
            .prepare("SELECT name FROM ssh_download_transfers")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(left, ["resumes-later.bin"]);
        let lines: i64 = c
            .query_row("SELECT count(*) FROM ssh_download_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(lines, 0);
        drop(c);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend(std::fs::read(dir.path().join(format!("{CONTROL}-wal"))).unwrap_or_default());
        for gone in ["cleared-name-1.bin", "cleared-name-2.bin"] {
            assert!(
                !bytes.windows(gone.len()).any(|w| w == gone.as_bytes()),
                "{gone} is still in the backup"
            );
        }
        // A copy without the tables (or no copy at all) is left as it is.
        let empty = tempfile::tempdir().unwrap();
        assert!(!backup(empty.path()).unwrap());
    }
}
