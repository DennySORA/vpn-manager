//! What the control database deletes does not linger in it.
//!
//! Some rows hold what the user may want gone for good — an SSH download's log and history name
//! remote files. The writer overwrites deleted content with zeros (`secure_delete`), so a deleted
//! row leaves nothing in the database's free pages or in the free space of its pages; once the
//! WAL is checkpointed and truncated, no earlier image of a page (with the row still in it) is
//! left in the WAL either. A database written before deletions were overwritten is rebuilt once
//! (`VACUUM`), which drops whatever earlier deletions left behind.
//!
//! The volume's own blocks are another matter: a file system may keep what a file once held
//! (journaling, copy-on-write, flash wear levelling) — only full-disk encryption covers that.

use rusqlite::{Connection, OptionalExtension, params};

/// Set once the database was rebuilt with deletions overwritten (`meta`).
const SCRUBBED: &str = "secure_delete_since";

/// How often a checkpoint that readers hold up is tried again, and how long it waits between.
const TRUNCATE_TRIES: u32 = 20;
const TRUNCATE_PAUSE: std::time::Duration = std::time::Duration::from_millis(50);

/// Overwrite deleted content on `c` (the writer: the setting is the connection's).
pub fn overwrite_deleted(c: &Connection) -> rusqlite::Result<()> {
    c.pragma_update(None, "secure_delete", "ON")
}

/// Rebuild the database once, so what deletions before [`overwrite_deleted`] left in free pages
/// is gone too. Best effort: a database that cannot be rebuilt now (no room for the rebuild) is
/// rebuilt at the next start.
pub fn rebuild_once(c: &Connection) {
    let done: Option<String> = c
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![SCRUBBED],
            |r| r.get(0),
        )
        .optional()
        .unwrap_or(None);
    if done.is_some() {
        return;
    }
    let started = std::time::Instant::now();
    match c.execute_batch("VACUUM") {
        Ok(()) => {
            truncate_wal(c);
            let at = vpn_domain::Timestamp::now().to_string();
            if let Err(e) = c.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![SCRUBBED, at],
            ) {
                tracing::warn!(error = %e, "control database rebuilt, but not marked so");
            }
            tracing::info!(
                ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "control database rebuilt once: earlier deletions leave nothing behind"
            );
        }
        Err(e) => tracing::warn!(
            error = %e,
            "control database not rebuilt (tried again at the next start); deletions from now on are overwritten"
        ),
    }
}

/// Checkpoint the whole WAL into the database and cut the WAL to nothing, so no earlier image of
/// a page is left in it; tried again while a reader holds an older snapshot. `true` when done.
pub fn truncate_wal(c: &Connection) -> bool {
    for _ in 0..TRUNCATE_TRIES {
        // (busy, frames in the log, frames checkpointed); busy is 0 once it is done.
        match c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        }) {
            Ok(0) => return true,
            Ok(_) => std::thread::sleep(TRUNCATE_PAUSE),
            Err(e) => {
                tracing::warn!(error = %e, "WAL checkpoint failed");
                return false;
            }
        }
    }
    tracing::warn!("WAL not truncated: readers held it up; tried again later");
    false
}
