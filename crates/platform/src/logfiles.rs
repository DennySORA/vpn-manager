//! Log files VPN Manager writes itself: the daemon's `--log-file`, each managed App's output.
//!
//! Each is kept below a size limit with one previous file, `<file>.1`, and on a full disk
//! shortened from its oldest lines so that new ones still fit.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// What a log keeps of its current file when the disk is full and its previous file is already
/// empty: its newest lines, about this many bytes.
pub const KEEP_WHEN_FULL: u64 = 64 * 1024;

/// `<file>.1`: the previous file of a log.
#[must_use]
pub fn backup(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// The write failed because the volume (or the user's disk quota) is full.
#[must_use]
pub fn is_full(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT))
}

fn open(path: &Path) -> io::Result<File> {
    // Append: a line another process writes meanwhile lands after what is kept, never under it.
    OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Empty a log file in place. Its blocks are freed at once, also while a process (a worker that
/// inherited it before a rotation) still writes to it.
///
/// # Errors
///
/// Fails when the file cannot be opened (including a symlink) or truncated.
pub fn empty(path: &Path) -> io::Result<()> {
    open(path)?.set_len(0)
}

/// The disk is full: make room for the new lines of the log at `path`. True when anything was
/// freed.
///
/// Its oldest lines go: the previous file first, then all of the current one but its newest
/// [`KEEP_WHEN_FULL`] bytes (from the start of a line).
#[must_use]
pub fn drop_oldest(path: &Path) -> bool {
    let previous = backup(path);
    if fs::symlink_metadata(&previous).is_ok_and(|m| m.is_file() && m.len() > 0)
        && empty(&previous).is_ok()
    {
        return true;
    }
    keep_newest(path, KEEP_WHEN_FULL).unwrap_or(false)
}

/// Cut the file at `path` down to (about) its last `keep` bytes, starting at a line. True when it
/// was longer.
fn keep_newest(path: &Path, keep: u64) -> io::Result<bool> {
    let mut f = open(path)?;
    let len = f.metadata()?.len();
    if len <= keep {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(len - keep))?;
    // At most `keep` bytes; only a capacity hint.
    let mut tail = Vec::with_capacity(usize::try_from(keep).unwrap_or(0));
    f.read_to_end(&mut tail)?;
    // The first bytes belong to a line cut in two: they go with the older lines.
    let start = tail
        .iter()
        .position(|&b| b == b'\n')
        .map_or(tail.len(), |i| i + 1);
    f.set_len(0)?;
    f.write_all(tail.get(start..).unwrap_or_default())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Room made on a full disk takes only the log's own oldest lines: its regular previous file,
    /// then the older part of the current one — never a file a link points to.
    #[test]
    fn a_full_disk_drops_only_the_logs_own_oldest_lines() {
        let line = |n: usize| format!("line {n:05} {}\n", "x".repeat(90));
        let current: String = (0..2_000).map(line).collect();
        // (previous file: none, a regular file, a link to another file)
        let cases = ["none", "file", "link"];
        for case in cases {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("manager.log");
            let other = dir.path().join("secret");
            fs::write(&log, &current).unwrap();
            fs::write(&other, "not a log").unwrap();
            match case {
                "file" => fs::write(backup(&log), "older lines\n").unwrap(),
                "link" => std::os::unix::fs::symlink(&other, backup(&log)).unwrap(),
                _ => {}
            }
            assert!(drop_oldest(&log), "{case}: room was made");
            assert_eq!(fs::read_to_string(&other).unwrap(), "not a log", "{case}");
            let kept = fs::read_to_string(&log).unwrap();
            if case == "file" {
                // The previous file goes first; the current one is left whole.
                assert_eq!(fs::metadata(backup(&log)).unwrap().len(), 0, "{case}");
                assert_eq!(kept, current, "{case}");
            } else {
                // Only the newest lines of the current file stay, from a line's start.
                assert!(
                    kept.len() as u64 <= KEEP_WHEN_FULL,
                    "{case}: {}",
                    kept.len()
                );
                assert!(kept.starts_with("line "), "{case}");
                assert!(current.ends_with(&kept), "{case}");
            }
        }
    }
}
