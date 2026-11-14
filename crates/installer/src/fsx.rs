//! File operations and checks the installer relies on: every program and service definition is
//! written under a hidden staged name and renamed into place, so nothing ever runs or loads a
//! half-written file; paths written into definitions are checked first.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Hidden name beside `dest` that no supervisor treats as a definition.
fn staged_name(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map_or_default(|n| n.to_string_lossy().into_owned());
    dest.with_file_name(format!(".{name}.staged-{}", std::process::id()))
}

/// Writes `bytes` to `dest` atomically with `mode` (a running program keeps its old file).
pub fn write_atomic(dest: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let staged = staged_name(dest);
    let _ = fs::remove_file(&staged);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // The creation mode is narrowed by the umask.
        fs::set_permissions(&staged, fs::Permissions::from_mode(mode))?;
        fs::rename(&staged, dest)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result?;
    if let Some(dir) = dest.parent().and_then(|d| fs::File::open(d).ok()) {
        // Best effort: the rename is atomic either way.
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn remove_dir_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Absolute, UTF-8, without control characters or `.`/`..` parts: written verbatim into service
/// definitions.
pub fn check_path(p: &Path) -> anyhow::Result<&str> {
    let s = p
        .to_str()
        .with_context(|| format!("路徑不是 UTF-8：{}", p.display()))?;
    // `Path::components` drops inner `.` parts, so the text is checked instead.
    if !p.is_absolute()
        || s.chars().any(char::is_control)
        || s.split('/').any(|part| part == "." || part == "..")
    {
        bail!("不支援的路徑（需要不含 . 或 .. 的絕對路徑）：{s}");
    }
    Ok(s)
}

/// A part of a service name: a lowercase letter, then letters or digits, single hyphens between
/// groups.
pub fn check_slug(s: &str, max: usize) -> anyhow::Result<()> {
    let ok = s.len() <= max
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!("「{s}」不是有效的名稱：小寫英文字母開頭，只用小寫英數與單一連字號，最多 {max} 字元");
    }
    Ok(())
}

/// Copies `name` and its SQLite companions (`-wal`, `-shm`) from `from` to `to`, removing a
/// companion at `to` that `from` does not have: a stray write-ahead log would otherwise be
/// replayed into the copied database.
pub fn copy_database(from: &Path, to: &Path, name: &str) -> io::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let file = format!("{name}{suffix}");
        let src = from.join(&file);
        let dst = to.join(&file);
        if src.exists() {
            fs::copy(&src, &dst)?;
        } else {
            remove_if_present(&dst)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_paths_follow_the_rules() {
        for good in ["main", "check", "r20261027-a1", "a"] {
            assert!(check_slug(good, 48).is_ok(), "{good}");
        }
        for bad in [
            "",
            "Main",
            "1st",
            "a--b",
            "a-",
            "a_b",
            "a.b",
            "a b",
            &"a".repeat(49),
        ] {
            assert!(check_slug(bad, 48).is_err(), "{bad:?}");
        }
        assert!(
            check_path(Path::new(
                "/Users/x/Library/Application Support/VPN Manager"
            ))
            .is_ok()
        );
        for bad in ["relative/dir", "/a/../b", "/a/./b", "/a/\nb"] {
            assert!(check_path(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    /// Restoring a database never keeps a write-ahead log the backup did not have.
    #[test]
    fn database_copies_carry_exactly_their_companions() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        fs::write(a.path().join("control.sqlite"), b"db").unwrap();
        fs::write(b.path().join("control.sqlite-wal"), b"newer log").unwrap();
        copy_database(a.path(), b.path(), "control.sqlite").unwrap();
        assert_eq!(fs::read(b.path().join("control.sqlite")).unwrap(), b"db");
        assert!(!b.path().join("control.sqlite-wal").exists());
    }
}
