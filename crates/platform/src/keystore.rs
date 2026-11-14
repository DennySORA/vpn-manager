//! Keys VPN Manager keeps itself: 32-byte random key files in the private state directory, owned
//! by this user, mode 0600 inside the 0700 directory.
//!
//! Nothing is delegated to an OS keystore, so the vault master key (`vault.key`) and the Gateway
//! installation key (`gateway.key`) stay with the data they protect: backed up, moved and removed
//! together with it. Whoever can read this user's files can read the keys; the store refuses a key
//! that does not match it.
#![allow(
    unsafe_code,
    reason = "the key file store compares file ownership against getuid(2)"
)]

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use rand::TryRng;
use zeroize::Zeroizing;

/// Read a 32-byte key file, creating it (0600, random) when missing. Refuses a file that is not
/// this user's, that others can read, or that has the wrong length.
///
/// # Errors
///
/// Fails when the file cannot be created, written or read, when the random source fails, or when
/// an existing file is not this user's, is readable by others, is a symlink or is not 32 bytes.
pub fn load_or_create_key_file(path: &Path) -> std::io::Result<Zeroizing<[u8; 32]>> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(mut f) => {
            let mut key = Zeroizing::new([0u8; 32]);
            rand::rngs::SysRng
                .try_fill_bytes(key.as_mut())
                .map_err(std::io::Error::other)?;
            f.write_all(key.as_ref())?;
            f.sync_all()?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read_key_file(path).map_err(|e| match e {
                KeyFileError::Io(e) => e,
                other => std::io::Error::other(other.to_string()),
            })
        }
        Err(e) => Err(e),
    }
}

/// Why an existing key file cannot be used. Its text is for logs (English); a report for people
/// tells the variants apart.
#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("the key file does not exist")]
    Missing,
    #[error("the owner, permissions or length of the key file are wrong")]
    Unsafe,
    #[error("cannot read the key file: {0}")]
    Io(std::io::Error),
}

/// Read an existing 32-byte key file without ever creating one; the same checks as
/// [`load_or_create_key_file`] (this user's, private, exactly 32 bytes, no symlink).
///
/// # Errors
///
/// [`KeyFileError::Missing`] when there is no file, [`KeyFileError::Unsafe`] when it is a
/// symlink, not this user's, readable by others or not 32 bytes, [`KeyFileError::Io`] when it
/// cannot be read.
pub fn read_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => KeyFileError::Missing,
            // O_NOFOLLOW on a symlink.
            _ if e.raw_os_error() == Some(libc::ELOOP) => KeyFileError::Unsafe,
            _ => KeyFileError::Io(e),
        })?;
    let m = f.metadata().map_err(KeyFileError::Io)?;
    // SAFETY: getuid has no preconditions.
    if !m.is_file()
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || m.len() != 32
    {
        return Err(KeyFileError::Unsafe);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    f.read_exact(key.as_mut()).map_err(KeyFileError::Io)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn key_file_is_created_once_and_must_stay_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        let a = load_or_create_key_file(&path).unwrap();
        let b = load_or_create_key_file(&path).unwrap();
        assert_eq!(*a, *b);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_create_key_file(&path).is_err());
    }

    #[test]
    fn reading_never_creates_and_tells_the_problems_apart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        assert_matches!(read_key_file(&path), Err(KeyFileError::Missing));
        assert!(!path.exists(), "a read never creates the file");
        let created = load_or_create_key_file(&path).unwrap();
        assert_eq!(*read_key_file(&path).unwrap(), *created);
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_matches!(read_key_file(&link), Err(KeyFileError::Unsafe));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_matches!(read_key_file(&path), Err(KeyFileError::Unsafe));
    }
}
