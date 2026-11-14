//! Read-only probes of the files and sockets VPN Manager owns: sizes, ownership, and whether a
//! process listens on a Unix socket. Nothing here changes what it looks at.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use crate::process::current_uid;

/// How long a connection attempt to a local socket may take before it counts as "someone is
/// there but busy" (a full backlog).
const CONNECT_PROBE: Duration = Duration::from_millis(500);

/// Size of a regular file (no symlinks followed); None when it does not exist or is not one.
#[must_use]
pub fn file_size(path: &Path) -> Option<u64> {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|m| m.len())
}

/// What a path in one of our private directories is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// A regular file of this user.
    File,
    /// A Unix socket of this user.
    Socket,
    /// A directory of this user (not a symlink).
    Dir,
    /// Anything else: a symlink, another user's file, a device… never touched.
    Foreign,
}

#[must_use]
pub fn entry(path: &Path) -> Option<Entry> {
    let m = std::fs::symlink_metadata(path).ok()?;
    let t = m.file_type();
    Some(if m.uid() != current_uid() || t.is_symlink() {
        Entry::Foreign
    } else if t.is_file() {
        Entry::File
    } else if t.is_socket() {
        Entry::Socket
    } else if t.is_dir() {
        Entry::Dir
    } else {
        Entry::Foreign
    })
}

/// Seconds since `path` was last modified (no symlinks followed).
#[must_use]
pub fn age_secs(path: &Path) -> Option<u64> {
    let modified = std::fs::symlink_metadata(path).ok()?.modified().ok()?;
    std::time::SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|d| d.as_secs())
}

/// Refused connection attempts before a socket counts as one nobody listens on, and the pause
/// between them.
const REFUSED_ATTEMPTS: u32 = 3;
const REFUSED_PAUSE: Duration = Duration::from_millis(50);

/// Whether some process accepts connections on the Unix socket at `path`.
///
/// `Some(true)` it answered (or is too busy to, which also means it is there), `Some(false)` nobody
/// listens (refused every time, or no such file), `None` it could not be told.
///
/// macOS refuses a connection to a socket whose accept queue is full exactly as it refuses one
/// nobody holds, so a refusal is only believed when it repeats: a busy listener drains its queue
/// between attempts. A listener that never accepts still reads as gone here; callers that know
/// the socket's owner (a leftover worker) must not rely on this alone.
pub async fn unix_socket_listening(path: &Path) -> Option<bool> {
    for attempt in 1..=REFUSED_ATTEMPTS {
        match tokio::time::timeout(CONNECT_PROBE, tokio::net::UnixStream::connect(path)).await {
            Ok(Ok(_)) | Err(_) => return Some(true),
            Ok(Err(e)) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused if attempt < REFUSED_ATTEMPTS => {
                    tokio::time::sleep(REFUSED_PAUSE).await;
                }
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    return Some(false);
                }
                _ => return None,
            },
        }
    }
    Some(false)
}
