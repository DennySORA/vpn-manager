//! `api.sock`: the same API as HTTP on 127.0.0.1, for non-browser clients (`vpnctl`).
//!
//! No Host, Origin or Fetch-Metadata checks apply there: the boundary is the socket itself — a
//! 0600 file in the 0700 runtime directory — and the peer's credentials, which must be this
//! user's. Body limits and idempotency rules are those of the shared router.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::net::{UnixListener, UnixStream};

/// A Unix listener that hands over only connections from processes of `uid`; any other peer is
/// closed before a byte is read.
#[derive(Debug)]
pub struct SameUserListener {
    inner: UnixListener,
    uid: u32,
}

impl SameUserListener {
    pub const fn new(inner: UnixListener, uid: u32) -> Self {
        Self { inner, uid }
    }
}

impl axum::serve::Listener for SameUserListener {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => match stream.peer_cred() {
                    Ok(c) if c.uid() == self.uid => return (stream, addr),
                    Ok(c) => {
                        tracing::warn!(
                            peer_uid = c.uid(),
                            "refused an API socket client of another user"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "refused an API socket client without credentials");
                    }
                },
                Err(e) => {
                    // Out of descriptors and the like: back off instead of spinning.
                    tracing::debug!(error = %e, "API socket accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// The bound API socket; [`ApiSocket::remove`] deletes the file only while it is still the one
/// we created.
#[derive(Debug)]
pub struct ApiSocket {
    pub listener: UnixListener,
    path: PathBuf,
    inode: (u64, u64),
}

impl ApiSocket {
    /// Bind `path` (mode 0600). A socket file of ours nobody answers on is a leftover of a
    /// controller that did not exit cleanly and is replaced; one a running controller answers on
    /// is never taken over; anything else (another user's file, a regular file, a symlink) is
    /// never removed.
    ///
    /// # Errors
    ///
    /// When `path` exists and is not a stale socket of ours (another file, another user's
    /// socket, a socket a controller answers on, or one whose state cannot be told), and when
    /// inspecting, removing, binding or restricting the socket file fails.
    pub async fn bind(path: &Path) -> anyhow::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("inspect {}", path.display())),
            Ok(m) => {
                let me = vpn_platform::process::current_uid();
                if !m.file_type().is_socket() || m.uid() != me {
                    bail!(
                        "{} exists and is not our API socket; not replacing it",
                        path.display()
                    );
                }
                match vpn_platform::probe::unix_socket_listening(path).await {
                    Some(false) => {
                        std::fs::remove_file(path)
                            .with_context(|| format!("remove stale {}", path.display()))?;
                        tracing::info!(path = %path.display(), "replaced a stale API socket");
                    }
                    Some(true) => bail!(
                        "another controller already serves {}; stop it first",
                        path.display()
                    ),
                    None => bail!("cannot tell whether {} is in use", path.display()),
                }
            }
        }
        let listener = UnixListener::bind(path).context("bind API socket")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let m = std::fs::symlink_metadata(path)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            inode: (m.dev(), m.ino()),
        })
    }

    /// Delete the socket file, unless another process has replaced it meanwhile. A replacement
    /// can get the freed inode number back (ext4 reuses one at once), so it also has to still be
    /// a socket: a file that is not one is never removed.
    pub fn remove(path: &Path, inode: (u64, u64)) {
        if std::fs::symlink_metadata(path)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == inode)
            && let Err(e) = std::fs::remove_file(path)
        {
            // Left behind, it is a stale socket of ours that the next start replaces.
            tracing::warn!(error = %e, path = %path.display(), "API socket file not removed");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn inode(&self) -> (u64, u64) {
        self.inode
    }
}
