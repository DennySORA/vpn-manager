//! Private state and runtime directories. Created with mode 0700; refused when they are symlinks,
//! owned by another user or writable by group/others.
#![allow(
    unsafe_code,
    reason = "path ownership checks compare against getuid(2)"
)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    /// Databases, key file (if any), lock files.
    pub state: PathBuf,
    /// Unix sockets (manager.sock, api.sock, per-instance connectors).
    pub run: PathBuf,
}

impl Paths {
    /// Platform defaults: macOS `~/Library/Application Support/VPN Manager`; Linux
    /// `$XDG_DATA_HOME/vpn-manager` (`~/.local/share/vpn-manager`) with sockets in
    /// `$XDG_RUNTIME_DIR/vpn-manager`. Everything VPN Manager keeps — data, keys, logs and the
    /// installed programs — is under this one directory.
    ///
    /// # Errors
    ///
    /// Fails when `HOME` is not set.
    pub fn default_for_user() -> std::io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other("HOME is not set"))?;
        #[cfg(target_os = "macos")]
        {
            let state = home.join("Library/Application Support/VPN Manager");
            Ok(Self {
                run: state.join("run"),
                state,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let state = std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .filter(|d| d.is_absolute())
                .unwrap_or_else(|| home.join(".local/share"))
                .join("vpn-manager");
            let run = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
                || state.join("run"),
                |d| PathBuf::from(d).join("vpn-manager"),
            );
            Ok(Self { state, run })
        }
    }

    #[must_use]
    pub fn under(root: &Path) -> Self {
        Self {
            state: root.to_path_buf(),
            run: root.join("run"),
        }
        .with_short_run_dir()
    }

    /// Unix socket paths are limited (104 bytes on macOS, 108 on Linux). When the run directory
    /// would make socket paths too long, use a private per-state directory under the user's
    /// temporary directory instead (macOS `$TMPDIR` is already a 0700 per-user directory).
    fn with_short_run_dir(mut self) -> Self {
        use std::hash::{Hash, Hasher};
        const LIMIT: usize = 100;
        let longest = self.run.join("instance-00000000.sock");
        if longest.as_os_str().len() <= LIMIT {
            return self;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.state.hash(&mut h);
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the directory name keeps the low 32 bits of the hash on purpose"
        )]
        let tag = h.finish() as u32;
        self.run = std::env::temp_dir().join(format!("vpnm-{uid}-{tag:08x}"));
        self
    }

    /// Create (if missing) and verify the private state, run and locks directories.
    ///
    /// # Errors
    ///
    /// Fails as [`ensure_private_dir`] does for the state, run or locks directory.
    pub fn ensure(&self) -> std::io::Result<()> {
        ensure_private_dir(&self.state)?;
        ensure_private_dir(&self.run)?;
        ensure_private_dir(&self.locks())?;
        Ok(())
    }

    #[must_use]
    pub fn manager_socket(&self) -> PathBuf {
        self.run.join("manager.sock")
    }

    #[must_use]
    pub fn api_socket(&self) -> PathBuf {
        self.run.join("api.sock")
    }

    #[must_use]
    pub fn locks(&self) -> PathBuf {
        self.state.join("locks")
    }

    /// Lock file guarding one `WireGuard` identity (hex fingerprint of the public key).
    #[must_use]
    pub fn key_lock(&self, fingerprint: &str) -> PathBuf {
        self.locks().join(format!("key-{fingerprint}.lock"))
    }

    /// Private management connector of one Instance generation (`short` = first 8 hex of its id).
    #[must_use]
    pub fn connector_socket(&self, short: &str, generation: u64) -> PathBuf {
        self.run.join(format!("c-{short}-{generation}.sock"))
    }

    /// Rendezvous socket of an Instance's strict sandbox (Linux). Short (`sb-` and the first 16
    /// hex digits of the Instance id) so it fits a socket address under any runtime directory
    /// this type accepts.
    pub fn sandbox_socket(&self, instance_id: &str) -> PathBuf {
        let short: String = instance_id
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(16)
            .collect();
        self.run.join(format!("sb-{short}.sock"))
    }

    /// Installation key with which Gateways prove themselves to `vpnctl` (0600).
    #[must_use]
    pub fn gateway_key(&self) -> PathBuf {
        self.state.join("gateway.key")
    }

    /// Master key of the secret vault (0600), kept by VPN Manager itself.
    #[must_use]
    pub fn vault_key(&self) -> PathBuf {
        self.state.join("vault.key")
    }

    /// Log files of the long-running roles (`--log-file`).
    #[must_use]
    pub fn logs(&self) -> PathBuf {
        self.state.join("logs")
    }

    #[must_use]
    pub fn manager_lock(&self) -> PathBuf {
        self.locks().join("manager.lock")
    }

    /// Records of the worker processes the manager started, kept until each is reaped (what
    /// proves a leftover worker is ours after a manager crash).
    #[must_use]
    pub fn worker_records(&self) -> PathBuf {
        self.run.join("workers")
    }

    /// Private directory of one managed App (`<state>/apps/<id>`, 0700).
    #[must_use]
    pub fn app_dir(&self, id: &str) -> PathBuf {
        self.state.join("apps").join(id)
    }

    /// The App's `HOME`.
    #[must_use]
    pub fn app_home(&self, id: &str) -> PathBuf {
        self.app_dir(id).join("home")
    }

    /// The App's `TMPDIR`: inside its directory when that path is short, otherwise a private
    /// directory in the system's temporary area. Programs create Unix sockets there (a
    /// browser's singleton socket, for one) and macOS limits a socket path to 104 bytes, which a
    /// path under `~/Library/Application Support/VPN Manager/apps/<id>/` already nearly fills.
    #[must_use]
    pub fn app_tmp(&self, id: &str) -> PathBuf {
        use std::hash::{Hash, Hasher};
        let inside = self.app_dir(id).join("tmp");
        if inside.as_os_str().len() <= 48 {
            return inside;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.state.hash(&mut h);
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let short: String = id.chars().filter(|c| *c != '-').take(8).collect();
        let base = if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the directory name keeps the low 24 bits of the hash on purpose"
        )]
        let tag = h.finish() as u32 & 0xff_ffff;
        PathBuf::from(base).join(format!("vpnm-{uid}-{tag:06x}-{short}"))
    }

    /// The App's own stdout/stderr log.
    #[must_use]
    pub fn app_log(&self, id: &str) -> PathBuf {
        self.logs().join("apps").join(format!("{id}.log"))
    }
}

/// Create (if missing) and verify a private directory.
///
/// # Errors
///
/// Fails when the path is a symlink or not a directory, is owned by another user, is open to group
/// or others, or cannot be created or inspected.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::other(format!(
                    "{} must be a real directory, not a symlink",
                    dir.display()
                )));
            }
            // SAFETY: getuid has no preconditions.
            let uid = unsafe { libc::getuid() };
            if meta.uid() != uid {
                return Err(std::io::Error::other(format!(
                    "{} is owned by another user",
                    dir.display()
                )));
            }
            if meta.mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        }
        Err(e) => Err(e),
    }
}
