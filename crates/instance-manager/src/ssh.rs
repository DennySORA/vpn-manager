//! SSH Manager projection.
//!
//! It renders the stored SSH hosts into `vpn-manager.conf` and reports the
//! files as they are. Writes are serialized; a file changed by someone else since our last write
//! is never overwritten unless the user asks (after a backup).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio::sync::Mutex;
use vpn_domain::{
    ApiError, ErrorCode, GatewayId, GatewaySpec, SshFileState, SshHost, SshIncludeState, SshStatus,
    Text, tr,
};
use vpn_ssh::config::{self, UserConfig};
use vpn_ssh::files::{Found, SshDir};
use vpn_ssh::render::{self, Entry, Routing};
use vpn_store::{Store, StoreError};

/// The current text of a hand-modified file is shown up to this size.
const SHOW_MAX: usize = 64 * 1024;

pub struct SshProjector {
    dir: SshDir,
    display: String,
    /// How `~/.ssh/config` names our file in its `Include`.
    include_target: String,
    routing: Result<Routing, Text>,
    /// SHA-256 of what we last wrote (in the manager's private state directory).
    digest_file: PathBuf,
    state: Mutex<Option<Text>>,
}

fn path_safe(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '@' | '~'))
}

/// `~/.ssh/config` as the SSH Manager sees it.
pub struct UserView {
    pub config: UserConfig,
    pub include: SshIncludeState,
    pub linked: bool,
    pub problem: Option<Text>,
}

impl SshProjector {
    /// `dir`: the SSH directory; `home`: the user's home (for `~` display); `vpnctl`: the proxy
    /// binary written into `ProxyCommand`; `key_file`: the Gateway key it proves Gateways with.
    #[must_use]
    pub fn new(
        dir: PathBuf,
        home: Option<&Path>,
        vpnctl: &Path,
        key_file: &Path,
        state_dir: &Path,
    ) -> Self {
        let tilde = home
            .and_then(|h| dir.strip_prefix(h).ok())
            .map(|rest| format!("~/{}", rest.display()));
        let display = tilde.unwrap_or_else(|| dir.display().to_string());
        let include_target = format!("{display}/{}", vpn_ssh::MANAGED_FILE);
        let routing = Routing::new(vpnctl, key_file, &display, &dir);
        Self {
            dir: SshDir::new(dir),
            display,
            include_target,
            routing,
            digest_file: state_dir.join("ssh-projection.sha256"),
            state: Mutex::new(None),
        }
    }

    pub fn include_line(&self) -> String {
        format!("Include {}", self.include_target)
    }

    /// The SSH directory written to (where a crashed write could leave a temporary file).
    pub fn ssh_dir(&self) -> &Path {
        self.dir.path()
    }

    fn is_ours(&self, arg: &str) -> bool {
        arg == self.include_target
            || Path::new(arg) == self.dir.managed_path()
            || arg == vpn_ssh::MANAGED_FILE
    }

    fn unavailable(&self) -> Option<Text> {
        if let Err(e) = &self.routing {
            return Some(e.clone());
        }
        if !path_safe(&self.include_target) {
            let path = &self.display;
            return Some(tr!(
                "The SSH directory path holds characters an Include line cannot carry safely: {path}",
                "SSH 目錄路徑含有 Include 無法安全表示的字元：{path}",
                "SSH ディレクトリのパスに、Include で安全に表せない文字が含まれています：{path}"
            ));
        }
        None
    }

    fn last_digest(&self) -> Option<String> {
        std::fs::read_to_string(&self.digest_file)
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn save_digest(&self, text: &str) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let r = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.digest_file)
            .and_then(|mut f| f.write_all(render::digest(text).as_bytes()));
        if let Err(e) = r {
            tracing::warn!(error = %e, "could not record the SSH projection digest");
        }
    }

    /// The user's config as far as SSH Manager reads it (through a dotfiles symlink too).
    pub fn user_config(&self) -> UserView {
        let none = || config::parse("", |_| false);
        let linked = std::fs::symlink_metadata(self.dir.config_path())
            .is_ok_and(|m| m.file_type().is_symlink());
        let (config, include, problem) = match self.dir.read_through_link("config") {
            Found::Absent => (none(), SshIncludeState::NoConfig, None),
            Found::Text(t) | Found::Linked(t) => {
                let c = config::parse(&t, |a| self.is_ours(a));
                let include = c.include;
                (c, include, None)
            }
            Found::Unsafe(why) => (none(), SshIncludeState::Unsafe, Some(why)),
            Found::Symlink => (
                none(),
                SshIncludeState::Unsafe,
                Some(tr!(
                    "a symbolic link that cannot be read",
                    "是無法讀取的符號連結",
                    "読み取れないシンボリックリンクです"
                )),
            ),
        };
        UserView {
            config,
            include,
            linked,
            problem,
        }
    }

    async fn hosts(&self, store: &Store) -> Result<Vec<SshHost>, Text> {
        store
            .list()
            .await
            .map_err(|e: StoreError| e.to_api().message)
    }

    async fn generated(&self, store: &Store) -> Result<String, Text> {
        let hosts = self.hosts(store).await?;
        let gateways: Vec<GatewaySpec> = store
            .list()
            .await
            .map_err(|e: StoreError| e.to_api().message)?;
        let ports: HashMap<GatewayId, u16> = gateways.iter().map(|g| (g.id, g.port)).collect();
        let user = self.user_config().config;
        let entries: Vec<Entry<'_>> = hosts
            .iter()
            .map(|h| {
                let port = h.gateway_id.and_then(|g| ports.get(&g).copied());
                Entry::new(h, port, user.host(&h.alias))
            })
            .collect();
        render::render(&entries, self.routing.as_ref().ok())
    }

    pub async fn status(&self, store: &Store) -> SshStatus {
        let last_error = self.state.lock().await.clone();
        let user = self.user_config();
        let generated = self.generated(store).await;
        let unavailable = self
            .unavailable()
            .or_else(|| generated.as_ref().err().cloned());
        let preview = generated.clone().unwrap_or_default();
        let has_hosts = self.hosts(store).await.is_ok_and(|h| !h.is_empty());
        let (file, current_text, pending) = match self.dir.read(vpn_ssh::MANAGED_FILE) {
            Found::Absent => (SshFileState::Absent, None, has_hosts),
            Found::Symlink | Found::Linked(_) | Found::Unsafe(_) => {
                (SshFileState::Unsafe, None, true)
            }
            Found::Text(t) => {
                let ours =
                    self.last_digest().is_some_and(|d| d == render::digest(&t)) || t == preview;
                if ours {
                    (SshFileState::Ok, None, t != preview)
                } else {
                    let shown: String = t.chars().take(SHOW_MAX).collect();
                    (SshFileState::Modified, Some(shown), true)
                }
            }
        };
        SshStatus {
            available: unavailable.is_none(),
            unavailable_reason: unavailable,
            ssh_dir: self.display.clone(),
            managed_path: self.include_target.clone(),
            include_line: self.include_line(),
            include: user.include,
            config_linked: user.linked,
            config_problem: user.problem,
            file,
            pending,
            existing: user.config.hosts,
            preview,
            proxy_command: self
                .routing
                .as_ref()
                .ok()
                .map(|r| r.proxy_command("{port}")),
            control_path: self.routing.as_ref().ok().map(|r| r.control_path("{port}")),
            current_text,
            last_error,
        }
    }

    /// Write the generated file unless it was changed by someone else.
    ///
    /// # Errors
    ///
    /// Why it was not written: the projection is unavailable, the Store cannot be read, the SSH
    /// directory is unsafe, the file was modified by hand, is a link or is unsafe, or the write
    /// failed.
    pub async fn apply(&self, store: &Store) -> Result<(), Text> {
        let mut state = self.state.lock().await;
        let r = self.apply_locked(store).await;
        *state = r.as_ref().err().cloned();
        r
    }

    async fn apply_locked(&self, store: &Store) -> Result<(), Text> {
        if let Some(why) = self.unavailable() {
            return Err(why);
        }
        let text = self.generated(store).await?;
        let found = self.dir.read(vpn_ssh::MANAGED_FILE);
        // Nothing to project and nothing projected yet: leave the user's SSH directory alone.
        if found == Found::Absent && self.hosts(store).await?.is_empty() {
            return Ok(());
        }
        self.dir.check(true)?;
        match found {
            Found::Text(t) if t == text => {
                self.save_digest(&text);
                return Ok(());
            }
            Found::Text(t) if self.last_digest().is_none_or(|d| d != render::digest(&t)) => {
                return Err(tr!(
                    "vpn-manager.conf was changed by hand; writing is paused so your changes are not overwritten",
                    "vpn-manager.conf 已被手動修改，為避免覆蓋你的變更，暫停寫入",
                    "vpn-manager.conf は手動で変更されています。その変更を上書きしないよう、書き込みを一時停止しています"
                ));
            }
            Found::Symlink | Found::Linked(_) => {
                return Err(tr!(
                    "vpn-manager.conf is a symbolic link and is not written",
                    "vpn-manager.conf 是符號連結，不會寫入",
                    "vpn-manager.conf はシンボリックリンクのため、書き込みません"
                ));
            }
            Found::Unsafe(why) => {
                return Err(tr!(
                    "vpn-manager.conf: {why}; it is not written",
                    "vpn-manager.conf {why}，不會寫入",
                    "vpn-manager.conf：{why}。書き込みません";
                    why = why
                ));
            }
            Found::Absent | Found::Text(_) => {}
        }
        self.dir
            .write(vpn_ssh::MANAGED_FILE, &text, 0o600)
            .map_err(|e| {
                tr!(
                    "Cannot write vpn-manager.conf: {e}",
                    "無法寫入 vpn-manager.conf：{e}",
                    "vpn-manager.conf に書き込めません：{e}";
                    e = e.text()
                )
            })?;
        self.save_digest(&text);
        Ok(())
    }

    /// Put the `Include` line first in `~/.ssh/config` (and make sure the file it loads exists).
    /// Returns the backup of the old config, if one was made.
    ///
    /// # Errors
    ///
    /// `InvalidState` when the projection is unavailable, the SSH directory is unsafe or the
    /// `Include` line cannot be added.
    pub async fn include(&self, store: &Store) -> Result<Option<String>, ApiError> {
        let backup = {
            let _state = self.state.lock().await;
            if let Some(why) = self.unavailable() {
                return Err(ApiError::new(ErrorCode::InvalidState, why));
            }
            self.dir
                .check(true)
                .map_err(|e| ApiError::new(ErrorCode::InvalidState, e))?;
            if self.user_config().include == SshIncludeState::Present {
                None
            } else {
                self.dir
                    .add_include(&self.include_line())
                    .map_err(|e| ApiError::new(ErrorCode::InvalidState, e))?
            }
        };
        // A missing vpn-manager.conf is created; a modified one is left alone (reported).
        let _ = self.apply(store).await;
        Ok(backup)
    }

    /// Replace a hand-modified file with the generated one, keeping the old text as a backup.
    ///
    /// # Errors
    ///
    /// `InvalidState` when the backup cannot be written or the generated file is not written.
    pub async fn overwrite(&self, store: &Store) -> Result<Option<String>, ApiError> {
        let backup = {
            let _state = self.state.lock().await;
            match self.dir.read(vpn_ssh::MANAGED_FILE) {
                Found::Text(t) => {
                    let name = self
                        .dir
                        .backup(&format!("{}.manual-backup", vpn_ssh::MANAGED_FILE), &t)
                        .map_err(|e| ApiError::new(ErrorCode::InvalidState, e))?;
                    // Recorded as ours, so the next apply replaces it.
                    self.save_digest(&t);
                    Some(name)
                }
                _ => None,
            }
        };
        self.apply(store)
            .await
            .map_err(|e| ApiError::new(ErrorCode::InvalidState, e))?;
        Ok(backup)
    }
}
