//! File operations on the SSH directory.
//!
//! Only regular files owned by this user and not writable
//! by others are read or replaced. Symlinks are never written through or replaced (only
//! `~/.ssh/config` is read through one, for a dotfiles setup), and a file with other hard links
//! is never replaced (that would silently split it from its other names). Writes go to a fresh
//! temporary file (`O_EXCL|O_NOFOLLOW`, 0600), are written completely and fsynced, renamed over
//! the target, and the directory is fsynced: a write either lands whole or leaves the old file.
//! Backups are new files (`O_EXCL`) that never replace anything.

#![expect(
    unsafe_code,
    reason = "getuid for the ownership checks of the SSH directory and its files"
)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use vpn_domain::{Text, tr};

/// Largest file the SSH Manager reads (a larger "config" is not one we should touch).
const MAX_READ: u64 = 1024 * 1024;

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// UTC stamp used in backup file names, e.g. `20261026T142843Z`.
#[must_use]
pub fn backup_stamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .unwrap_or_else(|_| "backup".into())
}

/// A file as found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Absent,
    Text(String),
    /// Read through a symlink (its target passed the same checks); never written.
    Linked(String),
    Symlink,
    /// Present but not safe to use; the reason is user-facing, a phrase about the file that
    /// follows its name ("~/.ssh/config: …").
    Unsafe(Text),
}

/// Why [`SshDir::write`] replaced nothing. [`WriteError::text`] is the reason a person reads;
/// `Display` is its English.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The target is a symlink or not a regular file.
    NotRegular,
    /// The target is not this user's, or others may write it.
    Unsafe,
    /// The target has other hard links.
    HardLinks,
    /// Writing, syncing or renaming failed.
    Io(#[from] io::Error),
}

impl WriteError {
    /// The reason, in the three languages (the operating system's words as they are).
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::NotRegular => tr!(
                "The target is not a regular file (or is a symbolic link); it is not overwritten",
                "目標不是一般檔案（或是符號連結），不會覆寫",
                "対象が通常のファイルではない（またはシンボリックリンクである）ため、上書きしません"
            ),
            Self::Unsafe => tr!(
                "The target is not owned by the current user or is writable by others; it is not overwritten",
                "目標不屬於目前使用者或可被他人寫入，不會覆寫",
                "対象が現在のユーザーの所有ではないか、ほかのユーザーが書き込めるため、上書きしません"
            ),
            Self::HardLinks => tr!(
                "The target has other hard links, and replacing it would split it from its other names; it is not overwritten",
                "目標還有其他硬連結，取代會讓它與其他名稱分離，不會覆寫",
                "対象にはほかのハードリンクがあり、置き換えるとほかの名前から切り離されるため、上書きしません"
            ),
            Self::Io(e) => Text::verbatim(e.to_string()),
        }
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

/// Why a path may not be used, or `None`.
fn unsafe_reason(m: &fs::Metadata) -> Option<Text> {
    if m.uid() != uid() {
        Some(tr!(
            "not owned by the current user",
            "不屬於目前的使用者",
            "現在のユーザーの所有ではありません"
        ))
    } else if m.mode() & 0o022 != 0 {
        Some(tr!(
            "writable by other users",
            "可被其他使用者寫入",
            "ほかのユーザーが書き込めます"
        ))
    } else {
        None
    }
}

/// The SSH directory (normally `~/.ssh`).
#[derive(Debug, Clone)]
pub struct SshDir {
    path: PathBuf,
}

impl SshDir {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.path.join("config")
    }

    #[must_use]
    pub fn managed_path(&self) -> PathBuf {
        self.path.join(crate::MANAGED_FILE)
    }

    /// The directory itself: a real directory of this user, not writable by others. Created
    /// (0700) when missing.
    ///
    /// # Errors
    ///
    /// A user-facing reason when the directory is missing (and not `create`), cannot be created
    /// or read, is a symlink or not a directory, or is not this user's or writable by others.
    pub fn check(&self, create: bool) -> Result<(), Text> {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                fs::create_dir_all(&self.path).map_err(|e| {
                    tr!(
                        "Cannot create the SSH directory: {e}",
                        "無法建立 SSH 目錄：{e}",
                        "SSH ディレクトリを作成できません：{e}"
                    )
                })?;
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700)).map_err(
                    |e| {
                        tr!(
                            "Cannot set the permissions of the SSH directory: {e}",
                            "無法設定 SSH 目錄權限：{e}",
                            "SSH ディレクトリの権限を設定できません：{e}"
                        )
                    },
                )?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(tr!(
                "The SSH directory does not exist",
                "SSH 目錄不存在",
                "SSH ディレクトリがありません"
            )),
            Err(e) => Err(tr!(
                "Cannot read the SSH directory: {e}",
                "無法讀取 SSH 目錄：{e}",
                "SSH ディレクトリを読み取れません：{e}"
            )),
            Ok(m) if m.file_type().is_symlink() => Err(tr!(
                "The SSH directory is a symbolic link; for safety nothing is written to it",
                "SSH 目錄是符號連結，為安全起見不會寫入",
                "SSH ディレクトリがシンボリックリンクなので、安全のため書き込みません"
            )),
            Ok(m) if !m.is_dir() => Err(tr!(
                "The SSH directory is not a folder",
                "SSH 目錄不是資料夾",
                "SSH ディレクトリがフォルダーではありません"
            )),
            Ok(m) => unsafe_reason(&m).map_or(Ok(()), |why| {
                Err(tr!(
                    "For safety nothing is written to the SSH directory: {why}",
                    "SSH 目錄{why}，為安全起見不會寫入",
                    "安全のため SSH ディレクトリには書き込みません：{why}";
                    why = why
                ))
            }),
        }
    }

    /// Read a file of the directory without following symlinks.
    #[must_use]
    pub fn read(&self, name: &str) -> Found {
        read_regular(&self.path.join(name))
    }

    /// Like [`read`](Self::read), but a symlink (a config kept with the user's dotfiles) is
    /// followed for reading only: its target must be a regular file that passes the same checks.
    #[must_use]
    pub fn read_through_link(&self, name: &str) -> Found {
        match self.read(name) {
            Found::Symlink => match fs::canonicalize(self.path.join(name)) {
                Ok(target) => match read_regular(&target) {
                    Found::Text(t) => Found::Linked(t),
                    Found::Absent => Found::Unsafe(dangling()),
                    Found::Unsafe(why) => Found::Unsafe(tr!(
                        "{why} (the link's target)",
                        "連結的目標{why}",
                        "{why}（リンク先）";
                        why = why
                    )),
                    other => other,
                },
                Err(e) if e.kind() == io::ErrorKind::NotFound => Found::Unsafe(dangling()),
                Err(e) => Found::Unsafe(tr!(
                    "cannot resolve the symbolic link: {e}",
                    "無法解析符號連結：{e}",
                    "シンボリックリンクを解決できません：{e}"
                )),
            },
            other => other,
        }
    }

    /// Atomically replace (or create) `name` with `text`, keeping `mode`.
    ///
    /// # Errors
    ///
    /// Fails when the target is a symlink, not a regular file, not safe to replace (owner,
    /// permissions, other hard links), or when writing, syncing or renaming fails.
    pub fn write(&self, name: &str, text: &str, mode: u32) -> Result<(), WriteError> {
        let target = self.path.join(name);
        match fs::symlink_metadata(&target) {
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
                return Err(WriteError::NotRegular);
            }
            Ok(m) if unsafe_reason(&m).is_some() => return Err(WriteError::Unsafe),
            Ok(m) if m.nlink() > 1 => return Err(WriteError::HardLinks),
            _ => {}
        }
        let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let tmp = self
            .path
            .join(format!(".{name}.tmp-{}-{nanos}", std::process::id()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        let written = f.write_all(text.as_bytes()).and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written {
            discard(&tmp);
            return Err(e.into());
        }
        if let Err(e) = fs::rename(&tmp, &target) {
            discard(&tmp);
            return Err(e.into());
        }
        Ok(File::open(&self.path)?.sync_all()?)
    }

    /// Keep `text` as a new 0600 file `<prefix>-<UTC stamp>[-n]`; an existing file is never
    /// replaced. Returns the backup's file name.
    ///
    /// # Errors
    ///
    /// A user-facing reason when the backup cannot be created or written completely, or when
    /// no unused name is left.
    pub fn backup(&self, prefix: &str, text: &str) -> Result<String, Text> {
        let stamp = backup_stamp();
        for n in 1..=100 {
            let name = if n == 1 {
                format!("{prefix}-{stamp}")
            } else {
                format!("{prefix}-{stamp}-{n}")
            };
            let path = self.path.join(&name);
            let mut f = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(tr!(
                        "Cannot create the backup: {e}",
                        "無法建立備份：{e}",
                        "バックアップを作成できません：{e}"
                    ));
                }
            };
            if let Err(e) = f.write_all(text.as_bytes()).and_then(|()| f.sync_all()) {
                drop(f);
                discard(&path);
                return Err(tr!(
                    "Cannot write the whole backup: {e}",
                    "無法完整寫入備份：{e}",
                    "バックアップを最後まで書き込めません：{e}"
                ));
            }
            return Ok(name);
        }
        Err(tr!(
            "No unused backup file name is left",
            "無法取得未使用的備份檔名",
            "未使用のバックアップファイル名がありません"
        ))
    }

    /// Put `include_line` first in `config` (after a full 0600 backup of the old file). Returns
    /// the backup's file name, or `None` when there was no config before.
    ///
    /// # Errors
    ///
    /// A user-facing reason when the config is a symlink or not safe to change, or cannot be
    /// read, backed up or written.
    pub fn add_include(&self, include_line: &str) -> Result<Option<String>, Text> {
        const NOTE: &str =
            "# Added by VPN Manager: its SSH hosts take effect only while this line comes first.\n";
        match self.read("config") {
            Found::Absent => {
                self.write("config", &format!("{NOTE}{include_line}\n"), 0o600)
                    .map_err(|e| {
                        tr!(
                            "Cannot create ~/.ssh/config: {why}",
                            "無法建立 ~/.ssh/config：{why}",
                            "~/.ssh/config を作成できません：{why}";
                            why = e.text()
                        )
                    })?;
                Ok(None)
            }
            Found::Symlink | Found::Linked(_) => Err(tr!(
                "~/.ssh/config is a symbolic link and is not changed automatically; add the Include line at the very top of the file by hand",
                "~/.ssh/config 是符號連結，不會自動修改；請手動在檔案最前面加入 Include",
                "~/.ssh/config はシンボリックリンクなので自動では変更しません。ファイルの先頭に Include を手動で追加してください"
            )),
            Found::Unsafe(why) => Err(tr!(
                "~/.ssh/config is not changed automatically: {why}",
                "~/.ssh/config {why}，不會自動修改",
                "~/.ssh/config は自動では変更しません：{why}";
                why = why
            )),
            Found::Text(old) => {
                let mode =
                    fs::symlink_metadata(self.config_path()).map_or(0o600, |m| m.mode() & 0o777);
                let backup = self.backup("config.vpn-manager-backup", &old)?;
                self.write("config", &format!("{NOTE}{include_line}\n\n{old}"), mode)
                    .map_err(|e| {
                        tr!(
                            "Cannot update ~/.ssh/config (the original file is unchanged; the backup is {backup}): {why}",
                            "無法更新 ~/.ssh/config（原檔未變更，備份在 {backup}）：{why}",
                            "~/.ssh/config を更新できません（元のファイルは変更されていません。バックアップは {backup} です）：{why}";
                            why = e.text()
                        )
                    })?;
                Ok(Some(backup))
            }
        }
    }
}

/// Remove a file this module has just created (a temporary file or a backup) after writing it
/// failed. Best effort: the caller gets the error that stopped the write, and a file left behind
/// has a name of its own and replaces nothing.
fn discard(path: &Path) {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "best effort: the caller already gets the error that stopped the write"
    )]
    let _ = fs::remove_file(path);
}

/// A symlink whose target does not exist, as [`Found::Unsafe`] names it.
fn dangling() -> Text {
    tr!(
        "a symbolic link to a file that does not exist",
        "是指向不存在檔案的符號連結",
        "存在しないファイルを指すシンボリックリンクです"
    )
}

/// A file that cannot be read, as [`Found::Unsafe`] names it.
fn unreadable(e: &io::Error) -> Text {
    tr!(
        "cannot be read: {e}",
        "無法讀取：{e}",
        "読み取れません：{e}"
    )
}

/// Read a regular file without following a symlink at `path`.
fn read_regular(path: &Path) -> Found {
    let m = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Found::Absent,
        Err(e) => return Found::Unsafe(unreadable(&e)),
        Ok(m) => m,
    };
    if m.file_type().is_symlink() {
        return Found::Symlink;
    }
    if !m.is_file() {
        return Found::Unsafe(tr!(
            "not a regular file",
            "不是一般檔案",
            "通常のファイルではありません"
        ));
    }
    if let Some(why) = unsafe_reason(&m) {
        return Found::Unsafe(why);
    }
    if m.len() > MAX_READ {
        return Found::Unsafe(tr!(
            "the file is too large",
            "檔案過大",
            "ファイルが大きすぎます"
        ));
    }
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            return Found::Unsafe(tr!(
                "cannot be opened: {e}",
                "無法開啟：{e}",
                "開けません：{e}"
            ));
        }
    };
    // The file opened must be the one inspected (not swapped in between).
    match f.metadata() {
        Ok(o) if o.dev() == m.dev() && o.ino() == m.ino() => {}
        _ => {
            return Found::Unsafe(tr!(
                "the file was replaced while it was read",
                "檔案在讀取時被替換",
                "読み取り中にファイルが置き換えられました"
            ));
        }
    }
    let mut bytes = Vec::new();
    if let Err(e) = Read::by_ref(&mut f)
        .take(MAX_READ + 1)
        .read_to_end(&mut bytes)
    {
        return Found::Unsafe(unreadable(&e));
    }
    String::from_utf8(bytes).map_or_else(
        |_| {
            Found::Unsafe(tr!(
                "not UTF-8 text",
                "不是 UTF-8 文字",
                "UTF-8 のテキストではありません"
            ))
        },
        Found::Text,
    )
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::os::unix::fs::symlink;

    use super::*;

    fn dir() -> (tempfile::TempDir, SshDir) {
        let t = tempfile::tempdir().unwrap();
        let ssh = t.path().join(".ssh");
        let d = SshDir::new(ssh);
        d.check(true).unwrap();
        (t, d)
    }

    #[test]
    fn writes_atomically_with_private_mode() {
        let (_t, d) = dir();
        d.write("vpn-manager.conf", "Host a\n", 0o600).unwrap();
        assert_eq!(d.read("vpn-manager.conf"), Found::Text("Host a\n".into()));
        let m = fs::metadata(d.managed_path()).unwrap();
        assert_eq!(m.mode() & 0o777, 0o600);
        d.write("vpn-manager.conf", "Host b\n", 0o600).unwrap();
        assert_eq!(d.read("vpn-manager.conf"), Found::Text("Host b\n".into()));
        // No temporary files are left behind.
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn never_follows_or_replaces_symlinks() {
        let (t, d) = dir();
        let elsewhere = t.path().join("victim");
        fs::write(&elsewhere, "keep").unwrap();
        symlink(&elsewhere, d.managed_path()).unwrap();
        assert_eq!(d.read("vpn-manager.conf"), Found::Symlink);
        assert!(d.write("vpn-manager.conf", "x", 0o600).is_err());
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "keep");
    }

    #[test]
    fn reads_a_dotfiles_config_through_its_symlink_but_never_writes_it() {
        let (t, d) = dir();
        let dotfiles = t.path().join("dotfiles-ssh-config");
        fs::write(&dotfiles, "Host pc\n  HostName 10.0.0.5\n").unwrap();
        fs::set_permissions(&dotfiles, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&dotfiles, d.config_path()).unwrap();
        assert_eq!(
            d.read_through_link("config"),
            Found::Linked("Host pc\n  HostName 10.0.0.5\n".into())
        );
        assert!(d.add_include("Include ~/.ssh/vpn-manager.conf").is_err());
        assert_eq!(
            fs::read_to_string(&dotfiles).unwrap(),
            "Host pc\n  HostName 10.0.0.5\n"
        );
        // The target passes the same checks as a plain file.
        fs::set_permissions(&dotfiles, fs::Permissions::from_mode(0o666)).unwrap();
        assert_matches!(d.read_through_link("config"), Found::Unsafe(_));
        fs::remove_file(&dotfiles).unwrap();
        assert_matches!(d.read_through_link("config"), Found::Unsafe(_));
    }

    #[test]
    fn never_replaces_a_file_with_other_hard_links() {
        let (t, d) = dir();
        fs::write(d.config_path(), "Host a\n").unwrap();
        fs::set_permissions(d.config_path(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(d.config_path(), t.path().join("other-name")).unwrap();
        assert!(d.add_include("Include ~/.ssh/vpn-manager.conf").is_err());
        assert_eq!(fs::read_to_string(d.config_path()).unwrap(), "Host a\n");
    }

    #[test]
    fn backups_never_replace_each_other() {
        let (_t, d) = dir();
        let first = d.backup("x.backup", "one").unwrap();
        let second = d.backup("x.backup", "two").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read_to_string(d.path().join(&first)).unwrap(), "one");
        assert_eq!(fs::read_to_string(d.path().join(&second)).unwrap(), "two");
    }

    #[test]
    fn refuses_files_writable_by_others() {
        let (_t, d) = dir();
        fs::write(d.config_path(), "Host a\n").unwrap();
        fs::set_permissions(d.config_path(), fs::Permissions::from_mode(0o666)).unwrap();
        assert_matches!(d.read("config"), Found::Unsafe(_));
        assert!(d.add_include("Include ~/.ssh/vpn-manager.conf").is_err());
    }

    #[test]
    fn adds_the_include_first_after_a_backup() {
        let (_t, d) = dir();
        let original = "Host old\n  User me\n";
        fs::write(d.config_path(), original).unwrap();
        fs::set_permissions(d.config_path(), fs::Permissions::from_mode(0o644)).unwrap();
        let backup = d
            .add_include("Include ~/.ssh/vpn-manager.conf")
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::read_to_string(d.path().join(&backup)).unwrap(),
            original
        );
        assert_eq!(
            fs::metadata(d.path().join(&backup)).unwrap().mode() & 0o777,
            0o600
        );
        let now = fs::read_to_string(d.config_path()).unwrap();
        let parsed = crate::config::parse(&now, |a| a == "~/.ssh/vpn-manager.conf");
        assert_eq!(parsed.include, vpn_domain::SshIncludeState::Present);
        assert!(now.ends_with(original));
        // The user's mode is kept.
        assert_eq!(fs::metadata(d.config_path()).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn creates_a_missing_config_with_only_the_include() {
        let (_t, d) = dir();
        assert_eq!(
            d.add_include("Include ~/.ssh/vpn-manager.conf").unwrap(),
            None
        );
        let parsed = crate::config::parse(&fs::read_to_string(d.config_path()).unwrap(), |a| {
            a == "~/.ssh/vpn-manager.conf"
        });
        assert_eq!(parsed.include, vpn_domain::SshIncludeState::Present);
    }
}
