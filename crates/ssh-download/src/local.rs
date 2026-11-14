//! The local folder a job downloads into.
//!
//! It must be a real directory of this user that no one
//! else can write (no other user can create, swap or rename entries in it), and it is opened once
//! without following a symlink: every later operation — the partial file, the final rename — is
//! relative to that open directory (`openat`, `renameat`), so swapping a path component later
//! redirects nothing.
//!
//! Partial files wait in `<folder>/.vpn-manager-partial/<id>.part` (0700, same filesystem as the
//! folder), and a finished one is moved to its final name with a rename that never replaces an
//! existing file: a name that is taken yields an error, never a lost file.
#![allow(
    unsafe_code,
    reason = "this module owns the libc boundary for the destination folder: openat/fstatat/mkdirat/renameat2/linkat/unlinkat/fsync on descriptors it holds"
)]

use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use vpn_domain::{SshDownloadDirCheck, Text, tr};

/// The folder of partial downloads, inside the destination folder.
pub const PARTIAL_DIR: &str = ".vpn-manager-partial";

/// The real user id of this process.
pub(crate) fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

fn cstr(s: &[u8]) -> io::Result<CString> {
    CString::new(s).map_err(|_| {
        tr!(
            "the path contains NUL",
            "路徑含有 NUL",
            "パスに NUL が含まれています"
        )
        .into_io_error(io::ErrorKind::InvalidInput)
    })
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a valid open descriptor and a buffer of the right size.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(last_error());
    }
    // SAFETY: fstat succeeded and filled it.
    Ok(unsafe { st.assume_init() })
}

/// `fstatat` of `name` in `dir`, never following a symlink; `None` when it does not exist.
fn stat_at(dir: &OwnedFd, name: &str) -> io::Result<Option<libc::stat>> {
    let c = cstr(name.as_bytes())?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor, NUL-terminated name, buffer of the right size.
    let r = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        let e = last_error();
        return if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e)
        };
    }
    // SAFETY: fstatat succeeded and filled it.
    Ok(Some(unsafe { st.assume_init() }))
}

const fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

const fn is_file(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// Why a directory may not take downloads (what is wrong with it, said after its path), or
/// `None`.
fn dir_problem(st: &libc::stat) -> Option<Text> {
    if !is_dir(st) {
        return Some(tr!(
            "is not a folder",
            "不是資料夾",
            "フォルダーではありません"
        ));
    }
    if st.st_uid != uid() {
        return Some(tr!(
            "does not belong to the user who runs VPN Manager",
            "不屬於執行 VPN Manager 的使用者",
            "VPN Manager を実行しているユーザーの所有ではありません"
        ));
    }
    let mode = st.st_mode & 0o7777;
    if mode & 0o022 != 0 {
        return Some(tr!(
            "is writable by other users or the group (permissions {mode:04o}); change them to 0755 or 0700, for example with chmod go-w",
            "可被其他使用者或群組寫入（權限 {mode:04o}）；請改成 0755 或 0700，例如 chmod go-w",
            "ほかのユーザーまたはグループが書き込めます（権限 {mode:04o}）。0755 または 0700 に変更してください（例：chmod go-w）"
        ));
    }
    None
}

fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = cstr(path.as_os_str().as_bytes())?;
    // SAFETY: NUL-terminated path; the descriptor is owned below.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: a fresh descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir_at(dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    let c = cstr(name.as_bytes())?;
    // SAFETY: valid descriptor and NUL-terminated name; the result is owned below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: a fresh descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A local folder that cannot be used, with the reason the user sees (`Display` is its English).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.en)]
pub struct Unusable(pub Text);

/// Why a finished file could not be moved to its name.
#[derive(Debug)]
pub enum PlaceError {
    /// The name is taken (by another file: ours would never be replaced).
    Exists,
    /// The partial file is not there.
    PartialMissing,
    Io(io::Error),
}

/// "Cannot read the folder {shown}: {e}".
fn cannot_read(shown: &impl fmt::Display, e: &io::Error) -> Text {
    tr!(
        "Cannot read the folder {shown}: {e}",
        "無法讀取資料夾 {shown}：{e}",
        "フォルダー {shown} を読み取れません：{e}";
        e = Text::of_io_error(e)
    )
}

/// The open destination folder and its folder of partial files.
#[derive(Debug)]
pub struct LocalDir {
    path: PathBuf,
    dir: OwnedFd,
    partial: OwnedFd,
}

impl LocalDir {
    /// Open the folder (created with 0755 when missing and `create`), check it and prepare its
    /// partial folder. Blocking: call it off the async runtime.
    ///
    /// # Errors
    ///
    /// [`Unusable`] when the folder is missing (and `create` is false) or cannot be created, is a
    /// symlink, cannot be opened or read, is not a directory of this user, is writable by group
    /// or others, or its partial folder cannot be created, opened or is not this user's.
    pub fn open(path: &Path, create: bool) -> Result<Self, Unusable> {
        let shown = path.display();
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o755)
                    .create(path)
                    .map_err(|e| {
                        Unusable(tr!(
                            "Cannot create the folder {shown}: {e}",
                            "無法建立資料夾 {shown}：{e}",
                            "フォルダー {shown} を作成できません：{e}"
                        ))
                    })?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Unusable(tr!(
                    "The folder {shown} does not exist",
                    "資料夾 {shown} 不存在",
                    "フォルダー {shown} が存在しません"
                )));
            }
            Err(e) => return Err(Unusable(cannot_read(&shown, &e))),
            Ok(m) if m.file_type().is_symlink() => {
                return Err(Unusable(tr!(
                    "{shown} is a symbolic link; so that files are not led elsewhere, use the folder it actually points to",
                    "{shown} 是符號連結；為避免檔案被導向別處，請改用它實際指向的資料夾",
                    "{shown} はシンボリックリンクです。ファイルが別の場所に導かれないよう、実際のリンク先のフォルダーを使ってください"
                )));
            }
            Ok(_) => {}
        }
        let dir = open_dir(path).map_err(|e| {
            Unusable(tr!(
                "Cannot open the folder {shown}: {e}",
                "無法開啟資料夾 {shown}：{e}",
                "フォルダー {shown} を開けません：{e}";
                e = Text::of_io_error(&e)
            ))
        })?;
        let st = fstat(&dir).map_err(|e| Unusable(cannot_read(&shown, &e)))?;
        if let Some(why) = dir_problem(&st) {
            return Err(Unusable(tr!(
                "{shown} {why}",
                "{shown} {why}",
                "{shown} は{why}";
                why = why
            )));
        }
        let partial = match open_dir_at(&dir, PARTIAL_DIR) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let c =
                    cstr(PARTIAL_DIR.as_bytes()).map_err(|e| Unusable(Text::of_io_error(&e)))?;
                // SAFETY: valid descriptor and NUL-terminated name.
                if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
                    let e = last_error();
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(Unusable(tr!(
                            "Cannot create the temporary folder in {shown}: {e}",
                            "無法在 {shown} 建立暫存資料夾：{e}",
                            "{shown} に一時フォルダーを作成できません：{e}"
                        )));
                    }
                }
                open_dir_at(&dir, PARTIAL_DIR).map_err(|e| {
                    Unusable(tr!(
                        "Cannot open {shown}/{PARTIAL_DIR}: {e}",
                        "無法開啟 {shown}/{PARTIAL_DIR}：{e}",
                        "{shown}/{PARTIAL_DIR} を開けません：{e}";
                        e = Text::of_io_error(&e)
                    ))
                })?
            }
            Err(e) => {
                return Err(Unusable(tr!(
                    "{shown}/{PARTIAL_DIR} cannot be used ({e}); it must be a folder VPN Manager created",
                    "{shown}/{PARTIAL_DIR} 無法使用（{e}）；它必須是 VPN Manager 建立的資料夾",
                    "{shown}/{PARTIAL_DIR} は使えません（{e}）。VPN Manager が作成したフォルダーである必要があります";
                    e = Text::of_io_error(&e)
                )));
            }
        };
        let st = fstat(&partial).map_err(|e| Unusable(Text::of_io_error(&e)))?;
        if !is_dir(&st) || st.st_uid != uid() {
            return Err(Unusable(tr!(
                "{shown}/{PARTIAL_DIR} does not belong to the current user",
                "{shown}/{PARTIAL_DIR} 不屬於目前的使用者",
                "{shown}/{PARTIAL_DIR} は現在のユーザーの所有ではありません"
            )));
        }
        if st.st_mode & 0o077 != 0 {
            // Ours (a umask made it wider): partial files are for this user alone.
            // SAFETY: a valid descriptor we own.
            unsafe { libc::fchmod(partial.as_raw_fd(), 0o700) };
        }
        Ok(Self {
            path: path.to_path_buf(),
            dir,
            partial,
        })
    }

    /// Whether `path` can take downloads; nothing is created. Blocking.
    #[must_use]
    pub fn check(path: &Path) -> SshDownloadDirCheck {
        let shown = path.display().to_string();
        let answer = |exists, would_create, problem: Option<Text>| SshDownloadDirCheck {
            path: shown.clone(),
            exists,
            would_create,
            problem,
        };
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => answer(
                true,
                false,
                Some(tr!(
                    "is a symbolic link; so that files are not led elsewhere, use the folder it actually points to",
                    "是符號連結；為避免檔案被導向別處，請改用它實際指向的資料夾",
                    "シンボリックリンクです。ファイルが別の場所に導かれないよう、実際のリンク先のフォルダーを使ってください"
                )),
            ),
            Ok(_) => match open_dir(path).and_then(|fd| fstat(&fd).map(|st| (fd, st))) {
                Err(e) => answer(
                    true,
                    false,
                    Some(tr!(
                        "cannot be opened: {e}",
                        "無法開啟：{e}",
                        "開けません：{e}";
                        e = Text::of_io_error(&e)
                    )),
                ),
                Ok((fd, st)) => {
                    let problem = dir_problem(&st).or_else(|| match stat_at(&fd, PARTIAL_DIR) {
                        Ok(Some(p)) if !is_dir(&p) || p.st_uid != uid() => Some(tr!(
                            "the {PARTIAL_DIR} inside is not a folder of the current user",
                            "裡面的 {PARTIAL_DIR} 不是目前使用者的資料夾",
                            "中の {PARTIAL_DIR} が現在のユーザーのフォルダーではありません"
                        )),
                        _ => None,
                    });
                    answer(true, false, problem)
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // The nearest existing ancestor must let this user create the rest.
                let mut up = path.parent();
                while let Some(p) = up {
                    if p.exists() {
                        break;
                    }
                    up = p.parent();
                }
                let Some(ancestor) = up else {
                    return answer(
                        false,
                        false,
                        Some(tr!("the path is not valid", "路徑無效", "パスが無効です")),
                    );
                };
                let writable = cstr(ancestor.as_os_str().as_bytes()).is_ok_and(|c| {
                    // SAFETY: NUL-terminated path.
                    unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
                });
                if !ancestor.is_dir() || !writable {
                    let parent = ancestor.display();
                    answer(
                        false,
                        false,
                        Some(tr!(
                            "the folder does not exist and cannot be created in {parent} (no write permission)",
                            "資料夾不存在，也無法在 {parent} 建立（沒有寫入權限）",
                            "フォルダーが存在せず、{parent} に作成することもできません（書き込み権限がありません）"
                        )),
                    )
                } else {
                    answer(false, true, None)
                }
            }
            Err(e) => answer(
                false,
                false,
                Some(tr!(
                    "cannot be read: {e}",
                    "無法讀取：{e}",
                    "読み取れません：{e}"
                )),
            ),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn partial_name(id: &str) -> String {
        format!("{id}.part")
    }

    /// The partial file of record `id`, created when missing (never through a symlink, and only
    /// a regular file of this user). Blocking.
    ///
    /// # Errors
    ///
    /// The I/O error of `openat`/`fstat`, `InvalidInput` for a NUL in the id, or
    /// `PermissionDenied` when the entry is not a regular file of this user.
    pub fn open_partial(&self, id: &str) -> io::Result<std::fs::File> {
        let c = cstr(Self::partial_name(id).as_bytes())?;
        // SAFETY: valid descriptor and NUL-terminated name; the result is owned below.
        let fd = unsafe {
            libc::openat(
                self.partial.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(last_error());
        }
        // SAFETY: a fresh descriptor nobody else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(&fd)?;
        if !is_file(&st) || st.st_uid != uid() {
            return Err(tr!(
                "the temporary file is not a regular file of the current user",
                "暫存檔不是目前使用者的一般檔案",
                "一時ファイルが現在のユーザーの通常ファイルではありません"
            )
            .into_io_error(io::ErrorKind::PermissionDenied));
        }
        Ok(std::fs::File::from(fd))
    }

    /// Remove record `id`'s partial file (none is fine).
    ///
    /// # Errors
    ///
    /// The I/O error of `unlinkat` other than "not found", or `InvalidInput` for a NUL in the id.
    pub fn remove_partial(&self, id: &str) -> io::Result<()> {
        let c = cstr(Self::partial_name(id).as_bytes())?;
        // SAFETY: valid descriptor and NUL-terminated name.
        if unsafe { libc::unlinkat(self.partial.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            let e = last_error();
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
        }
        Ok(())
    }

    /// Whether an entry named `name` exists in the folder (of any kind, links not followed).
    ///
    /// # Errors
    ///
    /// The I/O error of `fstatat` other than "not found", or `InvalidInput` for a NUL in the name.
    pub fn exists(&self, name: &str) -> io::Result<bool> {
        Ok(stat_at(&self.dir, name)?.is_some())
    }

    /// Give record `id`'s partial file the name `name` in the folder, never replacing anything.
    ///
    /// A hard link where the filesystem has them: the partial name stays (the caller removes it
    /// once the record says the file is in place), so after a crash [`Self::is_placed`] tells
    /// from the file itself whether `name` is this download. Without hard links the file is
    /// moved, and a crash between the move and the record leaves nothing to prove it by.
    ///
    /// # Errors
    ///
    /// [`PlaceError::Exists`] when `name` is taken, [`PlaceError::PartialMissing`] when the partial
    /// file is not there, and [`PlaceError::Io`] for any other failure of the link or rename.
    pub fn place(&self, id: &str, name: &str) -> Result<(), PlaceError> {
        let from = cstr(Self::partial_name(id).as_bytes()).map_err(PlaceError::Io)?;
        let to = cstr(name.as_bytes()).map_err(PlaceError::Io)?;
        let (pd, dd) = (self.partial.as_raw_fd(), self.dir.as_raw_fd());
        let classify = |e: io::Error| match e.raw_os_error() {
            Some(libc::EEXIST | libc::ENOTEMPTY) => PlaceError::Exists,
            Some(libc::ENOENT) => PlaceError::PartialMissing,
            _ => PlaceError::Io(e),
        };
        // A hard link fails on an existing name and keeps the partial name.
        // SAFETY: valid descriptors and NUL-terminated names.
        if unsafe { libc::linkat(pd, from.as_ptr(), dd, to.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        let e = last_error();
        // ENOTSUP and EOPNOTSUPP are one value on Linux, two on macOS.
        let no_links = [
            libc::EPERM,
            libc::ENOTSUP,
            libc::EOPNOTSUPP,
            libc::EMLINK,
            libc::EXDEV,
        ];
        if !e.raw_os_error().is_some_and(|c| no_links.contains(&c)) {
            return Err(classify(e));
        }
        // No hard links here (FAT, some network mounts): an atomic rename that refuses an
        // existing target, where the filesystem has one.
        #[cfg(target_os = "linux")]
        {
            // SAFETY: valid descriptors and NUL-terminated names.
            let r = unsafe {
                libc::renameat2(pd, from.as_ptr(), dd, to.as_ptr(), libc::RENAME_NOREPLACE)
            };
            if r == 0 {
                return Ok(());
            }
            let e = last_error();
            if !matches!(
                e.raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP)
            ) {
                return Err(classify(e));
            }
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: valid descriptors and NUL-terminated names.
            let r = unsafe {
                libc::renameatx_np(pd, from.as_ptr(), dd, to.as_ptr(), libc::RENAME_EXCL)
            };
            if r == 0 {
                return Ok(());
            }
            let e = last_error();
            if !matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) {
                return Err(classify(e));
            }
        }
        // A filesystem with neither: look, then rename.
        if self.exists(name).map_err(PlaceError::Io)? {
            return Err(PlaceError::Exists);
        }
        // SAFETY: valid descriptors and NUL-terminated names.
        if unsafe { libc::renameat(pd, from.as_ptr(), dd, to.as_ptr()) } != 0 {
            return Err(classify(last_error()));
        }
        Ok(())
    }

    /// Whether `name` in the folder is record `id`'s partial file under a second name: the very
    /// file [`Self::place`] linked, not another one of the same name.
    ///
    /// # Errors
    ///
    /// The I/O error of `fstatat` other than "not found", or `InvalidInput` for a NUL in a name.
    pub fn is_placed(&self, id: &str, name: &str) -> io::Result<bool> {
        let partial = stat_at(&self.partial, &Self::partial_name(id))?;
        let named = stat_at(&self.dir, name)?;
        Ok(match (partial, named) {
            (Some(p), Some(n)) => is_file(&n) && p.st_dev == n.st_dev && p.st_ino == n.st_ino,
            _ => false,
        })
    }

    /// Flush both folders' entries to disk (after a link or rename).
    ///
    /// # Errors
    ///
    /// The I/O error of `fsync` on either folder, except `EINVAL`/`ENOTSUP` (a filesystem that
    /// does not sync directories), which is ignored.
    pub fn sync(&self) -> io::Result<()> {
        for fd in [&self.dir, &self.partial] {
            // SAFETY: a valid descriptor we own.
            if unsafe { libc::fsync(fd.as_raw_fd()) } != 0 {
                let e = last_error();
                // Some filesystems do not sync directories; the data itself was synced.
                if !matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOTSUP)) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// The full local path of `name` in the folder.
    #[must_use]
    pub fn final_path(&self, name: &str) -> String {
        self.path.join(name).display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn folder() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = t.path().join("in");
        (t, p)
    }

    #[test]
    fn a_taken_name_is_never_replaced() {
        let (_t, p) = folder();
        let d = LocalDir::open(&p, true).unwrap();
        std::fs::write(p.join("a.txt"), b"theirs").unwrap();
        d.open_partial("id2").unwrap().write_all(b"ours").unwrap();
        assert_matches!(d.place("id2", "a.txt"), Err(PlaceError::Exists));
        assert_eq!(std::fs::read(p.join("a.txt")).unwrap(), b"theirs");
        let partial = p.join(PARTIAL_DIR).join("id2.part");
        assert_eq!(std::fs::read(&partial).unwrap(), b"ours", "ours is kept");
        // A file of the same name and size is not ours: only the linked file itself is.
        std::fs::write(p.join("b.txt"), b"same").unwrap();
        assert!(!d.is_placed("id2", "b.txt").unwrap());
        d.place("id2", "c.txt").unwrap();
        assert!(d.is_placed("id2", "c.txt").unwrap());
        assert_eq!(std::fs::read(p.join("c.txt")).unwrap(), b"ours");
        assert_matches!(d.place("nope", "d.txt"), Err(PlaceError::PartialMissing));
        d.remove_partial("id2").unwrap();
        d.remove_partial("id2").unwrap();
        assert!(
            !d.is_placed("id2", "c.txt").unwrap(),
            "no partial, no proof"
        );
        assert_eq!(std::fs::read(p.join("c.txt")).unwrap(), b"ours");
    }

    #[test]
    fn symlinks_and_folders_others_can_write_are_refused() {
        let (t, p) = folder();
        std::fs::create_dir(&p).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let e = LocalDir::open(&link, true).unwrap_err();
        assert!(e.0.zh_tw.contains("符號連結"), "{e}");
        assert!(LocalDir::check(&link).problem.is_some());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o775)).unwrap();
        let e = LocalDir::open(&p, true).unwrap_err();
        assert!(e.0.zh_tw.contains("0775"), "{e}");
        assert!(
            LocalDir::check(&p)
                .problem
                .unwrap()
                .zh_tw
                .contains("chmod go-w")
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A partial "folder" that is a link elsewhere is refused, not followed.
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, p.join(PARTIAL_DIR)).unwrap();
        assert!(LocalDir::open(&p, true).is_err());
        let file = t.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(LocalDir::open(&file, true).is_err());
    }

    #[test]
    fn a_partial_file_that_is_a_link_is_not_followed() {
        let (t, p) = folder();
        let d = LocalDir::open(&p, true).unwrap();
        let target = t.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, p.join(PARTIAL_DIR).join("id3.part")).unwrap();
        assert!(d.open_partial("id3").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }
}
