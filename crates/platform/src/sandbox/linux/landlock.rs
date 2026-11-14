//! Landlock: where a strict App may write (`AppCommand::write_confinement`).
//!
//! The App's launcher builds the ruleset inside the App's own mount namespace, so each directory
//! is the one the App sees; the App's process restricts itself to it right before `exec`, after
//! `no_new_privs`, and everything it starts inherits the restriction. The ruleset handles the
//! write rights of Landlock ABI 3 (`<linux/landlock.h>`) — write and truncate files; create,
//! remove, link and rename entries (rename and link across directories, `REFER`, are denied
//! from ABI 2 on whether handled or not, so it is handled and allowed too) — and allows all of
//! them beneath each writable directory. Reading and executing stay as they were, and so do
//! descriptors already open (the App's log). Without Landlock in the kernel, or with one older
//! than ABI 3 (which cannot refuse truncation: a file anywhere the user may write could still
//! be emptied), nothing is applied: the start fails, it never runs unconfined or half confined.
#![expect(
    unsafe_code,
    reason = "landlock_create_ruleset, landlock_add_rule and landlock_restrict_self via libc::syscall"
)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use vpn_domain::{Text, tr};

const CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const RULE_PATH_BENEATH: libc::c_int = 1;

const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2: link or rename into another directory.
const ACCESS_FS_REFER: u64 = 1 << 13;
/// ABI 3: truncate.
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// `struct landlock_ruleset_attr` up to the first field: every ABI accepts it.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr` (packed in the kernel's header).
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The oldest Landlock ABI that confines writing: the first that can refuse truncation.
const MIN_ABI: i64 = 3;

/// The write rights of ABI 3, handled and allowed beneath each writable directory.
const WRITE_RIGHTS: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE;

/// Why the kernel's answer to the version query — `version`, or below 1 with `errno` — cannot
/// confine an App's writing, in words for the user; `None` when it can.
fn refusal(version: i64, errno: Option<i32>) -> Option<Text> {
    let why = match (version, errno) {
        (v, _) if v >= MIN_ABI => return None,
        (v, _) if v >= 1 => tr!(
            "This host's kernel has Landlock version {v}, which cannot stop files from being emptied (version {MIN_ABI}, Linux 6.2 or later, is needed)",
            "這台主機核心的 Landlock 是第 {v} 版，擋不住清空檔案（需要第 {MIN_ABI} 版，Linux 6.2 以上）",
            "このホストのカーネルの Landlock は第 {v} 版で、ファイルの切り詰めを防げません（第 {MIN_ABI} 版、Linux 6.2 以降が必要です）"
        ),
        (_, Some(libc::ENOSYS)) => tr!(
            "This host's kernel has no Landlock (Linux 6.2 or later is needed)",
            "這台主機的核心沒有 Landlock（需要 Linux 6.2 以上）",
            "このホストのカーネルには Landlock がありません（Linux 6.2 以降が必要です）"
        ),
        (_, Some(libc::EOPNOTSUPP)) => tr!(
            "This host's kernel has Landlock turned off (the lsm= boot parameter lacks landlock)",
            "這台主機的核心停用了 Landlock（開機參數 lsm= 沒有 landlock）",
            "このホストのカーネルでは Landlock が無効になっています（起動パラメーター lsm= に landlock がありません）"
        ),
        _ => tr!(
            "This host cannot use Landlock",
            "這台主機無法使用 Landlock",
            "このホストでは Landlock を使用できません"
        ),
    };
    Some(tr!(
        "{why}, so the app's writing cannot be confined; to let it write as usual, turn off “Confine writes” in the app's settings",
        "{why}，無法限制 App 的寫入位置；要讓它照常寫入，請在 App 設定關閉「限制寫入位置」",
        "{why}。そのため、アプリの書き込み先を制限できません。通常どおり書き込ませるには、アプリの設定で「書き込み先を制限」をオフにしてください";
        why = why
    ))
}

/// Whether the running kernel's Landlock can confine writing.
///
/// # Errors
///
/// Why not, in words for the user ([`refusal`]).
fn supported() -> io::Result<()> {
    // SAFETY: the version query takes no attribute (null, size 0).
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    let errno = (version < 1)
        .then(|| io::Error::last_os_error().raw_os_error())
        .flatten();
    refusal(version, errno).map_or(Ok(()), |why| {
        Err(why.into_io_error(io::ErrorKind::Unsupported))
    })
}

/// A ruleset that allows writing only beneath `writable` (directories, as this process sees
/// them); everything else may still be read and executed. For [`restrict_self`].
///
/// # Errors
///
/// A kernel whose Landlock cannot confine writing ([`supported`]), or a directory that cannot
/// be opened (missing, not a directory).
pub fn ruleset(writable: &[&Path]) -> io::Result<OwnedFd> {
    supported()?;
    let attr = RulesetAttr {
        handled_access_fs: WRITE_RIGHTS,
    };
    // SAFETY: a valid attribute of the size passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            size_of::<RulesetAttr>(),
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = RawFd::try_from(fd)
        .map_err(|_out_of_range| io::Error::other("ruleset descriptor out of range"))?;
    // SAFETY: a new descriptor we own (the kernel sets close-on-exec on it).
    let ruleset = unsafe { OwnedFd::from_raw_fd(raw) };
    for dir in writable {
        let parent = open_dir(dir)?;
        let rule = PathBeneathAttr {
            allowed_access: WRITE_RIGHTS,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: a valid rule for the ruleset we own.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &raw const rule,
                0 as libc::c_uint,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            let (kind, dir) = (e.kind(), dir.display());
            return Err(tr!(
                "Cannot allow writing to {dir}: {e}",
                "無法允許寫入 {dir}：{e}",
                "{dir} への書き込みを許可できません：{e}";
                e = Text::of_io_error(&e)
            )
            .into_io_error(kind));
        }
    }
    Ok(ruleset)
}

/// `dir` opened as a path only, refusing anything but a directory.
fn open_dir(dir: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(dir.as_os_str().as_bytes()).map_err(|_nul| {
        tr!(
            "The path contains NUL",
            "路徑含 NUL",
            "パスに NUL が含まれています"
        )
        .into_io_error(io::ErrorKind::InvalidInput)
    })?;
    // SAFETY: open with a valid C string; the result is checked.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        let (kind, dir) = (e.kind(), dir.display());
        let why = match e.raw_os_error() {
            Some(libc::ENOENT) => tr!(
                "The writable folder {dir} does not exist",
                "可寫入的資料夾 {dir} 不存在",
                "書き込み可能なフォルダー {dir} は存在しません"
            ),
            Some(libc::ENOTDIR) => tr!(
                "The writable folder {dir} is not a folder",
                "可寫入的資料夾 {dir} 不是資料夾",
                "書き込み可能なフォルダー {dir} はフォルダーではありません"
            ),
            _ => tr!(
                "The writable folder {dir} cannot be opened: {e}",
                "可寫入的資料夾 {dir} {e}",
                "書き込み可能なフォルダー {dir} を開けません：{e}"
            ),
        };
        return Err(why.into_io_error(kind));
    }
    // SAFETY: a new descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Restrict this process (and everything it starts) to `ruleset`. Needs `no_new_privs`.
/// Async-signal-safe: one system call.
///
/// # Errors
///
/// The kernel refused (for example without `no_new_privs`).
pub fn restrict_self(ruleset: RawFd) -> io::Result<()> {
    // SAFETY: a ruleset descriptor and no flags.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0 as libc::c_uint) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writing is confined only by a Landlock that can refuse truncation: an older one, a
    /// missing one and a disabled one are all refused, each with its own reason.
    #[test]
    fn only_a_landlock_that_refuses_truncation_confines_writing() {
        for version in [3, 4, 6, 99] {
            assert_eq!(refusal(version, None), None, "ABI {version}");
        }
        let cases = [
            (2, None, "第 2 版"),
            (1, None, "第 1 版"),
            (-1, Some(libc::ENOSYS), "沒有 Landlock"),
            (-1, Some(libc::EOPNOTSUPP), "停用了 Landlock"),
            (-1, Some(libc::EINVAL), "無法使用 Landlock"),
            (0, None, "無法使用 Landlock"),
        ];
        for (version, errno, want) in cases {
            let why = refusal(version, errno).expect("refused");
            assert!(
                why.zh_tw.contains(want),
                "{version} {errno:?}: {}",
                why.zh_tw
            );
            assert!(why.zh_tw.contains("關閉「限制寫入位置」"), "{}", why.zh_tw);
        }
    }
}
