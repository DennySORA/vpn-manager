//! `--log-file`: everything the process writes to stderr — its logs, a panic, and the stderr the
//! instance workers inherit — goes to one file. At [`LIMIT`] the file moves to `<file>.1`
//! (replacing the previous one) and a new file takes over; checked as lines are written and every
//! [`CHECK_EVERY`] (a deleted file or directory is created again then). launchd itself is given no
//! log path: a plist path whose directory is gone keeps the job from starting at all.
//!
//! Workers keep the file they inherited, so after a rotation they write to `<file>.1` until they
//! end.
//!
//! Every log line, with or without `--log-file`, goes through [`Stderr`]: written whole, or
//! dropped and counted — never a panic. (tracing reports a failed write by printing to the same
//! stderr, and a print that fails panics: on a full disk every thread that logged died, the
//! metrics database's writer among them.) With `--log-file` a line the full disk refused makes
//! room by dropping the oldest lines — `<file>.1` first, then the older part of the current file
//! ([`vpn_platform::logfiles::drop_oldest`]) — and is written again; the next line written after
//! a loss says how many were lost.

#![expect(unsafe_code, reason = "dup2 FFI that points stderr at the log file")]

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use vpn_platform::logfiles;

pub const LIMIT: u64 = 8 * 1024 * 1024;
const CHECK_EVERY: Duration = Duration::from_secs(300);
/// Bytes this process writes between two checks of the file's size.
const CHECK_BYTES: u64 = 256 * 1024;
const STDERR: RawFd = 2;

/// The `--log-file` path, once stderr points at it.
static PATH: OnceLock<PathBuf> = OnceLock::new();
/// Lines not written since the last one that was.
static LOST: AtomicU64 = AtomicU64::new(0);
/// The last failed write stopped inside a line: what comes next starts on a new one.
static CUT: AtomicBool = AtomicBool::new(false);
/// Bytes written since the file's size was last checked.
static UNCHECKED: AtomicU64 = AtomicU64::new(0);

/// Send stderr to `path` from now on and keep the file below [`LIMIT`].
pub fn redirect(path: &Path) -> io::Result<()> {
    check(path, STDERR, LIMIT, true)?;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "cannot fail: `main` redirects stderr only once, at start-up, so the cell is still empty here"
    )]
    let _ = PATH.set(path.to_path_buf());
    let path = path.to_path_buf();
    std::thread::Builder::new()
        .name("log-file".into())
        .spawn(move || {
            loop {
                std::thread::sleep(CHECK_EVERY);
                // Never in the middle of a line (the writer rotates under the same lock).
                let _lines = io::stderr().lock();
                recheck(&path);
            }
        })?;
    Ok(())
}

/// Move `path` aside at `limit` and create it when missing, pointing `fd` at the new file; with
/// `force`, point `fd` at it in any case.
fn check(path: &Path, fd: RawFd, limit: u64, force: bool) -> io::Result<()> {
    let reopen = match fs::symlink_metadata(path) {
        Ok(m) if m.len() >= limit => {
            let previous = logfiles::backup(path);
            // A worker may still write to the file it replaces: emptied, its blocks are freed
            // now rather than when that worker ends.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "best effort: the rename below replaces the previous file either way (before the first rotation there is none)"
            )]
            let _ = logfiles::empty(&previous);
            fs::rename(path, previous)?;
            true
        }
        Ok(_) => force,
        Err(e) if e.kind() == io::ErrorKind::NotFound => true,
        Err(e) => return Err(e),
    };
    if reopen {
        open_onto(path, fd)?;
    }
    Ok(())
}

/// A routine [`check`]: the periodic one, or the writer's after every [`CHECK_BYTES`]. A failure
/// has nowhere else to be reported, and the next check tries again.
fn recheck(path: &Path) {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a failed check leaves stderr on the file it has, so lines are still written; the log it would be reported to is the file that failed"
    )]
    let _ = check(path, STDERR, LIMIT, false);
}

fn open_onto(path: &Path, fd: RawFd) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.exists()) {
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    // SAFETY: both descriptors are open. dup2 replaces `fd` atomically, so a concurrent write
    // lands in the old file or the new one.
    if unsafe { libc::dup2(file.as_raw_fd(), fd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The log's writer for `tracing_subscriber`: one formatted event per write, to stderr.
#[derive(Clone, Copy)]
pub struct Stderr;

impl<'a> MakeWriter<'a> for Stderr {
    type Writer = Line;

    fn make_writer(&'a self) -> Self::Writer {
        Line
    }
}

/// One event's line. Writing it never fails: what cannot be written is counted (module docs).
pub struct Line;

impl Write for Line {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        put(buf);
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        put(buf);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A line of our own in the log, formatted like tracing's.
fn note(text: &str) -> String {
    let mut line = String::new();
    #[expect(
        clippy::let_underscore_must_use,
        reason = "cannot fail: the timestamp is written into a `String`, whose writes always succeed"
    )]
    let _ = SystemTime.format_time(&mut tracing_subscriber::fmt::format::Writer::new(&mut line));
    line.push_str("  WARN vpnd::logfile: ");
    line.push_str(text);
    line.push('\n');
    line
}

/// Write `buf` whole; on failure, the error and whether part of it was written.
fn write_whole(out: &mut impl Write, mut buf: &[u8]) -> Result<(), (io::Error, bool)> {
    let mut cut = false;
    while !buf.is_empty() {
        match out.write(buf) {
            Ok(0) => return Err((io::ErrorKind::WriteZero.into(), cut)),
            Ok(n) => {
                buf = buf.get(n..).unwrap_or_default();
                cut = true;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err((e, cut)),
        }
    }
    Ok(())
}

/// Write one line to stderr (see the module docs).
fn put(line: &[u8]) {
    // Orders this process's lines with its rotations and the room made on a full disk.
    let mut out = io::stderr().lock();
    let path = PATH.get();
    if let Some(path) = path
        && UNCHECKED.fetch_add(line.len() as u64, Ordering::Relaxed) >= CHECK_BYTES
    {
        UNCHECKED.store(0, Ordering::Relaxed);
        recheck(path);
    }
    let mut room_made = false;
    loop {
        let mut text = Vec::with_capacity(line.len() + 256);
        if CUT.load(Ordering::Relaxed) {
            text.push(b'\n');
        }
        if room_made {
            text.extend_from_slice(
                note("the disk is full: dropped the oldest log lines to keep logging").as_bytes(),
            );
        }
        let lost = LOST.load(Ordering::Relaxed);
        if lost > 0 {
            text.extend_from_slice(
                note(&format!(
                    "{lost} log lines were lost: the log could not be written (disk full?)"
                ))
                .as_bytes(),
            );
        }
        text.extend_from_slice(line);
        match write_whole(&mut out, &text) {
            Ok(()) => {
                LOST.store(0, Ordering::Relaxed);
                CUT.store(false, Ordering::Relaxed);
                return;
            }
            Err((e, cut)) => {
                if cut {
                    CUT.store(true, Ordering::Relaxed);
                }
                // Once per line: the oldest lines go, and it is written again in their room.
                if !room_made
                    && logfiles::is_full(&e)
                    && path.is_some_and(|p| logfiles::drop_oldest(p))
                {
                    room_made = true;
                    continue;
                }
                LOST.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
}
