//! An App's own output, piped into a size-limited log file.
//!
//! A pipe whose write end becomes the App's stdout and stderr, and a pump that appends what arrives
//! to `<logs>/apps/<id>.log`, moving the file to `<id>.log.1` at [`LIMIT`] (like the daemon log).
//! The pump always drains the pipe, so a slow or failing disk never blocks the App on a full pipe.
//! On a full disk the oldest output makes room first ([`crate::logfiles::drop_oldest`]: `.1`,
//! then the older part of the current file); what still cannot be written is dropped.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use tokio::io::AsyncReadExt;

use crate::logfiles;

/// Size at which the log moves to `.1` (replacing the previous one).
pub const LIMIT: u64 = 2 * 1024 * 1024;
/// Longest line returned by [`tail`]; longer ones are cut.
const MAX_LINE: usize = 2000;
/// Bytes read from the end of a file to find its last lines.
const TAIL_WINDOW: u64 = 256 * 1024;

/// The reading side of an App's output.
pub struct LogPump {
    reader: OwnedFd,
    path: PathBuf,
}

/// A pipe for an App's output: the write end (hand it to the App as stdout and stderr; drop
/// our copy after the spawn) and the pump that writes `path`.
///
/// The log directory is created private (0700) when missing.
///
/// # Errors
///
/// Fails when the log directory cannot be created or verified private, or the pipe cannot be
/// made.
pub fn pipe(path: &Path) -> io::Result<(OwnedFd, LogPump)> {
    if let Some(dir) = path.parent() {
        crate::paths::ensure_private_dir(dir)?;
    }
    let (reader, writer) = io::pipe()?;
    Ok((
        OwnedFd::from(writer),
        LogPump {
            reader: OwnedFd::from(reader),
            path: path.to_path_buf(),
        },
    ))
}

fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

struct Sink {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

impl Sink {
    fn write(&mut self, data: &[u8]) {
        if let Err(e) = self.try_write(data)
            && logfiles::is_full(&e)
            && logfiles::drop_oldest(&self.path)
        {
            // Written once more, in the room the oldest output left.
            let _ = self.try_write(data);
        }
    }

    fn try_write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.file.is_none() {
            self.file = open(&self.path).ok();
            self.size = self
                .file
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .map_or(0, |m| m.len());
        }
        if self.size >= LIMIT {
            self.file = None;
            if std::fs::rename(&self.path, logfiles::backup(&self.path)).is_ok() {
                self.file = open(&self.path).ok();
                self.size = 0;
            }
        }
        let Some(f) = self.file.as_mut() else {
            return Err(io::ErrorKind::NotFound.into());
        };
        let written = f.write_all(data);
        if written.is_ok() {
            self.size += data.len() as u64;
        } else {
            // Try a fresh file next time (deleted directory, full disk...).
            self.file = None;
        }
        written
    }
}

/// Whether the log ends inside a line: the previous run's last output had no newline.
fn ends_mid_line(path: &Path) -> bool {
    let Ok(mut f) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    else {
        return false;
    };
    let mut last = [0u8; 1];
    f.metadata().is_ok_and(|m| m.len() > 0)
        && f.seek(SeekFrom::End(-1)).is_ok()
        && f.read_exact(&mut last).is_ok()
        && last[0] != b'\n'
}

impl LogPump {
    /// Append `header` (one line, on a line of its own), then everything the App writes, until
    /// every process of the tree has closed its output.
    pub async fn run(self, header: String) {
        let lead = if ends_mid_line(&self.path) { "\n" } else { "" };
        let mut sink = Sink {
            path: self.path,
            file: None,
            size: 0,
        };
        sink.write(format!("{lead}{header}\n").as_bytes());
        let Ok(mut rx) = tokio::net::unix::pipe::Receiver::from_owned_fd(self.reader) else {
            return;
        };
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => sink.write(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
}

/// The last `max` lines of the log (with the rotated file when the current one is short), and
/// whether older lines exist. A missing log is empty.
///
/// # Errors
///
/// Fails when a log file exists but cannot be opened (including a symlink), read or seeked.
pub fn tail(path: &Path, max: usize) -> io::Result<(Vec<String>, bool)> {
    let (mut lines, mut more) = tail_of(path, max)?;
    if lines.len() < max {
        let (older, older_more) = tail_of(&logfiles::backup(path), max - lines.len())?;
        if !older.is_empty() {
            more = older_more;
            lines.splice(0..0, older);
        }
    } else if logfiles::backup(path).exists() {
        more = true;
    }
    Ok((lines, more))
}

fn tail_of(path: &Path, max: usize) -> io::Result<(Vec<String>, bool)> {
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let start = len.saturating_sub(TAIL_WINDOW);
    f.seek(SeekFrom::Start(start))?;
    // At most TAIL_WINDOW bytes; only a capacity hint.
    let mut bytes = Vec::with_capacity(usize::try_from(len - start).unwrap_or(0));
    f.take(TAIL_WINDOW).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut all: Vec<&str> = text.lines().collect();
    // A window that starts mid-file starts mid-line: that partial line is not shown.
    let cut = start > 0;
    if cut && !all.is_empty() {
        all.remove(0);
    }
    let more = cut || all.len() > max;
    let keep = all.len().saturating_sub(max);
    let lines = all[keep..]
        .iter()
        .map(|l| {
            if l.chars().count() > MAX_LINE {
                l.chars().take(MAX_LINE).collect::<String>() + "…"
            } else {
                (*l).to_string()
            }
        })
        .collect();
    Ok((lines, more))
}
