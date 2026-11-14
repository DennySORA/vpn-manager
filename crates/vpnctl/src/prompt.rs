//! Secrets given to `vpnctl`: read from standard input only — never from arguments or the
//! environment, which other processes, `ps` and shell histories can see. On a terminal each
//! prompt goes to stderr and what is typed is not echoed (the terminal's settings come back
//! afterwards, also when the read is interrupted); from a pipe the lines are read as they are.

#![allow(
    unsafe_code,
    reason = "termios and isatty FFI for reading a secret without echo"
)]

use std::io::{self, BufRead};
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use crate::cmd::Failure;

/// The longest line read (an `AirVPN` password, a Mullvad account number with spaces).
const MAX_LINE: usize = 1024;

/// Standard input is a terminal.
pub fn stdin_is_terminal() -> bool {
    // SAFETY: isatty on a constant descriptor.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// The terminal settings to put back if a signal ends `vpnctl` while echo is off.
struct Saved(std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>);

// SAFETY: written once before `SAVED_SET` is published, then only read (also by the handler).
unsafe impl Sync for Saved {}

static SAVED: Saved = Saved(std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()));
static SAVED_SET: AtomicBool = AtomicBool::new(false);

extern "C" fn restore_and_reraise(sig: libc::c_int) {
    if SAVED_SET.load(Ordering::Acquire) {
        // SAFETY: SAVED was written before SAVED_SET; tcsetattr, signal and raise are
        // async-signal-safe.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, (*SAVED.0.get()).as_ptr());
        }
    }
    // SAFETY: the default action for the signal that arrived, then that signal again.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Echo off on the terminal until dropped (a newline still shows, so the cursor moves on).
struct NoEcho {
    saved: libc::termios,
}

impl NoEcho {
    fn new() -> io::Result<Self> {
        // SAFETY: termios is plain data that tcgetattr fills in.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: a descriptor and a struct of the right type.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &raw mut t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = t;
        if !SAVED_SET.load(Ordering::Acquire) {
            // SAFETY: the only write, before SAVED_SET is published.
            unsafe { (*SAVED.0.get()).write(saved) };
            SAVED_SET.store(true, Ordering::Release);
            let handler: extern "C" fn(libc::c_int) = restore_and_reraise;
            for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                // SAFETY: an extern "C" handler that only calls async-signal-safe functions.
                unsafe {
                    libc::signal(sig, handler as *const () as libc::sighandler_t);
                }
            }
        }
        t.c_lflag &= !libc::ECHO;
        t.c_lflag |= libc::ECHONL;
        // SAFETY: as above.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw const t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { saved })
    }
}

impl Drop for NoEcho {
    fn drop(&mut self) {
        // SAFETY: the settings read when echo was turned off.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const self.saved);
        }
    }
}

/// One line of `input`, without its line ending, into a buffer that is wiped when dropped (it is
/// never reallocated while read: a longer line is refused).
fn read_line(input: &mut impl BufRead) -> io::Result<Option<Zeroizing<String>>> {
    let mut line = Zeroizing::new(String::with_capacity(MAX_LINE + 2));
    let n = io::Read::take(&mut *input, MAX_LINE as u64 + 2).read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') && n > MAX_LINE {
        return Err(io::Error::other(format!("一行最多 {MAX_LINE} 個位元組")));
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Some(line))
}

/// One secret per prompt, from standard input. `what` names each (for the message when input
/// ends early).
pub fn secrets(prompts: &[(&str, &str)]) -> Result<Vec<Zeroizing<String>>, Failure> {
    let terminal = stdin_is_terminal();
    let _no_echo = if terminal {
        Some(NoEcho::new().map_err(|e| {
            Failure::Usage(format!(
                "無法關閉終端機的回顯，不讀取憑證（{e}）；可改從管線輸入"
            ))
        })?)
    } else {
        None
    };
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut out = Vec::with_capacity(prompts.len());
    for (prompt, what) in prompts {
        if terminal {
            eprint!("{prompt}");
        }
        match read_line(&mut input) {
            Ok(Some(line)) => out.push(line),
            Ok(None) => {
                return Err(Failure::Usage(format!(
                    "標準輸入沒有提供{what}（憑證只從標準輸入讀取，例如：echo … | vpnctl …，或直接在終端機輸入）"
                )));
            }
            Err(e) => {
                return Err(Failure::Usage(format!("無法讀取{what}：{e}")));
            }
        }
    }
    Ok(out)
}
