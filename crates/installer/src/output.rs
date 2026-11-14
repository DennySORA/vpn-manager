//! What the installer writes to the terminal: progress (`say!`) and the licences on stdout, the
//! reason it stopped on stderr. Every write goes through here.

use std::fmt;
use std::io::{self, Write as _};

/// One line of progress for the user (`say!`). Writing it may fail (a closed pipe or terminal);
/// the steps it describes must still finish, so a failed write is passed over instead of
/// panicking like `println!`.
pub fn say(line: fmt::Arguments<'_>) {
    if writeln!(io::stdout(), "{line}").is_err() {
        // Nowhere to show it: the install, upgrade or removal goes on.
    }
}

/// `text` as it is (the licences). The reader may stop early (a pager, `head`): a closed pipe is
/// not a failure.
pub fn text(text: &str) {
    if io::stdout().write_all(text.as_bytes()).is_err() {
        // The reader is gone: nothing is left to show it to.
    }
}

/// One line on stderr: why the installer stopped or has nothing to do.
#[expect(
    clippy::print_stderr,
    reason = "the installer's failures go to stderr, and only through this function"
)]
pub fn error(line: fmt::Arguments<'_>) {
    eprintln!("{line}");
}
