//! What `vpnd` prints itself, outside its log: the answer of `vpnd build-info` on standard output
//! and what `vpnd sandbox-exec` tells the person at the terminal on standard error. Everything else
//! goes through `tracing` (with `--log-file`, into the log file).

use std::fmt::Arguments;

/// One line on standard output, for the program that started `vpnd`.
#[expect(
    clippy::print_stdout,
    reason = "standard output is where `vpnd build-info` answers the installer"
)]
pub fn stdout_line(line: Arguments<'_>) {
    println!("{line}");
}

/// One line on standard error, for the person at the terminal.
#[expect(
    clippy::print_stderr,
    reason = "standard error is where `vpnd sandbox-exec` tells the person at the terminal what it started; standard output belongs to the command"
)]
pub fn stderr_line(line: Arguments<'_>) {
    eprintln!("{line}");
}
