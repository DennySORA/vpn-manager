//! `vpnd sandbox-exec`: run one command inside a strict connection's sandbox (Linux), with this
//! terminal as its standard input and output — a diagnostic for "what does a process see in
//! there". It talks to the sandbox's holder through its rendezvous socket in the state
//! directory's runtime directory, the same way the manager starts managed Apps, and leaves the
//! sandbox's management to the manager. The command gets the sandbox's network (only the
//! connection's tunnel), its private `/run`, `/tmp` and `/proc`, no capabilities and
//! `no_new_privs`.

#![allow(
    unsafe_code,
    reason = "borrows the inherited raw file descriptors of the sandbox's terminal"
)]

use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use vpn_platform::paths::Paths;
use vpn_platform::sandbox::{ExitStatus, SandboxClient, SpawnSpec};

/// Environment passed through to the command.
const PASSED_ENV: [&str; 6] = ["PATH", "HOME", "TERM", "LANG", "USER", "XDG_RUNTIME_DIR"];

fn stdio(fd: i32) -> anyhow::Result<OwnedFd> {
    // SAFETY: the standard descriptors are open for the life of this process.
    Ok(unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?)
}

/// `program` as an absolute path: as given, or the first match on `PATH` (the sandbox sees the
/// same programs as the host; only runtime and temporary directories are its own).
fn absolute(program: &str) -> anyhow::Result<String> {
    if program.starts_with('/') {
        return Ok(program.to_owned());
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    bail!("{program}: not found on PATH")
}

pub async fn run(
    state_dir: Option<PathBuf>,
    instance: String,
    mut command: Vec<String>,
) -> anyhow::Result<i32> {
    let paths = match &state_dir {
        Some(d) => Paths::under(d),
        None => Paths::default_for_user()?,
    };
    let socket = paths.sandbox_socket(&instance);
    let client = SandboxClient::connect(Path::new(&socket))
        .await
        .with_context(|| format!("no sandbox of connection {instance} ({})", socket.display()))?;
    if client.identity().instance_id != instance {
        bail!(
            "the sandbox at {} belongs to connection {}",
            socket.display(),
            client.identity().instance_id
        );
    }
    let Some(first) = command.first_mut() else {
        bail!("no command");
    };
    *first = absolute(first)?;
    let env = PASSED_ENV
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_owned(), v)))
        .collect();
    let mut process = client
        .spawn(SpawnSpec {
            argv: command,
            env,
            cwd: None,
            umask: 0o022,
            stdin: Some(stdio(0)?),
            stdout: Some(stdio(1)?),
            stderr: Some(stdio(2)?),
        })
        .await?;
    let start = process
        .identity()
        .map_or_else(|| "unknown".into(), |id| id.start.clone());
    eprintln!(
        "sandbox-exec: connection {instance} sandbox epoch {}: pid {} (start {start})",
        client.identity().epoch,
        process.pid(),
    );
    Ok(match process.wait().await {
        Some(ExitStatus::Code(c)) => c,
        Some(ExitStatus::Signal(s)) => 128 + s,
        None => 1,
    })
}
