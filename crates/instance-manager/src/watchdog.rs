//! The manager's liveness watchdog.
//!
//! A manager that is alive but no longer answers on its own
//! socket must not sit "running" forever. launchd (`KeepAlive` on an unsuccessful exit) and
//! systemd (`Restart=on-failure`) restart a manager only once it exits.
//!
//! The watchdog runs on its own OS thread with its own small runtime, so a wedged manager runtime
//! cannot stop it. Every [`WatchdogConfig::every`] it makes a real round trip to `manager.sock`
//! with the controller's own client — the protocol and build handshake, then the cheap `System`
//! call — within [`WatchdogConfig::timeout`]. After [`WatchdogConfig::failures`] failed checks in
//! a row it calls `unresponsive` (the manager logs an error and exits non-zero; its workers fail
//! closed when it dies). An answer within the timeout, however slow, is a success, and so is a
//! refusal: a stopping manager refuses calls by design. Checks do not count during the start
//! grace or while `quiet` says the manager is stopping.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vpn_ipc::control::{Call, ControlClient};

#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Time between checks.
    pub every: Duration,
    /// How long one check may take: connect, handshake and the call's answer.
    pub timeout: Duration,
    /// Failed checks in a row that mean the manager is unresponsive.
    pub failures: u32,
    /// Checks are not counted this long after the start.
    pub grace: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            every: Duration::from_secs(20),
            timeout: Duration::from_secs(10),
            failures: 3,
            grace: Duration::from_secs(60),
        }
    }
}

/// Start the watchdog on its own thread. `quiet`: the manager is stopping (checks do not count).
/// `unresponsive` gets what failed and since when; the thread ends after it.
///
/// # Errors
///
/// The OS error when the watchdog thread cannot be spawned.
pub fn start(
    socket: PathBuf,
    config: WatchdogConfig,
    quiet: impl Fn() -> bool + Send + 'static,
    unresponsive: impl FnOnce(String) + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("manager-watchdog".into())
        .spawn(move || watch(&socket, config, quiet, unresponsive))
}

fn watch(
    socket: &Path,
    config: WatchdogConfig,
    quiet: impl Fn() -> bool,
    unresponsive: impl FnOnce(String),
) {
    let started = Instant::now();
    let mut last_answer = started;
    let mut failed = 0u32;
    loop {
        std::thread::sleep(config.every);
        if started.elapsed() < config.grace || quiet() {
            failed = 0;
            continue;
        }
        match check(socket, config.timeout) {
            Ok(()) => {
                failed = 0;
                last_answer = Instant::now();
            }
            // A stop that began during the check explains it.
            Err(_) if quiet() => failed = 0,
            Err(why) => {
                failed += 1;
                tracing::warn!(
                    %why,
                    failed,
                    of = config.failures,
                    "the manager did not answer its own socket"
                );
                if failed >= config.failures {
                    unresponsive(format!(
                        "{failed} checks in a row failed (the last: {why}); the last answer came {} s ago",
                        last_answer.elapsed().as_secs()
                    ));
                    return;
                }
            }
        }
    }
}

/// One round trip, as the controller makes it: connect, handshake, `System`.
fn check(socket: &Path, timeout: Duration) -> Result<(), String> {
    // A runtime of its own per check: nothing of the manager's runtime is needed, and nothing
    // of a check outlives it.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("no runtime for the check: {e}"))?;
    runtime.block_on(async {
        let round_trip = async {
            let client = ControlClient::connect(socket)
                .await
                .map_err(|e| format!("connect: {e}"))?;
            match client.call(Call::System).await {
                Ok(_) => Ok(()),
                // Answered, if only to refuse (stopping).
                Err(_) if client.is_connected() => Ok(()),
                Err(e) => Err(format!("call: {e}")),
            }
        };
        tokio::time::timeout(timeout, round_trip)
            .await
            .unwrap_or_else(|_| Err(format!("no answer within {timeout:?}")))
    })
}
