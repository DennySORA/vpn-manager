//! The machine's own service manager runs the two programs: launchd on macOS (per-user
//! `LaunchAgents`), the systemd user manager on Linux. Either way they run as the user, start
//! without anyone asking (launchd: at login; systemd: at boot with lingering), come back after a
//! failed exit at most every 10 s, and get time to stop: the web UI 30 s, the manager up to 16
//! minutes (it stops its managed Apps first, each with its own grace of up to 15 minutes).

#![expect(unsafe_code, reason = "getpwuid and getuid for the current user name")]

use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, bail};

use crate::layout::{Component, Job, Layout};
use crate::{launchd, systemd};

/// Seconds the supervisor waits after SIGTERM before SIGKILL: the web UI's, and the manager's —
/// which ends every managed App first, all at once, each with its own grace (at most 900 s,
/// `vpn_domain::APP_STOP_GRACE_SECS`), then its connections. It exits as soon as they are done.
pub const STOP_TIMEOUT_SECS: u64 = 30;
pub const MANAGER_STOP_TIMEOUT_SECS: u64 = 960;

/// How long `component` gets to stop.
pub const fn stop_timeout_secs(component: Component) -> u64 {
    match component {
        Component::Manager => MANAGER_STOP_TIMEOUT_SECS,
        Component::Controller => STOP_TIMEOUT_SECS,
    }
}
/// Least seconds between two launches after a failed exit.
pub const RESTART_DELAY_SECS: u64 = 10;

pub struct JobState {
    pub loaded: bool,
    pub running: bool,
    /// One line for people.
    pub summary: String,
}

pub trait Supervisor {
    fn kind(&self) -> &'static str;
    fn job(&self, layout: &Layout, component: Component) -> Job;
    fn render(&self, job: &Job, argv: &[String], working_dir: &str) -> String;
    /// Checks a rendered definition written to `staged`, a file named like the real one.
    fn validate(&self, staged: &Path) -> anyhow::Result<()>;
    fn state(&self, job: &Job) -> anyhow::Result<JobState>;
    /// Stops a job until the next `start` (its definition stays).
    fn stop(&self, job: &Job) -> anyhow::Result<()>;
    /// Starts jobs whose definitions are in place, in order, and has them start on their own
    /// from now on.
    fn start(&self, jobs: &[Job]) -> anyhow::Result<()>;
    /// Stops jobs, forgets them and deletes their definitions.
    fn remove(&self, jobs: &[Job]) -> anyhow::Result<()>;
    /// What else the services need to run without a login session; returns whether this
    /// changed anything (Linux lingering).
    fn ensure_unattended(&self) -> anyhow::Result<bool>;
}

pub fn for_this_machine(layout: &Layout) -> anyhow::Result<Box<dyn Supervisor>> {
    if cfg!(target_os = "macos") {
        Ok(Box::new(launchd::Launchd::new(&layout.home)))
    } else if cfg!(target_os = "linux") {
        Ok(Box::new(systemd::Systemd::new(&layout.home)?))
    } else {
        bail!("VPN Manager 只支援 macOS 與 Linux")
    }
}

pub fn run(program: &str, args: &[&str]) -> anyhow::Result<Output> {
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("執行 {program} {}", args.first().copied().unwrap_or("")))
}

pub fn expect_ok(out: &Output, what: &str) -> anyhow::Result<()> {
    if out.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stdout));
    bail!("{what} 失敗（{}）：{}", out.status, text.trim())
}

/// The user this process runs as.
pub fn user_name() -> anyhow::Result<String> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getpwuid has no preconditions; it returns null or a pointer into static storage
    // that stays valid until the next getpw* call, and this single-threaded program makes none
    // before the name is copied out below.
    let pw = unsafe { libc::getpwuid(uid) };
    // SAFETY: `pw` is null or points to the valid `passwd` entry getpwuid just filled in.
    let entry = unsafe { pw.as_ref() };
    let Some(name) = entry.map(|e| e.pw_name).filter(|n| !n.is_null()) else {
        bail!("無法取得目前使用者名稱");
    };
    // SAFETY: `name` is non-null and points to the entry's NUL-terminated user name, which stays
    // unchanged while it is copied out here.
    let name = unsafe { std::ffi::CStr::from_ptr(name) };
    Ok(name.to_string_lossy().into_owned())
}
