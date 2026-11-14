//! Managed Apps in a strict sandbox (`AppIsolation::StrictNetns`).
//!
//! The manager's App supervisor needs each App's root process to be its own child, so the App
//! is not started by the holder: the manager starts `vpnd sandbox-app` (the App's *launcher*,
//! with the App's log as stdout/stderr and `/dev/null` as stdin) and hands it, over its control
//! socket, the sandbox's user, network and pid namespaces and the App's command. The launcher —
//! single-threaded, nothing of the App runs yet —
//!
//! 1. joins the sandbox's user namespace (which grants it the right to the rest), then its
//!    network namespace: the App's only interfaces are `lo` and the tunnel's TUN device;
//! 2. makes a mount namespace of the App's own from the host's view, with the sandbox's covers
//!    (empty tmpfs over `/run`, `$XDG_RUNTIME_DIR`, `/tmp`, …, VPN Manager's directories, `~/.ssh`)
//!    and the App's HOME, TMPDIR and working directory kept in place;
//! 3. joins the sandbox's pid namespace for what it starts, and forks: the child starts the
//!    App's tree under its own init (pid 1 of a pid namespace nested in the sandbox's), which
//!    mounts the tree's `/proc`, sheds every capability and becomes non-dumpable, then starts
//!    the App with `no_new_privs`, its exact argv, environment and directory, and no descriptor
//!    but stdio — with writes confined by Landlock when the App asks for it (its writable
//!    directories, `HOME`, `TMPDIR` and `/dev`; the ruleset is built in step 2's mount
//!    namespace, [`super::landlock`]);
//! 4. answers the manager with the host pids of the tree's init and the App, forwards
//!    termination signals to the tree's init, and when the tree is gone exits the way the App
//!    did. For an App with local access ports it forks a relay process first, which takes the
//!    control socket and relays the connections the manager hands it to those ports on the
//!    sandbox's loopback ([`super::access`]).
//!
//! The tree lives exactly as long as the App: when the App process exits, the rest of its tree
//! gets SIGTERM, then SIGKILL. Tearing the sandbox down ends every App in it (they are in its
//! pid namespace).
#![allow(
    unsafe_code,
    reason = "this module owns the App launch into the sandbox: setns, fork/exec and fds via libc"
)]

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, Weak};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpn_domain::{Text, tr};

use super::holder::{self, Launch, Report, TreeInit};
use super::{caps, mounts, wire};
use crate::apps::{self, AppCommand, IsolationBackend, ProcessIdentity, SpawnedApp};
use crate::process::{CONTROL_FD, cloexec_from};

/// The hidden `vpnd` role of an App's launcher (dispatched before anything else runs).
pub const APP_ROLE: &str = "sandbox-app";

/// Most arguments and environment variables a launcher accepts (the App supervisor allows far
/// fewer).
const MAX_ARGS: usize = 1024;
const MAX_ENV: usize = 1024;
/// How long the manager waits for the launcher to report the App started (or why not).
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// What managed Apps need to start in one sandbox; held for the manager while the sandbox is.
pub struct AppEntry {
    pub(crate) user: OwnedFd,
    pub(crate) net: OwnedFd,
    pub(crate) pid: OwnedFd,
    /// Covered with an empty read-only tmpfs (VPN Manager's directories; more per App).
    pub(crate) hide: Vec<PathBuf>,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
    pub(crate) epoch: u64,
}

impl AppEntry {
    /// The sandbox's epoch (it changes when the sandbox is rebuilt).
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Manager → launcher, one message each (an argument or variable can be up to 8 KiB, the whole
/// command far more than one message).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum AppMsg {
    /// First; descriptors: the sandbox's user, network and pid namespaces.
    Setup(Box<AppSetup>),
    /// One element of argv (the program first).
    Arg {
        value: String,
    },
    Env {
        name: String,
        value: String,
    },
    /// Everything was sent: start.
    Go,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppSetup {
    cwd: PathBuf,
    umask: u32,
    /// The App's own directories, kept in place inside the covers.
    keep: Vec<PathBuf>,
    /// Covered read-only.
    hide: Vec<PathBuf>,
    xdg_runtime_dir: Option<PathBuf>,
    /// The App's ports its local access ports relay to; none: the control socket closes once
    /// the App runs.
    #[serde(default)]
    access: Vec<u16>,
    /// The only directories the App may write to besides its `HOME`, `TMPDIR` and `/dev`
    /// (Landlock); `None`: unconfined.
    #[serde(default)]
    writable: Option<Vec<PathBuf>>,
}

/// Launcher → manager.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum AppReply {
    /// The App was `exec`uted; host pids of its tree's init and of the App.
    Started { tree_init: u32, app: u32 },
    Failed {
        stage: String,
        errno: Option<i32>,
        message: Text,
    },
}

/// The [`IsolationBackend`] of one App start in one sandbox (`AppIsolation::StrictNetns`).
pub struct AppBackend {
    exe: PathBuf,
    entry: Weak<AppEntry>,
    /// Directories covered for this App on top of the sandbox's.
    private: Vec<PathBuf>,
    /// The tree's init, once started: ending it ends the tree.
    tree_init: Mutex<Option<ProcessIdentity>>,
}

impl AppBackend {
    /// `exe`: the running `vpnd`. `private`: more directories the App must not see (`~/.ssh`, the
    /// SSH Manager's directory, another VPN Manager's data).
    #[must_use]
    pub const fn new(exe: PathBuf, entry: Weak<AppEntry>, private: Vec<PathBuf>) -> Self {
        Self {
            exe,
            entry,
            private,
            tree_init: Mutex::new(None),
        }
    }
}

impl IsolationBackend for AppBackend {
    fn name(&self) -> &'static str {
        "strict_netns"
    }

    fn spawn(&self, cmd: AppCommand) -> io::Result<SpawnedApp> {
        let entry = self.entry.upgrade().ok_or_else(|| {
            tr!(
                "The strict isolation sandbox of this connection no longer exists",
                "這個連線的嚴格隔離 sandbox 已不存在",
                "この接続の厳格な分離のサンドボックスはもう存在しません"
            )
            .into_io_error(io::ErrorKind::NotFound)
        })?;
        let mut hide = entry.hide.clone();
        for p in &self.private {
            if !hide.contains(p) {
                hide.push(p.clone());
            }
        }
        let (child, tree_init, access) = spawn_app(&self.exe, &entry, hide, cmd)?;
        drop(entry);
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("the started process has no pid"))?;
        // Our child: its pid cannot be reused before we reap it.
        let identity = apps::proc::identity(pid).unwrap_or_else(|| ProcessIdentity {
            pid,
            started_us: apps::proc::now_start_us(),
        });
        if let Ok(mut init) = self.tree_init.lock() {
            *init = apps::proc::identity(tree_init);
        }
        Ok(SpawnedApp {
            child,
            identity,
            access,
        })
    }

    /// The tree's init forwards SIGTERM to the whole tree; SIGKILL to it ends the tree's pid
    /// namespace at once. Without it (already gone), every tracked process is signalled.
    fn terminate(&self, root: ProcessIdentity, tracked: &[ProcessIdentity], force: bool) {
        let init = self.tree_init.lock().ok().and_then(|i| *i);
        match init.filter(|i| apps::proc::is_alive(*i)) {
            Some(init) => {
                let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
                let _ = apps::proc::signal(init, sig);
                if force {
                    apps::proc::signal_tree(root, tracked, true);
                }
            }
            None => apps::proc::signal_tree(root, tracked, force),
        }
    }
}

/// `s` as UTF-8; `what` names it, as the start of a sentence (“An argument”).
fn utf8(s: OsString, what: impl FnOnce() -> Text) -> io::Result<String> {
    s.into_string().map_err(|_| {
        tr!(
            "{what} is not valid UTF-8",
            "{what}不是有效的 UTF-8",
            "{what}が有効な UTF-8 ではありません";
            what = what()
        )
        .into_io_error(io::ErrorKind::InvalidInput)
    })
}

/// What [`spawn_app`] started: the launcher (the App's root, our child), the host pid of the
/// tree's init, and the channel of the App's local access ports.
type Started = (
    tokio::process::Child,
    u32,
    Option<super::access::AccessChannel>,
);

/// An App's program, arguments and environment, as the launcher is sent them.
type CommandStrings = (String, Vec<String>, Vec<(String, String)>);

/// The App's program, arguments and environment as the UTF-8 strings the launcher is sent.
fn command_strings(
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
) -> io::Result<CommandStrings> {
    let program = utf8(program.into_os_string(), || {
        tr!("The executable path", "執行檔路徑", "実行ファイルのパス")
    })?;
    let args: Vec<String> = args
        .into_iter()
        .map(|a| utf8(a, || tr!("An argument", "參數", "引数")))
        .collect::<io::Result<_>>()?;
    let env: Vec<(String, String)> = env
        .into_iter()
        .map(|(k, v)| {
            Ok((
                utf8(k, || {
                    tr!(
                        "An environment variable's name",
                        "環境變數名稱",
                        "環境変数の名前"
                    )
                })?,
                utf8(v, || tr!("An environment variable", "環境變數", "環境変数"))?,
            ))
        })
        .collect::<io::Result<_>>()?;
    Ok((program, args, env))
}

/// The App's `HOME` and `TMPDIR` (absolute paths only): kept in place inside the covers.
fn home_and_tmp(env: &[(String, String)]) -> Vec<PathBuf> {
    env.iter()
        .filter(|(k, v)| (k == "HOME" || k == "TMPDIR") && v.starts_with('/'))
        .map(|(_, v)| PathBuf::from(v))
        .collect()
}

/// Send the launcher its setup (with the sandbox's namespaces), the App's command and `Go`.
fn send_command(
    ctl: RawFd,
    setup: &AppMsg,
    entry: &AppEntry,
    (program, args, env): CommandStrings,
) -> io::Result<()> {
    wire::send_json(
        ctl,
        setup,
        &[
            entry.user.as_raw_fd(),
            entry.net.as_raw_fd(),
            entry.pid.as_raw_fd(),
        ],
    )?;
    for value in std::iter::once(program).chain(args) {
        wire::send_json(ctl, &AppMsg::Arg { value }, &[])?;
    }
    for (name, value) in env {
        wire::send_json(ctl, &AppMsg::Env { name, value }, &[])?;
    }
    wire::send_json(ctl, &AppMsg::Go, &[])
}

/// Start the App's launcher and hand it the App; returns what runs once the App runs.
fn spawn_app(
    exe: &Path,
    entry: &AppEntry,
    hide: Vec<PathBuf>,
    cmd: AppCommand,
) -> io::Result<Started> {
    let AppCommand {
        program,
        args,
        env,
        cwd,
        output,
        limits,
        access_ports,
        write_confinement,
    } = cmd;
    let (program, args, env) = command_strings(program, args, env)?;
    let mut keep = home_and_tmp(&env);
    keep.push(cwd.clone());

    let (mine, theirs) = wire::seqpacket_pair()?;
    wire::set_receive_timeout(mine.as_raw_fd(), START_TIMEOUT)?;
    holder::bound_sends(mine.as_raw_fd());
    let stderr = output.try_clone()?;
    let theirs_raw = theirs.as_raw_fd();
    let mut c = tokio::process::Command::new(exe);
    c.arg(APP_ROLE)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(stderr))
        .process_group(0)
        // The App outlives a dropped handle: only an explicit stop ends it.
        .kill_on_drop(false);
    // SAFETY: runs in the forked child before exec and only calls async-signal-safe functions
    // (write, setrlimit, dup2, fcntl, close_range).
    unsafe {
        c.pre_exec(move || {
            // The App's cgroup and open-files limit first, before the launcher enters any
            // namespace: the whole tree it starts inherits both.
            if let Some(fd) = limits.cgroup_procs {
                libc::write(fd, b"0".as_ptr().cast(), 1);
            }
            if let Some(n) = limits.open_files {
                crate::limits::set_open_files(n)?;
            }
            if theirs_raw == CONTROL_FD {
                let flags = libc::fcntl(CONTROL_FD, libc::F_GETFD);
                libc::fcntl(CONTROL_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            } else if libc::dup2(theirs_raw, CONTROL_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            cloexec_from(CONTROL_FD + 1);
            Ok(())
        });
    }
    let child = c.spawn()?;
    drop(theirs);
    let ctl = mine.as_raw_fd();
    let relays = !access_ports.is_empty();
    let setup = AppMsg::Setup(Box::new(AppSetup {
        cwd,
        umask: 0o077,
        keep,
        hide,
        xdg_runtime_dir: entry.xdg_runtime_dir.clone(),
        access: access_ports,
        writable: write_confinement,
    }));
    let sent = send_command(ctl, &setup, entry, (program, args, env));
    // A launcher that went away early still answers with its reason first, if it can.
    let answer = wire::recv_json::<AppReply>(ctl);
    match (answer, sent) {
        (Ok(Some((AppReply::Started { tree_init, .. }, _, _))), Ok(())) => {
            // The App runs; its access ports' connections go out on the same socket from now
            // on. Without the channel (it cannot fail but for a runtime without its reactor)
            // the App runs on and its ports say they do not serve.
            let access = if relays {
                match super::access::AccessChannel::new(mine) {
                    Ok(channel) => Some(channel),
                    Err(e) => {
                        tracing::warn!(error = %e, "access relay channel not set up");
                        None
                    }
                }
            } else {
                None
            };
            Ok((child, tree_init, access))
        }
        (Ok(Some((AppReply::Failed { stage, message, .. }, _, _))), _) => Err(tr!(
            "Cannot start in the strict isolation sandbox ({stage}): {message}",
            "無法在嚴格隔離 sandbox 內啟動（{stage}）：{message}",
            "厳格な分離のサンドボックス内で起動できません（{stage}）：{message}";
            message = message
        )
        .into_io_error(io::ErrorKind::Other)),
        (_, Err(e)) => Err(e),
        (Err(e), _) => {
            let kind = e.kind();
            Err(tr!(
                "The strict isolation launcher did not answer: {e}",
                "嚴格隔離的啟動程序沒有回應：{e}",
                "厳格な分離の起動プロセスが応答しませんでした：{e}";
                e = Text::of_io_error(&e)
            )
            .into_io_error(kind))
        }
        _ => Err(tr!(
            "The strict isolation launcher did not answer",
            "嚴格隔離的啟動程序沒有回應",
            "厳格な分離の起動プロセスが応答しませんでした"
        )
        .into_io_error(io::ErrorKind::Other)),
    }
}

/// Write one line to our stderr (the App's log): why the App (or a part of it) did not start.
pub(super) fn log_line(message: &str) {
    let line = format!("vpn-manager: {message}\n");
    // SAFETY: write a local buffer to fd 2.
    unsafe {
        libc::write(2, line.as_ptr().cast(), line.len());
    }
}

fn dup(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC on a descriptor we hold returns a new one or -1.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Wait for one child; its exit code (128 + signal when killed).
fn wait_code(pid: libc::pid_t) -> i32 {
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a pointer to a local.
        let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if r == pid {
            if libc::WIFEXITED(status) {
                return libc::WEXITSTATUS(status);
            }
            if libc::WIFSIGNALED(status) {
                return 128 + libc::WTERMSIG(status);
            }
            continue;
        }
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return 126;
    }
}

/// End this process the way the App ended: its exit code, or the same signal.
fn mirror(code: Option<i32>, signal: Option<i32>) -> i32 {
    if let Some(code) = code {
        return code;
    }
    let sig = signal.unwrap_or(libc::SIGKILL);
    // SAFETY: plain signal-state calls on this process, then kill ourselves.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, sig);
        libc::signal(sig, libc::SIG_DFL);
        libc::sigprocmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
        libc::kill(libc::getpid(), sig);
    }
    128 + sig
}

fn setns(fd: &OwnedFd, kind: libc::c_int) -> io::Result<()> {
    // SAFETY: setns on a namespace descriptor we hold.
    holder::check(unsafe { libc::setns(fd.as_raw_fd(), kind) }).map(|_| ())
}

/// Entry point of `vpnd sandbox-app` (an App's launcher). Must run before any thread exists.
#[must_use]
pub fn run_app() -> i32 {
    let Ok(control) = crate::process::take_control_fd() else {
        return 2;
    };
    let ctl = control.as_raw_fd();
    let failed = |stage: &str, e: &io::Error| -> i32 { report_failure(ctl, stage, e) };
    let (setup, fds) = match wire::recv_json::<AppMsg>(ctl) {
        Ok(Some((AppMsg::Setup(s), fds, _))) => (*s, fds),
        _ => return 2,
    };
    let [user, net, pid]: [OwnedFd; 3] = match fds.try_into() {
        Ok(a) => a,
        Err(_) => {
            return failed(
                "descriptors",
                &io::Error::other("expected the user, network and pid namespaces"),
            );
        }
    };
    let Some((argv, env)) = receive_command(ctl) else {
        return 2;
    };
    // Read while the host's /proc is still in view.
    let last_cap = caps::last_capability();
    let mut launch = match launch_of(&setup, &argv, &env, last_cap) {
        Ok(l) => l,
        Err(e) => return failed("command", &e),
    };

    if let Err((stage, e)) = enter_sandbox(&user, &net, &pid, &setup) {
        return failed(stage, &e);
    }
    drop((user, net, pid));
    if let Err(e) = confine_writes(&mut launch, setup.writable.as_deref(), &env) {
        return failed("landlock", &e);
    }

    let (report, theirs) = match report_pair() {
        Ok(p) => p,
        Err(e) => return failed("report", &e),
    };
    let stdio = match (dup(1), dup(2)) {
        (Ok(out), Ok(err)) => [None, Some(out), Some(err)],
        (Err(e), _) | (_, Err(e)) => return failed("stdio", &e),
    };
    // Termination signals wait on a signalfd from now on (inherited blocked by the tree's init,
    // which reads its own; the App unblocks them).
    let sigfd = match holder::signal_fd(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT])
    {
        Ok(fd) => fd,
        Err(e) => return failed("signals", &e),
    };

    // SAFETY: fork in this single-threaded process.
    let starter = unsafe { libc::fork() };
    if starter < 0 {
        return failed("fork", &io::Error::last_os_error());
    }
    if starter == 0 {
        run_starter(control, report, sigfd, theirs, stdio, &launch);
    }
    drop(theirs);
    drop(stdio);

    let report_fd = report.as_raw_fd();
    let StartReports {
        started,
        init,
        app,
        mut exited,
    } = collect_start_reports(report_fd);
    let init = match (started, init, app) {
        (Ok(()), Some(init), Some(app)) => {
            let _ = wire::send_json(
                ctl,
                &AppReply::Started {
                    tree_init: init,
                    app,
                },
                &[],
            );
            init
        }
        (Err(errno), _, _) => {
            let code = failed("exec", &io::Error::from_raw_os_error(errno));
            wait_code(starter);
            return code;
        }
        _ => {
            let code = failed(
                "start",
                &io::Error::other("the App's process ids were not reported"),
            );
            wait_code(starter);
            return code;
        }
    };
    // The App runs. Its local access ports' connections arrive on the control socket, for a
    // relay process forked here (still without a thread); without any, the socket closes.
    if setup.access.is_empty() {
        drop(control);
    } else if let Err(e) = super::access::start_relay(control, setup.access, last_cap) {
        log_line(&format!("local access ports are not enabled: {e}"));
    }
    let pidfd = open_pidfd(init);
    supervise(report_fd, &sigfd, pidfd.as_ref(), &mut exited);
    wait_code(starter);
    match exited {
        Some((code, signal)) => mirror(code, signal),
        // Ended without a report: the tree was killed.
        None => mirror(None, Some(libc::SIGKILL)),
    }
}

/// Tell the manager (and the log) that starting the App failed at `stage`; the launcher's exit
/// code.
fn report_failure(ctl: RawFd, stage: &str, e: &io::Error) -> i32 {
    log_line(&format!(
        "cannot start in the strict isolation sandbox ({stage}): {e}"
    ));
    let _ = wire::send_json(
        ctl,
        &AppReply::Failed {
            stage: stage.into(),
            errno: holder::errno_of(e),
            message: Text::of_io_error(e),
        },
        &[],
    );
    126
}

/// An App's argv and environment.
type Command = (Vec<String>, Vec<(String, String)>);

/// The App's argv and environment, one message each until `Go`; `None` on anything else (or
/// past the limits).
fn receive_command(ctl: RawFd) -> Option<Command> {
    let mut argv: Vec<String> = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    loop {
        match wire::recv_json::<AppMsg>(ctl) {
            Ok(Some((AppMsg::Arg { value }, _, _))) if argv.len() < MAX_ARGS => argv.push(value),
            Ok(Some((AppMsg::Env { name, value }, _, _))) if env.len() < MAX_ENV => {
                env.push((name, value));
            }
            Ok(Some((AppMsg::Go, _, _))) => return Some((argv, env)),
            _ => return None,
        }
    }
}

/// Into the sandbox: its user namespace first (it grants the right to join the others), its
/// network namespace, a mount namespace of the App's own, then its pid namespace. The stage
/// that failed otherwise.
/// What the App's process `exec`s, checked now (before anything of the sandbox is entered).
fn launch_of(
    setup: &AppSetup,
    argv: &[String],
    env: &[(String, String)],
    last_cap: u32,
) -> io::Result<Launch> {
    CString::new(setup.cwd.as_os_str().as_bytes())
        .map_err(|_| "NUL in working directory".to_owned())
        .and_then(|cwd| Launch::new(argv, env, cwd, setup.umask, last_cap))
        .map_err(|m| io::Error::new(io::ErrorKind::InvalidInput, m))
}

/// The App writes only beneath `writable`, its `HOME` and `TMPDIR` and `/dev`, as it sees them
/// (called in its mount namespace); `None`: unconfined.
fn confine_writes(
    launch: &mut Launch,
    writable: Option<&[PathBuf]>,
    env: &[(String, String)],
) -> io::Result<()> {
    let Some(writable) = writable else {
        return Ok(());
    };
    let private = home_and_tmp(env);
    let dirs: Vec<&Path> = writable
        .iter()
        .map(PathBuf::as_path)
        .chain(private.iter().map(PathBuf::as_path))
        .chain(std::iter::once(Path::new("/dev")))
        .collect();
    launch.confine_writes(super::landlock::ruleset(&dirs)?);
    Ok(())
}

fn enter_sandbox(
    user: &OwnedFd,
    net: &OwnedFd,
    pid: &OwnedFd,
    setup: &AppSetup,
) -> Result<(), (&'static str, io::Error)> {
    setns(user, libc::CLONE_NEWUSER).map_err(|e| ("userns", e))?;
    setns(net, libc::CLONE_NEWNET).map_err(|e| ("netns", e))?;
    // SAFETY: unshare with a constant flag in this single-threaded process.
    holder::check(unsafe { libc::unshare(libc::CLONE_NEWNS) }).map_err(|e| ("mountns", e))?;
    mounts::setup_app(setup.xdg_runtime_dir.as_deref(), &setup.hide, &setup.keep)
        .map_err(|e| ("mounts", e))?;
    setns(pid, libc::CLONE_NEWPID).map_err(|e| ("pidns", e))
}

/// The socket pair the tree's init and the App report on; our end receives their credentials.
fn report_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (report, theirs) = wire::seqpacket_pair()?;
    wire::pass_credentials(report.as_raw_fd())?;
    Ok((report, theirs))
}

/// The forked starter, in the sandbox's pid namespace: start the tree under its own init, wait
/// for it, exit.
fn run_starter(
    control: OwnedFd,
    report: OwnedFd,
    sigfd: OwnedFd,
    theirs: OwnedFd,
    stdio: [Option<OwnedFd>; 3],
    launch: &Launch,
) -> ! {
    drop(control);
    drop(report);
    drop(sigfd);
    let code = holder::start_tree(
        theirs,
        stdio,
        launch,
        TreeInit {
            mount_proc: true,
            end_with_app: true,
        },
    )
    .map_or(126, wait_code);
    // SAFETY: _exit is always safe.
    unsafe { libc::_exit(code) }
}

/// How the App ended: its exit code, or the signal that ended it.
type Exit = (Option<i32>, Option<i32>);

/// What the tree's init and the App reported until the App's `exec`.
struct StartReports {
    /// `Err(errno)`: the `exec` failed, or the reports ended early (`EIO`).
    started: Result<(), i32>,
    /// Host pids of the tree's init and the App.
    init: Option<u32>,
    app: Option<u32>,
    /// How the App ended, when it already did.
    exited: Option<Exit>,
}

/// The tree's init and the App report themselves (their credentials carry their host pids).
fn collect_start_reports(report_fd: RawFd) -> StartReports {
    let (mut init, mut app) = (None, None);
    let mut exited: Option<Exit> = None;
    let started: Result<(), i32> = loop {
        match wire::recv_json::<Report>(report_fd) {
            Ok(Some((Report::Init, _, creds))) => init = creds.map(|c| c.pid.cast_unsigned()),
            Ok(Some((Report::App, _, creds))) => app = creds.map(|c| c.pid.cast_unsigned()),
            Ok(Some((Report::Exec { errno: 0 }, _, _))) => break Ok(()),
            Ok(Some((Report::Exec { errno }, _, _))) => break Err(errno),
            Ok(Some((Report::Exited { code, signal }, _, _))) => exited = Some((code, signal)),
            Ok(None) | Err(_) => break Err(libc::EIO),
        }
    };
    StartReports {
        started,
        init,
        app,
        exited,
    }
}

/// Signals for the tree go to its init through a pidfd (its pid cannot be mistaken); `None`
/// when it cannot be opened.
fn open_pidfd(init: u32) -> Option<OwnedFd> {
    // SAFETY: plain syscall with a pid and no flags; the result is checked.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, init as libc::pid_t, 0u32) };
    (pidfd >= 0).then(|| {
        // SAFETY: a fresh descriptor we own.
        unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) }
    })
}

/// Until the tree is gone: forward termination signals, remember how the App ended.
fn supervise(
    report_fd: RawFd,
    sigfd: &OwnedFd,
    pidfd: Option<&OwnedFd>,
    exited: &mut Option<Exit>,
) {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: report_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sigfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll on an array of pollfd we own.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            continue;
        }
        if fds[1].revents != 0 {
            for sig in holder::read_signals(sigfd.as_raw_fd()) {
                if let Some(fd) = pidfd {
                    // SAFETY: signal through a pidfd we own; no siginfo, no flags.
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            fd.as_raw_fd(),
                            sig.number.cast_signed(),
                            std::ptr::null::<libc::siginfo_t>(),
                            0u32,
                        );
                    }
                }
            }
        }
        if fds[0].revents != 0 {
            match wire::recv_json::<Report>(report_fd) {
                Ok(Some((Report::Exited { code, signal }, _, _))) => {
                    *exited = Some((code, signal));
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }
}
