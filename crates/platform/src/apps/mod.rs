//! Managed Apps, the OS side.
//!
//! Starting an App's process tree under an isolation backend, identifying and watching its
//! processes, Seatbelt profiles, executable approval and what an executable is ([`class`]:
//! browsers, macOS apps, launchers).
//!
//! Every backend starts the App the same way: an exact argv (no shell), a complete environment
//! (nothing inherited from VPN Manager), stdin from `/dev/null`, stdout and stderr on the
//! descriptor the manager hands in, no other descriptor (everything above stdio is closed at
//! `exec`), and the App as the leader of a new process group. What differs is how its network is
//! confined:
//!
//! | `AppIsolation`   | backend                | where                                   |
//! |------------------|------------------------|-----------------------------------------|
//! | `proxy_env`      | [`Plain`]              | macOS, Linux (proxy variables only)     |
//! | `enforced_proxy` | [`Seatbelt`]           | macOS (`sandbox-exec`)                  |
//! | `strict_netns`   | a [`SandboxProvider`]  | Linux; supplied by the strict sandbox   |
#![allow(
    unsafe_code,
    reason = "managed App launch calls fcntl, write, getuid and getpwuid_r via libc"
)]

pub mod class;
pub mod executable;
pub mod log;
pub mod proc;
pub mod seatbelt;

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use vpn_domain::{Text, tr};

pub use proc::ProcessIdentity;

/// This user's login name and home directory from the account database (not `$HOME`, which
/// the caller's environment can set to anything).
#[must_use]
pub fn account() -> Option<(String, PathBuf)> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    // SAFETY: passwd is plain data; getpwuid_r fills it, with strings in `buf`.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf.len()` is its size.
    let r = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut found,
        )
    };
    if r != 0 || found.is_null() || pwd.pw_name.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded: both are NUL-terminated strings inside `buf`.
    let (name, dir) = unsafe { (CStr::from_ptr(pwd.pw_name), CStr::from_ptr(pwd.pw_dir)) };
    Some((
        name.to_string_lossy().into_owned(),
        PathBuf::from(OsStr::from_bytes(dir.to_bytes())),
    ))
}

/// What to run. `program` is the approved, resolved executable; `args` follow it (placeholders
/// already replaced); `env` is the whole environment.
pub struct AppCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
    /// Receives stdout and stderr (the manager's end of it writes the App's log).
    pub output: OwnedFd,
    /// Applied to the root before `exec` where the backend can (VPN Manager's own `launch` does).
    /// The manager also applies them right after `spawn` on Linux (cgroup by pid, `prlimit`), so a
    /// backend that cannot still gets them; it may ignore this field.
    pub limits: SpawnLimits,
    /// The App's ports its local access ports relay to (`strict_netns` only: the sandbox's
    /// loopback is out of the host's reach). A backend without a sandbox gets none.
    pub access_ports: Vec<u16>,
    /// `strict_netns` only: the App may write only under these directories, its `HOME` and
    /// `TMPDIR` (the private ones) and `/dev` (Landlock); `None`: wherever its user can. Another
    /// backend gets `None` (Seatbelt confines writes its own way).
    pub write_confinement: Option<Vec<PathBuf>>,
}

/// Resource limits a backend applies to the root before `exec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpawnLimits {
    /// `RLIMIT_NOFILE` (soft and hard).
    pub open_files: Option<u64>,
    /// The open `cgroup.procs` of the App's cgroup ([`crate::limits::Leaf::procs_fd`]).
    pub cgroup_procs: Option<std::os::fd::RawFd>,
}

/// A started App: its root process (the manager is its parent and reaps it) and that process's
/// identity.
pub struct SpawnedApp {
    pub child: tokio::process::Child,
    pub identity: ProcessIdentity,
    /// Where the connections of the App's local access ports go (a sandboxed App started with
    /// `access_ports`).
    pub access: Option<crate::sandbox::AccessChannel>,
}

/// One way of confining an App.
///
/// `spawn` must not let the App's own code run before the confinement is in place (INV-03):
/// Seatbelt applies its profile in `sandbox-exec` before it `exec`s the App; the strict sandbox
/// enters its namespaces before `exec`.
pub trait IsolationBackend: Send + Sync {
    /// Recorded with a run: `plain`, `seatbelt`, `strict_netns`.
    fn name(&self) -> &'static str;

    /// Start the App's process tree as `cmd` says, confined before any of its code runs.
    ///
    /// # Errors
    ///
    /// Fails when the process cannot be started or confined; the App's code has not run then.
    fn spawn(&self, cmd: AppCommand) -> io::Result<SpawnedApp>;

    /// Ask the tree to end (`force = false`: SIGTERM) or end it (`true`: SIGKILL). `tracked`
    /// lists every process of the tree seen so far; only those whose identity still matches are
    /// signalled. The strict sandbox overrides this to tear down its pid namespace.
    fn terminate(&self, root: ProcessIdentity, tracked: &[ProcessIdentity], force: bool) {
        proc::signal_tree(root, tracked, force);
    }
}

/// `proxy_env`: the App's network is not confined; only its proxy variables point at the
/// Gateway.
pub struct Plain;

impl IsolationBackend for Plain {
    fn name(&self) -> &'static str {
        "plain"
    }

    fn spawn(&self, cmd: AppCommand) -> io::Result<SpawnedApp> {
        let program = cmd.program.clone();
        let args = cmd.args.clone();
        launch(program.as_os_str().to_os_string(), args, cmd)
    }
}

/// `enforced_proxy` on macOS: `sandbox-exec -p <profile> <program> <args…>` (same pid; the
/// profile is in force before the App's first instruction).
pub struct Seatbelt {
    pub profile: String,
}

impl IsolationBackend for Seatbelt {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn spawn(&self, cmd: AppCommand) -> io::Result<SpawnedApp> {
        if !cfg!(target_os = "macos") {
            return Err(io::Error::other("Seatbelt is macOS-only"));
        }
        let mut args: Vec<OsString> = vec!["-p".into(), self.profile.clone().into()];
        args.push(cmd.program.clone().into_os_string());
        args.extend(cmd.args.iter().cloned());
        launch(seatbelt::SANDBOX_EXEC.into(), args, cmd)
    }
}

/// Where the Linux strict sandbox plugs in (the lead wires it to `AppIsolation::StrictNetns`).
///
/// The strict sandbox of an Instance (a rootless user+net+mount+pid namespace whose only
/// interface is the Instance's TUN) is owned by its own module; the launcher only needs a
/// backend that spawns into it. The returned backend's `spawn` must:
/// - enter the Instance's namespaces and set `PR_SET_NO_NEW_PRIVS` before `exec`;
/// - start `cmd.program` with exactly `cmd.args`, `cmd.env` and `cmd.cwd`, stdin `/dev/null`,
///   stdout and stderr on `cmd.output`, and close every other descriptor;
/// - return the root process as the manager's child (so it is reaped and its exit observed)
///   with its identity in host terms (host pid + start time);
/// - apply `cmd.limits` (join the cgroup, set `RLIMIT_NOFILE`) to the root before it enters any
///   namespace, so its whole tree inherits them (the manager checks and repeats both by pid).
///
/// Its `terminate` may tear down the pid namespace instead of signalling processes; the
/// manager still confirms the end from the process table.
pub trait SandboxProvider: Send + Sync {
    /// The backend that spawns into the sandbox of `instance_id`, or why there is none now
    /// (shown to the user).
    ///
    /// # Errors
    ///
    /// The reason when the Instance has no usable sandbox now.
    fn backend(&self, instance_id: &str) -> Result<Arc<dyn IsolationBackend>, Text>;
}

/// Spawn `program args…` with `cmd`'s environment, directory and output, as the leader of a new
/// process group, with nothing but stdio inherited.
fn launch(program: OsString, args: Vec<OsString>, cmd: AppCommand) -> io::Result<SpawnedApp> {
    let AppCommand {
        env,
        cwd,
        output,
        limits,
        ..
    } = cmd;
    let stderr = output.try_clone()?;
    let mut c = tokio::process::Command::new(program);
    c.args(args)
        .env_clear()
        .envs(env)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(stderr))
        .process_group(0)
        // The App outlives a dropped handle: only an explicit stop ends it.
        .kill_on_drop(false);
    // SAFETY: runs in the forked child before exec (after stdio is in place) and only calls
    // async-signal-safe functions (write, setrlimit, fcntl / close_range).
    unsafe {
        c.pre_exec(move || {
            if let Some(fd) = limits.cgroup_procs {
                // "0" moves the writing process; the manager confirms it after the spawn.
                libc::write(fd, b"0".as_ptr().cast(), 1);
            }
            if let Some(n) = limits.open_files {
                // A limit the user asked for is in force before the App runs, or it does not run.
                crate::limits::set_open_files(n)?;
            }
            crate::process::cloexec_from(3);
            Ok(())
        });
    }
    let child = c.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("the started process has no pid"))?;
    // Our child: its pid cannot be reused before we reap it, so this is its identity even when
    // it already exited.
    let identity = proc::identity(pid).unwrap_or_else(|| ProcessIdentity {
        pid,
        started_us: proc::now_start_us(),
    });
    Ok(SpawnedApp {
        child,
        identity,
        access: None,
    })
}

/// Wait at most `limit` for `child`, killing it after that.
#[cfg(target_os = "macos")]
pub(crate) fn wait_bounded(
    child: &mut std::process::Child,
    limit: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// The App capabilities this host offers (`app_proxy_env`, `app_enforced_proxy`,
/// `app_strict_netns`). `strict_backend`: whether a [`SandboxProvider`] is wired into this
/// build.
#[must_use]
pub fn capabilities(strict_backend: bool) -> Vec<vpn_domain::Capability> {
    use vpn_domain::{Capability, CapabilityState};
    let cap = |name: &str, state, reason: Text| Capability {
        name: name.into(),
        state,
        reason: Some(reason),
    };
    let enforced = match seatbelt::available() {
        Ok(()) => cap(
            "app_enforced_proxy",
            CapabilityState::Supported,
            tr!(
                "macOS Seatbelt: the app's process tree can reach only its Gateway, over TCP, and every other network is refused; it is not complete app isolation (system services that connect on its behalf are not covered)",
                "macOS Seatbelt：App 的程序樹只能以 TCP 連到所屬代理埠，其他網路一律拒絕；不是完整的 App 隔離（系統服務代為連線不在此限）",
                "macOS Seatbelt：アプリのプロセスツリーは TCP で所属のゲートウェイにだけ接続でき、ほかのネットワークはすべて拒否されます。完全なアプリの分離ではありません（システムサービスが代わりに行う接続は対象外です）"
            ),
        ),
        Err(reason) => cap("app_enforced_proxy", CapabilityState::Unsupported, reason),
    };
    let strict = if cfg!(target_os = "linux") {
        match crate::capabilities::linux_host_problem() {
            Some(problem) => cap("app_strict_netns", CapabilityState::Blocked, problem),
            None if strict_backend => cap(
                "app_strict_netns",
                CapabilityState::Supported,
                tr!(
                    "Rootless network namespace: the tunnel is the app's only network interface",
                    "rootless network namespace：App 只有 tunnel 一個網路介面",
                    "rootless network namespace：アプリのネットワークインターフェースはトンネルだけです"
                ),
            ),
            None => cap(
                "app_strict_netns",
                CapabilityState::Unsupported,
                tr!(
                    "This host can build a rootless network namespace, but this version has no strict isolation backend wired in yet",
                    "此主機可建立 rootless network namespace，但這個版本尚未接上嚴格隔離後端",
                    "このホストでは rootless network namespace を作成できますが、このバージョンにはまだ厳格な分離のバックエンドが組み込まれていません"
                ),
            ),
        }
    } else {
        cap(
            "app_strict_netns",
            CapabilityState::Unsupported,
            tr!(
                "Strict isolation (rootless network namespace) is available only on Linux",
                "嚴格隔離（rootless network namespace）只在 Linux 提供",
                "厳格な分離（rootless network namespace）は Linux でのみ利用できます"
            ),
        )
    };
    vec![
        cap(
            "app_proxy_env",
            CapabilityState::Supported,
            tr!(
                "Proxy environment variables only: the traffic of programs that do not read these variables is not protected",
                "只設定代理環境變數：不讀取這些變數的程式，流量不受保護",
                "プロキシ環境変数の設定のみ：これらの変数を読まないプログラムの通信は保護されません"
            ),
        ),
        enforced,
        strict,
    ]
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn pipe() -> (std::io::PipeReader, OwnedFd) {
        let (r, w) = std::io::pipe().unwrap();
        (r, OwnedFd::from(w))
    }

    fn cmd(program: &str, args: &[&str], output: OwnedFd) -> AppCommand {
        AppCommand {
            program: program.into(),
            args: args.iter().map(OsString::from).collect(),
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("ONLY".into(), "this".into()),
            ],
            cwd: std::env::temp_dir(),
            output,
            limits: SpawnLimits::default(),
            access_ports: Vec::new(),
            write_confinement: None,
        }
    }

    #[tokio::test]
    async fn the_app_gets_exact_argv_its_own_env_a_new_group_and_only_stdio() {
        // A descriptor of ours that is not close-on-exec must not leak into the App.
        let (leak, _keep) = std::os::unix::net::UnixStream::pair().unwrap();
        let leaked = std::os::fd::AsRawFd::as_raw_fd(&leak);
        // SAFETY: clearing FD_CLOEXEC on a descriptor this test owns.
        unsafe {
            let flags = libc::fcntl(leaked, libc::F_GETFD);
            libc::fcntl(leaked, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
        let (mut r, w) = pipe();
        let script = format!(
            "printf '%s|' \"$@\"; echo; env | sort | tr '\\n' ' '; echo; [ -e /dev/fd/{leaked} ] && echo LEAKED; ps -o pgid= -p $$ | tr -d ' '; echo err >&2"
        );
        let mut app = Plain
            .spawn(cmd(
                "/bin/sh",
                &["-c", &script, "sh", "a b", "$HOME", "{x}"],
                w,
            ))
            .unwrap();
        let status = app.child.wait().await.unwrap();
        assert!(status.success());
        let mut out = String::new();
        r.read_to_string(&mut out).unwrap();
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("a b|$HOME|{x}|"), "{out}");
        let env = lines.next().unwrap_or_default();
        assert!(
            env.contains("ONLY=this") && !env.contains("HOME=") && !env.contains("RUST"),
            "{env}"
        );
        let pgid = lines.next().unwrap_or_default();
        assert_eq!(
            pgid,
            app.identity.pid.to_string(),
            "own process group: {out}"
        );
        assert!(!out.contains("LEAKED"), "{out}");
        assert!(out.contains("err"), "stderr shares the output: {out}");
        assert!(app.identity.started_us > 0);
    }
}
