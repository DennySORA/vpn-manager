//! The manager's side of a sandbox: creating it, adopting it after a restart, handing its
//! descriptors to workers, starting Apps in it, tearing it down.
#![allow(
    unsafe_code,
    reason = "this module owns lease fds: pidfd syscalls, fcntl and poll via libc"
)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use vpn_domain::{Text, tr};

use super::app::AppEntry;
use super::holder::{self, DESCRIPTORS, HolderConfig, Report, Request, SpawnRequest};
use super::wire;
use crate::process::{self as os, ProcessIdentity};
use crate::sandbox::{ExitStatus, SandboxError, SandboxIdentity, SandboxSpec, SpawnSpec, TUN_NAME};

/// Bound on one exchange with a holder.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on building a sandbox (namespaces, network, mounts).
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: raw syscall with a pid and no flags; the result is checked.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn pidfd_signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: raw syscall on a pidfd we own, no siginfo, no flags.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A pidfd of this process, for a holder to tell whether its manager still lives (none on a
/// kernel without `pidfd_open`: the holder then goes by the connection alone).
fn own_pidfd() -> Vec<OwnedFd> {
    pidfd_open(std::process::id()).into_iter().collect()
}

/// Whether the process behind a pidfd has exited (non-blocking).
fn exited(pidfd: &OwnedFd) -> bool {
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll one pollfd we own, no wait.
    unsafe { libc::poll(&raw mut p, 1, 0) > 0 }
}

/// Wait until the process behind a pidfd has exited; `false` when it cannot be watched.
async fn exit(pidfd: &OwnedFd) -> bool {
    if exited(pidfd) {
        return true;
    }
    let Ok(dup) = pidfd.try_clone() else {
        return false;
    };
    // SAFETY: an `OwnedFd` stays open until the `AsyncFd` owning it is dropped.
    let Ok(watch) = (unsafe { AsyncFd::register_with_interest(dup, Interest::READABLE) }) else {
        return false;
    };
    watch.readable().await.is_ok()
}

/// Wait (bounded) until the process behind a pidfd has exited.
async fn wait_exit(pidfd: &OwnedFd, limit: Duration) -> bool {
    tokio::time::timeout(limit, exit(pidfd))
        .await
        .unwrap_or(false)
}

/// The OS identity of a process right now. The holder and each App tree's init are not dumpable
/// (Apps run with the same uid and must not ptrace them), so no other process can read their
/// program: pid, user and start time identify them (see [`same_process`]).
fn identify(pid: u32) -> io::Result<ProcessIdentity> {
    os::identity(pid)
        .filter(|i| !i.zombie)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the process is gone"))
}

/// Whether `now` is the sandbox process `then` described: pid, user and OS start time (the
/// program of a non-dumpable process cannot be read, so it is not compared).
#[must_use]
pub fn same_process(then: &ProcessIdentity, now: &ProcessIdentity) -> bool {
    then.pid == now.pid && then.uid == now.uid && then.start == now.start && !now.zombie
}

/// The OS start token the holder's own report stands for.
fn reported_start(identity: &SandboxIdentity) -> String {
    format!("{}:{}", identity.boot_id, identity.holder_start)
}

/// Descriptors a worker of this sandbox needs to enter it. Dropped after the spawn.
pub struct WorkerEntry {
    pub(crate) user: OwnedFd,
    pub(crate) net: OwnedFd,
    pub(crate) cap_last: u32,
}

/// One connection's sandbox, held by the manager. See the module documentation.
pub struct SandboxLease {
    identity: SandboxIdentity,
    holder: ProcessIdentity,
    pidfd: OwnedFd,
    control: Arc<Mutex<OwnedFd>>,
    tun: OwnedFd,
    dns_udp: OwnedFd,
    dns_tcp: OwnedFd,
    userns: OwnedFd,
    netns: OwnedFd,
    /// The sandbox's pid namespace (managed Apps start in it); `None` from a holder of an
    /// earlier build.
    pidns: Option<OwnedFd>,
    rendezvous: Option<PathBuf>,
    /// The holder can raise the kernel's TCP buffer limits (one of an earlier build cannot).
    tunes: bool,
}

/// Exchange one request with a holder (blocking, on the blocking pool).
async fn exchange(
    control: Arc<Mutex<OwnedFd>>,
    request: Request,
    fds: Vec<OwnedFd>,
) -> io::Result<(holder::Reply, Vec<OwnedFd>, Option<libc::ucred>)> {
    tokio::task::spawn_blocking(move || {
        let socket = control
            .lock()
            .map_err(|_| io::Error::other("holder connection poisoned"))?;
        let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        wire::send_json(socket.as_raw_fd(), &request, &raw)?;
        drop(fds);
        wire::recv_json::<holder::Reply>(socket.as_raw_fd())?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the sandbox holder closed the connection",
            )
        })
    })
    .await
    .map_err(io::Error::other)?
}

/// Turn a holder's set-up failure into a concrete, user-facing reason.
fn classify(stage: &str, errno: Option<i32>, message: &str) -> SandboxError {
    let denied = matches!(
        errno,
        Some(libc::EPERM | libc::EACCES | libc::EINVAL | libc::ENOSPC | libc::EUSERS)
    );
    let missing = matches!(errno, Some(libc::ENOENT | libc::ENODEV | libc::ENXIO));
    let blocked = SandboxError::Blocked;
    match stage {
        "userns" | "setgroups" | "uid_map" | "gid_map" if denied => blocked(tr!(
            "This host does not let unprivileged users create a user namespace (kernel.unprivileged_userns_clone, user.max_user_namespaces or AppArmor restrictions)",
            "此主機不允許非特權使用者建立 user namespace（kernel.unprivileged_userns_clone、user.max_user_namespaces 或 AppArmor 限制）",
            "このホストでは特権のないユーザーが user namespace を作成できません（kernel.unprivileged_userns_clone、user.max_user_namespaces、または AppArmor による制限）"
        )),
        "tun" if missing => blocked(tr!(
            "This host has no usable /dev/net/tun (the TUN driver is not loaded)",
            "此主機沒有可用的 /dev/net/tun（TUN 驅動未載入）",
            "このホストには使用できる /dev/net/tun がありません（TUN ドライバーが読み込まれていません）"
        )),
        "tun" if denied => blocked(tr!(
            "The TUN device cannot be created in the sandbox (/dev/net/tun permissions, AppArmor or seccomp restrictions)",
            "sandbox 內無法建立 TUN 裝置（/dev/net/tun 權限、AppArmor 或 seccomp 限制）",
            "サンドボックス内で TUN デバイスを作成できません（/dev/net/tun の権限、AppArmor、または seccomp による制限）"
        )),
        "netlink" | "lo" | "tun_up" | "address" | "route" | "dns" if denied => blocked(tr!(
            "The network cannot be set up in the sandbox (permission denied, possibly by AppArmor or seccomp)",
            "sandbox 內無法設定網路（權限被拒，可能受 AppArmor 或 seccomp 限制）",
            "サンドボックス内でネットワークを設定できません（権限が拒否されました。AppArmor または seccomp による制限の可能性があります）"
        )),
        "mounts" if denied => blocked(tr!(
            "The host's directories cannot be covered in the sandbox (mount was refused)",
            "sandbox 內無法遮蔽主機的目錄（mount 被拒）",
            "サンドボックス内でホストのディレクトリを覆い隠せません（mount が拒否されました）"
        )),
        "proc" if denied || errno == Some(libc::EBUSY) => blocked(tr!(
            "A private /proc cannot be mounted in the sandbox (the host's /proc is masked, as is common in containers); isolation cannot be guaranteed",
            "sandbox 內無法掛載私有 /proc（主機的 /proc 有遮蔽，常見於容器內）；無法保證隔離",
            "サンドボックス内に専用の /proc をマウントできません（ホストの /proc が覆い隠されています。コンテナー内でよくあります）。分離を保証できません"
        )),
        "pidns" if denied => blocked(tr!(
            "This host does not allow creating a pid namespace",
            "此主機不允許建立 pid namespace",
            "このホストでは pid namespace を作成できません"
        )),
        _ => SandboxError::Failed(tr!(
            "Building the sandbox failed ({stage}): {message}",
            "sandbox 建立失敗（{stage}）：{message}",
            "サンドボックスの作成に失敗しました（{stage}）：{message}"
        )),
    }
}

impl SandboxLease {
    /// Build a new sandbox with `exe sandbox-holder` (the running `vpnd`).
    ///
    /// # Errors
    ///
    /// [`SandboxError`] when the holder cannot be started or the host refuses a namespace, the TUN
    /// device or another stage of the setup.
    pub async fn create(exe: &Path, spec: SandboxSpec) -> Result<Self, SandboxError> {
        let config = HolderConfig {
            installation_id: spec.installation_id,
            instance_id: spec.instance_id,
            epoch: spec.epoch,
            tun_name: TUN_NAME.into(),
            mtu: spec.mtu,
            addresses: spec.addresses,
            hide: spec.hide,
            xdg_runtime_dir: spec.xdg_runtime_dir,
            rendezvous: Some(spec.rendezvous),
            orphan_grace_secs: spec.orphan_grace.as_secs(),
            probe: false,
        };
        let (control, holder, identity, fds) = start_holder(exe, config.clone()).await?;
        // Started from this program: it knows every request this program sends.
        let lease = Self::from_parts(control, holder, identity, fds, config.rendezvous, true)?;
        tracing::info!(
            instance = %lease.identity.instance_id,
            epoch = lease.identity.epoch,
            holder = lease.holder.pid,
            "sandbox created"
        );
        Ok(lease)
    }

    fn from_parts(
        control: OwnedFd,
        pid: u32,
        identity: SandboxIdentity,
        fds: Vec<OwnedFd>,
        rendezvous: Option<PathBuf>,
        tunes: bool,
    ) -> Result<Self, SandboxError> {
        if !(DESCRIPTORS - 1..=DESCRIPTORS).contains(&fds.len()) {
            return Err(SandboxError::Failed(
                "sandbox holder sent the wrong descriptors".into(),
            ));
        }
        // Open the pidfd first, then check the start time: if they match, the pidfd names the
        // holder and no recycled pid.
        let pidfd = pidfd_open(pid)?;
        let holder = identify(pid)?;
        if holder.start != reported_start(&identity) {
            return Err(SandboxError::Failed(
                "sandbox holder identity does not match its process".into(),
            ));
        }
        let mut fds = fds.into_iter();
        let mut next = || {
            fds.next()
                .ok_or_else(|| SandboxError::Failed("missing descriptor".into()))
        };
        Ok(Self {
            tun: next()?,
            dns_udp: next()?,
            dns_tcp: next()?,
            userns: next()?,
            netns: next()?,
            pidns: next().ok(),
            identity,
            holder,
            pidfd,
            control: Arc::new(Mutex::new(control)),
            rendezvous,
            tunes,
        })
    }

    /// Adopt a sandbox left by a previous manager, if it proves it is ours: same installation,
    /// same boot, and its pid still names the process that reported the identity.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Failed`] when nobody answers on `socket`, the sandbox belongs to another
    /// installation or boot, its pid now names another process, or its answer is unexpected.
    pub async fn attach(socket: &Path, installation_id: &str) -> Result<Self, SandboxError> {
        let Identified {
            control,
            identity,
            holder,
            tunes,
            ..
        } = identified(socket).await?;
        let pid = holder.pid;
        if identity.installation_id != installation_id {
            return Err(SandboxError::Failed(
                "sandbox belongs to another installation".into(),
            ));
        }
        let (reply, fds, _) = exchange(control.clone(), Request::Attach, own_pidfd()).await?;
        match reply {
            holder::Reply::Attached => {}
            holder::Reply::Busy => {
                return Err(SandboxError::Failed(
                    "another manager still manages this sandbox".into(),
                ));
            }
            _ => return Err(SandboxError::Failed("sandbox refused to attach".into())),
        }
        let control = Arc::try_unwrap(control)
            .map_err(|_| SandboxError::Failed("holder connection still in use".into()))?
            .into_inner()
            .map_err(|_| SandboxError::Failed("holder connection poisoned".into()))?;
        let rendezvous = Some(socket.to_path_buf());
        let lease = Self::from_parts(control, pid, identity, fds, rendezvous, tunes)?;
        tracing::info!(
            instance = %lease.identity.instance_id,
            epoch = lease.identity.epoch,
            holder = lease.holder.pid,
            "sandbox adopted"
        );
        Ok(lease)
    }

    #[must_use]
    pub const fn identity(&self) -> &SandboxIdentity {
        &self.identity
    }

    /// The holder process (pid 1 of the sandbox's pid namespace). It is not dumpable, so its
    /// program is not known (`exe` is `None`); compare identities with [`same_process`].
    #[must_use]
    pub const fn holder(&self) -> &ProcessIdentity {
        &self.holder
    }

    #[must_use]
    pub fn is_alive(&self) -> bool {
        !exited(&self.pidfd)
    }

    /// Resolves once the holder has exited (killed, out of memory, crashed): the sandbox's Apps
    /// went with it — it is their pid namespace's init — and nothing can start in it again.
    /// Never resolves where the holder cannot be watched; [`Self::check`] still tells then.
    pub async fn holder_gone(&self) {
        if !exit(&self.pidfd).await {
            std::future::pending::<()>().await;
        }
    }

    /// Whether the sandbox is intact: its holder alive, its network namespace still holding
    /// exactly `lo` and the TUN device, the TUN descriptor still attached.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Failed`] when the holder is gone, does not answer, or reports a problem.
    pub async fn check(&self) -> Result<(), SandboxError> {
        if !self.is_alive() {
            return Err(SandboxError::Failed("sandbox holder is gone".into()));
        }
        let (reply, _, _) = exchange(self.control.clone(), Request::Check, Vec::new()).await?;
        match reply {
            holder::Reply::Checked { problem: None } => Ok(()),
            holder::Reply::Checked {
                problem: Some(problem),
            } => Err(SandboxError::Failed(problem.into())),
            _ => Err(SandboxError::Failed(
                "unexpected answer from the sandbox".into(),
            )),
        }
    }

    /// Raise the kernel's limits on the receive and the send buffer of one TCP socket in the
    /// sandbox to at least these, in bytes; the limits in force afterwards. The kernel sizes
    /// each socket's buffers itself, up to them; a limit is never lowered. `None` from a
    /// holder of an earlier build, which cannot: the kernel's own limits stand.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Failed`] when the holder is gone, does not answer or could not set them.
    pub async fn raise_tcp_limits(
        &self,
        receive_max: u64,
        send_max: u64,
    ) -> Result<Option<(u64, u64)>, SandboxError> {
        if !self.tunes {
            return Ok(None);
        }
        let request = Request::Tune {
            receive_max,
            send_max,
        };
        let (reply, _, _) = exchange(self.control.clone(), request, Vec::new()).await?;
        match reply {
            holder::Reply::Tuned {
                receive_max,
                send_max,
            } => Ok(Some((receive_max, send_max))),
            holder::Reply::Failed { message, .. } => Err(SandboxError::Failed(message.into())),
            _ => Err(SandboxError::Failed(
                "unexpected answer from the sandbox".into(),
            )),
        }
    }

    /// The namespaces a worker joins (user, then network) before it starts.
    ///
    /// # Errors
    ///
    /// Fails when a namespace descriptor cannot be duplicated.
    pub fn worker_entry(&self) -> io::Result<WorkerEntry> {
        Ok(WorkerEntry {
            user: self.userns.try_clone()?,
            net: self.netns.try_clone()?,
            cap_last: super::caps::last_capability(),
        })
    }

    /// What managed Apps need to start in this sandbox: its user, network and pid namespaces,
    /// and the directories their own mount namespaces cover (`hide` read-only and empty, the
    /// usual socket directories and `xdg_runtime_dir` empty and private).
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::Unsupported`] for a sandbox without a pid namespace (made by an older
    /// version); otherwise fails when a namespace descriptor cannot be duplicated.
    pub fn app_entry(
        &self,
        hide: Vec<PathBuf>,
        xdg_runtime_dir: Option<PathBuf>,
    ) -> io::Result<AppEntry> {
        let pid = self.pidns.as_ref().ok_or_else(|| {
            tr!(
                "This sandbox was built by an older version and cannot start apps; restart the connection to rebuild it",
                "這個 sandbox 由較舊的版本建立，無法啟動 App；請重新啟動連線以重建 sandbox",
                "このサンドボックスは古いバージョンで作成されたため、アプリを起動できません。接続を再起動してサンドボックスを作り直してください"
            )
            .into_io_error(io::ErrorKind::Unsupported)
        })?;
        Ok(AppEntry {
            user: self.userns.try_clone()?,
            net: self.netns.try_clone()?,
            pid: pid.try_clone()?,
            hide,
            xdg_runtime_dir,
            epoch: self.identity.epoch,
        })
    }

    /// The TUN device (a new descriptor for the worker).
    ///
    /// # Errors
    ///
    /// Fails when the descriptor cannot be duplicated.
    pub fn tun(&self) -> io::Result<OwnedFd> {
        self.tun.try_clone()
    }

    /// The resolver's UDP socket on 127.0.0.53:53 inside the sandbox.
    ///
    /// # Errors
    ///
    /// Fails when the descriptor cannot be duplicated.
    pub fn dns_udp(&self) -> io::Result<OwnedFd> {
        self.dns_udp.try_clone()
    }

    /// The resolver's TCP listener on 127.0.0.53:53 inside the sandbox.
    ///
    /// # Errors
    ///
    /// Fails when the descriptor cannot be duplicated.
    pub fn dns_tcp(&self) -> io::Result<OwnedFd> {
        self.dns_tcp.try_clone()
    }

    /// Start a process in the sandbox. Returns once it was `exec`uted (or failed to be).
    ///
    /// # Errors
    ///
    /// [`SandboxError`] when the holder does not answer or cannot start the process.
    pub async fn spawn(&self, spec: SpawnSpec) -> Result<SandboxProcess, SandboxError> {
        spawn_on(&self.control, spec).await
    }

    /// Tear the sandbox down: every process in it gets SIGTERM, then (after `grace`) the holder
    /// leaves and the kernel kills what is left; the holder is killed outright if it does not
    /// answer. Returns once the holder is gone (`true`), or could not be confirmed gone (`false`,
    /// logged; its rendezvous socket then stays, so recovery can still find it).
    pub async fn teardown(self, grace: Duration) -> bool {
        let grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
        let asked = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(
                self.control.clone(),
                Request::Shutdown { grace_ms },
                Vec::new(),
            ),
        )
        .await;
        let mut gone = matches!(asked, Ok(Ok(_)))
            && wait_exit(&self.pidfd, grace + Duration::from_secs(2)).await;
        if !gone {
            let _ = pidfd_signal(&self.pidfd, libc::SIGKILL);
            gone = wait_exit(&self.pidfd, Duration::from_secs(5)).await;
        }
        if gone {
            // A holder that was killed could not remove its socket file.
            if let Some(path) = &self.rendezvous {
                let _ = std::fs::remove_file(path);
            }
            tracing::info!(
                instance = %self.identity.instance_id,
                epoch = self.identity.epoch,
                "sandbox torn down"
            );
        } else {
            tracing::error!(
                instance = %self.identity.instance_id,
                holder = self.holder.pid,
                "sandbox holder did not exit"
            );
        }
        gone
    }
}

/// Ask the holder on `control` to start a process; wait until it was `exec`uted.
async fn spawn_on(
    control: &Arc<Mutex<OwnedFd>>,
    spec: SpawnSpec,
) -> Result<SandboxProcess, SandboxError> {
    if spec.argv.is_empty() {
        return Err(SandboxError::Failed("empty command".into()));
    }
    let (mine, theirs) = wire::seqpacket_pair()?;
    wire::pass_credentials(mine.as_raw_fd())?;
    wire::set_receive_timeout(mine.as_raw_fd(), REQUEST_TIMEOUT)?;
    let request = SpawnRequest {
        argv: spec.argv,
        env: spec.env,
        cwd: spec.cwd,
        umask: spec.umask,
        stdin: spec.stdin.is_some(),
        stdout: spec.stdout.is_some(),
        stderr: spec.stderr.is_some(),
    };
    let mut fds = vec![theirs];
    fds.extend(spec.stdin);
    fds.extend(spec.stdout);
    fds.extend(spec.stderr);
    let (reply, _, _) = exchange(control.clone(), Request::Spawn(Box::new(request)), fds).await?;
    match reply {
        holder::Reply::Spawned => {}
        holder::Reply::SpawnFailed { message } => {
            return Err(SandboxError::Failed(message.into()));
        }
        _ => {
            return Err(SandboxError::Failed(
                "unexpected answer from the sandbox".into(),
            ));
        }
    }
    let (mine, init, app) = tokio::task::spawn_blocking(move || {
        let mut init = None;
        let mut app = None;
        loop {
            let Some((report, _, creds)) = wire::recv_json::<Report>(mine.as_raw_fd())? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the App ended before it started",
                ));
            };
            let pid = creds.map(|c| c.pid.cast_unsigned());
            match report {
                Report::Init => init = pid,
                Report::App => app = pid,
                Report::Exec { errno: 0 } => break,
                Report::Exec { errno } => {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                Report::Exited { .. } => {}
            }
        }
        match (init, app) {
            (Some(i), Some(a)) => Ok((mine, i, a)),
            _ => Err(io::Error::other("the App's process ids were not reported")),
        }
    })
    .await
    .map_err(io::Error::other)?
    .map_err(|e| {
        SandboxError::Failed(tr!(
            "Cannot start in the sandbox: {e}",
            "無法在 sandbox 內啟動：{e}",
            "サンドボックス内で起動できません：{e}";
            e = Text::of_io_error(&e)
        ))
    })?;
    let init_pidfd = pidfd_open(init)?;
    // Either may already have ended (an App that exits at once takes its tree with it): their
    // identity is then unknown, not invented.
    let tree_init = identify(init).ok();
    let identity = identify(app).ok();
    // SAFETY: plain fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(mine.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(mine.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    // SAFETY: an `OwnedFd` stays open until the `AsyncFd` owning it is dropped.
    let report = unsafe { AsyncFd::register_with_interest(mine, Interest::READABLE) }
        .map_err(io::Error::from)?;
    Ok(SandboxProcess {
        pid: app,
        identity,
        tree_init_pid: init,
        tree_init,
        init_pidfd,
        report,
        status: None,
    })
}

/// A holder that answered and proved who it is.
struct Identified {
    control: Arc<Mutex<OwnedFd>>,
    identity: SandboxIdentity,
    holder: ProcessIdentity,
    managed: bool,
    tunes: bool,
}

/// Connect to a holder's rendezvous socket and check who answers: our user, this boot, and a
/// pid that still names the process that reported the identity.
async fn identified(socket: &Path) -> Result<Identified, SandboxError> {
    let path = socket.to_path_buf();
    let control = tokio::task::spawn_blocking(move || -> io::Result<OwnedFd> {
        let fd = holder::connect_to(&path)?;
        wire::pass_credentials(fd.as_raw_fd())?;
        wire::set_receive_timeout(fd.as_raw_fd(), REQUEST_TIMEOUT)?;
        Ok(fd)
    })
    .await
    .map_err(io::Error::other)??;
    let control = Arc::new(Mutex::new(control));
    let (reply, _, creds) = exchange(control.clone(), Request::Identify, Vec::new()).await?;
    let holder::Reply::Identity {
        identity,
        managed,
        tunes,
    } = reply
    else {
        return Err(SandboxError::Failed(
            "unexpected answer from a sandbox".into(),
        ));
    };
    let creds = creds.ok_or_else(|| SandboxError::Failed("no peer credentials".into()))?;
    if creds.uid != os::current_uid() {
        return Err(SandboxError::Failed(
            "sandbox belongs to another user".into(),
        ));
    }
    if identity.boot_id != holder::boot_id()? {
        return Err(SandboxError::Failed("sandbox is from another boot".into()));
    }
    let holder = identify(creds.pid.cast_unsigned())?;
    if holder.start != reported_start(&identity) {
        return Err(SandboxError::Failed(
            "sandbox identity does not match its process".into(),
        ));
    }
    Ok(Identified {
        control,
        identity: *identity,
        holder,
        managed,
        tunes,
    })
}

/// A connection to a sandbox that may start processes in it but does not manage it.
///
/// The manager keeps managing it. This is for diagnostics such as `vpnd sandbox-exec`, and for
/// recovery, which tells a sandbox in use from a leftover by [`SandboxClient::managed`].
pub struct SandboxClient {
    control: Arc<Mutex<OwnedFd>>,
    identity: SandboxIdentity,
    holder: ProcessIdentity,
    managed: bool,
}

impl SandboxClient {
    /// Connect to the holder listening on the rendezvous `socket` and learn its identity.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Failed`] when nobody answers on `socket` or the answer is not a holder's
    /// identity.
    pub async fn connect(socket: &Path) -> Result<Self, SandboxError> {
        let Identified {
            control,
            identity,
            holder,
            managed,
            ..
        } = identified(socket).await?;
        Ok(Self {
            control,
            identity,
            holder,
            managed,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &SandboxIdentity {
        &self.identity
    }

    /// The holder process (program unknown: it is not dumpable).
    #[must_use]
    pub const fn holder(&self) -> &ProcessIdentity {
        &self.holder
    }

    /// Whether a manager managed the sandbox when it answered: its connection, or its process
    /// that still lives.
    #[must_use]
    pub const fn managed(&self) -> bool {
        self.managed
    }

    /// Start a process in the sandbox. Returns once it was `exec`uted (or failed to be).
    ///
    /// # Errors
    ///
    /// [`SandboxError`] when the holder does not answer or cannot start the process.
    pub async fn spawn(&self, spec: SpawnSpec) -> Result<SandboxProcess, SandboxError> {
        spawn_on(&self.control, spec).await
    }
}

/// Whether a holder listens on a rendezvous socket: `Some(false)` nobody does (refused, or no
/// such file), `Some(true)` someone does, `None` it could not be told.
#[must_use]
pub fn listening(socket: &Path) -> Option<bool> {
    match holder::connect_nonblocking(socket) {
        Ok(_) => Some(true),
        Err(e) => match e.raw_os_error() {
            Some(libc::ECONNREFUSED | libc::ENOENT) => Some(false),
            // The backlog is full: someone is there.
            Some(libc::EAGAIN) => Some(true),
            _ => None,
        },
    }
}

/// Start `exe sandbox-holder`, send it `config` and wait for `Ready` (or its reason not to be).
async fn start_holder(
    exe: &Path,
    config: HolderConfig,
) -> Result<(OwnedFd, u32, SandboxIdentity, Vec<OwnedFd>), SandboxError> {
    let (mine, theirs) = wire::seqpacket_pair()?;
    wire::pass_credentials(mine.as_raw_fd())?;
    wire::set_receive_timeout(mine.as_raw_fd(), SETUP_TIMEOUT)?;
    let mut first = crate::process::spawn_with_control_fd(exe, ["sandbox-holder"], theirs)?;
    let control = Arc::new(Mutex::new(mine));
    let result = exchange(
        control.clone(),
        Request::Setup(Box::new(config)),
        own_pidfd(),
    )
    .await;
    // The first process forks the holder and leaves at once.
    if tokio::time::timeout(Duration::from_secs(5), first.wait())
        .await
        .is_err()
    {
        let _ = first.start_kill();
        let _ = first.wait().await;
    }
    let (reply, fds, creds) = result
        .map_err(|e| SandboxError::Failed(format!("sandbox holder did not start: {e}").into()))?;
    match reply {
        holder::Reply::Ready { identity } => {
            let pid = creds
                .map(|c| c.pid.cast_unsigned())
                .ok_or_else(|| SandboxError::Failed("no holder credentials".into()))?;
            let control = Arc::try_unwrap(control)
                .map_err(|_| SandboxError::Failed("holder connection still in use".into()))?
                .into_inner()
                .map_err(|_| SandboxError::Failed("holder connection poisoned".into()))?;
            Ok((control, pid, *identity, fds))
        }
        holder::Reply::Failed {
            stage,
            errno,
            message,
        } => Err(classify(&stage, errno, &message)),
        _ => Err(SandboxError::Failed(
            "unexpected answer from the sandbox holder".into(),
        )),
    }
}

/// Build a throw-away sandbox to find out whether this host allows one at all. Nothing stays:
/// the holder reports and exits, its namespaces vanish with it.
///
/// # Errors
///
/// [`SandboxError`] naming what the host refuses (user, network or pid namespace, TUN device, ...).
pub async fn probe(exe: &Path) -> Result<(), SandboxError> {
    let config = HolderConfig {
        installation_id: String::new(),
        instance_id: "probe".into(),
        epoch: 0,
        tun_name: TUN_NAME.into(),
        mtu: 1280,
        addresses: vec![("192.0.2.1".parse().map_err(io::Error::other)?, 32)],
        hide: Vec::new(),
        xdg_runtime_dir: None,
        rendezvous: None,
        orphan_grace_secs: 0,
        probe: true,
    };
    start_holder(exe, config).await.map(|_| ())
}

/// Rendezvous sockets in a manager's runtime directory (`sb-*.sock`).
#[must_use]
pub fn discover(run: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(run) else {
        return Vec::new();
    };
    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "rendezvous sockets are named `sb-<id>.sock` by the holder itself"
    )]
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sb-") && n.ends_with(".sock"))
        })
        .collect();
    found.sort();
    found
}

/// A process started in a sandbox.
pub struct SandboxProcess {
    pid: u32,
    identity: Option<ProcessIdentity>,
    tree_init_pid: u32,
    tree_init: Option<ProcessIdentity>,
    init_pidfd: OwnedFd,
    report: AsyncFd<OwnedFd>,
    status: Option<ExitStatus>,
}

impl SandboxProcess {
    /// Host pid of the App process.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// The App process as the OS knows it (pid, user, start time, program), observed right after
    /// its `exec`; `None` if it had already ended by then.
    #[must_use]
    pub const fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// Host pid of the init of the App's tree (pid 1 of its nested pid namespace).
    #[must_use]
    pub const fn tree_init_pid(&self) -> u32 {
        self.tree_init_pid
    }

    /// The tree's init (not dumpable: no program); `None` if the tree had already ended.
    #[must_use]
    pub const fn tree_init(&self) -> Option<&ProcessIdentity> {
        self.tree_init.as_ref()
    }

    /// Send `signal` to every process of the App's tree (through its init).
    ///
    /// # Errors
    ///
    /// Fails when the signal cannot be sent through the init's pidfd.
    pub fn signal(&self, signal: i32) -> io::Result<()> {
        pidfd_signal(&self.init_pidfd, signal)
    }

    /// Kill the whole tree at once: killing its init ends its pid namespace.
    ///
    /// # Errors
    ///
    /// Fails when the signal cannot be sent through the init's pidfd.
    pub fn kill_tree(&self) -> io::Result<()> {
        pidfd_signal(&self.init_pidfd, libc::SIGKILL)
    }

    /// Wait until the whole tree has ended. The App's own status, if it was reported (an App
    /// killed together with its init has none).
    pub async fn wait(&mut self) -> Option<ExitStatus> {
        loop {
            let Ok(mut guard) = self.report.readable().await else {
                return self.status;
            };
            let got = guard.try_io(|fd| wire::recv(fd.get_ref().as_raw_fd()));
            match got {
                Ok(Ok(Some(msg))) => {
                    if let Ok(Report::Exited { code, signal }) = serde_json::from_slice(&msg.data) {
                        self.status = match (code, signal) {
                            (Some(c), _) => Some(ExitStatus::Code(c)),
                            (None, Some(s)) => Some(ExitStatus::Signal(s)),
                            _ => None,
                        };
                    }
                }
                Ok(Ok(None) | Err(_)) => return self.status,
                Err(_would_block) => {}
            }
        }
    }

    /// SIGTERM to the tree, then SIGKILL after `grace`; returns once the tree is gone.
    pub async fn terminate(mut self, grace: Duration) -> Option<ExitStatus> {
        let _ = self.signal(libc::SIGTERM);
        if let Ok(status) = tokio::time::timeout(grace, self.wait()).await {
            return status;
        }
        let _ = self.kill_tree();
        tokio::time::timeout(Duration::from_secs(5), self.wait())
            .await
            .unwrap_or(self.status)
    }
}

/// The `WireGuard` underlay socket of a strict worker, made in the host network namespace.
///
/// The worker lives in the sandbox's namespace. The socket is bound to an ephemeral port of the
/// endpoint's family and connected to the endpoint, so the kernel too only accepts datagrams from
/// the pinned peer.
///
/// # Errors
///
/// Fails when the socket cannot be bound or connected.
pub fn underlay_socket(endpoint: std::net::SocketAddr) -> io::Result<OwnedFd> {
    let any: std::net::SocketAddr = if endpoint.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(any)?;
    socket.connect(endpoint)?;
    Ok(OwnedFd::from(socket))
}

/// Static host checks for the capability list; a real [`probe`] is the final word.
///
/// # Errors
///
/// The reason when the host disables or restricts unprivileged user namespaces or lacks what
/// the sandbox needs.
pub fn detect() -> Result<(), Text> {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    if read("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return Err(tr!(
            "This host has turned off unprivileged user namespaces (kernel.unprivileged_userns_clone=0)",
            "此主機停用了非特權 user namespace（kernel.unprivileged_userns_clone=0）",
            "このホストでは特権のない user namespace が無効になっています（kernel.unprivileged_userns_clone=0）"
        ));
    }
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return Err(tr!(
            "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1)",
            "AppArmor 限制了非特權 user namespace（kernel.apparmor_restrict_unprivileged_userns=1）",
            "AppArmor が特権のない user namespace を制限しています（kernel.apparmor_restrict_unprivileged_userns=1）"
        ));
    }
    if read("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        return Err(tr!(
            "This host does not allow creating user namespaces (user.max_user_namespaces=0)",
            "此主機不允許建立 user namespace（user.max_user_namespaces=0）",
            "このホストでは user namespace を作成できません（user.max_user_namespaces=0）"
        ));
    }
    if !Path::new("/dev/net/tun").exists() {
        return Err(tr!(
            "This host has no /dev/net/tun (the TUN driver is not loaded)",
            "此主機沒有 /dev/net/tun（TUN 驅動未載入）",
            "このホストには /dev/net/tun がありません（TUN ドライバーが読み込まれていません）"
        ));
    }
    Ok(())
}
