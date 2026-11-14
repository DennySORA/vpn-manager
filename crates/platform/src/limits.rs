//! Resource limits of the process trees VPN Manager starts: connection workers and managed Apps.
//!
//! **Linux: cgroup v2 under the cgroup systemd delegated to the manager's unit** (`Delegate=yes`,
//! recognised by the `user.delegate`/`trusted.delegate` attribute systemd sets on it). At start
//! the manager moves itself into `<unit>/manager` (in cgroup v2 a cgroup that hands controllers
//! to its children holds no processes itself), enables memory, pids and cpu for `<unit>/workers`
//! and `<unit>/apps`, and removes the empty leftovers there. Each tree then gets a leaf of its own
//! (`workers/<instance>-<generation>`, `apps/<app>`) whose limits are written and read back — the
//! values the kernel accepted are what is reported — and which is removed when the tree has
//! ended. Without such a delegated cgroup (a terminal, the development stack, no systemd) nothing
//! is limited and the capabilities say why.
//!
//! These limits contain runaway trees (a leak, a fork loop). They are not a boundary against a
//! process of the same user, which can move itself into another cgroup it may write.
//!
//! **macOS** has no cgroups and does not enforce `RLIMIT_AS`/`RLIMIT_DATA`; its `RLIMIT_NPROC`
//! counts every process of the user, and there is no CPU-share limit. Memory, CPU and process
//! limits are unsupported there. **Open files** (`RLIMIT_NOFILE`, each process on its own) work
//! on both.
#![allow(
    unsafe_code,
    reason = "resource limits call getrlimit/setrlimit/prlimit64, statfs and getxattr via libc"
)]

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use vpn_domain::{
    Capability, CapabilityState, EnforcedLimit, LimitKind, LimitMechanism, ResourceStatus, Text,
    Timestamp, UnenforcedLimit, tr,
};

/// Which group of trees a leaf belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Workers,
    Apps,
}

impl Group {
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux cgroup code names the directories")
    )]
    const fn dir(self) -> &'static str {
        match self {
            Self::Workers => "workers",
            Self::Apps => "apps",
        }
    }
}

/// What one leaf limits; `None` leaves the resource alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeLimits {
    pub memory_bytes: Option<u64>,
    pub tasks: Option<u64>,
    /// Percent of one core.
    pub cpu_percent: Option<u32>,
}

/// The resource control this manager has, decided once at start.
pub struct ResourceControl {
    cgroups: Result<sys::Cgroups, Text>,
}

/// Why `controller` limits nothing: systemd did not delegate it.
fn not_delegated(controller: &str) -> Text {
    tr!(
        "systemd did not delegate the {controller} controller to this service's cgroup",
        "systemd 沒有把 {controller} controller 委派給這個服務的 cgroup",
        "systemd がこのサービスの cgroup に {controller} コントローラーを委任していません"
    )
}

impl ResourceControl {
    /// Find and prepare the delegated cgroup (Linux); on other systems, or when there is none,
    /// a control that limits nothing and says why. Call once, early, before any child starts:
    /// on Linux it moves this process into its leaf. `unit_delegated`: the unit this process
    /// runs in has `Delegate=yes` (systemd's user manager marks no cgroup as delegated; the
    /// installer's unit says so on the command line).
    pub fn init(unit_delegated: bool) -> Self {
        let cgroups = sys::Cgroups::init(unit_delegated);
        match &cgroups {
            Ok(c) => tracing::info!(cgroup = %c.rel, "resource limits: delegated cgroup in use"),
            Err(reason) => {
                tracing::info!(reason = %reason.en, "resource limits: no delegated cgroup");
            }
        }
        Self { cgroups }
    }

    /// A control that limits nothing, with the reason (tests; managers without systemd).
    pub fn none(reason: impl Into<Text>) -> Self {
        Self {
            cgroups: Err(reason.into()),
        }
    }

    /// Why `kind` cannot be limited here; `None` when it can.
    #[must_use]
    pub fn unavailable(&self, kind: LimitKind) -> Option<Text> {
        if kind == LimitKind::OpenFiles {
            return None;
        }
        match &self.cgroups {
            Err(reason) => Some(reason.clone()),
            Ok(c) => {
                let (ok, controller) = match kind {
                    LimitKind::Memory => (c.memory, "memory"),
                    LimitKind::Processes => (c.pids, "pids"),
                    LimitKind::Cpu => (c.cpu, "cpu"),
                    LimitKind::OpenFiles => (true, ""),
                };
                (!ok).then(|| not_delegated(controller))
            }
        }
    }

    /// `limit_memory`, `limit_cpu`, `limit_processes`, `limit_open_files`.
    #[must_use]
    pub fn capabilities(&self) -> Vec<Capability> {
        let what = [
            (
                LimitKind::Memory,
                "limit_memory",
                tr!(
                    "cgroup v2 memory.max: a memory limit for the whole process tree (no swap); the system ends it when it goes over",
                    "cgroup v2 memory.max：整個程序樹的記憶體上限（不使用 swap），超過時由系統結束",
                    "cgroup v2 memory.max：プロセスツリー全体のメモリ上限（スワップは使いません）。超えるとシステムが終了させます"
                ),
            ),
            (
                LimitKind::Cpu,
                "limit_cpu",
                tr!(
                    "cgroup v2 cpu.max: a CPU time limit for the whole process tree (a percentage of one core)",
                    "cgroup v2 cpu.max：整個程序樹的 CPU 時間上限（單一核心的百分比）",
                    "cgroup v2 cpu.max：プロセスツリー全体の CPU 時間の上限（1 コアに対する割合）"
                ),
            ),
            (
                LimitKind::Processes,
                "limit_processes",
                tr!(
                    "cgroup v2 pids.max: a limit on the total number of processes and threads of the whole process tree",
                    "cgroup v2 pids.max：整個程序樹的程序與執行緒總數上限",
                    "cgroup v2 pids.max：プロセスツリー全体のプロセスとスレッドの総数の上限"
                ),
            ),
            (
                LimitKind::OpenFiles,
                "limit_open_files",
                tr!(
                    "RLIMIT_NOFILE: the most files each process may have open on its own (sockets included)",
                    "RLIMIT_NOFILE：每個程序各自最多開啟的檔案數（含 socket）",
                    "RLIMIT_NOFILE：各プロセスがそれぞれ開けるファイル数の上限（ソケットを含む）"
                ),
            ),
        ];
        what.into_iter()
            .map(|(kind, name, how)| {
                self.unavailable(kind).map_or_else(
                    || Capability {
                        name: name.into(),
                        state: CapabilityState::Supported,
                        reason: Some(how),
                    },
                    |reason| Capability {
                        name: name.into(),
                        state: CapabilityState::Unsupported,
                        reason: Some(reason),
                    },
                )
            })
            .collect()
    }

    /// A new leaf for one tree with `limits` written and read back. A limit whose controller is
    /// missing is listed as not enforced; `Err` when there is no delegated cgroup at all or the
    /// leaf could not be made.
    ///
    /// # Errors
    ///
    /// The reason when there is no delegated cgroup or the leaf cannot be created.
    pub fn create(&self, group: Group, name: &str, limits: &TreeLimits) -> Result<Leaf, Text> {
        match &self.cgroups {
            Ok(c) => c.create(group, name, limits),
            Err(reason) => Err(reason.clone()),
        }
    }
}

/// One tree's cgroup.
pub struct Leaf {
    path: PathBuf,
    /// Below the delegated cgroup: `workers/<id>-<generation>`, `apps/<id>`.
    rel: String,
    /// `cgroup.procs`, opened for writing: a child writes `0` to it to move itself in.
    procs: OwnedFd,
    enforced: Vec<EnforcedLimit>,
    unenforced: Vec<UnenforcedLimit>,
}

impl Leaf {
    #[must_use]
    pub fn rel(&self) -> &str {
        &self.rel
    }

    /// The open `cgroup.procs`, for a child to join before `exec`.
    #[must_use]
    pub fn procs_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// Move process `pid` (all its threads) into this cgroup.
    ///
    /// # Errors
    ///
    /// Fails when `cgroup.procs` cannot be written (no such process, or not permitted).
    pub fn place(&self, pid: u32) -> std::io::Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), pid.to_string())
    }

    /// Whether `pid` is in this cgroup now.
    #[must_use]
    pub fn contains(&self, pid: u32) -> bool {
        sys::cgroup_of(pid).is_some_and(|p| p.ends_with(&format!("/{}", self.rel)))
    }

    /// The processes in it now (`None`: could not be read).
    #[must_use]
    pub fn pids(&self) -> Option<Vec<u32>> {
        let text = std::fs::read_to_string(self.path.join("cgroup.procs")).ok()?;
        Some(text.lines().filter_map(|l| l.trim().parse().ok()).collect())
    }

    /// Times the kernel killed a process of it for exceeding `memory.max`.
    #[must_use]
    pub fn oom_kills(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.path.join("memory.events")).ok()?;
        text.lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|v| v.trim().parse().ok())
    }

    /// The limit in force for `kind`, as the kernel accepted it.
    #[must_use]
    pub fn enforced(&self, kind: LimitKind) -> Option<u64> {
        self.enforced
            .iter()
            .find(|e| e.kind == kind)
            .map(|e| e.value)
    }

    /// The tree's confinement now: limits in force (read back at creation), the ones that are
    /// not, current memory and OOM kills.
    #[must_use]
    pub fn status(&self) -> ResourceStatus {
        let memory = std::fs::read_to_string(self.path.join("memory.current"))
            .ok()
            .and_then(|v| v.trim().parse().ok());
        ResourceStatus {
            cgroup: Some(self.rel.clone()),
            enforced: self.enforced.clone(),
            unenforced: self.unenforced.clone(),
            memory_bytes: memory,
            oom_kills: self.oom_kills(),
            observed_at: Timestamp::now(),
        }
    }

    /// SIGKILL every process still in it (`cgroup.kill`, Linux 5.14+).
    ///
    /// # Errors
    ///
    /// Fails when `cgroup.kill` cannot be written (missing before Linux 5.14).
    pub fn kill(&self) -> std::io::Result<()> {
        std::fs::write(self.path.join("cgroup.kill"), "1")
    }

    /// Remove it; fails while a process is still in it.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be removed, e.g. while a process is still in it; an already
    /// missing cgroup is not an error.
    pub fn remove(&self) -> std::io::Result<()> {
        match std::fs::remove_dir(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

/// Set this process's open-files limit (soft and hard) to `n`. Async-signal-safe: meant for a
/// child between `fork` and `exec`.
///
/// # Errors
///
/// Fails with the OS error when `setrlimit` refuses the value.
pub fn set_open_files(n: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: n as libc::rlim_t,
        rlim_max: n as libc::rlim_t,
    };
    // SAFETY: setrlimit with a valid rlimit; no memory is touched besides `lim`.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The open-files limit this process may hand to a child (its hard limit; only lowering is
/// allowed without privileges).
#[must_use]
pub fn open_files_max() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills `lim`.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } == 0).then_some(lim.rlim_max)
}

/// Set (and read back) the open-files limit of another process of ours (Linux `prlimit`), for
/// a tree started by a backend that could not set it before `exec`.
///
/// # Errors
///
/// Fails when `pid` is out of range or `prlimit` refuses either call; always on other systems
/// than Linux.
pub fn set_open_files_of(pid: u32, n: u64) -> std::io::Result<u64> {
    sys::set_open_files_of(pid, n)
}

/// What a limit is in force as, for a status.
#[must_use]
pub const fn enforced(kind: LimitKind, mechanism: LimitMechanism, value: u64) -> EnforcedLimit {
    EnforcedLimit {
        kind,
        mechanism,
        value,
        note: None,
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use std::ffi::CString;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use vpn_domain::{EnforcedLimit, LimitKind, LimitMechanism, Text, UnenforcedLimit, tr};

    use super::{Group, Leaf, TreeLimits, not_delegated};

    const MOUNT: &str = "/sys/fs/cgroup";
    /// `CGROUP2_SUPER_MAGIC` (linux/magic.h).
    const CGROUP2_MAGIC: i64 = 0x6367_7270;
    /// The manager's own leaf.
    const LEAF: &str = "manager";
    /// cpu.max period: 100 ms, in which `percent × 1 ms` of CPU time is allowed.
    const CPU_PERIOD_US: u64 = 100_000;

    #[expect(
        clippy::struct_excessive_bools,
        reason = "one independent flag per cgroup controller found delegated"
    )]
    pub(super) struct Cgroups {
        root: PathBuf,
        pub(super) rel: String,
        pub(super) memory: bool,
        pub(super) pids: bool,
        pub(super) cpu: bool,
        /// `memory.swap.max` exists: swap can be denied, so `memory.max` is a real ceiling.
        swap: bool,
    }

    /// The cgroup v2 path of `pid` (`0::/…`), `None` when unreadable.
    pub(super) fn cgroup_of(pid: u32) -> Option<String> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        own_path(&text)
    }

    /// The unified-hierarchy path in a `/proc/<pid>/cgroup` text.
    pub(super) fn own_path(text: &str) -> Option<String> {
        text.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(|p| p.trim().to_string())
    }

    fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
        let p = CString::new(path.as_os_str().as_bytes()).ok()?;
        let n = CString::new(name).ok()?;
        let mut buf = [0u8; 16];
        // SAFETY: both strings are NUL-terminated; the buffer and its length match.
        let len =
            unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(len).ok().map(|l| buf[..l].to_vec())
    }

    /// The system manager marks a cgroup it delegated with `trusted.delegate=1` and (readable
    /// without privileges) `user.delegate=1`. The user manager sets neither: for a user unit the
    /// caller states it (`unit_delegated`, from the unit's own command line), and the cgroup must
    /// be that unit's (`*.service`, `*.scope`).
    fn delegated(path: &Path, unit_delegated: bool) -> bool {
        let marked = ["user.delegate", "trusted.delegate"]
            .iter()
            .any(|n| xattr(path, n).is_some_and(|v| v == b"1"));
        #[expect(
            clippy::case_sensitive_file_extension_comparisons,
            reason = "systemd unit names are case-sensitive: only `.service` and `.scope` are units"
        )]
        let unit = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".service") || n.ends_with(".scope"));
        marked || (unit_delegated && unit)
    }

    fn write(path: &Path, value: &str) -> Result<(), Text> {
        std::fs::write(path, value).map_err(|e| {
            let path = path.display();
            tr!(
                "Cannot write {path}: {e}",
                "無法寫入 {path}：{e}",
                "{path} に書き込めません：{e}"
            )
        })
    }

    /// Why `dir` could not be created.
    fn not_created(dir: &Path, e: &std::io::Error) -> Text {
        let dir = dir.display();
        tr!(
            "Cannot create {dir}: {e}",
            "無法建立 {dir}：{e}",
            "{dir} を作成できません：{e}"
        )
    }

    impl Cgroups {
        /// The cgroup systemd delegated to this service (cgroup v2 only) and its path below the
        /// mount.
        fn delegated_root(unit_delegated: bool) -> Result<(PathBuf, String), Text> {
            let mount = CString::new(MOUNT).map_err(|e| Text::verbatim(e.to_string()))?;
            // SAFETY: statfs fills the zeroed struct for a NUL-terminated path.
            let mut st: libc::statfs = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { libc::statfs(mount.as_ptr(), &raw mut st) } != 0
                || st.f_type as i64 != CGROUP2_MAGIC
            {
                return Err(tr!(
                    "This host's /sys/fs/cgroup is not cgroup v2 (unified)",
                    "此主機的 /sys/fs/cgroup 不是 cgroup v2（unified）",
                    "このホストの /sys/fs/cgroup は cgroup v2（unified）ではありません"
                ));
            }
            let own = std::fs::read_to_string("/proc/self/cgroup")
                .ok()
                .and_then(|t| own_path(&t))
                .ok_or_else(|| {
                    tr!(
                        "Cannot read this process's cgroup (/proc/self/cgroup)",
                        "讀不到這個程序的 cgroup（/proc/self/cgroup）",
                        "このプロセスの cgroup を読み取れません（/proc/self/cgroup）"
                    )
                })?;
            let here = Path::new(MOUNT).join(own.trim_start_matches('/'));
            let in_leaf = here.file_name().is_some_and(|n| n == LEAF);
            if delegated(&here, unit_delegated) {
                Ok((here, own))
            } else if in_leaf
                && let Some(parent) = here.parent().filter(|p| delegated(p, unit_delegated))
            {
                // Restarted in place (exec): already in our leaf.
                let rel = own.rsplit_once('/').map_or_default(|(p, _)| p.to_string());
                Ok((parent.to_path_buf(), rel))
            } else {
                Err(tr!(
                    "The manager is not in a cgroup that systemd delegated with Delegate=yes (it is in {own}); this works only when it is installed with vpn-installer and started by the systemd user service",
                    "manager 不在 systemd 委派（Delegate=yes）的 cgroup 中（目前在 {own}）；以 vpn-installer 安裝、由 systemd 使用者服務啟動時才能使用",
                    "manager は systemd が委任した（Delegate=yes）cgroup の中にありません（現在は {own}）。vpn-installer でインストールし、systemd のユーザーサービスとして起動した場合にだけ使えます"
                ))
            }
        }

        pub(super) fn init(unit_delegated: bool) -> Result<Self, Text> {
            let (root, rel) = Self::delegated_root(unit_delegated)?;
            let available =
                std::fs::read_to_string(root.join("cgroup.controllers")).map_err(|e| {
                    tr!(
                        "Cannot read the controller list of the delegated cgroup: {e}",
                        "讀不到委派 cgroup 的 controller 清單：{e}",
                        "委任された cgroup のコントローラー一覧を読み取れません：{e}"
                    )
                })?;
            let has = |c: &str| available.split_whitespace().any(|x| x == c);
            let (memory, pids, cpu) = (has("memory"), has("pids"), has("cpu"));
            // Into the leaf: the delegated cgroup itself may hold no process once it hands
            // controllers to its children. Writing 0 moves this whole process.
            let leaf = root.join(LEAF);
            match std::fs::create_dir(&leaf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(not_created(&leaf, &e)),
            }
            write(&leaf.join("cgroup.procs"), "0")?;
            let others = std::fs::read_to_string(root.join("cgroup.procs")).unwrap_or_default();
            if !others.trim().is_empty() {
                let others = others.split_whitespace().collect::<Vec<_>>().join(", ");
                return Err(tr!(
                    "The service's cgroup still holds other processes ({others}), so no cgroup can be made for child processes",
                    "服務的 cgroup 裡還有其他程序（{others}），無法替子程序建立 cgroup",
                    "サービスの cgroup にほかのプロセス（{others}）が残っているため、子プロセス用の cgroup を作成できません"
                ));
            }
            let enable = |names: &[(&str, bool)]| -> String {
                names
                    .iter()
                    .filter(|(_, on)| *on)
                    .map(|(n, _)| format!("+{n}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let all = enable(&[("memory", memory), ("pids", pids), ("cpu", cpu)]);
            if !all.is_empty() {
                write(&root.join("cgroup.subtree_control"), &all)?;
            }
            for (group, controllers) in [
                (
                    Group::Workers,
                    enable(&[("memory", memory), ("pids", pids)]),
                ),
                (Group::Apps, all),
            ] {
                let dir = root.join(group.dir());
                match std::fs::create_dir(&dir) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(not_created(&dir, &e)),
                }
                if !controllers.is_empty() {
                    write(&dir.join("cgroup.subtree_control"), &controllers)?;
                }
                // Leaves an earlier manager left: empty ones go (a populated one cannot).
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for e in entries.flatten() {
                        if e.path().is_dir() {
                            let _ = std::fs::remove_dir(e.path());
                        }
                    }
                }
            }
            let swap = leaf.join("memory.swap.max").exists();
            Ok(Self {
                root,
                rel,
                memory,
                pids,
                cpu,
                swap,
            })
        }

        pub(super) fn create(
            &self,
            group: Group,
            name: &str,
            limits: &TreeLimits,
        ) -> Result<Leaf, Text> {
            if name.is_empty() || name.contains('/') || name.starts_with('.') {
                return Err(tr!(
                    "Invalid cgroup name: {name}",
                    "cgroup 名稱無效：{name}",
                    "cgroup の名前が無効です：{name}"
                ));
            }
            let path = self.root.join(group.dir()).join(name);
            if let Err(e) = std::fs::create_dir(&path) {
                let shown = path.display();
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(tr!(
                        "Cannot create the cgroup {shown}: {e}",
                        "無法建立 cgroup {shown}：{e}",
                        "cgroup {shown} を作成できません：{e}"
                    ));
                }
                // An empty leftover of the same tree: start over with fresh limits.
                std::fs::remove_dir(&path)
                    .and_then(|()| std::fs::create_dir(&path))
                    .map_err(|e| {
                        tr!(
                            "The cgroup {shown} is still in use: {e}",
                            "cgroup {shown} 仍在使用中：{e}",
                            "cgroup {shown} はまだ使用中です：{e}"
                        )
                    })?;
            }
            let result = self.configure(&path, limits);
            let (enforced, unenforced) = match result {
                Ok(v) => v,
                Err(e) => {
                    let _ = std::fs::remove_dir(&path);
                    return Err(e);
                }
            };
            let procs: OwnedFd = std::fs::OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.procs"))
                .map_err(|e| {
                    tr!(
                        "Cannot open cgroup.procs: {e}",
                        "無法開啟 cgroup.procs：{e}",
                        "cgroup.procs を開けません：{e}"
                    )
                })?
                .into();
            Ok(Leaf {
                rel: format!("{}/{name}", group.dir()),
                path,
                procs,
                enforced,
                unenforced,
            })
        }

        /// Write the limits, then read back what the kernel holds.
        fn configure(
            &self,
            path: &Path,
            limits: &TreeLimits,
        ) -> Result<(Vec<EnforcedLimit>, Vec<UnenforcedLimit>), Text> {
            let mut unenforced = Vec::new();
            let missing = |kind, controller: &str| UnenforcedLimit {
                kind,
                reason: not_delegated(controller),
            };
            if let Some(bytes) = limits.memory_bytes {
                if self.memory {
                    write(&path.join("memory.max"), &bytes.to_string())?;
                    if self.swap {
                        write(&path.join("memory.swap.max"), "0")?;
                    }
                    // One OOM ends the whole tree, not a part of it.
                    let _ = write(&path.join("memory.oom.group"), "1");
                } else {
                    unenforced.push(missing(LimitKind::Memory, "memory"));
                }
            }
            if let Some(n) = limits.tasks {
                if self.pids {
                    write(&path.join("pids.max"), &n.to_string())?;
                } else {
                    unenforced.push(missing(LimitKind::Processes, "pids"));
                }
            }
            if let Some(pct) = limits.cpu_percent {
                if self.cpu {
                    let quota = u64::from(pct) * CPU_PERIOD_US / 100;
                    write(&path.join("cpu.max"), &format!("{quota} {CPU_PERIOD_US}"))?;
                } else {
                    unenforced.push(missing(LimitKind::Cpu, "cpu"));
                }
            }
            let read = |file: &str| std::fs::read_to_string(path.join(file)).ok();
            let mut enforced = Vec::new();
            if let Some(v) = read("memory.max").and_then(|v| v.trim().parse::<u64>().ok()) {
                enforced.push(EnforcedLimit {
                    kind: LimitKind::Memory,
                    mechanism: LimitMechanism::Cgroup,
                    value: v,
                    note: (!self.swap).then(|| {
                        tr!(
                            "This host has no control of swap use: what goes over the limit may be swapped out first",
                            "此主機沒有 swap 用量控制：超過上限的部分可能先被換出到 swap",
                            "このホストにはスワップ使用量の制御がありません。上限を超えた分は先にスワップへ追い出される可能性があります"
                        )
                    }),
                });
            }
            if let Some(v) = read("pids.max").and_then(|v| v.trim().parse::<u64>().ok()) {
                enforced.push(super::enforced(
                    LimitKind::Processes,
                    LimitMechanism::Cgroup,
                    v,
                ));
            }
            if let Some(pct) = read("cpu.max").and_then(|v| cpu_percent(&v)) {
                enforced.push(super::enforced(LimitKind::Cpu, LimitMechanism::Cgroup, pct));
            }
            Ok((enforced, unenforced))
        }
    }

    /// `"50000 100000"` → 50 (percent of one core); `"max …"` → none.
    pub(super) fn cpu_percent(text: &str) -> Option<u64> {
        let mut it = text.split_whitespace();
        let quota: u64 = it.next()?.parse().ok()?;
        let period: u64 = it.next()?.parse().ok()?;
        (period > 0).then(|| (quota * 100 + period / 2) / period)
    }

    pub(super) fn set_open_files_of(pid: u32, n: u64) -> std::io::Result<u64> {
        let new = libc::rlimit64 {
            rlim_cur: n,
            rlim_max: n,
        };
        let mut old = libc::rlimit64 {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let pid = libc::pid_t::try_from(pid).map_err(|_| std::io::Error::other("pid"))?;
        // SAFETY: prlimit64 with valid pointers to two rlimit64 values.
        if unsafe { libc::prlimit64(pid, libc::RLIMIT_NOFILE, &raw const new, &raw mut old) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut now = old;
        // SAFETY: as above, reading only.
        if unsafe { libc::prlimit64(pid, libc::RLIMIT_NOFILE, std::ptr::null(), &raw mut now) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(now.rlim_max)
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use vpn_domain::{Text, tr};

    use super::{Group, Leaf, TreeLimits};

    #[allow(
        dead_code,
        reason = "never built on this operating system; the shared code still reads its fields"
    )]
    pub(super) struct Cgroups {
        pub(super) rel: String,
        pub(super) memory: bool,
        pub(super) pids: bool,
        pub(super) cpu: bool,
    }

    impl Cgroups {
        pub(super) fn init(_unit_delegated: bool) -> Result<Self, Text> {
            Err(if cfg!(target_os = "macos") {
                tr!(
                    "macOS has no cgroups and does not enforce RLIMIT_AS/RLIMIT_DATA; RLIMIT_NPROC counts every process of the user: the memory, CPU or process count of one process tree cannot be limited",
                    "macOS 沒有 cgroup，也不強制 RLIMIT_AS／RLIMIT_DATA；RLIMIT_NPROC 以使用者的所有程序計算：無法限制一個程序樹的記憶體、CPU 或程序數",
                    "macOS には cgroup がなく、RLIMIT_AS／RLIMIT_DATA も強制されません。RLIMIT_NPROC はユーザーのすべてのプロセスで数えられるため、1 つのプロセスツリーのメモリ、CPU、プロセス数は制限できません"
                )
            } else {
                tr!(
                    "This operating system has no cgroup v2",
                    "這個作業系統沒有 cgroup v2",
                    "この OS には cgroup v2 がありません"
                )
            })
        }

        #[expect(
            clippy::unused_self,
            reason = "same signature as on Linux, where the leaf is made below the delegated cgroup"
        )]
        pub(super) fn create(&self, _: Group, _: &str, _: &TreeLimits) -> Result<Leaf, Text> {
            Err(tr!("No cgroup", "沒有 cgroup", "cgroup がありません"))
        }
    }

    pub(super) const fn cgroup_of(_pid: u32) -> Option<String> {
        None
    }

    pub(super) fn set_open_files_of(_pid: u32, _n: u64) -> std::io::Result<u64> {
        Err(tr!(
            "This operating system cannot set another process's RLIMIT_NOFILE",
            "這個作業系統不能設定另一個程序的 RLIMIT_NOFILE",
            "この OS では別のプロセスの RLIMIT_NOFILE を設定できません"
        )
        .into_io_error(std::io::ErrorKind::Other))
    }
}
