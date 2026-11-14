//! The installer's jobs: install, upgrade, uninstall and status.
//!
//! - Everything is prepared and checked before a running installation is touched: the payload
//!   is staged and asked what it is, definitions are rendered and validated.
//! - An upgrade stops the services (controller first), backs up the databases and definitions,
//!   keeps the previous programs in `bin.previous/`, installs, starts and waits until the web UI
//!   answers from the new build with the manager connected. Any failure on the way restores the
//!   previous programs, definitions and databases and starts them again — only once the new
//!   version is confirmed stopped, so the two never run side by side and the previous programs
//!   never open databases the new one may have migrated. What happened is written next to the
//!   backup (`rollback.txt`).
//! - A failed fresh install leaves no service or program behind (data and logs stay).
//! - Uninstall removes the services and programs; data, the vault key, logs and backups stay
//!   unless `--purge`.

#![expect(unsafe_code, reason = "getuid to refuse running as root")]

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use ipnetwork::IpNetwork;
use vpn_platform::lock::{FileLock, LockError};
use vpn_platform::paths::ensure_private_dir;

use crate::fsx::{self, check_path, remove_dir_if_present, remove_if_present};
use crate::health;
use crate::layout::{Component, Job, Layout, Listen, Target};
use crate::payload::{Payload, Staged};
use crate::record::{self, Record};
use crate::supervisor::{self, Supervisor};

pub const DEFAULT_PORT: u16 = 18765;
/// Startup includes opening (and possibly migrating) the databases.
const READY_WITHIN: Duration = Duration::from_secs(60);
const KEEP_BACKUPS: usize = 3;
const DATABASES: [&str; 2] = ["control.sqlite", "metrics.sqlite"];
const BACKUP_COMPLETE: &str = "complete";
/// Written into the backup directory when an upgrade was rolled back (or could not be).
const ROLLBACK_NOTE: &str = "rollback.txt";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Install,
    Upgrade,
}

pub struct InstallOptions {
    pub target: Target,
    pub port: Option<u16>,
    /// `--listen-address`; `None`: the installed one (else 127.0.0.1).
    pub listen_address: Option<IpAddr>,
    /// `--allow-client`; `None`: none given.
    pub allow_clients: Option<Vec<IpNetwork>>,
    pub ssh_dir: Option<PathBuf>,
}

/// Where the web UI listens and for whom, from the options and what is installed: an option
/// given replaces the installed value; a new loopback address drops the allow list, another
/// address keeps it. A reachable address without an allow list is refused before anything is
/// touched.
fn exposure(
    opts: &InstallOptions,
    record: Option<&Record>,
) -> anyhow::Result<(IpAddr, Vec<IpNetwork>)> {
    let installed_address = record
        .and_then(|r| r.listen_address.as_deref())
        .map(str::parse::<IpAddr>)
        .transpose()
        .context("安裝紀錄的 listen_address 無法解讀")?
        .unwrap_or(Listen::DEFAULT_ADDRESS);
    let installed_allow: Vec<IpNetwork> = record
        .map(|r| {
            r.allow_clients
                .iter()
                .map(|n| n.parse::<IpNetwork>())
                .collect::<Result<_, _>>()
        })
        .transpose()
        .context("安裝紀錄的 allow_clients 無法解讀")?
        .unwrap_or_default();
    let address = opts.listen_address.unwrap_or(installed_address);
    let allow = match &opts.allow_clients {
        Some(given) => given.clone(),
        None if address.is_loopback() => Vec::new(),
        None => installed_allow,
    };
    // Networks as networks: 192.168.10.5/24 is 192.168.10.0/24.
    let allow: Vec<IpNetwork> = allow
        .into_iter()
        .map(|n| IpNetwork::new(n.network(), n.prefix()).unwrap_or(n))
        .collect();
    vpn_platform::admission::check_exposure(address, &allow)
        .map_err(|e| anyhow!(e.zh_tw.clone()))?;
    Ok((address, allow))
}

struct Session {
    layout: Layout,
    sup: Box<dyn Supervisor>,
    jobs: Vec<Job>,
    record: Option<Record>,
}

fn open(target: &Target) -> anyhow::Result<Session> {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        bail!("請以要使用 VPN Manager 的一般使用者執行，不要用 root 或 sudo：服務裝在該使用者底下");
    }
    let layout = Layout::new(target)?;
    let sup = supervisor::for_this_machine(&layout)?;
    let jobs = Component::ALL
        .iter()
        .map(|c| sup.job(&layout, *c))
        .collect();
    let record = Record::load(&layout.record)?;
    Ok(Session {
        layout,
        sup,
        jobs,
        record,
    })
}

impl Session {
    fn present(&self) -> bool {
        self.record.is_some() || self.jobs.iter().any(|j| j.definition.exists())
    }

    fn stop_all(&self) -> anyhow::Result<()> {
        for job in self.jobs.iter().rev() {
            self.sup.stop(job)?;
        }
        Ok(())
    }

    fn render(&self, job: &Job, listen: &Listen, ssh_dir: Option<&Path>) -> anyhow::Result<String> {
        let argv = self.layout.argv(job.component, listen, ssh_dir)?;
        Ok(self.sup.render(job, &argv, check_path(&self.layout.root)?))
    }

    /// Renders, validates and puts every definition in place.
    fn publish_definitions(&self, listen: &Listen, ssh_dir: Option<&Path>) -> anyhow::Result<()> {
        for job in &self.jobs {
            let text = self.render(job, listen, ssh_dir)?;
            let name = job.definition.file_name().context("definition path")?;
            let staged = self.layout.staging.join(name);
            fsx::write_atomic(&staged, text.as_bytes(), 0o644)?;
            self.sup
                .validate(&staged)
                .with_context(|| format!("{} 的定義檔沒有通過檢查", job.name))?;
            if let Some(dir) = job.definition.parent() {
                fs::create_dir_all(dir)?;
            }
            fsx::write_atomic(&job.definition, text.as_bytes(), 0o644)
                .with_context(|| format!("寫入 {}", job.definition.display()))?;
        }
        Ok(())
    }

    fn definitions_match(&self, listen: &Listen, ssh_dir: Option<&Path>) -> bool {
        self.jobs.iter().all(|job| {
            self.render(job, listen, ssh_dir)
                .ok()
                .zip(fs::read_to_string(&job.definition).ok())
                .is_some_and(|(want, have)| want == have)
        })
    }

    /// Copies the staged programs into a fresh `bin/`, plus this installer for later upgrades,
    /// status checks and removal.
    fn place_programs(&self, staged: &Staged) -> anyhow::Result<()> {
        ensure_private_dir(&self.layout.bin)?;
        for (from, name) in [(&staged.vpnd, "vpnd"), (&staged.vpnctl, "vpnctl")] {
            let bytes = fs::read(from)?;
            fsx::write_atomic(&self.layout.bin.join(name), &bytes, 0o755)?;
        }
        let me = self.layout.staging.join("vpn-installer");
        if let Ok(bytes) = fs::read(&me) {
            fsx::write_atomic(&self.layout.bin.join("vpn-installer"), &bytes, 0o755)?;
        }
        Ok(())
    }

    fn print_logs(&self) {
        for job in &self.jobs {
            let Ok(text) = fs::read_to_string(&job.log) else {
                continue;
            };
            let lines: Vec<&str> = text.lines().collect();
            say!(
                "── {}（最後 {} 行）",
                job.log.display(),
                lines.len().min(15)
            );
            for l in &lines[lines.len().saturating_sub(15)..] {
                say!("{l}");
            }
        }
    }

    fn print_summary(&self, rec: &Record) {
        say!("VPN Manager {}（build {}）", rec.version, rec.build_id);
        say!("網頁介面：http://127.0.0.1:{}", rec.port);
        print_lan(rec);
        let names: Vec<&str> = self.jobs.iter().map(|j| j.name.as_str()).collect();
        say!("服務（{}）：{}", self.sup.kind(), names.join("、"));
        say!(
            "資料目錄：{}（程式、資料、保險庫金鑰、日誌都在這裡）",
            self.layout.root.display()
        );
        say!(
            "管理：\"{}\" status｜upgrade｜uninstall",
            self.layout.bin.join("vpn-installer").display()
        );
    }
}

pub fn install(opts: &InstallOptions, payload: &Payload, mode: Mode) -> anyhow::Result<()> {
    let ctx = open(&opts.target)?;
    let present = ctx.present();
    match (mode, present) {
        (Mode::Upgrade, false) => bail!(
            "{} 沒有安裝 VPN Manager：請改用 install",
            ctx.layout.root.display()
        ),
        (Mode::Install, true) => say!("已經安裝，改為升級。"),
        _ => {}
    }
    let layout = &ctx.layout;
    layout.paths.ensure().context("準備資料目錄")?;
    for dir in [
        &layout.logs,
        &layout.installer,
        &layout.staging,
        &layout.backups,
    ] {
        ensure_private_dir(dir)?;
    }
    let _lock = lock(layout)?;
    stage_self(&layout.staging);
    let staged = payload.stage(&layout.staging).context("檢查要安裝的程式")?;
    let ssh_dir = match &opts.ssh_dir {
        Some(d) => Some(std::path::absolute(d)?),
        None => ctx.record.as_ref().and_then(|r| r.ssh_dir.clone()),
    };
    if present {
        upgrade(&ctx, opts, &staged, ssh_dir)
    } else {
        fresh(&ctx, opts, &staged, ssh_dir)
    }
}

/// One installer at a time changes an installation.
fn lock(layout: &Layout) -> anyhow::Result<FileLock> {
    let path = layout.installer.join("lock");
    FileLock::try_acquire(&path).map_err(|e| match e {
        LockError::Held => anyhow!("另一個 vpn-installer 正在處理這份安裝，請等它結束"),
        // Not another installer: the lock file itself could not be used.
        LockError::Io(io) => anyhow::Error::new(io).context(format!("鎖定 {}", path.display())),
    })
}

/// Keeps a copy of this installer so the installation can manage itself later.
fn stage_self(staging: &Path) {
    // nosemgrep: rust.lang.security.current-exe.current-exe -- copies this installer for later upgrades; nothing is decided by its path
    if let Ok(me) = std::env::current_exe().and_then(fs::read) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort, like reading the executable above: without the copy the installation only lacks bin/vpn-installer"
        )]
        let _ = fsx::write_atomic(&staging.join("vpn-installer"), &me, 0o755);
    }
}

/// Where other hosts reach the web UI, and the risk, when it is open to them.
fn print_lan(rec: &Record) {
    let Some(address) = rec.listen_address.as_deref() else {
        return;
    };
    let shown: Vec<String> = match address.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => vpn_platform::netif::reachable_addresses()
            .unwrap_or_default()
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V6(v6) => format!("http://[{v6}]:{}", rec.port),
                v4 @ IpAddr::V4(_) => format!("http://{v4}:{}", rec.port),
            })
            .collect(),
        Ok(IpAddr::V6(v6)) => vec![format!("http://[{v6}]:{}", rec.port)],
        _ => vec![format!("http://{address}:{}", rec.port)],
    };
    for url in shown {
        say!("區網：{url}");
    }
    say!("允許連入的網段：{}", rec.allow_clients.join("、"));
    say!(
        "注意：這些網段裡的任何裝置都能操作 VPN Manager（包括啟動受管 App），沒有登入；這台主機上的程式仍只接受同一個使用者的。"
    );
}

fn choose_port(explicit: Option<u16>, preferred: u16, address: IpAddr) -> anyhow::Result<u16> {
    match explicit {
        Some(port) if health::port_is_free(port, address) => Ok(port),
        Some(port) => {
            bail!("port {port} 已被其他程式使用；換一個 --port，或不指定讓安裝程式自動挑選")
        }
        None => {
            let port = health::free_port(preferred, address).ok_or_else(|| {
                anyhow!("從 {preferred} 起的 100 個 port 都被占用；請以 --port 指定")
            })?;
            if port != preferred {
                say!("port {preferred} 被其他程式使用，改用 {port}。");
            }
            Ok(port)
        }
    }
}

fn new_record(
    ctx: &Session,
    staged: &Staged,
    listen: &Listen,
    ssh_dir: Option<PathBuf>,
    linger: bool,
) -> Record {
    let now = record::now();
    Record {
        schema: record::SCHEMA,
        version: staged.version.clone(),
        build_id: staged.build_id.clone(),
        vpnd_sha256: staged.vpnd_sha256.clone(),
        vpnctl_sha256: staged.vpnctl_sha256.clone(),
        port: listen.port,
        listen_address: (listen.address != Listen::DEFAULT_ADDRESS)
            .then(|| listen.address.to_string()),
        allow_clients: listen.allow.iter().map(ToString::to_string).collect(),
        ssh_dir,
        supervisor: ctx.sup.kind().into(),
        services: ctx.jobs.iter().map(|j| j.name.clone()).collect(),
        installed_at: ctx
            .record
            .as_ref()
            .map_or_else(|| now.clone(), |r| r.installed_at.clone()),
        updated_at: now,
        linger_enabled: linger || ctx.record.as_ref().is_some_and(|r| r.linger_enabled),
    }
}

fn unattended(ctx: &Session) -> bool {
    match ctx.sup.ensure_unattended() {
        Ok(changed) => {
            if changed {
                say!("已為這個使用者啟用 lingering：開機後即使沒有登入，服務也會執行。");
            }
            changed
        }
        Err(e) => {
            say!(
                "注意：無法讓服務在沒有登入時執行（{e:#}）；目前只會在登入期間執行。系統管理員可執行 loginctl enable-linger {}",
                supervisor::user_name().unwrap_or_default()
            );
            false
        }
    }
}

fn fresh(
    ctx: &Session,
    opts: &InstallOptions,
    staged: &Staged,
    ssh_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let (address, allow) = exposure(opts, None)?;
    let port = choose_port(opts.port, DEFAULT_PORT, address)?;
    let listen = Listen {
        port,
        address,
        allow,
    };
    let result = (|| -> anyhow::Result<health::Status> {
        ctx.place_programs(staged)?;
        ctx.publish_definitions(&listen, ssh_dir.as_deref())?;
        ctx.sup.start(&ctx.jobs)?;
        health::wait_ready(port, Some(&staged.build_id), READY_WITHIN)
    })();
    if let Err(e) = result {
        ctx.print_logs();
        let undo = ctx
            .sup
            .remove(&ctx.jobs.iter().rev().map(clone_job).collect::<Vec<_>>());
        fsx::discard_dir(&ctx.layout.bin);
        return Err(match undo {
            Ok(()) => e.context("安裝失敗：這次安裝的服務與程式已移除，資料與日誌保留"),
            Err(u) => e.context(format!("安裝失敗，而且沒能完全移除這次安裝的服務（{u:#}）")),
        });
    }
    let linger = unattended(ctx);
    let rec = new_record(ctx, staged, &listen, ssh_dir, linger);
    rec.save(&ctx.layout.record)?;
    fsx::discard_dir(&ctx.layout.staging);
    say!("安裝完成。");
    ctx.print_summary(&rec);
    Ok(())
}

fn clone_job(j: &Job) -> Job {
    Job {
        component: j.component,
        name: j.name.clone(),
        definition: j.definition.clone(),
        log: j.log.clone(),
    }
}

fn upgrade(
    ctx: &Session,
    opts: &InstallOptions,
    staged: &Staged,
    ssh_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let layout = &ctx.layout;
    let preferred = opts
        .port
        .or_else(|| ctx.record.as_ref().map(|r| r.port))
        .unwrap_or(DEFAULT_PORT);
    // Refused before anything is stopped.
    let (address, allow) = exposure(opts, ctx.record.as_ref())?;
    if let Some(rec) = &ctx.record
        && rec.vpnd_sha256 == staged.vpnd_sha256
        && rec.vpnctl_sha256 == staged.vpnctl_sha256
        && opts.port.is_none_or(|p| p == rec.port)
        && ctx.definitions_match(
            &Listen {
                port: rec.port,
                address,
                allow: allow.clone(),
            },
            ssh_dir.as_deref(),
        )
        && health::probe(rec.port).is_ok_and(|s| s.manager_connected && s.build_id == rec.build_id)
    {
        say!(
            "已安裝 build {}，服務正常，沒有需要變更的地方。",
            rec.build_id
        );
        fsx::discard_dir(&layout.staging);
        return Ok(());
    }
    let from = ctx
        .record
        .as_ref()
        .map_or_else(|| "unrecorded".to_owned(), |r| r.build_id.clone());
    let backup = layout.backups.join(format!("{}-{from}", record::stamp()));
    let result = (|| -> anyhow::Result<Listen> {
        ctx.stop_all().context("停止目前的服務")?;
        back_up(ctx, &backup).context("備份資料庫與服務定義")?;
        let listen = Listen {
            port: choose_port(opts.port, preferred, address)?,
            address,
            allow,
        };
        remove_dir_if_present(&layout.bin_previous)?;
        if layout.bin.exists() {
            fs::rename(&layout.bin, &layout.bin_previous)?;
        }
        ctx.place_programs(staged)?;
        ctx.publish_definitions(&listen, ssh_dir.as_deref())?;
        ctx.sup.start(&ctx.jobs)?;
        health::wait_ready(listen.port, Some(&staged.build_id), READY_WITHIN)?;
        Ok(listen)
    })();
    let listen = match result {
        Ok(port) => port,
        Err(e) => {
            ctx.print_logs();
            let rolled = roll_back(ctx, &backup);
            let outcome = match &rolled {
                Ok(()) => "restored: the previous programs, definitions and databases are back and answered".to_owned(),
                Err(r) => format!("not_restored: {r:#}"),
            };
            if let Err(w) = note_rollback(
                &backup,
                &from,
                &staged.build_id,
                &format!("{e:#}"),
                &outcome,
            ) {
                say!("無法寫入回復紀錄（{w}）");
            }
            return Err(match rolled {
                Ok(()) => e.context(format!("升級失敗，已回復到原本的版本（{from}）")),
                Err(r) => e.context(format!(
                    "升級失敗，而且回復也失敗（{r:#}）；備份在 {}",
                    backup.display()
                )),
            });
        }
    };
    fsx::discard_dir(&layout.bin_previous);
    prune_backups(&layout.backups);
    let linger = unattended(ctx);
    let rec = new_record(ctx, staged, &listen, ssh_dir, linger);
    rec.save(&layout.record)?;
    fsx::discard_dir(&layout.staging);
    say!("升級完成（{from} → {}）。", rec.build_id);
    ctx.print_summary(&rec);
    Ok(())
}

/// Databases (taken while the services are stopped, so consistent) and the current definitions.
fn back_up(ctx: &Session, backup: &Path) -> anyhow::Result<()> {
    ensure_private_dir(backup)?;
    for db in DATABASES {
        fsx::copy_database(&ctx.layout.root, backup, db)?;
    }
    // The copy keeps no SSH download log or finished records (they name remote files); a copy
    // that cannot be scrubbed is kept as it is: a rollback needs it more.
    if let Err(e) = crate::scrub::backup(backup) {
        say!("注意：備份中的 SSH 下載日誌與傳輸紀錄未能清除（{e}）；備份照常保留。");
    }
    for job in &ctx.jobs {
        if let (Ok(bytes), Some(name)) = (fs::read(&job.definition), job.definition.file_name()) {
            fs::write(backup.join(name), bytes)?;
        }
    }
    // Only a finished backup is restored: before it nothing was changed.
    fs::write(backup.join(BACKUP_COMPLETE), b"")?;
    Ok(())
}

fn roll_back(ctx: &Session, backup: &Path) -> anyhow::Result<()> {
    let layout = &ctx.layout;
    // The new version may be half started. Nothing moves back until it is confirmed down: the
    // previous programs must not run beside it (same keys, same ports) or open the databases
    // while it still writes them.
    ctx.stop_all()
        .context("新版本沒有停止，所以沒有回復任何檔案；請先停止服務，再以原本的安裝檔重新升級")?;
    if !backup.join(BACKUP_COMPLETE).exists() {
        // Stopped before anything changed: start what is there again.
        return restart(ctx);
    }
    if layout.bin_previous.exists() {
        remove_dir_if_present(&layout.bin)?;
        fs::rename(&layout.bin_previous, &layout.bin)?;
    }
    for job in &ctx.jobs {
        let saved = job
            .definition
            .file_name()
            .map(|n| backup.join(n))
            .and_then(|p| fs::read(p).ok());
        match saved {
            Some(bytes) => fsx::write_atomic(&job.definition, &bytes, 0o644)?,
            None => {
                remove_if_present(&job.definition)?;
            }
        }
    }
    for db in DATABASES {
        fsx::copy_database(backup, &layout.root, db)?;
    }
    restart(ctx)
}

/// Leaves the evidence of a rollback beside the backup it used: when, from and to which build,
/// why the upgrade failed and what the rollback did.
fn note_rollback(
    backup: &Path,
    from: &str,
    to: &str,
    failure: &str,
    outcome: &str,
) -> std::io::Result<()> {
    if !backup.exists() {
        ensure_private_dir(backup)?;
    }
    let text = format!(
        "time: {}\nfrom: {from}\nto: {to}\nfailure: {failure}\noutcome: {outcome}\n",
        record::stamp()
    );
    fsx::write_atomic(&backup.join(ROLLBACK_NOTE), text.as_bytes(), 0o600)
}

/// Starts the jobs whose definitions exist and waits for the recorded build.
fn restart(ctx: &Session) -> anyhow::Result<()> {
    let present: Vec<Job> = ctx
        .jobs
        .iter()
        .filter(|j| j.definition.exists())
        .map(clone_job)
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    ctx.sup.start(&present)?;
    let port = ctx.record.as_ref().map_or(DEFAULT_PORT, |r| r.port);
    let build = ctx.record.as_ref().map(|r| r.build_id.as_str());
    health::wait_ready(port, build, READY_WITHIN)?;
    Ok(())
}

fn prune_backups(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut names: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    // Names start with a UTC timestamp, so they sort by age.
    names.sort();
    let excess = names.len().saturating_sub(KEEP_BACKUPS);
    for old in names.into_iter().take(excess) {
        fsx::discard_dir(&old);
    }
}

pub fn uninstall(target: &Target, purge: bool) -> anyhow::Result<()> {
    let ctx = open(target)?;
    let layout = &ctx.layout;
    // Refuse a wrong --root before anything is touched.
    if purge {
        check_purgeable(layout)?;
    }
    let _lock = if layout.installer.exists() {
        Some(lock(layout)?)
    } else {
        None
    };
    let installed: Vec<&Job> = ctx
        .jobs
        .iter()
        .filter(|j| j.definition.exists() || ctx.sup.state(j).is_ok_and(|s| s.loaded))
        .collect();
    if installed.is_empty() && ctx.record.is_none() && !purge {
        say!("{} 沒有安裝 VPN Manager。", layout.root.display());
        return Ok(());
    }
    let reversed: Vec<Job> = ctx.jobs.iter().rev().map(clone_job).collect();
    ctx.sup.remove(&reversed).context("移除服務")?;
    for job in installed {
        say!("已移除服務 {}", job.name);
    }
    for dir in [&layout.bin, &layout.bin_previous, &layout.staging] {
        remove_dir_if_present(dir)?;
    }
    remove_if_present(&layout.record)?;
    if purge {
        let kept = purge_root(layout)?;
        if kept.is_empty() {
            say!(
                "已刪除 {}（資料、保險庫金鑰、日誌與備份）。",
                layout.root.display()
            );
        } else {
            say!(
                "已刪除 VPN Manager 放在 {} 的資料、保險庫金鑰、日誌與備份。這個目錄裡還有 {} 個不是 VPN Manager 的項目，沒有動，目錄也保留：{}",
                layout.root.display(),
                kept.len(),
                listed(&kept)
            );
        }
    } else {
        say!(
            "已移除程式。保留：資料與保險庫金鑰、日誌、升級備份（{}）；要一併刪除請加 --purge。",
            layout.root.display()
        );
    }
    if ctx.record.as_ref().is_some_and(|r| r.linger_enabled) {
        say!(
            "安裝時啟用了 lingering；若這個使用者沒有其他需要開機執行的服務，可執行 loginctl disable-linger {}",
            supervisor::user_name().unwrap_or_default()
        );
    }
    Ok(())
}

/// Only a directory that is recognisably VPN Manager's is ever deleted (a missing one is fine).
fn check_purgeable(layout: &Layout) -> anyhow::Result<()> {
    let root = &layout.root;
    if !root.exists() {
        return Ok(());
    }
    let ours = ["control.sqlite", "vault.key", "installer", "gateway.key"]
        .iter()
        .any(|n| root.join(n).exists());
    if !ours || root == &layout.home || root.parent().is_none() {
        bail!(
            "{} 看起來不是 VPN Manager 的資料目錄，不刪除",
            root.display()
        );
    }
    Ok(())
}

/// Whether an entry of the root is one VPN Manager keeps there: the programs, the installer's
/// own directory, the two databases with `SQLite`'s companions and their reserves, the keys,
/// logs, sockets, locks, App state and stop markers.
fn is_ours(name: &str) -> bool {
    const ENTRIES: [&str; 11] = [
        "apps",
        "bin",
        "bin.previous",
        "gateway.key",
        "installer",
        "locks",
        "logs",
        "pending-stops",
        "run",
        "ssh-projection.sha256",
        "vault.key",
    ];
    ENTRIES.contains(&name)
        || ["control.", "metrics."].iter().any(|store| {
            name.strip_prefix(store)
                .is_some_and(|rest| rest == "reserve" || rest.starts_with("sqlite"))
        })
}

/// The first names of a list, for a message.
fn listed(names: &[String]) -> String {
    const SHOWN: usize = 8;
    let mut text = names
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("、");
    if names.len() > SHOWN {
        text.push('…');
    }
    text
}

/// Deletes what VPN Manager keeps in its root and nothing else: a root may hold other things
/// (an installation made with `--root` into a directory that was in use). The directory itself
/// goes only when that leaves it empty. Returns the names left in place.
fn purge_root(layout: &Layout) -> anyhow::Result<Vec<String>> {
    let root = &layout.root;
    check_purgeable(layout)?;
    let mut kept = Vec::new();
    if root.exists() {
        let entries = fs::read_dir(root).with_context(|| format!("讀取 {}", root.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("讀取 {}", root.display()))?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(is_ours) {
                kept.push(name.to_string_lossy().into_owned());
                continue;
            }
            let path = entry.path();
            // `file_type` does not follow a link: a link is removed, never what it leads to.
            let removed = if entry.file_type()?.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            removed.with_context(|| format!("刪除 {}", path.display()))?;
        }
        if kept.is_empty() {
            fs::remove_dir(root).with_context(|| format!("刪除 {}", root.display()))?;
        }
    }
    // Sockets may live outside the root (Linux runtime directory).
    if !layout.paths.run.starts_with(root) {
        fsx::discard_dir(&layout.paths.run);
    }
    kept.sort();
    Ok(kept)
}

pub fn status(target: &Target, payload: Option<&Payload>) -> anyhow::Result<bool> {
    let ctx = open(target)?;
    let layout = &ctx.layout;
    match &ctx.record {
        Some(r) => say!(
            "已安裝 VPN Manager {}（build {}），安裝於 {}，最後更新 {}",
            r.version,
            r.build_id,
            r.installed_at,
            r.updated_at
        ),
        None if ctx.present() => {
            say!("已安裝（沒有安裝紀錄：由較早的安裝方式建立；執行 upgrade 會補上）");
        }
        None => {
            say!("{} 沒有安裝 VPN Manager。", layout.root.display());
            return Ok(false);
        }
    }
    let mut healthy = true;
    for job in &ctx.jobs {
        let state = ctx.sup.state(job)?;
        say!("{:<10} {}", job.component.name(), job.name);
        say!("{:<10} {}", "", state.summary);
        healthy &= state.running;
    }
    say!("資料目錄：{}", layout.root.display());
    say!("日誌：{}", layout.logs.display());
    let port = ctx.record.as_ref().map_or(DEFAULT_PORT, |r| r.port);
    match health::probe(port) {
        Ok(s) => {
            say!(
                "網頁介面：http://127.0.0.1:{port}（manager {}，版本 {}，build {}）",
                if s.manager_connected {
                    "已連線"
                } else {
                    "未連線"
                },
                s.version,
                s.build_id
            );
            healthy &= s.manager_connected;
            if let Some(r) = &ctx.record
                && r.build_id != s.build_id
            {
                say!("注意：執行中的 build 與安裝紀錄（{}）不同。", r.build_id);
                healthy = false;
            }
        }
        Err(e) => {
            say!("網頁介面：http://127.0.0.1:{port} 沒有回應（{e:#}）");
            healthy = false;
        }
    }
    if let Some(r) = &ctx.record {
        print_lan(r);
    }
    if let Some(r) = &ctx.record
        && let Some(payload) = payload
    {
        let same = payload.vpnd_sha256() == r.vpnd_sha256;
        say!(
            "這個安裝程式內含的版本{}",
            if same {
                "與已安裝的相同"
            } else {
                "與已安裝的不同：執行 upgrade 會換成它"
            }
        );
    }
    Ok(healthy)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// A service manager whose stop can be made to fail; it records starts.
    struct Fake {
        dir: PathBuf,
        stop_fails: bool,
        starts: Cell<usize>,
    }

    impl Supervisor for Fake {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn job(&self, layout: &Layout, component: Component) -> Job {
            Job {
                component,
                name: format!("fake.{}", component.name()),
                definition: self.dir.join(format!("{}.def", component.name())),
                log: layout.logs.join(format!("{}.log", component.name())),
            }
        }
        fn render(&self, _: &Job, argv: &[String], _: &str) -> String {
            argv.join(" ")
        }
        fn validate(&self, _: &Path) -> anyhow::Result<()> {
            Ok(())
        }
        fn state(&self, _: &Job) -> anyhow::Result<supervisor::JobState> {
            Ok(supervisor::JobState {
                loaded: true,
                running: true,
                summary: String::new(),
            })
        }
        fn stop(&self, job: &Job) -> anyhow::Result<()> {
            if self.stop_fails {
                bail!("{} 沒有停止", job.name);
            }
            Ok(())
        }
        fn start(&self, _: &[Job]) -> anyhow::Result<()> {
            self.starts.set(self.starts.get() + 1);
            Ok(())
        }
        fn remove(&self, _: &[Job]) -> anyhow::Result<()> {
            Ok(())
        }
        fn ensure_unattended(&self) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    fn session(root: &Path, stop_fails: bool) -> Session {
        let layout = Layout::new(&Target {
            root: Some(root.to_path_buf()),
            environment: "test".into(),
            instance: "rollback".into(),
        })
        .unwrap();
        let sup = Fake {
            dir: root.join("definitions"),
            stop_fails,
            starts: Cell::new(0),
        };
        let jobs = Component::ALL
            .iter()
            .map(|c| sup.job(&layout, *c))
            .collect();
        Session {
            layout,
            sup: Box::new(sup),
            jobs,
            record: None,
        }
    }

    #[test]
    fn a_rollback_moves_nothing_while_the_new_version_still_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = session(tmp.path(), true);
        let l = &ctx.layout;
        fs::create_dir_all(&l.bin).unwrap();
        fs::create_dir_all(&l.bin_previous).unwrap();
        fs::write(l.bin.join("vpnd"), b"new").unwrap();
        fs::write(l.bin_previous.join("vpnd"), b"old").unwrap();
        fs::write(l.root.join("control.sqlite"), b"migrated by new").unwrap();
        let backup = l.backups.join("b");
        fs::create_dir_all(&backup).unwrap();
        fs::write(backup.join("control.sqlite"), b"before upgrade").unwrap();
        fs::write(backup.join(BACKUP_COMPLETE), b"").unwrap();

        let err = roll_back(&ctx, &backup).unwrap_err();
        assert!(format!("{err:#}").contains("新版本沒有停止"), "{err:#}");
        // Neither the programs nor the database moved, and nothing was started.
        assert_eq!(fs::read(l.bin.join("vpnd")).unwrap(), b"new");
        assert_eq!(fs::read(l.bin_previous.join("vpnd")).unwrap(), b"old");
        assert_eq!(
            fs::read(l.root.join("control.sqlite")).unwrap(),
            b"migrated by new"
        );
    }

    /// The names in a directory, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_purge_deletes_only_what_vpn_manager_keeps_in_its_root() {
        let tmp = tempfile::tempdir().unwrap();
        // An installation made with `--root` into a directory that holds other things.
        let root = tmp.path().join("checkout");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(outside.join("deep")).unwrap();
        fs::write(outside.join("deep/keep"), b"not ours").unwrap();
        let ctx = session(&root, false);
        let l = &ctx.layout;
        for dir in [
            "apps/a",
            "bin",
            "bin.previous",
            "installer/backups/b",
            "logs",
            "pending-stops",
            "run",
        ] {
            fs::create_dir_all(l.root.join(dir)).unwrap();
        }
        for file in [
            "bin/vpnd",
            "control.reserve",
            "control.sqlite",
            "control.sqlite-shm",
            "control.sqlite-wal",
            "gateway.key",
            "installer/state.json",
            "logs/manager.log",
            "metrics.reserve",
            "metrics.sqlite",
            "ssh-projection.sha256",
            "vault.key",
        ] {
            fs::write(l.root.join(file), b"ours").unwrap();
        }
        // An entry with one of our names that is a link: the link goes, not what it leads to.
        std::os::unix::fs::symlink(&outside, l.root.join("locks")).unwrap();
        fs::create_dir_all(l.root.join(".git")).unwrap();
        fs::write(l.root.join(".git/HEAD"), b"ref: refs/heads/main").unwrap();
        fs::create_dir_all(l.root.join("src")).unwrap();
        fs::write(l.root.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(
            l.root.join("control.txt"),
            b"a name that only looks like ours",
        )
        .unwrap();

        let kept = purge_root(l).unwrap();
        assert_eq!(kept, [".git", "control.txt", "src"]);
        assert_eq!(names(&l.root), [".git", "control.txt", "src"]);
        assert_eq!(
            fs::read(l.root.join(".git/HEAD")).unwrap(),
            b"ref: refs/heads/main"
        );
        assert_eq!(
            fs::read(l.root.join("src/main.rs")).unwrap(),
            b"fn main() {}"
        );
        assert_eq!(fs::read(outside.join("deep/keep")).unwrap(), b"not ours");

        // A root that holds nothing else goes as a whole.
        let own = tmp.path().join("data");
        let ctx = session(&own, false);
        let l = &ctx.layout;
        fs::create_dir_all(l.root.join("installer")).unwrap();
        fs::write(l.root.join("vault.key"), b"ours").unwrap();
        assert_eq!(purge_root(l).unwrap(), Vec::<String>::new());
        assert!(!own.exists());
        // And a directory that is not recognisably an installation is refused untouched.
        let other = tmp.path().join("other");
        fs::create_dir_all(other.join("bin")).unwrap();
        let ctx = session(&other, false);
        assert!(purge_root(&ctx.layout).is_err());
        assert_eq!(names(&other), ["bin"]);
    }

    fn options(address: Option<&str>, allow: Option<&[&str]>) -> InstallOptions {
        InstallOptions {
            target: Target {
                root: None,
                environment: "test".into(),
                instance: "x".into(),
            },
            port: None,
            listen_address: address.map(|a| a.parse().unwrap()),
            allow_clients: allow.map(|a| a.iter().map(|n| n.parse().unwrap()).collect()),
            ssh_dir: None,
        }
    }

    fn record(address: Option<&str>, allow: &[&str]) -> Record {
        Record {
            schema: record::SCHEMA,
            version: "0.1.0".into(),
            build_id: "0.1.0+old".into(),
            vpnd_sha256: String::new(),
            vpnctl_sha256: String::new(),
            port: 18765,
            listen_address: address.map(Into::into),
            allow_clients: allow.iter().map(|n| (*n).to_string()).collect(),
            ssh_dir: None,
            supervisor: "fake".into(),
            services: Vec::new(),
            installed_at: String::new(),
            updated_at: String::new(),
            linger_enabled: false,
        }
    }

    #[test]
    fn a_reachable_listen_address_needs_an_allow_list() {
        // The default: this host only.
        let (address, allow) = exposure(&options(None, None), None).unwrap();
        assert_eq!((address, allow.len()), (Listen::DEFAULT_ADDRESS, 0));
        // The LAN, with its networks (host bits cleared).
        let (address, allow) = exposure(
            &options(
                Some("0.0.0.0"),
                Some(&["192.168.10.0/24", "192.168.20.100/24"]),
            ),
            None,
        )
        .unwrap();
        assert_eq!(address.to_string(), "0.0.0.0");
        assert_eq!(
            allow.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["192.168.10.0/24", "192.168.20.0/24"]
        );
        // No list: refused, saying what is missing.
        let e = exposure(&options(Some("0.0.0.0"), None), None).unwrap_err();
        assert!(format!("{e:#}").contains("--allow-client"), "{e:#}");
        // A list without a reachable address, or a list of everything: refused.
        assert!(exposure(&options(None, Some(&["192.168.10.0/24"])), None).is_err());
        assert!(exposure(&options(Some("0.0.0.0"), Some(&["0.0.0.0/0"])), None).is_err());
        // An upgrade keeps what is installed; back to loopback drops the list.
        let installed = record(Some("0.0.0.0"), &["192.168.10.0/24"]);
        let (address, allow) = exposure(&options(None, None), Some(&installed)).unwrap();
        assert_eq!((address.to_string(), allow.len()), ("0.0.0.0".into(), 1));
        let (address, allow) =
            exposure(&options(Some("127.0.0.1"), None), Some(&installed)).unwrap();
        assert_eq!((address, allow.len()), (Listen::DEFAULT_ADDRESS, 0));
        // An installation of an earlier version has neither: loopback.
        let earlier: Record = serde_json::from_str(
            r#"{"schema":1,"version":"0.1.0","build_id":"b","vpnd_sha256":"","vpnctl_sha256":"","port":18765,"ssh_dir":null,"supervisor":"systemd","services":[],"installed_at":"","updated_at":""}"#,
        )
        .unwrap();
        let (address, allow) = exposure(&options(None, None), Some(&earlier)).unwrap();
        assert_eq!((address, allow.len()), (Listen::DEFAULT_ADDRESS, 0));
    }
}
