//! A running job: its scheduler and its workers. Each worker owns at most one SSH connection
//! (through the Gateway) and works one task at a time — a listing of the source folder, a file
//! taken earlier that is not finished (those first), or a new file; with none of these, it helps
//! a large file another worker fetches until the job has work of its own again. Connection
//! attempts pass one gate per job: while the VPN cannot carry them, or after a failure, the gate
//! stays closed and nobody connects until it opens again (back-off, cut short when the
//! connection's state changes).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use russh::keys::{PrivateKey, PublicKey};
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpn_domain::{
    SecretRef, SshDownloadJob, SshDownloadJobId, SshDownloadLogLevel, SshDownloadTransferState,
    Text, Timestamp, tr,
};
use vpn_store::{SshDownloadTransferRow, StoredHostKey};
use vpn_sync::Mutex;
use zeroize::Zeroizing;

use crate::local::LocalDir;
use crate::names::{Skip, join_remote, take_name};
use crate::session::{
    self, Credentials, HostKeyVerdict, HostKeys, OpenError, RemoteError, Session, Target,
};
use crate::status::{Reason, StatusCell, host_key_view};
use crate::transfer::Assist;
use crate::wire::Counted;
use crate::{Ctx, Route};

/// Most entries one listing reads (the rest wait for the next one, after these are taken).
pub const LIST_CAP: usize = 10_000;
/// Largest private key file read.
const MAX_KEY_FILE: u64 = 64 * 1024;
/// The reason code while the job's records cannot be written.
pub const STORE_UNAVAILABLE: &str = "STORE_UNAVAILABLE";

/// What a worker does next.
pub enum Task {
    Scan,
    /// A file taken earlier, continued from its record.
    Resume(Box<SshDownloadTransferRow>),
    /// A new file of the source folder.
    Take(Listed),
    /// Help a large file another worker fetches, until the job has work of its own again.
    Assist(Arc<Assist>),
}

impl Task {
    /// The size of the file it downloads, where one is known.
    fn size(&self) -> Option<u64> {
        match self {
            Self::Resume(row) => row.size,
            Self::Take(file) => file.size,
            Self::Scan | Self::Assist(_) => None,
        }
    }
}

/// A file of the source folder as the last listing saw it.
pub struct Listed {
    pub name: String,
    /// `None` from a server that reports none.
    pub size: Option<u64>,
}

enum Next {
    Task(Task),
    /// Nothing to do until this instant (or a change).
    Wait(Option<Instant>),
}

/// A record waiting to be continued, not before `not_before`.
struct Pending {
    not_before: Instant,
    row: SshDownloadTransferRow,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalRetryToken(u64);

struct LocalRetry {
    token: LocalRetryToken,
    reason: Reason,
    next_retry_at: Timestamp,
}

#[derive(Default)]
struct Sched {
    resume: Vec<Pending>,
    /// New files, the smallest first: a small file never waits behind a large one that has not
    /// started.
    queue: VecDeque<Listed>,
    /// A file of at least this size is large (see [`Sched::fits`]).
    large_file: u64,
    /// The job's connections, and the large files being downloaded.
    connections: u32,
    large_running: u32,
    /// Source names taken or being taken (never listed again while so).
    busy: HashSet<String>,
    /// Names the server refused to move: left alone until the job restarts.
    poisoned: HashSet<String>,
    /// Large files being fetched that take help.
    offers: Vec<Arc<Assist>>,
    scan_due: Option<Instant>,
    scanning: bool,
    /// The working and failed folders exist (checked once per run).
    remote_ready: bool,
    /// No connection attempt before this instant.
    gate_until: Option<Instant>,
    /// The route-change count the last lookup saw: a change after it (even one that came while
    /// the lookup ran) ends the wait at once.
    route_seen: u64,
    /// Workers waiting for a task with a connection open: they get the next task, so a worker
    /// without one does not log in again for nothing.
    idle_connected: u32,
    vpn_backoff: Duration,
    retry_backoff: Duration,
    /// File failures survive unrelated files completing or connections reopening.
    local_retry_generation: u64,
    local_retries: HashMap<String, LocalRetry>,
    /// The VPN wait last logged, until a connection succeeds or another failure is logged: the
    /// same wait is not logged twice, and the connection that ends it says what it ended.
    waited: Option<Reason>,
    stopped: bool,
}

impl Sched {
    fn large(&self, size: Option<u64>) -> bool {
        size.is_some_and(|s| s >= self.large_file)
    }

    /// Whether a file of `size` may start now. A job with several connections keeps one of them
    /// off large files: it helps with one instead (see `transfer::Assist`) and is there at once
    /// for a small file that arrives, which would otherwise wait for a large one to finish.
    fn fits(&self, size: Option<u64>) -> bool {
        self.large_running < self.connections.saturating_sub(1).max(1) || !self.large(size)
    }

    /// The file taken earlier that is due at `now` and may start.
    fn resumable(&self, now: Instant) -> Option<usize> {
        self.resume
            .iter()
            .position(|p| p.not_before <= now && self.fits(p.row.size))
    }

    /// The new file that may start: the smallest one. With a connection kept for small files, a
    /// large one comes first while none is being downloaded, so that a steady stream of small
    /// files cannot keep the large ones waiting for ever.
    fn takeable(&self) -> Option<usize> {
        let large_first = self.connections > 1 && self.large_running == 0;
        large_first
            .then(|| self.queue.iter().position(|f| self.large(f.size)))
            .flatten()
            .or_else(|| self.queue.iter().position(|f| self.fits(f.size)))
    }
}

/// The job's own work that is due at `now`, taken: a file taken earlier first, then a listing,
/// then a new file. A large file counts as running from here on (see [`Core::large`]).
fn claim(st: &mut Sched, now: Instant) -> Option<Task> {
    let task = if let Some(i) = st.resumable(now) {
        Task::Resume(Box::new(st.resume.remove(i).row))
    } else if !st.scanning && st.scan_due.is_some_and(|d| d <= now) {
        st.scanning = true;
        Task::Scan
    } else {
        let file = st.takeable().and_then(|i| st.queue.remove(i))?;
        st.busy.insert(file.name.clone());
        Task::Take(file)
    };
    if st.large(task.size()) {
        st.large_running += 1;
    }
    Some(task)
}

/// Whether [`claim`] would find something at `now`.
fn due_now(st: &Sched, now: Instant) -> bool {
    st.takeable().is_some()
        || st.resumable(now).is_some()
        || (!st.scanning && st.scan_due.is_some_and(|d| d <= now))
}

/// When the job's own work next comes due without anything changing (a listing, a retry). What
/// is due at `now` and was not taken waits for a change — a large file for one that ends — not
/// for the clock.
fn next_due(st: &Sched, now: Instant) -> Option<Instant> {
    let scan = if st.scanning { None } else { st.scan_due };
    st.resume
        .iter()
        .map(|p| p.not_before)
        .chain(scan)
        .filter(|at| *at > now)
        .min()
}

/// A large file being downloaded, counted until it is dropped.
pub struct Large<'a>(&'a Core);

impl Drop for Large<'_> {
    fn drop(&mut self) {
        let mut st = self.0.st.lock();
        st.large_running = st.large_running.saturating_sub(1);
        drop(st);
        // A large file that waited for this one may start.
        self.0.changed();
    }
}

/// A large file on offer to the job's idle connections, until it is dropped.
pub struct Offered<'a> {
    core: &'a Core,
    assist: Arc<Assist>,
}

impl Drop for Offered<'_> {
    fn drop(&mut self) {
        self.assist.end();
        self.core
            .st
            .lock()
            .offers
            .retain(|a| !Arc::ptr_eq(a, &self.assist));
    }
}

/// The status exposes one current file failure; keep every owner in the scheduler.
fn show_local_retries(cell: &StatusCell, st: &Sched) {
    let latest = st.local_retries.values().max_by_key(|retry| retry.token.0);
    cell.update(|b| {
        b.local_retrying = latest.map(|r| r.reason.clone());
        b.local_next_retry_at = latest.map(|r| r.next_retry_at);
    });
}

/// An open connection and the share of the manager-wide connection budget it holds.
pub struct Conn {
    pub session: Session,
    _permit: OwnedSemaphorePermit,
}

/// The job's host key rule: trust on first use, refuse a different key until the user trusts it.
pub struct JobHostKeys {
    job_id: SshDownloadJobId,
    target: String,
    ctx: Arc<Ctx>,
    cell: Arc<StatusCell>,
    trusted: Mutex<Option<StoredHostKey>>,
}

impl HostKeys for JobHostKeys {
    fn check<'a>(&'a self, key: &'a PublicKey) -> BoxFuture<'a, HostKeyVerdict> {
        Box::pin(async move {
            let seen = StoredHostKey {
                target: self.target.clone(),
                algorithm: key.algorithm().to_string(),
                fingerprint: session::fingerprint(key),
                public_key: key.to_openssh().unwrap_or_default(),
                seen_ms: Timestamp::now().unix_millis(),
            };
            let known = self
                .trusted
                .lock()
                .clone()
                .filter(|k| k.target == self.target);
            let recorded = match known {
                Some(k) => k,
                None => match self
                    .ctx
                    .store
                    .record_ssh_download_host_key(self.job_id, seen.clone())
                    .await
                {
                    Ok(row) => {
                        let Some(k) = row.host_key else {
                            return HostKeyVerdict::Unavailable(tr!(
                                "The host key was not recorded",
                                "主機金鑰沒有記錄下來",
                                "ホスト鍵が記録されませんでした"
                            ));
                        };
                        *self.trusted.lock() = Some(k.clone());
                        self.cell.update(|b| b.host_key = Some(host_key_view(&k)));
                        if k.fingerprint == seen.fingerprint {
                            let (target, fingerprint, algorithm) =
                                (&self.target, &k.fingerprint, &k.algorithm);
                            self.ctx
                                .log(
                                    self.job_id,
                                    SshDownloadLogLevel::Info,
                                    "HOST_KEY_RECORDED",
                                    tr!(
                                        "First connection to {target}: recorded the host key {fingerprint} ({algorithm}); only this key is accepted from now on",
                                        "第一次連到 {target}：記錄主機金鑰 {fingerprint}（{algorithm}），之後只接受這把金鑰",
                                        "{target} への初回接続：ホスト鍵 {fingerprint}（{algorithm}）を記録しました。今後はこの鍵だけを受け付けます"
                                    ),
                                    None,
                                )
                                .await;
                        }
                        k
                    }
                    Err(e) => {
                        return HostKeyVerdict::Unavailable(tr!(
                            "Cannot record the host key: {why}",
                            "無法記錄主機金鑰：{why}",
                            "ホスト鍵を記録できません：{why}";
                            why = e.to_api().message
                        ));
                    }
                },
            };
            if recorded.fingerprint == seen.fingerprint {
                return HostKeyVerdict::Trusted;
            }
            if let Ok(row) = self
                .ctx
                .store
                .offer_ssh_download_host_key(self.job_id, seen.clone())
                .await
            {
                self.cell.update(|b| {
                    b.offered_host_key = row.offered_host_key.as_ref().map(host_key_view);
                });
            }
            HostKeyVerdict::Changed {
                offered: seen.fingerprint,
            }
        })
    }
}

/// One running job.
pub struct Core {
    pub job: Arc<SshDownloadJob>,
    pub ctx: Arc<Ctx>,
    pub cell: Arc<StatusCell>,
    pub local: Arc<LocalDir>,
    target: Target,
    creds: Credentials,
    host_keys: Arc<JobHostKeys>,
    pub cancel: CancellationToken,
    st: Mutex<Sched>,
    wake: watch::Sender<u64>,
    /// Serialises connection attempts while the job has no connection: one probe at a time.
    first: tokio::sync::Mutex<()>,
    /// The user asked to list the source folder now.
    scan_now: Arc<tokio::sync::Notify>,
}

/// Why a job cannot start, with the field it concerns.
#[derive(Debug, Clone)]
pub struct StartProblem {
    pub path: &'static str,
    pub reason: Reason,
}

fn problem(path: &'static str, code: &str, message: impl Into<Text>) -> StartProblem {
    StartProblem {
        path,
        reason: Reason::new(code, message),
    }
}

/// Read and decode the job's private key (with its passphrase). Blocking.
pub fn load_key(
    file: &str,
    home: Option<&std::path::Path>,
    passphrase: Option<&str>,
) -> Result<Arc<PrivateKey>, StartProblem> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let path: PathBuf = crate::names::expand_home(file, home).ok_or_else(|| {
        problem(
            "/identity_file",
            "KEY_UNUSABLE",
            tr!(
                "No home folder was found, so a key path starting with ~/ cannot be resolved",
                "找不到家目錄，無法解析 ~/ 開頭的金鑰路徑",
                "ホームフォルダーが見つからないため、~/ で始まる鍵のパスを解決できません"
            ),
        )
    })?;
    let shown = path.display();
    let unusable = |m: Text| problem("/identity_file", "KEY_UNUSABLE", m);
    let unreadable = |e: std::io::Error| {
        unusable(tr!(
            "Cannot read the key file {shown}: {e}",
            "無法讀取金鑰檔 {shown}：{e}",
            "鍵ファイル {shown} を読み取れません：{e}"
        ))
    };
    let m = std::fs::metadata(&path).map_err(unreadable)?;
    let me = crate::local::uid();
    if !m.is_file() {
        return Err(unusable(tr!(
            "The key file {shown} is not a regular file",
            "金鑰檔 {shown} 不是一般檔案",
            "鍵ファイル {shown} は通常のファイルではありません"
        )));
    }
    if m.uid() != me {
        return Err(unusable(tr!(
            "The key file {shown} does not belong to the user who runs VPN Manager",
            "金鑰檔 {shown} 不屬於執行 VPN Manager 的使用者",
            "鍵ファイル {shown} は VPN Manager を実行しているユーザーの所有ではありません"
        )));
    }
    if m.mode() & 0o077 != 0 {
        let mode = m.mode() & 0o7777;
        return Err(unusable(tr!(
            "The key file {shown} is readable by other users (permissions {mode:04o}); change them to 0600 (chmod 600)",
            "金鑰檔 {shown} 可被其他使用者讀取（權限 {mode:04o}）；請改成 0600（chmod 600）",
            "鍵ファイル {shown} はほかのユーザーが読み取れます（権限 {mode:04o}）。0600 に変更してください（chmod 600）"
        )));
    }
    if m.len() > MAX_KEY_FILE {
        return Err(unusable(tr!(
            "The key file {shown} is too large to be a private key",
            "金鑰檔 {shown} 太大，不像私鑰",
            "鍵ファイル {shown} は秘密鍵にしては大きすぎます"
        )));
    }
    let mut text = Zeroizing::new(String::new());
    std::fs::File::open(&path)
        .and_then(|mut f| f.read_to_string(&mut text))
        .map_err(unreadable)?;
    // RSA is not built in (its implementation carries an open advisory): such a key is refused
    // here, by name, instead of failing at every login.
    let rsa = || {
        unusable(tr!(
            "The key file {shown} holds an RSA key, and this version does not support RSA; use an ed25519 key instead (ssh-keygen -t ed25519)",
            "金鑰檔 {shown} 是 RSA 金鑰，這個版本不支援 RSA；請改用 ed25519 金鑰（ssh-keygen -t ed25519）",
            "鍵ファイル {shown} は RSA 鍵ですが、このバージョンは RSA に対応していません。代わりに ed25519 鍵を使ってください（ssh-keygen -t ed25519）"
        ))
    };
    let key =
        russh::keys::decode_secret_key(&text, passphrase).map_err(|e| match (e, passphrase) {
            (
                russh::keys::Error::UnsupportedKeyType {
                    key_type_string, ..
                },
                _,
            ) if key_type_string.eq_ignore_ascii_case("rsa") => rsa(),
            (russh::keys::Error::KeyIsEncrypted, None) => problem(
                "/key_passphrase",
                "KEY_PASSPHRASE_REQUIRED",
                tr!(
                    "This key is protected by a passphrase; enter the key passphrase",
                    "這把金鑰有密碼保護，請輸入金鑰密碼",
                    "この鍵はパスフレーズで保護されています。鍵のパスフレーズを入力してください"
                ),
            ),
            (_, Some(_)) => problem(
                "/key_passphrase",
                "KEY_PASSPHRASE_WRONG",
                tr!(
                    "Cannot unlock {shown} with this key passphrase (the passphrase is wrong, or the format is not supported)",
                    "無法用這個金鑰密碼解開 {shown}（密碼不正確，或格式不支援）",
                    "この鍵のパスフレーズでは {shown} を解除できません（パスフレーズが正しくないか、形式に対応していません）"
                ),
            ),
            (e, None) => unusable(tr!(
                "Cannot read the key {shown}: {e}",
                "無法讀取金鑰 {shown}：{e}",
                "鍵 {shown} を読み取れません：{e}"
            )),
        })?;
    if key.algorithm().is_rsa() {
        return Err(rsa());
    }
    Ok(Arc::new(key))
}

/// What a job needs before it can run: its folder, its credentials. The local folder is created
/// when missing.
pub async fn prepare(
    ctx: &Arc<Ctx>,
    job: &SshDownloadJob,
) -> Result<(LocalDir, Credentials), StartProblem> {
    let local_path =
        crate::names::expand_home(&job.local_dir, ctx.home.as_deref()).ok_or_else(|| {
            problem(
                "/local_dir",
                "LOCAL_DIR_UNUSABLE",
                tr!(
                    "No home folder was found, so a folder starting with ~/ cannot be resolved",
                    "找不到家目錄，無法解析 ~/ 開頭的資料夾",
                    "ホームフォルダーが見つからないため、~/ で始まるフォルダーを解決できません"
                ),
            )
        })?;
    let local = tokio::task::spawn_blocking(move || LocalDir::open(&local_path, true))
        .await
        .map_err(|_| {
            problem(
                "/local_dir",
                "LOCAL_DIR_UNUSABLE",
                tr!(
                    "Checking the local folder was interrupted",
                    "檢查本機資料夾時中斷",
                    "ローカルフォルダーの確認が中断されました"
                ),
            )
        })?
        .map_err(|e| problem("/local_dir", "LOCAL_DIR_UNUSABLE", e.0))?;
    let secret = |r: Option<SecretRef>, path: &'static str| {
        let store = ctx.store.clone();
        async move {
            match r {
                None => Ok(None),
                Some(r) => store
                    .open_secret(r)
                    .await
                    .map(|b| Some(Zeroizing::new(String::from_utf8_lossy(&b).into_owned())))
                    .map_err(|e| {
                        problem(
                            path,
                            "SECRET_UNAVAILABLE",
                            tr!(
                                "Cannot take it out of the key vault: {why}",
                                "無法從金鑰保管庫取出：{why}",
                                "鍵保管庫から取り出せません：{why}";
                                why = e.to_api().message
                            ),
                        )
                    }),
            }
        }
    };
    let passphrase = secret(job.key_passphrase, "/key_passphrase").await?;
    let password = secret(job.password, "/password").await?;
    let key = match &job.identity_file {
        None => None,
        Some(file) => {
            let (file, home) = (file.clone(), ctx.home.clone());
            Some(
                tokio::task::spawn_blocking(move || {
                    load_key(
                        &file,
                        home.as_deref(),
                        passphrase.as_ref().map(|p| p.as_str()),
                    )
                })
                .await
                .map_err(|_| {
                    problem(
                        "/identity_file",
                        "KEY_UNUSABLE",
                        tr!(
                            "Reading the key was interrupted",
                            "讀取金鑰時中斷",
                            "鍵の読み取りが中断されました"
                        ),
                    )
                })??,
            )
        }
    };
    Ok((
        local,
        Credentials {
            key,
            password: password.map(Arc::new),
        },
    ))
}

/// What a listing found: `fresh` new files, `queued` waiting in all.
fn scan_found(fresh: usize, queued: usize) -> Text {
    tr!(
        "New files in the source folder: {fresh} ({queued} waiting to be downloaded in all)",
        "來源資料夾有 {fresh} 個新檔案（共 {queued} 個等待下載）",
        "取得元フォルダーの新しいファイル：{fresh} 件（ダウンロード待ちは合計 {queued} 件）"
    )
}

/// The connection went while the source folder was listed (`m`: how).
fn lost_while_listing(m: Text) -> Text {
    tr!(
        "The connection to the server was broken while listing the source folder: {m}",
        "列出來源資料夾時與伺服器的連線中斷：{m}",
        "取得元フォルダーの一覧を取得している間にサーバーとの接続が切断されました：{m}";
        m = m
    )
}

/// Why the source folder (`dir`) could not be listed, or the other folders prepared.
fn remote_dir_problem(e: &RemoteError, dir: &str) -> Text {
    if *e == RemoteError::Missing {
        tr!(
            "The remote source folder {dir} does not exist",
            "遠端的來源資料夾 {dir} 不存在",
            "リモートの取得元フォルダー {dir} が存在しません"
        )
    } else {
        tr!(
            "Cannot list or prepare the remote folders: {why}",
            "無法列出或準備遠端資料夾：{why}",
            "リモートフォルダーを一覧または準備できません：{why}";
            why = e.text()
        )
    }
}

/// A remote path that is not a folder, as the server would refuse it.
fn not_a_folder(path: &str) -> RemoteError {
    RemoteError::Refused(tr!(
        "{path} is not a folder",
        "{path} 不是資料夾",
        "{path} はフォルダーではありません"
    ))
}

fn deadline(d: Duration) -> Instant {
    Instant::now() + d
}

pub async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The scheduler's facts the board shows.
fn show_queue(cell: &StatusCell, st: &Sched) {
    let queued = u32::try_from(st.queue.len()).unwrap_or(u32::MAX);
    let unfinished = u32::try_from(st.resume.len()).unwrap_or(u32::MAX);
    cell.update(|b| {
        b.queued = queued;
        b.unfinished = unfinished;
    });
}

impl Core {
    #[allow(
        clippy::too_many_arguments,
        reason = "the one constructor of a running job: every argument is a part it owns, passed once by the engine"
    )]
    pub(crate) fn new(
        job: Arc<SshDownloadJob>,
        ctx: Arc<Ctx>,
        cell: Arc<StatusCell>,
        local: LocalDir,
        creds: Credentials,
        trusted: Option<StoredHostKey>,
        cancel: CancellationToken,
        scan_now: Arc<tokio::sync::Notify>,
    ) -> Arc<Self> {
        let target = Target {
            host: job.host.trim().to_string(),
            port: job.port,
            user: job.user.clone(),
        };
        let host_keys = Arc::new(JobHostKeys {
            job_id: job.id,
            target: target.label(),
            ctx: ctx.clone(),
            cell: cell.clone(),
            trusted: Mutex::new(trusted),
        });
        let st = Sched {
            scan_due: Some(Instant::now()),
            vpn_backoff: ctx.opts.vpn_backoff.0,
            retry_backoff: ctx.opts.retry_backoff.0,
            large_file: ctx.opts.large_file,
            connections: job.connections,
            ..Sched::default()
        };
        Arc::new(Self {
            job,
            ctx,
            cell,
            local: Arc::new(local),
            target,
            creds,
            host_keys,
            cancel,
            st: Mutex::new(st),
            wake: watch::Sender::new(0),
            first: tokio::sync::Mutex::new(()),
            scan_now,
        })
    }

    fn changed(&self) {
        self.wake.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Run until cancelled (or stopped for the user): the unfinished records first, then N
    /// workers.
    pub(crate) async fn run(self: Arc<Self>, open: Vec<SshDownloadTransferRow>) {
        {
            let mut st = self.st.lock();
            for row in open {
                st.busy.insert(row.name.clone());
                st.resume.push(Pending {
                    not_before: Instant::now(),
                    row,
                });
            }
            show_queue(&self.cell, &st);
            drop(st);
        }
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..self.job.connections.max(1) {
            workers.spawn(self.clone().worker());
        }
        // "List now": the next free worker lists the source folder.
        let me = self.clone();
        workers.spawn(async move {
            loop {
                tokio::select! {
                    () = me.cancel.cancelled() => return,
                    () = me.scan_now.notified() => {
                        me.st.lock().scan_due = Some(Instant::now());
                        me.changed();
                    }
                }
            }
        });
        while workers.join_next().await.is_some() {}
    }

    /// Stop the job for the user (a host key changed, the login was refused): no worker takes a
    /// task again, and the open connections close.
    pub(crate) fn stop_for_user(&self, reason: Reason) {
        self.st.lock().stopped = true;
        self.cell.update(|b| {
            b.error = Some(reason);
            b.next_retry_at = None;
            b.running_since = None;
        });
        self.cancel.cancel();
    }

    /// The worker's next task, or how long to wait. `registered`: the worker (with a connection)
    /// is counted as idle; it stays counted until it takes a task here, so a worker without a
    /// connection never takes one first.
    fn next_task(&self, connected: bool, registered: &mut bool) -> Next {
        let mut st = self.st.lock();
        if st.stopped || (!connected && st.idle_connected > 0) {
            return Next::Wait(None);
        }
        let now = Instant::now();
        // Nothing of its own to do: the large file with the fewest helpers gets this one. A
        // worker does not log in for that with the manager's last free connection, which is
        // for some job's own work.
        let may_help = connected || self.ctx.conns.available_permits() >= 2;
        let task = claim(&mut st, now).or_else(|| {
            st.offers
                .iter()
                .filter(|a| may_help && a.takes_help())
                .min_by_key(|a| a.helpers())
                .cloned()
                .map(Task::Assist)
        });
        if let Some(task) = task {
            if *registered {
                st.idle_connected = st.idle_connected.saturating_sub(1);
                *registered = false;
            }
            show_queue(&self.cell, &st);
            // More work, or a large file that takes more help: the other workers look too
            // (those without a connection included).
            let more = due_now(&st, now) || st.offers.iter().any(|a| a.takes_help());
            drop(st);
            if more {
                self.changed();
            }
            return Next::Task(task);
        }
        if connected && !*registered {
            st.idle_connected += 1;
            *registered = true;
        }
        let until = next_due(&st, now);
        drop(st);
        Next::Wait(until)
    }

    /// Work of the job's own that came due, for a worker that helps a large file meanwhile: it
    /// is that worker's now. Nothing while an idle connection can take it instead.
    pub(crate) fn other_work(&self) -> Option<Task> {
        let mut st = self.st.lock();
        if st.stopped || st.idle_connected > 0 {
            return None;
        }
        let task = claim(&mut st, Instant::now());
        if task.is_some() {
            show_queue(&self.cell, &st);
        }
        drop(st);
        task
    }

    /// When a worker that helps a large file looks for other work again without a change.
    pub(crate) fn other_work_due(&self) -> Option<Instant> {
        next_due(&self.st.lock(), Instant::now())
    }

    /// A large file is being fetched: the job's connections with nothing else to do help with
    /// it until the guard drops.
    pub(crate) fn offer(&self, assist: Arc<Assist>) -> Offered<'_> {
        self.st.lock().offers.push(assist.clone());
        self.changed();
        Offered { core: self, assist }
    }

    /// The count of a large file `task` downloads, taken at its claim: given up when the
    /// returned guard drops, whatever became of the task.
    pub(crate) fn large(&self, task: &Task) -> Option<Large<'_>> {
        let large_file = self.ctx.opts.large_file;
        task.size()
            .is_some_and(|s| s >= large_file)
            .then(|| Large(self))
    }

    /// A change the job's workers look at (also those that help a large file).
    pub(crate) fn changes(&self) -> watch::Receiver<u64> {
        self.wake.subscribe()
    }

    /// The worker no longer counts as idle with a connection (it closed it, or it ends).
    fn unregister(&self, registered: &mut bool) {
        if *registered {
            let mut st = self.st.lock();
            st.idle_connected = st.idle_connected.saturating_sub(1);
            *registered = false;
            drop(st);
            self.changed();
        }
    }

    /// A task that could not run goes back.
    pub(crate) fn give_back(&self, task: Task) {
        let mut st = self.st.lock();
        match task {
            // Help is not owed: the file is fetched without it.
            Task::Assist(_) => return,
            Task::Scan => st.scanning = false,
            Task::Resume(row) => st.resume.push(Pending {
                not_before: Instant::now(),
                row: *row,
            }),
            Task::Take(file) => {
                st.busy.remove(&file.name);
                st.queue.push_front(file);
            }
        }
        show_queue(&self.cell, &st);
        drop(st);
        self.changed();
    }

    /// Continue `row` later (after `after`).
    pub(crate) fn later(&self, row: SshDownloadTransferRow, after: Duration) {
        let mut st = self.st.lock();
        st.resume.push(Pending {
            not_before: deadline(after),
            row,
        });
        show_queue(&self.cell, &st);
        drop(st);
        self.changed();
    }

    /// A source name is free again (its file is gone from the source folder, or its record ended).
    pub(crate) fn release(&self, name: &str) {
        self.st.lock().busy.remove(name);
    }

    /// The server refused to move `name`: it is left alone until the job restarts.
    pub(crate) fn poison(&self, name: &str) {
        let mut st = self.st.lock();
        st.busy.remove(name);
        st.poisoned.insert(name.to_string());
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the worker keeps its SSH connection open across tasks; it closes it itself"
    )]
    async fn worker(self: Arc<Self>) {
        let mut conn: Option<Conn> = None;
        let mut registered = false;
        let mut wake = self.wake.subscribe();
        // Work taken over while helping a large file, and the mark of a connection that only
        // helped being given back.
        let mut taken: Option<Task> = None;
        let mut yielding = None;
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            wake.borrow_and_update();
            let next = taken.take().map_or_else(
                || self.next_task(conn.is_some(), &mut registered),
                Next::Task,
            );
            let task = match next {
                Next::Task(t) => t,
                Next::Wait(until) => {
                    // An idle connection is closed after a while — except the job's last one,
                    // kept for the next listing (one login per listing would be one a minute).
                    let idle = conn.as_ref().map(|_| deadline(self.idle_for()));
                    tokio::select! {
                        () = self.cancel.cancelled() => break,
                        _ = wake.changed() => {}
                        () = sleep_until(until) => {}
                        () = sleep_until(idle) => {
                            // Without its connection, it no longer stands in the others' way.
                            self.unregister(&mut registered);
                            if let Some(c) = conn.take() {
                                self.closed(c).await;
                            }
                        }
                    }
                    continue;
                }
            };
            let _large = self.large(&task);
            if conn.as_ref().is_some_and(|c| c.session.is_closed())
                && let Some(c) = conn.take()
            {
                self.closed(c).await;
            }
            if conn.is_none() {
                if let Some(c) = self.connect().await {
                    conn = Some(c);
                } else {
                    self.give_back(task);
                    continue;
                }
            }
            let Some(c) = conn.as_ref() else { continue };
            let work = async {
                match task {
                    Task::Scan => self.scan(c).await,
                    Task::Resume(row) => self.transfer(c, *row).await,
                    Task::Take(file) => self.take(c, file).await,
                    Task::Assist(help) => {
                        let helped = self.assist(c, &help).await;
                        taken = helped.work;
                        yielding = helped.yielding;
                        helped.keep
                    }
                }
            };
            // A stop never waits for a slow server: the task is dropped where it is (each step is
            // recorded before it is taken, so the next run continues it).
            let keep = tokio::select! {
                () = self.cancel.cancelled() => break,
                keep = work => keep,
            };
            if !keep && let Some(c) = conn.take() {
                self.closed(c).await;
            }
            // The connection is back in the manager's budget: the next helper may go.
            drop(yielding.take());
        }
        self.unregister(&mut registered);
        if let Some(c) = conn.take() {
            self.closed(c).await;
        }
    }

    /// How long an idle connection stays open: the job's last one until after the next listing.
    fn idle_for(&self) -> Duration {
        let listing = Duration::from_secs(u64::from(self.job.scan_interval_secs));
        if self.cell.read(|b| b.sessions) <= 1 && listing <= Duration::from_secs(600) {
            self.ctx
                .opts
                .idle_close
                .max(listing + Duration::from_secs(60))
        } else {
            self.ctx.opts.idle_close
        }
    }

    /// The working or failed folder may be gone (a claim found no target): check them again with
    /// the next listing, which comes now.
    pub(crate) fn folders_again(&self) {
        let mut st = self.st.lock();
        st.remote_ready = false;
        st.scan_due = Some(Instant::now());
        drop(st);
        self.changed();
    }

    async fn closed(&self, c: Conn) {
        self.cell
            .update(|b| b.sessions = b.sessions.saturating_sub(1));
        c.session.close().await;
    }

    /// Open a connection through the Gateway when the gate lets one through; `None` when it did
    /// not (the gate, the reason and the back-off are on the board) or the job stops.
    async fn connect(&self) -> Option<Conn> {
        let mut changes = self.ctx.routes.changes();
        loop {
            let until = self.st.lock().gate_until.filter(|u| *u > Instant::now());
            let Some(until) = until else { break };
            // The connection's state changed after the last lookup: try now.
            let seen = *changes.borrow_and_update();
            if seen != self.st.lock().route_seen {
                self.st.lock().gate_until = None;
                break;
            }
            tokio::select! {
                () = self.cancel.cancelled() => return None,
                () = tokio::time::sleep_until(until) => {}
                // The connection's state changed: try now instead of at the end of the wait.
                r = changes.changed() => {
                    if r.is_ok() {
                        self.st.lock().gate_until = None;
                    } else {
                        tokio::time::sleep_until(until).await;
                    }
                }
            }
        }
        // While the job has no connection, one attempt at a time.
        let _first = if self.cell.read(|b| b.sessions) == 0 {
            let lock = tokio::select! {
                () = self.cancel.cancelled() => return None,
                g = self.first.lock() => g,
            };
            // Another worker may have failed meanwhile: its gate holds for this one too.
            if self
                .st
                .lock()
                .gate_until
                .is_some_and(|u| u > Instant::now())
            {
                return None;
            }
            Some(lock)
        } else {
            None
        };
        let permit = tokio::select! {
            () = self.cancel.cancelled() => return None,
            p = self.ctx.conns.clone().acquire_owned() => p.ok()?,
        };
        self.cell.update(|b| b.connecting += 1);
        let attempt = async {
            let seen = *changes.borrow_and_update();
            self.st.lock().route_seen = seen;
            match self.ctx.routes.route(self.job.gateway_id).await {
                Route::Ready(gateway) => {
                    session::open(
                        &gateway,
                        &self.target,
                        &self.creds,
                        self.host_keys.clone(),
                        self.ctx.opts.connect_timeout,
                        // The Gateway took it: no longer waiting for the VPN, but connecting.
                        // Its bytes count as the job's traffic (and as that Gateway's).
                        |stream| {
                            self.cell.update(|b| {
                                if b.waiting.take().is_some() {
                                    b.next_retry_at = None;
                                }
                            });
                            Counted::new(stream, self.cell.clone())
                        },
                    )
                    .await
                }
                // No route, no connection: nothing is dialled.
                Route::Waiting { code, reason } | Route::Invalid { code, reason } => {
                    Err(OpenError::Vpn { code, reason })
                }
            }
        };
        let result = tokio::select! {
            () = self.cancel.cancelled() => None,
            r = attempt => Some(r),
        };
        self.cell
            .update(|b| b.connecting = b.connecting.saturating_sub(1));
        let outcome = result?;
        match outcome {
            Ok(session) => {
                self.connected().await;
                Some(Conn {
                    session,
                    _permit: permit,
                })
            }
            Err(e) => {
                self.connect_failed(e).await;
                None
            }
        }
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the job state and the board change together under the state lock"
    )]
    async fn connected(&self) {
        let was = {
            let mut st = self.st.lock();
            st.gate_until = None;
            st.vpn_backoff = self.ctx.opts.vpn_backoff.0;
            st.retry_backoff = self.ctx.opts.retry_backoff.0;
            let waited = st.waited.take();
            self.cell.update(|b| {
                b.sessions += 1;
                b.waiting = None;
                b.next_retry_at = None;
                b.retrying.take().or(waited)
            })
        };
        if let Some(was) = was {
            let target = self.target.label();
            self.ctx
                .log(
                    self.job.id,
                    SshDownloadLogLevel::Info,
                    "CONNECTED",
                    tr!(
                        "Connected to {target} through the Gateway (before: {before})",
                        "已經由代理埠連上 {target}（先前：{before}）",
                        "ゲートウェイ経由で {target} に接続しました（直前：{before}）";
                        before = was.message
                    ),
                    None,
                )
                .await;
        }
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the job state and the board change together under the state lock"
    )]
    async fn connect_failed(&self, e: OpenError) {
        let reason = Reason::new(e.code(), e.reason());
        match e {
            OpenError::HostKeyChanged { .. } | OpenError::AuthRejected(_) => {
                self.ctx
                    .log(
                        self.job.id,
                        SshDownloadLogLevel::Error,
                        e.code(),
                        e.reason(),
                        None,
                    )
                    .await;
                self.stop_for_user(reason);
            }
            OpenError::Vpn { .. } => {
                let (wait, new) = {
                    let mut st = self.st.lock();
                    let wait = st.vpn_backoff;
                    st.vpn_backoff = (wait * 2).min(self.ctx.opts.vpn_backoff.1);
                    st.gate_until = Some(deadline(wait));
                    let new = st.waited.as_ref() != Some(&reason);
                    st.waited = Some(reason.clone());
                    self.cell.update(|b| {
                        b.waiting = Some(reason.clone());
                        b.retrying = None;
                        b.next_retry_at = Some(Timestamp::now().plus(wait));
                    });
                    (wait, new)
                };
                tracing::debug!(job = %self.job.id, ?wait, code = e.code(), "waiting for the VPN");
                if new {
                    self.ctx
                        .log(
                            self.job.id,
                            SshDownloadLogLevel::Warning,
                            e.code(),
                            tr!(
                                "Waiting for the VPN: {why} (it never falls back to the ordinary network)",
                                "等待 VPN：{why}（不會改走一般網路）",
                                "VPN を待っています：{why}（通常のネットワークには切り替わりません）";
                                why = reason.message.clone()
                            ),
                            None,
                        )
                        .await;
                }
            }
            OpenError::Transient { .. } => self.retry_later(reason).await,
        }
    }

    /// A failure that may pass: no connection attempt for the back-off.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the job state and the board change together under the state lock"
    )]
    pub(crate) async fn retry_later(&self, reason: Reason) {
        let new = {
            let mut st = self.st.lock();
            let wait = st.retry_backoff;
            st.retry_backoff = (wait * 2).min(self.ctx.opts.retry_backoff.1);
            st.gate_until = Some(deadline(wait));
            // Another kind of failure: a VPN wait after it is news again.
            st.waited = None;
            self.cell.update(|b| {
                let new = b.retrying.as_ref() != Some(&reason);
                b.retrying = Some(reason.clone());
                b.waiting = None;
                b.next_retry_at = Some(Timestamp::now().plus(wait));
                new
            })
        };
        if new {
            self.ctx
                .log(
                    self.job.id,
                    SshDownloadLogLevel::Warning,
                    &reason.code,
                    reason.message.clone(),
                    None,
                )
                .await;
        }
    }

    pub(crate) fn local_retry_token(&self, id: &str) -> Option<LocalRetryToken> {
        self.st.lock().local_retries.get(id).map(|r| r.token)
    }

    /// Only this file waits for local storage. Connection retries keep their own gate. `file`:
    /// how the log refers to the file. A cause is logged once — with the first file that met it
    /// — while any file still waits for it: a full disk fails every file of the queue the same
    /// way, and one line each would push everything else out of the job's log.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the scheduler and status projection change together under the state lock"
    )]
    pub(crate) async fn retry_local_transfer(&self, id: &str, file: String, reason: Reason) {
        let new = {
            let mut st = self.st.lock();
            let known = st.local_retries.values().any(|r| r.reason == reason);
            st.local_retry_generation = st.local_retry_generation.wrapping_add(1);
            let token = LocalRetryToken(st.local_retry_generation);
            st.local_retries.insert(
                id.to_owned(),
                LocalRetry {
                    token,
                    reason: reason.clone(),
                    next_retry_at: Timestamp::now().plus(self.ctx.opts.local_retry),
                },
            );
            show_local_retries(&self.cell, &st);
            !known
        };
        self.changed();
        if new {
            self.ctx
                .log(
                    self.job.id,
                    SshDownloadLogLevel::Warning,
                    &reason.code,
                    reason.message,
                    Some(file),
                )
                .await;
        }
    }

    /// The job's records are written again: the wait `retry_later` started for them is over
    /// (nothing else ends it while the connection that saw the failure stays open).
    pub(crate) fn store_answers(&self) {
        let waits = |b: &crate::status::Board| {
            b.retrying
                .as_ref()
                .is_some_and(|r| r.code == STORE_UNAVAILABLE)
        };
        if !self.cell.read(waits) {
            return;
        }
        let cleared = {
            let mut st = self.st.lock();
            let cleared = self.cell.update(|b| {
                let cleared = waits(b);
                if cleared {
                    b.retrying = None;
                    b.next_retry_at = None;
                }
                cleared
            });
            if cleared {
                st.gate_until = None;
            }
            cleared
        };
        if cleared {
            self.changed();
        }
    }

    /// A successful operation can only resolve the failure it actually retried.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the scheduler and status projection change together under the state lock"
    )]
    pub(crate) fn recover_local_retry(
        &self,
        id: &str,
        token: Option<LocalRetryToken>,
        expected_code: Option<&str>,
    ) {
        let Some(token) = token else { return };
        let recovered = {
            let mut st = self.st.lock();
            let matches = st.local_retries.get(id).is_some_and(|r| {
                r.token == token && expected_code.is_none_or(|code| r.reason.code == code)
            });
            if matches {
                st.local_retries.remove(id);
                show_local_retries(&self.cell, &st);
            }
            matches
        };
        if recovered {
            self.changed();
        }
    }

    /// Make sure a remote folder exists (creating the missing parts).
    async fn ensure_dir(&self, c: &Conn, dir: &str) -> Result<(), RemoteError> {
        let path = vpn_domain::remote_path(dir).to_string();
        let sftp = &c.session.sftp;
        match sftp.stat(path.clone()).await.map_err(session::remote_error) {
            Ok(a) if a.attrs.is_dir() => return Ok(()),
            Ok(_) => return Err(not_a_folder(&path)),
            Err(RemoteError::Missing) => {}
            Err(e) => return Err(e),
        }
        // Parents first, at most a few dozen levels.
        let mut parts = Vec::new();
        let mut cur = path.as_str();
        while let Some((parent, _)) = cur.rsplit_once('/') {
            if parent.is_empty() || parts.len() > 32 {
                break;
            }
            parts.push(parent.to_string());
            cur = parent;
        }
        for p in parts.iter().rev() {
            if sftp.stat(p.clone()).await.is_err() {
                let _ = sftp
                    .mkdir(p.clone(), russh_sftp::protocol::FileAttributes::empty())
                    .await;
            }
        }
        match sftp
            .mkdir(path.clone(), russh_sftp::protocol::FileAttributes::empty())
            .await
            .map_err(session::remote_error)
        {
            Ok(_) => Ok(()),
            Err(RemoteError::Lost(m)) => Err(RemoteError::Lost(m)),
            // Raced with someone else, or refused: what is there now decides.
            Err(e) => match sftp.stat(path.clone()).await {
                Ok(a) if a.attrs.is_dir() => Ok(()),
                _ => Err(e),
            },
        }
    }

    /// List the source folder (bounded) into the queue.
    async fn scan(&self, c: &Conn) -> bool {
        self.cell.update(|b| b.scanning = true);
        let result = self.list(c).await;
        let interval = Duration::from_secs(u64::from(self.job.scan_interval_secs));
        let done = |st: &mut Sched| {
            st.scanning = false;
            st.scan_due = Some(deadline(interval));
        };
        match result {
            Ok((files, skipped, truncated)) => {
                let (fresh, queued) = {
                    let mut st = self.st.lock();
                    done(&mut st);
                    let before: HashSet<String> = st.queue.iter().map(|f| f.name.clone()).collect();
                    let next: VecDeque<Listed> = files
                        .into_iter()
                        .filter(|f| !st.busy.contains(&f.name) && !st.poisoned.contains(&f.name))
                        .collect();
                    let fresh = next.iter().filter(|f| !before.contains(&f.name)).count();
                    st.queue = next;
                    show_queue(&self.cell, &st);
                    (fresh, st.queue.len())
                };
                self.cell.update(|b| {
                    b.scanning = false;
                    b.last_scan_at = Some(Timestamp::now());
                    b.next_scan_at = Some(Timestamp::now().plus(interval));
                    b.last_scan_skipped = skipped;
                    b.queue_truncated = truncated;
                    if b.retrying.as_ref().is_some_and(|r| r.code == "REMOTE_DIR") {
                        b.retrying = None;
                    }
                });
                if fresh > 0 {
                    self.ctx
                        .log(
                            self.job.id,
                            SshDownloadLogLevel::Info,
                            "SCAN_FOUND",
                            scan_found(fresh, queued),
                            None,
                        )
                        .await;
                }
                self.changed();
                true
            }
            Err(e) => {
                self.st.lock().scanning = false;
                self.cell.update(|b| b.scanning = false);
                match e {
                    RemoteError::Lost(m) => {
                        // Listing again as soon as a connection is back.
                        self.st.lock().scan_due = Some(Instant::now());
                        self.retry_later(Reason::new("CONNECTION_LOST", lost_while_listing(m)))
                            .await;
                        false
                    }
                    other => {
                        done(&mut self.st.lock());
                        let message = remote_dir_problem(&other, &self.job.source_dir);
                        let new = self.cell.update(|b| {
                            let r = Reason::new("REMOTE_DIR", message.clone());
                            let new = b.retrying.as_ref() != Some(&r);
                            b.retrying = Some(r);
                            b.next_retry_at = Some(Timestamp::now().plus(interval));
                            new
                        });
                        if new {
                            self.ctx
                                .log(
                                    self.job.id,
                                    SshDownloadLogLevel::Warning,
                                    "REMOTE_DIR",
                                    message,
                                    None,
                                )
                                .await;
                        }
                        true
                    }
                }
            }
        }
    }

    /// The files the job takes now (the smallest first), how many entries it left alone, and
    /// whether the listing stopped at its limit.
    async fn list(&self, c: &Conn) -> Result<(Vec<Listed>, u32, bool), RemoteError> {
        let sftp = &c.session.sftp;
        let source = vpn_domain::remote_path(&self.job.source_dir).to_string();
        match sftp
            .stat(source.clone())
            .await
            .map_err(session::remote_error)?
        {
            a if a.attrs.is_dir() => {}
            _ => return Err(not_a_folder(&source)),
        }
        if !self.st.lock().remote_ready {
            self.ensure_dir(c, &self.job.work_dir).await?;
            self.ensure_dir(c, &self.job.failed_dir).await?;
            self.st.lock().remote_ready = true;
        }
        let handle = sftp
            .opendir(source.clone())
            .await
            .map_err(session::remote_error)?
            .handle;
        let mut files = Vec::new();
        let mut skipped = 0u32;
        let mut seen = 0usize;
        let mut truncated = false;
        let listing = async {
            loop {
                let batch = match sftp.readdir(handle.clone()).await {
                    Ok(b) => b,
                    Err(russh_sftp::client::error::Error::Status(s))
                        if s.status_code == russh_sftp::protocol::StatusCode::Eof =>
                    {
                        break;
                    }
                    Err(e) => return Err(session::remote_error(e)),
                };
                for f in batch.files {
                    if f.filename == "." || f.filename == ".." {
                        continue;
                    }
                    seen += 1;
                    let regular = f
                        .attrs
                        .permissions
                        .is_some_and(|p| p & 0o170_000 == 0o100_000);
                    let take = if regular {
                        take_name(&f.filename, self.job.name_filter, self.job.skip_hidden)
                    } else {
                        Err(Skip::NotFile)
                    };
                    match take {
                        Ok(()) => files.push(Listed {
                            name: f.filename,
                            size: f.attrs.size,
                        }),
                        Err(_) => skipped += 1,
                    }
                }
                if seen >= LIST_CAP {
                    truncated = true;
                    break;
                }
            }
            Ok(())
        };
        let r = listing.await;
        let _ = sftp.close(handle).await;
        r?;
        // Files of unknown size last; the same sizes by name, so the order does not depend on
        // the server's.
        files.sort_by(|a, b| {
            (a.size.unwrap_or(u64::MAX), &a.name).cmp(&(b.size.unwrap_or(u64::MAX), &b.name))
        });
        Ok((files, skipped, truncated))
    }

    /// The remote paths of a new record of `name`.
    pub(crate) fn new_row(&self, name: String) -> SshDownloadTransferRow {
        let id = uuid::Uuid::new_v4().to_string();
        SshDownloadTransferRow {
            work_path: join_remote(&self.job.work_dir, &id),
            source_path: join_remote(&self.job.source_dir, &name),
            local_dir: self.local.path().display().to_string(),
            id,
            job_id: self.job.id,
            name,
            state: SshDownloadTransferState::Claiming,
            final_path: None,
            failed_path: None,
            size: None,
            bytes_done: None,
            attempts: 0,
            error: None,
            created_ms: Timestamp::now().unix_millis(),
            started_ms: None,
            finished_ms: None,
        }
    }
}

/// Load the records of a job that are not finished.
pub async fn open_records(ctx: &Ctx, job: SshDownloadJobId) -> Vec<SshDownloadTransferRow> {
    match ctx.store.ssh_download_open_transfers(job).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(job = %job, error = %e, "unfinished SSH download records not read");
            Vec::new()
        }
    }
}
