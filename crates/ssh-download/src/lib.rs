//! SSH download: an internal component of the manager that runs jobs pulling files from a remote
//! folder over SFTP into a local folder (the workflow of the user's `ssh-downloader`: claim into a
//! working folder, resumable download, atomic finalize, remote delete; the failed folder after the
//! last attempt).
//!
//! Its boundary is narrow:
//! - **Store**: its own entity kind (`ssh_download_job`) and tables (job state, file records, log)
//!   through the `Store` methods made for them, and the vault for its secrets;
//! - **Gateway lookup** ([`Routes`]): which loopback port carries a Gateway's traffic now, or why
//!   none does — the manager answers from the Instance's live state;
//! - **events** ([`Publish`]): each job's status, at most once a second.
//!
//! Every connection goes through the job's Gateway (SOCKS5; the host name is resolved inside the
//! tunnel; the Gateway must prove it is this installation's). There is no code path to a server
//! that bypasses it: without a route the job waits, and nothing is dialled
//! (`tests/no_direct.rs` checks the source).

mod job;
pub mod local;
pub mod names;
mod pipeline;
mod record;
pub mod session;
mod status;
mod transfer;
mod wire;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use vpn_domain::{
    ApiError, Counter, ErrorCode, FieldError, GatewayId, SecretId, SecretRef, Severity,
    SshDownloadAction, SshDownloadCleared, SshDownloadJob, SshDownloadJobId, SshDownloadLog,
    SshDownloadLogLevel, SshDownloadStatus, SshDownloadTransfer, SshDownloadTransferState,
    SshDownloadTransfers, SshDownloadView, Text, Timestamp, ValidationReport, check_ssh_download,
    local_path_ok, tr,
};
use vpn_ipc::ssh_download::{JobSecrets, SecretChange, SshDownloadCall, SshDownloadReply};
use vpn_store::{SshDownloadTransferRow, Store, StoreError};
use zeroize::Zeroizing;

pub use session::Gateway;
pub use status::Publish;

use job::{Core, StartProblem};
use status::{Board, StatusCell, host_key_view};

/// How a Gateway can carry a job's connection now.
#[derive(Debug, Clone)]
pub enum Route {
    /// Its loopback port and the key it proves itself with.
    Ready(Gateway),
    /// Not now (its connection is stopped, not ready, the Gateway is off…): the job waits.
    Waiting { code: &'static str, reason: Text },
    /// Never as configured (no such Gateway, an HTTP-only one): the job waits for its settings to
    /// change; a save is refused.
    Invalid { code: &'static str, reason: Text },
}

/// The Gateway lookup the manager provides.
pub trait Routes: Send + Sync + 'static {
    fn route(&self, gateway: GatewayId) -> BoxFuture<'_, Route>;
    /// Bumped whenever what a route depends on changed (an Instance's status): a waiting job
    /// tries again at once.
    fn changes(&self) -> watch::Receiver<u64>;
}

/// Timing and limits (the defaults are the product's; tests shorten them).
#[derive(Debug, Clone)]
pub struct Options {
    /// Each stage of opening a connection (CONNECT inside the tunnel, SSH, login, SFTP).
    pub connect_timeout: Duration,
    /// A download that receives nothing for this long is abandoned (and resumed later).
    pub stall_timeout: Duration,
    /// An idle connection is closed after this long.
    pub idle_close: Duration,
    /// Waiting for the VPN: first and longest wait between attempts.
    pub vpn_backoff: (Duration, Duration),
    /// After a failure that may pass: first and longest wait.
    pub retry_backoff: (Duration, Duration),
    /// A local folder or disk problem is looked at again after this long.
    pub local_retry: Duration,
    /// SSH connections of all jobs together.
    pub max_connections: usize,
    /// Bytes of reads asked for and not yet written, of all files being fetched together (see
    /// `pipeline::ReadBudget`).
    pub read_budget: u64,
    /// A file with at least this much left to fetch is large: the job's connections that have
    /// nothing else to do help with it (see `transfer::Assist`).
    pub large_file: u64,
    /// Status events per job at most this often.
    pub publish_every: Duration,
    /// How often each job's log lines and finished records past its keep period are deleted,
    /// and the control database's WAL is scrubbed of what was deleted since.
    pub upkeep_every: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            stall_timeout: Duration::from_secs(60),
            idle_close: Duration::from_secs(30),
            vpn_backoff: (Duration::from_secs(2), Duration::from_secs(60)),
            retry_backoff: (Duration::from_secs(5), Duration::from_secs(300)),
            local_retry: Duration::from_secs(60),
            max_connections: 24,
            // What one job keeps in flight at most: 8 connections at the deepest pipeline.
            read_budget: 128 * 1024 * 1024,
            // A few seconds on the paths measured: less is over before a helper has logged in.
            large_file: 64 * 1024 * 1024,
            publish_every: status::PUBLISH_EVERY,
            upkeep_every: Duration::from_secs(3600),
        }
    }
}

/// What every job of the component shares.
pub(crate) struct Ctx {
    pub store: Arc<Store>,
    pub routes: Arc<dyn Routes>,
    pub opts: Options,
    /// The manager-wide connection budget.
    pub conns: Arc<Semaphore>,
    /// The manager-wide budget of reads in flight.
    pub reads: pipeline::ReadBudget,
    /// A connection that only helped a large file is on its way back to `conns` (see
    /// `transfer::Yielding`).
    pub yielding: AtomicBool,
    /// For `~/` paths.
    pub home: Option<PathBuf>,
}

impl Ctx {
    /// A line of a job's log (best effort: a full queue drops it).
    pub async fn log(
        &self,
        job: SshDownloadJobId,
        level: SshDownloadLogLevel,
        code: &str,
        message: Text,
        file: Option<String>,
    ) {
        if let Err(e) = self
            .store
            .append_ssh_download_log(job, level, code.into(), message, file)
            .await
        {
            tracing::debug!(job = %job, error = %e, "SSH download log line dropped");
        }
    }
}

/// A job's runner: its task and the token that stops it.
struct Runner {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

/// One job as the component holds it.
struct Handle {
    job: Arc<SshDownloadJob>,
    cell: Arc<StatusCell>,
    runner: Option<Runner>,
    publisher: CancellationToken,
    /// "List the source folder now", for the running job.
    scan: Arc<tokio::sync::Notify>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.publisher.cancel();
        if let Some(r) = self.runner.take() {
            r.cancel.cancel();
        }
    }
}

/// The SSH download component.
pub struct SshDownloads {
    ctx: Arc<Ctx>,
    publish: Publish,
    jobs: tokio::sync::Mutex<HashMap<SshDownloadJobId, Handle>>,
    closing: AtomicBool,
    /// Stops the upkeep task ([`upkeep`]).
    upkeep: CancellationToken,
}

impl std::fmt::Debug for SshDownloads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshDownloads")
            .field("closing", &self.closing)
            .finish_non_exhaustive()
    }
}

/// Delete `job`'s log lines and finished records older than its keep period (`history_days`).
async fn purge(store: &Store, job: &SshDownloadJob) {
    let Some(days) = job.history_days else {
        return;
    };
    let before = Timestamp::now().unix_millis() - i64::from(days) * 86_400_000;
    match store.purge_ssh_download(job.id, before).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            job = %job.id,
            removed = n,
            days,
            "SSH download log lines and records past their keep period deleted"
        ),
        Err(e) => tracing::warn!(
            job = %job.id,
            error = %e,
            "SSH download log lines and records past their keep period not deleted"
        ),
    }
}

/// Every `every` (and at once): each job's keep period, then the WAL scrubbed of what the
/// periods and the count limits (500 lines, 1,000 records per job) deleted since.
async fn upkeep(store: Arc<Store>, every: Duration, stop: CancellationToken) {
    let mut tick = tokio::time::interval(every.max(Duration::from_millis(10)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = tick.tick() => {}
        }
        if let Ok(jobs) = store.list::<SshDownloadJob>().await {
            for job in &jobs {
                purge(&store, job).await;
            }
        }
        if let Err(e) = store.scrub_control_wal().await {
            tracing::warn!(error = %e, "control database WAL not scrubbed; tried again at the next upkeep");
        }
    }
}

/// A blocking task of an API call that did not finish (it panicked, or the runtime is shutting
/// down): logged with its cause, and an internal error for the caller.
fn unfinished(task: &'static str, e: &tokio::task::JoinError) -> ApiError {
    tracing::warn!(task, error = %e, "SSH download blocking task did not finish");
    ApiError::internal()
}

/// No home folder to resolve a `~/` path against.
fn no_home() -> Text {
    tr!(
        "No home folder was found",
        "找不到家目錄",
        "ホームフォルダーが見つかりません"
    )
}

fn count(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn api(e: &StoreError) -> ApiError {
    e.to_api()
}

fn field_error(path: &str, code: &str, message: impl Into<Text>) -> ApiError {
    let message = message.into();
    ApiError::new(ErrorCode::ValidationFailed, message.clone()).with_fields(vec![FieldError {
        path: path.into(),
        code: code.into(),
        message,
    }])
}

fn report_error(r: &ValidationReport) -> ApiError {
    let fields: Vec<FieldError> = r
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| FieldError {
            path: i.path.clone(),
            code: i.code.clone(),
            message: i.message.clone(),
        })
        .collect();
    let first = fields.first().map_or_else(
        || {
            tr!(
                "Validation failed",
                "資料驗證失敗",
                "データの検証に失敗しました"
            )
        },
        |f| f.message.clone(),
    );
    ApiError::new(ErrorCode::ValidationFailed, first).with_fields(fields)
}

/// The job a call names is not there.
fn job_not_found() -> ApiError {
    ApiError::not_found(tr!(
        "the SSH download job",
        "SSH 下載工作",
        "SSH ダウンロードジョブ"
    ))
}

/// The record as the API shows it.
fn transfer_view(r: SshDownloadTransferRow) -> SshDownloadTransfer {
    use SshDownloadTransferState::{Completed, Failed, Failing, LocalDone};
    let remote = match r.state {
        Failed | Failing => r.failed_path.clone().unwrap_or_else(|| r.work_path.clone()),
        _ => r.work_path.clone(),
    };
    SshDownloadTransfer {
        name_recorded: !r.source_path.is_empty(),
        id: r.id,
        job_id: r.job_id,
        name: r.name,
        state: r.state,
        size: r.size.map(Counter),
        bytes_done: r.bytes_done.map(Counter),
        local_path: match r.state {
            Completed | LocalDone => r.final_path,
            _ => None,
        },
        remote_path: remote,
        attempts: r.attempts,
        error: r.error,
        created_at: Timestamp::from_unix_millis(r.created_ms).unwrap_or_else(Timestamp::now),
        finished_at: r.finished_ms.and_then(Timestamp::from_unix_millis),
        duration_ms: match (r.state, r.started_ms, r.finished_ms) {
            (Completed, Some(s), Some(f)) if f >= s => Some((f - s).cast_unsigned()),
            _ => None,
        },
    }
}

impl SshDownloads {
    /// Load every job and start those that are not paused (their unfinished files continue).
    ///
    /// # Errors
    ///
    /// The [`StoreError`] of reading the jobs or their states from the Store.
    pub async fn start(
        store: Arc<Store>,
        routes: Arc<dyn Routes>,
        publish: Publish,
        opts: Options,
    ) -> Result<Arc<Self>, StoreError> {
        let ctx = Arc::new(Ctx {
            store: store.clone(),
            routes,
            conns: Arc::new(Semaphore::new(opts.max_connections.max(1))),
            reads: pipeline::ReadBudget::new(opts.read_budget),
            yielding: AtomicBool::new(false),
            home: std::env::var_os("HOME").map(PathBuf::from),
            opts,
        });
        let upkeep_every = ctx.opts.upkeep_every;
        let this = Arc::new(Self {
            ctx,
            publish,
            jobs: tokio::sync::Mutex::new(HashMap::new()),
            closing: AtomicBool::new(false),
            upkeep: CancellationToken::new(),
        });
        tokio::spawn(upkeep(store.clone(), upkeep_every, this.upkeep.clone()));
        let jobs: Vec<SshDownloadJob> = store.list().await?;
        let states = store.ssh_download_states().await?;
        let mut held = this.jobs.lock().await;
        for job in jobs {
            let state = states.iter().find(|s| s.job_id == job.id).cloned();
            let paused = state.as_ref().is_some_and(|s| s.paused);
            let mut h = this.handle(job, state.as_ref());
            if paused {
                this.show_paused(&h).await;
            } else {
                this.run(&mut h).await;
            }
            held.insert(h.job.id, h);
        }
        drop(held);
        Ok(this)
    }

    /// Stop every job (records stay: the next start continues them).
    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.upkeep.cancel();
        let mut jobs = self.jobs.lock().await;
        for h in jobs.values_mut() {
            Self::halt(h).await;
        }
        jobs.clear();
    }

    fn handle(
        &self,
        job: SshDownloadJob,
        state: Option<&vpn_store::SshDownloadStateRow>,
    ) -> Handle {
        let board = Board {
            connections_max: job.connections,
            paused: state.is_some_and(|s| s.paused),
            host_key: state.and_then(|s| s.host_key.as_ref()).map(host_key_view),
            offered_host_key: state
                .and_then(|s| s.offered_host_key.as_ref())
                .map(host_key_view),
            ..Board::default()
        };
        let cell = StatusCell::new(job.id, board);
        let publisher = CancellationToken::new();
        tokio::spawn(cell.clone().publish_loop(
            self.publish.clone(),
            self.ctx.opts.publish_every,
            publisher.clone(),
        ));
        Handle {
            job: Arc::new(job),
            cell,
            runner: None,
            publisher,
            scan: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// The unfinished count of a job that does not run.
    async fn show_paused(&self, h: &Handle) {
        let open =
            u32::try_from(job::open_records(&self.ctx, h.job.id).await.len()).unwrap_or(u32::MAX);
        h.cell.update(|b| {
            b.stopped();
            b.unfinished = open;
        });
    }

    /// Start `h`'s runner (it prepares the folder and credentials, then works until stopped).
    async fn run(&self, h: &mut Handle) {
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        Self::halt(h).await;
        let cancel = CancellationToken::new();
        let (ctx, job, cell, token, scan) = (
            self.ctx.clone(),
            h.job.clone(),
            h.cell.clone(),
            cancel.clone(),
            h.scan.clone(),
        );
        cell.update(|b| {
            b.paused = false;
            b.error = None;
            b.connections_max = job.connections;
        });
        let task = tokio::spawn(async move {
            loop {
                match job::prepare(&ctx, &job).await {
                    Ok((local, creds)) => {
                        cell.update(|b| {
                            b.error = None;
                            b.next_retry_at = None;
                            b.running_since = Some(Timestamp::now());
                        });
                        let trusted = ctx
                            .store
                            .ssh_download_state(job.id)
                            .await
                            .ok()
                            .and_then(|s| s.host_key);
                        let open = job::open_records(&ctx, job.id).await;
                        let core = Core::new(
                            job.clone(),
                            ctx.clone(),
                            cell.clone(),
                            local,
                            creds,
                            trusted,
                            token.clone(),
                            scan.clone(),
                        );
                        core.run(open).await;
                        return;
                    }
                    Err(StartProblem { reason, .. }) => {
                        // Looked at again after a while (a disk mounted, a permission fixed).
                        let again = ctx.opts.local_retry;
                        let new = cell.update(|b| {
                            let new = b.error.as_ref() != Some(&reason);
                            b.error = Some(reason.clone());
                            b.next_retry_at = Some(Timestamp::now().plus(again));
                            new
                        });
                        if new {
                            ctx.log(
                                job.id,
                                SshDownloadLogLevel::Error,
                                &reason.code,
                                reason.message.clone(),
                                None,
                            )
                            .await;
                        }
                        tokio::select! {
                            () = token.cancelled() => return,
                            () = tokio::time::sleep(again) => {}
                        }
                    }
                }
            }
        });
        h.runner = Some(Runner { cancel, task });
    }

    /// Stop `h`'s runner and wait for it (its workers drop their connections; records stay).
    async fn halt(h: &mut Handle) {
        if let Some(mut r) = h.runner.take() {
            r.cancel.cancel();
            if tokio::time::timeout(Duration::from_secs(10), &mut r.task)
                .await
                .is_err()
            {
                // Never two runners of one job: this one ends at its next await.
                tracing::warn!(job = %h.job.id, "SSH download runner did not stop within 10 s; aborted");
                r.task.abort();
                // Awaited so that it has ended before another runner starts: it ends cancelled
                // (or done, when it finished first).
                if let Err(e) = r.task.await
                    && e.is_panic()
                {
                    tracing::error!(job = %h.job.id, error = %e, "SSH download runner panicked");
                }
            }
        }
        h.cell.update(Board::stopped);
    }

    pub async fn status(&self, id: SshDownloadJobId) -> Option<SshDownloadStatus> {
        self.jobs.lock().await.get(&id).map(|h| h.cell.snapshot())
    }

    /// Answer one API call on SSH download jobs.
    ///
    /// # Errors
    ///
    /// `Unavailable` while the manager stops, `NotFound` for an unknown job, validation and
    /// revision errors for a create/update/delete, `InvalidRequest`/`InvalidState` for a bad
    /// cursor, path or action, and the Store's error otherwise.
    pub async fn call(&self, call: SshDownloadCall) -> Result<SshDownloadReply, ApiError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                tr!(
                    "The manager is stopping; please wait. This operation was neither run nor recorded",
                    "manager 正在停止，請稍候；這個操作沒有執行，也沒有記錄",
                    "manager が停止中です。しばらくお待ちください。この操作は実行も記録もされていません"
                ),
            ));
        }
        match call {
            SshDownloadCall::List => {
                let jobs: Vec<SshDownloadJob> = self.ctx.store.list().await.map_err(|e| api(&e))?;
                let held = self.jobs.lock().await;
                Ok(SshDownloadReply::Views(
                    jobs.into_iter()
                        .map(|job| SshDownloadView {
                            status: held.get(&job.id).map(|h| h.cell.snapshot()),
                            job,
                        })
                        .collect(),
                ))
            }
            SshDownloadCall::Get(id) => Ok(SshDownloadReply::View(Box::new(self.view(id).await?))),
            SshDownloadCall::Create {
                job,
                secrets,
                paused,
            } => Ok(SshDownloadReply::View(Box::new(
                self.create(*job, secrets, paused).await?,
            ))),
            SshDownloadCall::Update {
                job,
                expected_revision,
                secrets,
            } => Ok(SshDownloadReply::View(Box::new(
                self.update(*job, expected_revision, secrets).await?,
            ))),
            SshDownloadCall::Delete {
                id,
                expected_revision,
            } => {
                self.delete(id, expected_revision).await?;
                Ok(SshDownloadReply::Unit)
            }
            SshDownloadCall::Action {
                id,
                action,
                fingerprint,
            } => Ok(SshDownloadReply::Status(Box::new(
                self.action(id, action, fingerprint).await?,
            ))),
            SshDownloadCall::Transfers {
                id,
                finished,
                before,
                limit,
            } => self.transfers(id, finished, before.as_deref(), limit).await,
            SshDownloadCall::Log { id, limit } => {
                self.job(id).await?;
                let items = self
                    .ctx
                    .store
                    .ssh_download_log(id, limit.clamp(1, 500) as usize)
                    .await
                    .map_err(|e| api(&e))?;
                Ok(SshDownloadReply::Log(SshDownloadLog { items }))
            }
            SshDownloadCall::ClearLog { id } => self.clear_log(id).await,
            SshDownloadCall::ClearHistory { id } => self.clear_history(id).await,
            SshDownloadCall::CheckDir { path } => self.check_dir(&path).await,
        }
    }

    /// Delete every line of a job's log. One line says so afterwards (no file in it).
    async fn clear_log(&self, id: SshDownloadJobId) -> Result<SshDownloadReply, ApiError> {
        self.job(id).await?;
        let removed = self
            .ctx
            .store
            .clear_ssh_download_log(id)
            .await
            .map_err(|e| api(&e))?;
        self.ctx
            .log(
                id,
                SshDownloadLogLevel::Info,
                "LOG_CLEARED",
                tr!(
                    "Cleared the log (lines removed: {removed})",
                    "已清除日誌（{removed} 行）",
                    "ログを消去しました（{removed} 行）"
                ),
                None,
            )
            .await;
        Ok(SshDownloadReply::Cleared(SshDownloadCleared {
            removed: count(removed),
        }))
    }

    /// Delete a job's finished records. Unfinished ones stay (their files resume from them), and
    /// no file is touched; the log says so.
    async fn clear_history(&self, id: SshDownloadJobId) -> Result<SshDownloadReply, ApiError> {
        self.job(id).await?;
        let removed = self
            .ctx
            .store
            .clear_ssh_download_history(id)
            .await
            .map_err(|e| api(&e))?;
        let open = job::open_records(&self.ctx, id).await.len();
        let message = if open > 0 {
            tr!(
                "Cleared the transfer records (removed: {removed}); the unfinished files keep their records and will be downloaded on (unfinished: {open})",
                "已清除傳輸紀錄（{removed} 筆）；未完成的 {open} 個檔案保留紀錄，會接著下載",
                "転送記録を消去しました（{removed} 件）。未完了のファイル {open} 件は記録を残し、続きからダウンロードします"
            )
        } else {
            tr!(
                "Cleared the transfer records (removed: {removed})",
                "已清除傳輸紀錄（{removed} 筆）",
                "転送記録を消去しました（{removed} 件）"
            )
        };
        self.ctx
            .log(
                id,
                SshDownloadLogLevel::Info,
                "HISTORY_CLEARED",
                message,
                None,
            )
            .await;
        Ok(SshDownloadReply::Cleared(SshDownloadCleared {
            removed: count(removed),
        }))
    }

    /// One page of a job's records, newest first, after the cursor `before`.
    async fn transfers(
        &self,
        id: SshDownloadJobId,
        finished: bool,
        before: Option<&str>,
        limit: u32,
    ) -> Result<SshDownloadReply, ApiError> {
        self.job(id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let bad_cursor = || {
            ApiError::new(
                ErrorCode::InvalidRequest,
                tr!(
                    "before must be the next of the previous page",
                    "before 必須是上一頁的 next",
                    "before には前のページの next を指定してください"
                ),
            )
        };
        let cursor = match before.map(str::trim) {
            None | Some("") => None,
            Some(c) => {
                let (at, rid) = c.split_once(':').ok_or_else(bad_cursor)?;
                Some((
                    at.parse::<i64>().map_err(|_not_a_number| bad_cursor())?,
                    rid.to_string(),
                ))
            }
        };
        let rows = self
            .ctx
            .store
            .ssh_download_transfers(id, finished, cursor, limit + 1)
            .await
            .map_err(|e| api(&e))?;
        let more = rows.len() > limit;
        let rows: Vec<_> = rows.into_iter().take(limit).collect();
        let next = if more && finished {
            rows.last()
                .and_then(|r| r.finished_ms.map(|f| format!("{f}:{}", r.id)))
        } else {
            None
        };
        Ok(SshDownloadReply::Transfers(SshDownloadTransfers {
            items: rows.into_iter().map(transfer_view).collect(),
            next,
        }))
    }

    /// Whether a local folder can take downloads (nothing is created).
    async fn check_dir(&self, path: &str) -> Result<SshDownloadReply, ApiError> {
        let path = path.trim().to_string();
        if !local_path_ok(&path) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                tr!(
                    "path must be a full path starting with / or ~/",
                    "path 必須是以 / 或 ~/ 開頭的完整路徑",
                    "path は / または ~/ で始まる完全なパスにしてください"
                ),
            ));
        }
        let full = names::expand_home(&path, self.ctx.home.as_deref())
            .ok_or_else(|| ApiError::new(ErrorCode::InvalidState, no_home()))?;
        let mut check = tokio::task::spawn_blocking(move || local::LocalDir::check(&full))
            .await
            .map_err(|e| unfinished("checking a local folder", &e))?;
        check.path = path;
        Ok(SshDownloadReply::DirCheck(check))
    }

    async fn job(&self, id: SshDownloadJobId) -> Result<SshDownloadJob, ApiError> {
        self.ctx
            .store
            .get::<SshDownloadJob>(id.to_string())
            .await
            .map_err(|e| api(&e))?
            .ok_or_else(job_not_found)
    }

    async fn view(&self, id: SshDownloadJobId) -> Result<SshDownloadView, ApiError> {
        let job = self.job(id).await?;
        Ok(SshDownloadView {
            status: self.status(id).await,
            job,
        })
    }

    /// `job` as it will be once `secrets` apply, for the checks (a new secret has no reference
    /// yet: a placeholder stands for it).
    fn intended(job: &SshDownloadJob, secrets: &JobSecrets) -> SshDownloadJob {
        let resolve = |current: Option<SecretRef>, change: &SecretChange| match change {
            SecretChange::Keep => current,
            SecretChange::Set(_) => Some(current.unwrap_or_else(|| SecretRef(SecretId::new()))),
            SecretChange::Clear => None,
        };
        let mut j = job.clone();
        j.password = resolve(job.password, &secrets.password);
        j.key_passphrase = resolve(job.key_passphrase, &secrets.key_passphrase);
        j
    }

    /// The checks a job must pass on this host: its fields, its Gateway, its local folder (created
    /// when missing) and its key file (decoded with its passphrase).
    async fn check(&self, job: &SshDownloadJob, secrets: &JobSecrets) -> Result<(), ApiError> {
        let intended = Self::intended(job, secrets);
        let report = check_ssh_download(&intended);
        if report.has_errors() {
            return Err(report_error(&report));
        }
        if let Route::Invalid { code, reason } = self.ctx.routes.route(job.gateway_id).await {
            return Err(field_error("/gateway_id", code, reason));
        }
        let local = names::expand_home(job.local_dir.trim(), self.ctx.home.as_deref())
            .ok_or_else(|| field_error("/local_dir", "LOCAL_DIR_UNUSABLE", no_home()))?;
        tokio::task::spawn_blocking(move || local::LocalDir::open(&local, true))
            .await
            .map_err(|e| unfinished("checking the local folder", &e))?
            .map_err(|e| field_error("/local_dir", "LOCAL_DIR_UNUSABLE", e.0))?;
        if let Some(file) = &job.identity_file {
            let passphrase: Option<Zeroizing<String>> = match &secrets.key_passphrase {
                SecretChange::Set(b) => Some(Zeroizing::new(
                    String::from_utf8_lossy(b.expose()).into_owned(),
                )),
                SecretChange::Clear => None,
                SecretChange::Keep => match job.key_passphrase {
                    Some(r) => Some(Zeroizing::new(
                        String::from_utf8_lossy(
                            &self.ctx.store.open_secret(r).await.map_err(|e| api(&e))?,
                        )
                        .into_owned(),
                    )),
                    None => None,
                },
            };
            let (file, home) = (file.clone(), self.ctx.home.clone());
            tokio::task::spawn_blocking(move || {
                job::load_key(
                    &file,
                    home.as_deref(),
                    passphrase.as_ref().map(|p| p.as_str()),
                )
                .map(|_| ())
            })
            .await
            .map_err(|e| unfinished("reading the key", &e))?
            .map_err(|p| field_error(p.path, &p.reason.code, p.reason.message))?;
        }
        Ok(())
    }

    async fn forget(&self, refs: impl IntoIterator<Item = SecretRef>) {
        for r in refs {
            if let Err(e) = self.ctx.store.delete_secret(r).await
                && !matches!(e, StoreError::NotFound)
            {
                tracing::warn!(error = %e, "SSH download secret not deleted");
            }
        }
    }

    /// Apply `secrets` to `job` (new ones go into the vault): the job to store, the refs it
    /// created and the refs it replaced.
    async fn apply_secrets(
        &self,
        job: &mut SshDownloadJob,
        secrets: &JobSecrets,
    ) -> Result<(Vec<SecretRef>, Vec<SecretRef>), ApiError> {
        let mut created = Vec::new();
        let mut replaced = Vec::new();
        for (slot, change, kind) in [
            (
                &mut job.password,
                &secrets.password,
                "ssh_download_password",
            ),
            (
                &mut job.key_passphrase,
                &secrets.key_passphrase,
                "ssh_download_key_passphrase",
            ),
        ] {
            match change {
                SecretChange::Keep => {}
                SecretChange::Clear => replaced.extend(slot.take()),
                SecretChange::Set(bytes) => {
                    let r = match self
                        .ctx
                        .store
                        .put_secret(
                            kind.into(),
                            None,
                            Zeroizing::new(bytes.expose().to_vec()),
                            None,
                        )
                        .await
                    {
                        Ok(m) => m.secret_ref,
                        Err(e) => {
                            self.forget(created).await;
                            return Err(api(&e));
                        }
                    };
                    created.push(r);
                    replaced.extend(slot.replace(r));
                }
            }
        }
        Ok((created, replaced))
    }

    async fn create(
        &self,
        mut job: SshDownloadJob,
        secrets: JobSecrets,
        paused: bool,
    ) -> Result<SshDownloadView, ApiError> {
        job.password = None;
        job.key_passphrase = None;
        self.check(&job, &secrets).await?;
        let (created, _) = self.apply_secrets(&mut job, &secrets).await?;
        let job = match self.ctx.store.create_ssh_download(job, paused).await {
            Ok(j) => j,
            Err(e) => {
                self.forget(created).await;
                return Err(api(&e));
            }
        };
        let state = self.ctx.store.ssh_download_state(job.id).await.ok();
        let mut jobs = self.jobs.lock().await;
        let mut h = self.handle(job.clone(), state.as_ref());
        if !paused {
            self.run(&mut h).await;
        }
        let status = h.cell.snapshot();
        jobs.insert(job.id, h);
        drop(jobs);
        purge(&self.ctx.store, &job).await;
        self.ctx
            .log(
                job.id,
                SshDownloadLogLevel::Info,
                "CREATED",
                {
                    let (host, port, source, local) =
                        (&job.host, job.port, &job.source_dir, &job.local_dir);
                    tr!(
                        "Created: downloads from {source} on {host}:{port} to {local}, connecting only through the Gateway",
                        "已建立：從 {host}:{port} 的 {source} 下載到 {local}，只經代理埠連線",
                        "作成しました：{host}:{port} の {source} から {local} にダウンロードします。接続はゲートウェイ経由のみです"
                    )
                },
                None,
            )
            .await;
        Ok(SshDownloadView {
            job,
            status: Some(status),
        })
    }

    async fn update(
        &self,
        mut job: SshDownloadJob,
        expected_revision: u64,
        secrets: JobSecrets,
    ) -> Result<SshDownloadView, ApiError> {
        let current = self.job(job.id).await?;
        job.password = current.password;
        job.key_passphrase = current.key_passphrase;
        self.check(&job, &secrets).await?;
        let (created, replaced) = self.apply_secrets(&mut job, &secrets).await?;
        let job = match self
            .ctx
            .store
            .update_ssh_download(job, expected_revision)
            .await
        {
            Ok(j) => j,
            Err(e) => {
                self.forget(created).await;
                return Err(api(&e));
            }
        };
        self.forget(replaced).await;
        let mut jobs = self.jobs.lock().await;
        let state = self.ctx.store.ssh_download_state(job.id).await.ok();
        let paused = state.as_ref().is_some_and(|s| s.paused);
        // The same handle (its counters since the manager started stay), with the new revision.
        let mut fresh = None;
        let h = jobs.get_mut(&job.id).map_or_else(
            || fresh.insert(self.handle(job.clone(), state.as_ref())),
            |h| h,
        );
        Self::halt(h).await;
        h.job = Arc::new(job.clone());
        h.cell.update(|b| b.connections_max = job.connections);
        if paused {
            self.show_paused(h).await;
        } else {
            self.run(h).await;
        }
        let status = h.cell.snapshot();
        if let Some(h) = fresh {
            jobs.insert(job.id, h);
        }
        drop(jobs);
        // A keep period set or shortened applies at once.
        purge(&self.ctx.store, &job).await;
        Ok(SshDownloadView {
            job,
            status: Some(status),
        })
    }

    async fn delete(&self, id: SshDownloadJobId, expected_revision: u64) -> Result<(), ApiError> {
        let current = self.job(id).await?;
        if current.meta.revision != expected_revision {
            return Err(api(&StoreError::RevisionConflict {
                expected: expected_revision,
                current: current.meta.revision,
            }));
        }
        let mut jobs = self.jobs.lock().await;
        if let Some(h) = jobs.get_mut(&id) {
            Self::halt(h).await;
        }
        let open = job::open_records(&self.ctx, id).await;
        match self
            .ctx
            .store
            .delete_ssh_download(id, expected_revision)
            .await
        {
            Ok(gone) => {
                jobs.remove(&id);
                drop(jobs);
                self.forget(gone.password.into_iter().chain(gone.key_passphrase))
                    .await;
                // Partial files go; remote files stay where they are (the working folder).
                for row in open {
                    let path = PathBuf::from(&row.local_dir);
                    let rid = row.id.clone();
                    let removed = tokio::task::spawn_blocking(move || {
                        local::LocalDir::open(&path, false).map(|d| d.remove_partial(&rid))
                    })
                    .await;
                    match removed {
                        Ok(Ok(Ok(()))) => {}
                        // A folder that is gone or no longer usable is left alone.
                        Ok(Err(why)) => tracing::debug!(
                            job = %id,
                            transfer = %row.id,
                            error = %why,
                            "partial file not removed: its folder cannot be opened"
                        ),
                        Ok(Ok(Err(e))) => tracing::warn!(
                            job = %id,
                            transfer = %row.id,
                            error = %e,
                            "partial file not removed"
                        ),
                        Err(e) => tracing::warn!(
                            job = %id,
                            transfer = %row.id,
                            error = %e,
                            "partial file not removed"
                        ),
                    }
                }
                Ok(())
            }
            Err(e) => {
                // Not deleted: it runs again as it was.
                let state = self.ctx.store.ssh_download_state(id).await.ok();
                if let Some(h) = jobs.get_mut(&id)
                    && !state.as_ref().is_some_and(|s| s.paused)
                {
                    self.run(h).await;
                }
                drop(jobs);
                Err(api(&e))
            }
        }
    }

    async fn action(
        &self,
        id: SshDownloadJobId,
        action: SshDownloadAction,
        fingerprint: Option<String>,
    ) -> Result<SshDownloadStatus, ApiError> {
        self.job(id).await?;
        let mut jobs = self.jobs.lock().await;
        let h = jobs.get_mut(&id).ok_or_else(job_not_found)?;
        match action {
            SshDownloadAction::Pause => self.pause(h, id).await?,
            SshDownloadAction::Resume => {
                self.ctx
                    .store
                    .set_ssh_download_paused(id, false)
                    .await
                    .map_err(|e| api(&e))?;
                self.run(h).await;
                self.ctx
                    .log(
                        id,
                        SshDownloadLogLevel::Info,
                        "RESUMED",
                        tr!("Resumed", "已繼續", "再開しました"),
                        None,
                    )
                    .await;
            }
            SshDownloadAction::Scan => {
                if h.cell.read(|b| b.paused) {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "The job is paused; resume it first",
                            "工作已暫停；請先繼續",
                            "ジョブは一時停止中です。先に再開してください"
                        ),
                    ));
                }
                if let Some(e) = h.cell.read(|b| b.error.clone())
                    && h.runner.as_ref().is_none_or(|r| r.task.is_finished())
                {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "The job has stopped: {why}",
                            "工作已停止：{why}",
                            "ジョブは停止しています：{why}";
                            why = e.message
                        ),
                    ));
                }
                h.scan.notify_one();
            }
            SshDownloadAction::TrustHostKey => self.trust_host_key(h, id, fingerprint).await?,
        }
        let status = h.cell.snapshot();
        drop(jobs);
        Ok(status)
    }

    /// Pause a job: its runner stops and its unfinished files wait.
    async fn pause(&self, h: &mut Handle, id: SshDownloadJobId) -> Result<(), ApiError> {
        self.ctx
            .store
            .set_ssh_download_paused(id, true)
            .await
            .map_err(|e| api(&e))?;
        Self::halt(h).await;
        h.cell.update(|b| {
            b.paused = true;
            b.error = None;
        });
        let open = u32::try_from(job::open_records(&self.ctx, id).await.len()).unwrap_or(u32::MAX);
        h.cell.update(|b| b.unfinished = open);
        self.ctx
            .log(
                id,
                SshDownloadLogLevel::Info,
                "PAUSED",
                tr!(
                    "Paused; unfinished files are downloaded on once the job is resumed",
                    "已暫停；未完成的檔案會在繼續後接著下載",
                    "一時停止しました。未完了のファイルは再開後に続きからダウンロードします"
                ),
                None,
            )
            .await;
        Ok(())
    }

    /// Trust the host key the server offered (`fingerprint`), and run the job again unless paused.
    async fn trust_host_key(
        &self,
        h: &mut Handle,
        id: SshDownloadJobId,
        fingerprint: Option<String>,
    ) -> Result<(), ApiError> {
        let fp = fingerprint
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .ok_or_else(|| {
                field_error(
                    "/fingerprint",
                    "FINGERPRINT_REQUIRED",
                    tr!(
                        "Give the fingerprint of the key to trust",
                        "請提供要信任的金鑰指紋",
                        "信頼する鍵のフィンガープリントを指定してください"
                    ),
                )
            })?;
        let row = self
            .ctx
            .store
            .trust_ssh_download_host_key(id, fp.clone())
            .await
            .map_err(|e| api(&e))?;
        h.cell.update(|b| {
            b.host_key = row.host_key.as_ref().map(host_key_view);
            b.offered_host_key = None;
            if b.error
                .as_ref()
                .is_some_and(|e| e.code == "HOST_KEY_CHANGED")
            {
                b.error = None;
            }
        });
        self.ctx
            .log(
                id,
                SshDownloadLogLevel::Warning,
                "HOST_KEY_TRUSTED",
                tr!(
                    "The user trusted the new host key {fp}",
                    "使用者信任了新的主機金鑰 {fp}",
                    "ユーザーが新しいホスト鍵 {fp} を信頼しました"
                ),
                None,
            )
            .await;
        if !row.paused {
            self.run(h).await;
        }
        Ok(())
    }
}
