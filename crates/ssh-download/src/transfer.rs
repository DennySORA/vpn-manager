//! One file's life (the original tool's workflow): claim it — move `source/<name>` to
//! `work/<id>` —, download it into `<local>/.vpn-manager-partial/<id>.part` with resume, move it to
//! its final local name (unique, never replacing anything), then delete the remote copy. After the
//! last failed attempt the remote file goes to the failed folder and the partial file is removed.
//!
//! Every step is written to the file's record before it is taken, and every step can be taken
//! again: whatever a crash interrupts, the next run continues from the record — no file is lost
//! or downloaded twice, and the remote copy is deleted only once the local file is complete and
//! in place. Local file work runs on blocking threads, never on the manager's async workers.

use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesOrdered;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use vpn_domain::{
    SshDownloadLogLevel, SshDownloadStep, SshDownloadTransferState, Text, Timestamp, tr,
};
use vpn_store::SshDownloadTransferRow;

use crate::Ctx;
use crate::job::{Conn, Core, Listed, LocalRetryToken, STORE_UNAVAILABLE, Task, sleep_until};
use crate::local::{LocalDir, PlaceError};
use crate::names::{ResumePlan, join_remote, local_name, plan_resume, unique_name};
use crate::pipeline::{Lane, Reads, Reply, Turn};
use crate::record;
use crate::session::{RemoteError, remote_error};
use crate::status::{Active, Reason};

/// The longest wait after a failed attempt.
const MAX_BACKOFF: Duration = Duration::from_secs(600);
/// Bytes compared at each end of what is already downloaded before a download goes on after it.
const RESUME_SAMPLE: u64 = 64 * 1024;
/// Helpers a large file sends away before no more are sent to it.
const HELPER_TRIES: u32 = 3;

/// How one download attempt ended, when it did not finish.
enum Failure {
    /// The attempt failed; `lost`: the connection is gone with it.
    Attempt { message: Text, lost: bool },
    /// The remote file in the working folder is gone.
    Gone,
    /// Writing locally failed (a full disk, a folder that changed): not the file's fault.
    Local(Text),
    /// The job stops.
    Cancelled,
}

fn now_ms() -> i64 {
    Timestamp::now().unix_millis()
}

fn local_error(e: &std::io::Error) -> Failure {
    Failure::Local(tr!(
        "Writing locally failed: {e}",
        "本機寫入失敗：{e}",
        "ローカルへの書き込みに失敗しました：{e}";
        e = Text::of_io_error(e)
    ))
}

/// A local file operation that did not finish (its thread went away).
fn interrupted() -> Failure {
    Failure::Local(tr!(
        "A local file operation was interrupted",
        "本機檔案操作中斷",
        "ローカルのファイル操作が中断されました"
    ))
}

/// A blocking local operation on a blocking thread.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, Failure> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| interrupted())?
        .map_err(|e| local_error(&e))
}

/// What was being done to the remote file when a request failed, as [`read_failure`] names it.
#[derive(Clone, Copy)]
enum Doing {
    Open,
    Size,
    Recheck,
    Compare,
    Read,
}

impl Doing {
    fn text(self) -> Text {
        match self {
            Self::Open => tr!(
                "opening the remote file",
                "開啟遠端檔案",
                "リモートファイルを開く"
            ),
            Self::Size => tr!(
                "reading the file size",
                "讀取檔案大小",
                "ファイルサイズの読み取り"
            ),
            Self::Recheck => tr!(
                "checking the remote file again",
                "再次確認遠端檔案",
                "リモートファイルの再確認"
            ),
            Self::Compare => tr!(
                "comparing the part already downloaded",
                "比對已下載的部分",
                "ダウンロード済みの部分の比較"
            ),
            Self::Read => tr!("reading", "讀取", "読み取り"),
        }
    }
}

/// A remote failure while `doing` something to the file.
fn read_failure(e: RemoteError, doing: Doing) -> Failure {
    match e {
        RemoteError::Missing => Failure::Gone,
        RemoteError::Refused(m) => Failure::Attempt {
            message: tr!(
                "The server refused while {doing}: {m}",
                "{doing}時伺服器拒絕：{m}",
                "{doing}時にサーバーが拒否しました：{m}";
                doing = doing.text(),
                m = m
            ),
            lost: false,
        },
        RemoteError::Lost(m) => Failure::Attempt {
            message: tr!(
                "The connection broke off while {doing}: {m}",
                "{doing}時連線中斷：{m}",
                "{doing}時に接続が切断されました：{m}";
                doing = doing.text(),
                m = m
            ),
            lost: true,
        },
    }
}

/// An attempt that failed on the file's side, with the connection still good.
const fn attempt(message: Text) -> Failure {
    Failure::Attempt {
        message,
        lost: false,
    }
}

/// The server reported no size for the file.
fn no_size() -> Failure {
    attempt(tr!(
        "The server gave no file size",
        "伺服器沒有提供檔案大小",
        "サーバーがファイルサイズを返しませんでした"
    ))
}

/// The local file is not as long as the remote one.
fn size_differs(len: u64, size: u64) -> Failure {
    attempt(tr!(
        "The size after the download, {len}, is not the remote {size}",
        "下載後的大小 {len} 和遠端的 {size} 不同",
        "ダウンロード後のサイズ {len} がリモートの {size} と異なります"
    ))
}

/// The remote file could not be looked at again after the download.
fn unconfirmed() -> Failure {
    attempt(tr!(
        "Cannot check the remote file again; it is not deleted for now",
        "無法再次確認遠端檔案，暫不刪除遠端檔案",
        "リモートファイルを再確認できないため、まだ削除しません"
    ))
}

/// The server reported no size for the file after the download.
fn no_size_after() -> Failure {
    attempt(tr!(
        "After the download the server gave no file size; the remote file is not deleted for now",
        "下載完成後，伺服器沒有提供檔案大小，暫不刪除遠端檔案",
        "ダウンロード後にサーバーがファイルサイズを返さなかったため、リモートファイルはまだ削除しません"
    ))
}

/// The remote file is another version than when the download began.
fn changed_during() -> Failure {
    attempt(tr!(
        "The remote file changed during the download; trying again later",
        "遠端檔案在下載中被修改，稍後再試",
        "ダウンロード中にリモートファイルが変更されました。後でもう一度試します"
    ))
}

/// The DOWNLOADED line: where it went (`None` for a job that does not record names), its size
/// and, when known, how long it took.
fn downloaded(path: Option<&str>, size: u64, secs: Option<f64>) -> Text {
    match (path, secs) {
        (Some(path), Some(secs)) => tr!(
            "Downloaded to {path} ({size} bytes, {secs:.1} s)",
            "已下載到 {path}（{size} bytes，{secs:.1} 秒）",
            "{path} にダウンロードしました（{size} bytes、{secs:.1} 秒）"
        ),
        (Some(path), None) => tr!(
            "Downloaded to {path} ({size} bytes)",
            "已下載到 {path}（{size} bytes）",
            "{path} にダウンロードしました（{size} bytes）"
        ),
        (None, Some(secs)) => tr!(
            "Downloaded ({size} bytes, {secs:.1} s)",
            "已下載（{size} bytes，{secs:.1} 秒）",
            "ダウンロードしました（{size} bytes、{secs:.1} 秒）"
        ),
        (None, None) => tr!(
            "Downloaded ({size} bytes)",
            "已下載（{size} bytes）",
            "ダウンロードしました（{size} bytes）"
        ),
    }
}

/// Where a failed file's remote copy is, for the FAILED line.
enum Place<'a> {
    /// Its path in the failed folder.
    At(&'a str),
    /// The failed folder (a job that does not record names).
    FailedFolder(&'a str),
    /// Not moved: it is no longer in the working folder.
    Gone,
}

/// The FAILED line: why, and where the remote copy is.
fn download_failed(why: Text, place: &Place<'_>) -> Text {
    match place {
        Place::At(path) => tr!(
            "Download failed: {why}; the remote file is at {path}",
            "下載失敗：{why}；遠端檔案在 {path}",
            "ダウンロードに失敗しました：{why}。リモートファイルの場所：{path}";
            why = why
        ),
        Place::FailedFolder(dir) => tr!(
            "Download failed: {why}; the remote file is in the failed folder {dir}",
            "下載失敗：{why}；遠端檔案在 失敗資料夾 {dir}",
            "ダウンロードに失敗しました：{why}。リモートファイルは失敗フォルダー {dir} にあります";
            why = why
        ),
        Place::Gone => tr!(
            "Download failed: {why}; the remote file is no longer in the working folder",
            "下載失敗：{why}；遠端檔案在 （已不在處理中資料夾）",
            "ダウンロードに失敗しました：{why}。リモートファイルはもう処理中フォルダーにありません";
            why = why
        ),
    }
}

/// The remote copy of a downloaded file at `path` could not be deleted (`m`: the server's
/// reason).
fn undeleted(path: &str, m: Text) -> Text {
    tr!(
        "Downloaded, but the file {path} in the remote working folder cannot be deleted: {m}",
        "已下載完成，但無法刪除遠端處理中資料夾的檔案 {path}：{m}",
        "ダウンロードは完了しましたが、リモートの処理中フォルダーのファイル {path} を削除できません：{m}";
        m = m
    )
}

/// The file could not be moved to the failed folder (`m`: the server's reason).
fn fail_move_refused(m: Text) -> Text {
    tr!(
        "Cannot move the file to the failed folder ({m}); trying again later",
        "無法把檔案移到失敗資料夾（{m}）；稍後再試",
        "ファイルを失敗フォルダーに移動できません（{m}）。後でもう一度試します";
        m = m
    )
}

/// The download record could not be written (`why`).
fn record_unwritten(why: Text) -> Text {
    tr!(
        "Cannot write the download record: {why}",
        "無法寫入下載紀錄：{why}",
        "ダウンロード記録を書き込めません：{why}";
        why = why
    )
}

/// What tells one version of a remote file from another without reading it.
#[derive(Clone, Copy)]
struct RemoteStat {
    size: u64,
    /// In seconds; `None` from a server that reports none.
    mtime: Option<u32>,
}

impl RemoteStat {
    /// Whether `later` still describes the same version: the same size, and the same
    /// modification time where the server reports one both times.
    const fn unchanged(self, later: Self) -> bool {
        self.size == later.size
            && !matches!((self.mtime, later.mtime), (Some(a), Some(b)) if a != b)
    }
}

/// Size and modification time of the open remote file: what its handle reports, or — from a
/// server whose answer for a handle carries no size — what its path reports. `None`: the server
/// gives no size either way.
async fn remote_stat(
    c: &Conn,
    handle: &str,
    path: &str,
) -> Result<Option<RemoteStat>, RemoteError> {
    let sftp = &c.session.sftp;
    let by_handle = sftp
        .fstat(handle.to_owned())
        .await
        .map_err(remote_error)?
        .attrs;
    let attrs = if by_handle.size.is_some() {
        by_handle
    } else {
        sftp.stat(path.to_owned())
            .await
            .map_err(remote_error)?
            .attrs
    };
    Ok(attrs.size.map(|size| RemoteStat {
        size,
        mtime: attrs.mtime,
    }))
}

/// The two ends of the first `have` bytes of the partial file — `(offset, bytes)`, the later
/// end first — to compare with the remote file before a download goes on after them.
fn resume_samples(file: &std::fs::File, have: u64) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
    use std::os::unix::fs::FileExt;
    if have == 0 {
        return Ok(Vec::new());
    }
    let len = have.min(RESUME_SAMPLE);
    let mut offsets = vec![have - len];
    if have > len {
        offsets.push(0);
    }
    offsets
        .into_iter()
        .map(|offset| {
            let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
            file.read_exact_at(&mut bytes, offset)?;
            Ok((offset, bytes))
        })
        .collect()
}

/// `len` bytes of the open remote file from `offset`, or fewer where the file ends (a server
/// may answer a read in several parts).
async fn read_range(
    c: &Conn,
    handle: &str,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, RemoteError> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let want = u32::try_from(len - out.len())
            .unwrap_or(u32::MAX)
            .min(c.session.read_len.max(1));
        let read = c
            .session
            .sftp
            .read(handle.to_owned(), offset + out.len() as u64, want)
            .await;
        match read {
            Ok(d) if !d.data.is_empty() => out.extend_from_slice(&d.data),
            Ok(_) => break,
            Err(russh_sftp::client::error::Error::Status(s))
                if s.status_code == StatusCode::Eof =>
            {
                break;
            }
            Err(e) => return Err(remote_error(e)),
        }
    }
    Ok(out)
}

/// A large file being fetched, for the job's other connections to help with.
///
/// A helper opens the same remote file on its own connection and serves the transfer's reads
/// from it; the transfer still writes every answer in the order of the file. A helper serves
/// only a handle that shows what the transfer's shows — the same size and time, the same bytes
/// at both ends: where it shows something else the file was replaced under the path, and
/// nothing of the attempt is published.
pub struct Assist {
    path: String,
    stat: RemoteStat,
    ends: Vec<(u64, Vec<u8>)>,
    /// The length of the reads the transfer asks for.
    chunk: u32,
    reads: Reads,
    active: Arc<Active>,
    /// The transfer fetches no more.
    over: CancellationToken,
    /// A helper found another file under the path.
    differs: CancellationToken,
    /// Helpers that could not serve it.
    sent_away: AtomicU32,
}

impl Assist {
    /// Whether one more connection may be sent to help.
    pub fn takes_help(&self) -> bool {
        !self.over.is_cancelled()
            && !self.differs.is_cancelled()
            && self.sent_away.load(Ordering::Relaxed) < HELPER_TRIES
    }

    /// Connections that help it now.
    pub fn helpers(&self) -> u32 {
        self.active.helpers()
    }

    /// The transfer fetches no more: its helpers go.
    pub fn end(&self) {
        self.over.cancel();
    }

    /// A helper could not serve it.
    fn sent_away(&self) {
        self.sent_away.fetch_add(1, Ordering::Relaxed);
    }
}

/// A connection that only helped a large file, on its way back to the manager's budget because
/// none was free: some job's own work waits for one. One goes at a time; the next only when that
/// was not enough.
pub struct Yielding(Arc<Ctx>);

impl Drop for Yielding {
    fn drop(&mut self) {
        self.0.yielding.store(false, Ordering::Release);
    }
}

/// Why a helper leaves a file whose transfer still fetches.
enum Leave {
    /// The job's own work, taken over.
    Work(Task),
    Yield(Yielding),
}

/// What a worker does after it helped.
pub struct Helped {
    /// Its connection is still good, and it keeps it.
    pub keep: bool,
    /// The job's own work it took over.
    pub work: Option<Task>,
    /// Held until the connection it gives back is closed.
    pub yielding: Option<Yielding>,
}

/// Resolves when `token` is cancelled; never without one.
async fn cancelled(token: Option<&CancellationToken>) {
    match token {
        Some(token) => token.cancelled().await,
        None => std::future::pending().await,
    }
}

/// How a step of the record ended for the worker.
enum Step {
    /// Go on with the record's next state.
    Next,
    /// The worker is done with this file; `keep`: its connection is still good.
    Done { keep: bool },
}

impl Core {
    /// Write the record as the job keeps it ([`record::kept`]); a finished one of a job that does
    /// not record names leaves no earlier image with its name in the WAL either.
    async fn save(&self, row: &SshDownloadTransferRow) -> Result<(), Text> {
        let stored = record::kept(&self.job, row);
        let mut delay = Duration::from_millis(100);
        for _ in 0..5 {
            match self
                .ctx
                .store
                .update_ssh_download_transfer(stored.clone())
                .await
            {
                Ok(()) => {
                    if record::forgets_name(&self.job, row) {
                        let _ = self.ctx.store.scrub_control_wal().await;
                    }
                    self.store_answers();
                    return Ok(());
                }
                Err(vpn_store::StoreError::Busy) => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(e) => return Err(e.to_api().message),
            }
        }
        Err(tr!(
            "The storage queue is full",
            "儲存佇列已滿",
            "保存キューがいっぱいです"
        ))
    }

    /// The record could not be written: nothing more is done to the file until it can be (the
    /// next step must be on disk before it is taken).
    async fn unsaved(&self, row: SshDownloadTransferRow, why: Text) -> Step {
        tracing::warn!(job = %self.job.id, transfer = %row.id, error = %why.en, "SSH download record not written");
        self.retry_later(Reason::new(STORE_UNAVAILABLE, record_unwritten(why)))
            .await;
        self.later(row, Duration::from_secs(5));
        Step::Done { keep: true }
    }

    /// Write the record, then go on to its next state (or wait when it cannot be written).
    async fn save_step(&self, row: &SshDownloadTransferRow) -> Step {
        match self.save(row).await {
            Ok(()) => Step::Next,
            Err(e) => self.unsaved(row.clone(), e).await,
        }
    }

    /// The folder the record downloads into: the job's, or the one it was taken for.
    async fn local_for(&self, row: &SshDownloadTransferRow) -> Result<Arc<LocalDir>, Text> {
        if std::path::Path::new(&row.local_dir) == self.local.path() {
            return Ok(self.local.clone());
        }
        let path = std::path::PathBuf::from(&row.local_dir);
        tokio::task::spawn_blocking(move || LocalDir::open(&path, true))
            .await
            .map_err(|_| {
                tr!(
                    "Checking the local folder was interrupted",
                    "檢查本機資料夾時中斷",
                    "ローカルフォルダーの確認が中断されました"
                )
            })?
            .map(Arc::new)
            .map_err(|e| e.0)
    }

    /// Keep this file queued while its local storage is unavailable. The reason is kept the way
    /// the job keeps its log (no name for a job that does not record names).
    async fn wait_for_local(&self, row: SshDownloadTransferRow, code: &str, why: Text) {
        let reason = Reason::new(code, record::scrub(&self.job, &row, &why));
        self.retry_local_transfer(&row.id, record::file_ref(&self.job, &row), reason)
            .await;
        self.later(row, self.ctx.opts.local_retry);
    }

    /// Take a new file of the source folder. `false`: the connection is gone.
    pub(crate) async fn take(&self, c: &Conn, file: Listed) -> bool {
        let name = file.name.clone();
        let mut row = self.new_row(name.clone());
        if let Err(e) = self
            .ctx
            .store
            .insert_ssh_download_transfer(row.clone())
            .await
        {
            tracing::warn!(job = %self.job.id, error = %e, "SSH download record not created");
            self.give_back(Task::Take(file));
            self.retry_later(Reason::new(
                STORE_UNAVAILABLE,
                record_unwritten(e.to_api().message),
            ))
            .await;
            return true;
        }
        self.store_answers();
        {
            let _claiming = self
                .cell
                .begin(&row.id, &row.name, SshDownloadStep::Claiming, 1);
            let moved = c
                .session
                .sftp
                .rename(row.source_path.clone(), row.work_path.clone())
                .await
                .map_err(remote_error);
            match moved {
                Ok(_) => {}
                Err(RemoteError::Missing) => {
                    // Nothing happened here. The file is gone (someone else took it), or the
                    // working folder is (then the folders are made again with the next listing).
                    let _ = self
                        .ctx
                        .store
                        .delete_ssh_download_transfer(row.id.clone())
                        .await;
                    self.release(&name);
                    if c.session.sftp.stat(row.source_path.clone()).await.is_ok() {
                        self.folders_again();
                    }
                    return true;
                }
                Err(RemoteError::Refused(m)) => {
                    let (file, m) = (
                        record::file_ref(&self.job, &row),
                        record::scrub(&self.job, &row, &m),
                    );
                    let _ = self.ctx.store.delete_ssh_download_transfer(row.id).await;
                    self.poison(&name);
                    self.ctx
                        .log(
                            self.job.id,
                            SshDownloadLogLevel::Warning,
                            "CLAIM_REFUSED",
                            tr!(
                                "Cannot move the file to the working folder ({m}); it is not tried again while the job runs this time",
                                "無法把檔案移到處理中資料夾（{m}）；這次執行期間不再嘗試它",
                                "ファイルを処理中フォルダーに移動できません（{m}）。今回の実行中はもう試しません";
                                m = m
                            ),
                            Some(file),
                        )
                        .await;
                    return true;
                }
                Err(RemoteError::Lost(_)) => {
                    // Moved or not: the record decides when it is continued.
                    self.later(row, Duration::ZERO);
                    return false;
                }
            }
        }
        row.state = SshDownloadTransferState::Downloading;
        row.started_ms = Some(now_ms());
        if let Err(e) = self.save(&row).await {
            return matches!(self.unsaved(row, e).await, Step::Done { keep: true });
        }
        self.transfer(c, row).await
    }

    /// Continue a recorded file from its state. `false`: the connection is gone.
    pub(crate) async fn transfer(&self, c: &Conn, mut row: SshDownloadTransferRow) -> bool {
        use SshDownloadTransferState::{
            Claiming, Completed, Downloading, Failed, Failing, Finalizing, LocalDone,
        };
        let local_retry = self.local_retry_token(&row.id);
        let local = match self.local_for(&row).await {
            Ok(l) => l,
            Err(why) => {
                self.wait_for_local(row, "LOCAL_DIR_UNUSABLE", why).await;
                return true;
            }
        };
        self.recover_local_retry(&row.id, local_retry, Some("LOCAL_DIR_UNUSABLE"));
        let step = match row.state {
            Claiming => SshDownloadStep::Claiming,
            Downloading => SshDownloadStep::Downloading,
            Finalizing | LocalDone => SshDownloadStep::Finalizing,
            Failing => SshDownloadStep::Failing,
            Completed | Failed => return true,
        };
        let guard = self.cell.begin(&row.id, &row.name, step, row.attempts + 1);
        let active = guard.active.clone();
        loop {
            let step = match row.state {
                Claiming => self.resolve_claim(c, &mut row).await,
                Downloading => {
                    active.set_step(SshDownloadStep::Downloading);
                    match self
                        .download(c, &local, &mut row, &active, local_retry)
                        .await
                    {
                        Ok(()) => {
                            row.state = Finalizing;
                            Step::Next
                        }
                        Err(Failure::Cancelled) => {
                            self.later(row, Duration::ZERO);
                            return false;
                        }
                        Err(Failure::Gone) => {
                            row.error = Some(tr!(
                                "The file in the remote working folder is gone (another program may have moved or deleted it)",
                                "遠端處理中資料夾裡的檔案不見了（可能被其他程式移走或刪除）",
                                "リモートの処理中フォルダーにあったファイルがなくなりました（別のプログラムが移動または削除した可能性があります）"
                            ));
                            drop(guard);
                            return self.give_up(c, &local, row, false).await;
                        }
                        Err(Failure::Local(why)) => {
                            self.wait_for_local(row, "LOCAL_WRITE", why).await;
                            return true;
                        }
                        Err(Failure::Attempt { message, lost }) => {
                            let progressed = active.done() > active.resumed_from();
                            drop(guard);
                            return self
                                .attempt_failed(c, &local, row, progressed, message, lost)
                                .await;
                        }
                    }
                }
                Finalizing => {
                    active.set_step(SshDownloadStep::Finalizing);
                    match self.finalize(&local, &mut row).await {
                        Ok(true) => {
                            self.recover_local_retry(&row.id, local_retry, Some("LOCAL_WRITE"));
                            row.state = LocalDone;
                            self.save_step(&row).await
                        }
                        // The partial file is gone and nothing took its place: download it again.
                        Ok(false) => {
                            row.state = Downloading;
                            row.final_path = None;
                            self.save_step(&row).await
                        }
                        Err(Failure::Local(why)) => {
                            self.wait_for_local(row, "LOCAL_WRITE", why).await;
                            return true;
                        }
                        Err(_) => {
                            self.later(row, Duration::from_secs(5));
                            return true;
                        }
                    }
                }
                LocalDone => {
                    active.set_step(SshDownloadStep::Finalizing);
                    self.complete(c, &local, &mut row).await
                }
                Failing => {
                    drop(guard);
                    return self.give_up(c, &local, row, true).await;
                }
                Completed | Failed => Step::Done { keep: true },
            };
            match step {
                Step::Next => {}
                Step::Done { keep } => return keep,
            }
        }
    }

    /// A record whose claim may or may not have happened: the working folder decides.
    async fn resolve_claim(&self, c: &Conn, row: &mut SshDownloadTransferRow) -> Step {
        match c
            .session
            .sftp
            .stat(row.work_path.clone())
            .await
            .map_err(remote_error)
        {
            Ok(_) => {
                row.state = SshDownloadTransferState::Downloading;
                row.started_ms.get_or_insert_with(now_ms);
                match self.save(row).await {
                    Ok(()) => Step::Next,
                    Err(e) => self.unsaved(row.clone(), e).await,
                }
            }
            Err(RemoteError::Missing) => {
                // Never moved: it is still in the source folder (the next listing finds it), or
                // gone.
                let _ = self
                    .ctx
                    .store
                    .delete_ssh_download_transfer(row.id.clone())
                    .await;
                self.release(&row.name);
                Step::Done { keep: true }
            }
            Err(_) => {
                self.later(row.clone(), Duration::ZERO);
                Step::Done { keep: false }
            }
        }
    }

    /// One download attempt of a claimed file into its partial file.
    async fn download(
        &self,
        c: &Conn,
        local: &Arc<LocalDir>,
        row: &mut SshDownloadTransferRow,
        active: &Arc<Active>,
        local_retry: Option<LocalRetryToken>,
    ) -> Result<(), Failure> {
        let sftp = &c.session.sftp;
        let handle = sftp
            .open(
                row.work_path.clone(),
                OpenFlags::READ,
                FileAttributes::empty(),
            )
            .await
            .map_err(|e| read_failure(remote_error(e), Doing::Open))?
            .handle;
        let result = async {
            let before = remote_stat(c, &handle, &row.work_path)
                .await
                .map_err(|e| read_failure(e, Doing::Size))?
                .ok_or_else(no_size)?;
            let size = before.size;
            row.size = Some(size);
            let (mut file, plan) = self.resume_point(c, local, row, &handle, size).await?;
            active.begin(plan.offset, size);
            self.cell.touch();
            if !plan.complete {
                file.seek(SeekFrom::Start(plan.offset))
                    .await
                    .map_err(|e| local_error(&e))?;
                let help = self
                    .help_for(c, &handle, &row.work_path, before, plan.offset, active)
                    .await?;
                let fetched = self
                    .fetch(c, &handle, &mut file, plan.offset, size, active, help)
                    .await;
                // What arrived stays: the next attempt resumes after it.
                let _ = file.flush().await;
                fetched?;
            }
            file.flush().await.map_err(|e| local_error(&e))?;
            file.sync_all().await.map_err(|e| local_error(&e))?;
            let len = file.metadata().await.map_err(|e| local_error(&e))?.len();
            if len != size {
                return Err(size_differs(len, size));
            }
            self.recover_local_retry(&row.id, local_retry, Some("LOCAL_WRITE"));
            // Publication and remote deletion require a successful final check, read the way
            // it was read before the download (the handle, else the path): the same size and,
            // where the server reports it, the same modification time.
            let after = remote_stat(c, &handle, &row.work_path)
                .await
                .map_err(|e| match e {
                    RemoteError::Missing => unconfirmed(),
                    e => read_failure(e, Doing::Recheck),
                })?
                .ok_or_else(no_size_after)?;
            if !before.unchanged(after) {
                return Err(changed_during());
            }
            row.bytes_done = Some(size);
            Ok(())
        }
        .await;
        let _ = sftp.close(handle).await;
        result
    }

    /// Open the partial file and decide where the download goes on: after what it holds while
    /// both ends of that still are what the remote file holds there, from the start otherwise —
    /// a source replaced or rewritten since the last attempt (same length or longer) is never
    /// continued into a mix of two versions.
    async fn resume_point(
        &self,
        c: &Conn,
        local: &Arc<LocalDir>,
        row: &SshDownloadTransferRow,
        handle: &str,
        size: u64,
    ) -> Result<(tokio::fs::File, ResumePlan), Failure> {
        let (dir, id) = (local.clone(), row.id.clone());
        let (std_file, plan, samples) = blocking(move || {
            let f = dir.open_partial(&id)?;
            let plan = plan_resume(f.metadata()?.len(), size);
            if plan.truncate_local {
                f.set_len(0)?;
            }
            let samples = resume_samples(&f, plan.offset)?;
            Ok((f, plan, samples))
        })
        .await?;
        let file = tokio::fs::File::from_std(std_file);
        for (offset, held) in &samples {
            let there = read_range(c, handle, *offset, held.len())
                .await
                .map_err(|e| read_failure(e, Doing::Compare))?;
            if there == *held {
                continue;
            }
            file.set_len(0).await.map_err(|e| local_error(&e))?;
            self.ctx
                .log(
                    self.job.id,
                    SshDownloadLogLevel::Warning,
                    "SOURCE_CHANGED",
                    tr!(
                        "The remote file does not match the part already downloaded (the source was replaced or rewritten); downloading from the start",
                        "遠端檔案和已下載的部分不一致（來源被換過或改寫），從頭下載",
                        "リモートファイルがダウンロード済みの部分と一致しません（取得元が置き換えられたか書き換えられました）。最初からダウンロードします"
                    ),
                    Some(record::file_ref(&self.job, row)),
                )
                .await;
            return Ok((file, plan_resume(0, size)));
        }
        Ok((file, plan))
    }

    /// What a large file's helpers need, when the job has connections to help: `None` for a
    /// file with little left, and for a job of one connection.
    async fn help_for(
        &self,
        c: &Conn,
        handle: &str,
        path: &str,
        stat: RemoteStat,
        from: u64,
        active: &Arc<Active>,
    ) -> Result<Option<Arc<Assist>>, Failure> {
        if self.job.connections < 2 || stat.size.saturating_sub(from) < self.ctx.opts.large_file {
            return Ok(None);
        }
        // Both ends of the file as this connection reads them, for the helpers to compare.
        let len = stat.size.min(RESUME_SAMPLE);
        let mut ends = Vec::new();
        for offset in [0, stat.size - len] {
            if ends.iter().any(|(at, _)| *at == offset) {
                continue;
            }
            let bytes = read_range(
                c,
                handle,
                offset,
                usize::try_from(len).unwrap_or(usize::MAX),
            )
            .await
            .map_err(|e| read_failure(e, Doing::Read))?;
            ends.push((offset, bytes));
        }
        Ok(Some(Arc::new(Assist {
            path: path.to_owned(),
            stat,
            ends,
            chunk: c.session.read_len.max(1),
            reads: Reads::default(),
            active: active.clone(),
            over: CancellationToken::new(),
            differs: CancellationToken::new(),
            sent_away: AtomicU32::new(0),
        })))
    }

    /// Fetch `[from, size)` into the partial file: through the connection's own lane, and —
    /// with `help` — through the job's connections that have nothing else to do.
    #[allow(
        clippy::too_many_arguments,
        reason = "one attempt's parts, passed once by `download`: the connection and its handle, the local file, the range, the board entry and the offer"
    )]
    async fn fetch(
        &self,
        c: &Conn,
        handle: &str,
        file: &mut tokio::fs::File,
        from: u64,
        size: u64,
        active: &Arc<Active>,
        help: Option<Arc<Assist>>,
    ) -> Result<(), Failure> {
        let chunk = c.session.read_len.max(1);
        let alone = Reads::default();
        let reads = help.as_ref().map_or(&alone, |h| &h.reads);
        let differs = help.as_ref().map(|h| &h.differs);
        let _offered = help.clone().map(|h| self.offer(h));
        let mut own = Lane::new(
            c.session.sftp.clone(),
            handle,
            u64::from(chunk),
            reads,
            &self.ctx.reads,
        );
        let written = self.write_in_order(reads, chunk, file, from, size, active);
        tokio::pin!(written);
        loop {
            tokio::select! {
                done = &mut written => return done,
                () = cancelled(differs) => return Err(Failure::Attempt {
                    message: tr!(
                        "Another connection read a different file at the same path: the remote file was replaced during the download; trying again later",
                        "另一條連線在同一個路徑讀到不同的檔案：遠端檔案在下載中被換過，稍後再試",
                        "別の接続が同じパスで異なるファイルを読み取りました。ダウンロード中にリモートファイルが置き換えられたため、後でもう一度試します"
                    ),
                    lost: false,
                }),
                turn = own.turn() => {
                    // The transfer meets the reason when the read's turn comes: what was read
                    // before it is written first.
                    if let Turn::Failed(read, why) = turn {
                        read.answer(Err(why));
                    }
                }
            }
        }
    }

    /// Help a large file with this connection: serve its reads from a handle of the same remote
    /// file until its transfer fetches no more, the job has other work for this worker, or the
    /// manager has no connection left for some job's own work and this one is given back.
    pub(crate) async fn assist(&self, c: &Conn, help: &Assist) -> Helped {
        let stay = |keep| Helped {
            keep,
            work: None,
            yielding: None,
        };
        let sftp = &c.session.sftp;
        // Over while this worker was still logging in.
        if !help.takes_help() {
            return stay(true);
        }
        if c.session.read_len < help.chunk {
            help.sent_away();
            return stay(true);
        }
        let opened = sftp
            .open(help.path.clone(), OpenFlags::READ, FileAttributes::empty())
            .await
            .map_err(remote_error);
        let handle = match opened {
            Ok(h) => h.handle,
            Err(e) => {
                help.sent_away();
                return stay(!matches!(e, RemoteError::Lost(_)));
            }
        };
        let served = self.serve(c, &handle, help).await;
        let _ = sftp.close(handle).await;
        match served {
            Ok(None) => stay(true),
            Ok(Some(Leave::Work(task))) => Helped {
                keep: true,
                work: Some(task),
                yielding: None,
            },
            Ok(Some(Leave::Yield(yielding))) => Helped {
                keep: false,
                work: None,
                yielding: Some(yielding),
            },
            Err(e) => {
                help.sent_away();
                stay(!matches!(e, RemoteError::Lost(_)))
            }
        }
    }

    /// A helper's connection failed while it was leaving: work it had taken over goes back.
    fn left_with(&self, leave: Option<Leave>, why: RemoteError) -> RemoteError {
        if let Some(Leave::Work(task)) = leave {
            // A large file was counted at its claim: the count goes back with it.
            let _counted = self.large(&task);
            self.give_back(task);
        }
        why
    }

    /// The helper's lane on `handle`, after the handle is seen to be the transfer's file.
    /// `Ok(None)`: the transfer is over. `Ok(Some)`: the worker leaves — for the job's own work,
    /// or to give its connection back — and has answered the reads it had in flight. `Err`:
    /// this connection cannot serve the file.
    async fn serve(
        &self,
        c: &Conn,
        handle: &str,
        help: &Assist,
    ) -> Result<Option<Leave>, RemoteError> {
        let mut same = remote_stat(c, handle, &help.path)
            .await?
            .is_some_and(|stat| help.stat.unchanged(stat));
        for (offset, held) in &help.ends {
            same = same && read_range(c, handle, *offset, held.len()).await? == *held;
        }
        if !same {
            help.differs.cancel();
            return Ok(None);
        }
        let _joined = help.active.joined();
        let mut lane = Lane::new(
            c.session.sftp.clone(),
            handle,
            u64::from(help.chunk),
            &help.reads,
            &self.ctx.reads,
        );
        // A helper that hears nothing goes well before the transfer would give the file up:
        // its reads are asked again on the connections that answer.
        let patience = self.ctx.opts.stall_timeout / 2;
        let mut changes = self.changes();
        // Why this worker leaves: from then on no more reads are taken, and those in flight are
        // answered before it goes.
        let mut leave = None;
        // When the job's own work next comes due by the clock: looked at once that has come.
        let mut due = self.other_work_due();
        loop {
            if leave.is_some() && !lane.busy() {
                return Ok(leave);
            }
            let quiet = lane.waits_since().map(|since| since + patience);
            let look = tokio::select! {
                () = help.over.cancelled() => return Ok(leave),
                turn = lane.turn() => match turn {
                    Turn::Moved => false,
                    Turn::Failed(_, why) => return Err(self.left_with(leave, why)),
                },
                () = sleep_until(quiet) => {
                    return Err(self.left_with(leave, RemoteError::no_answer()));
                }
                _ = changes.changed() => true,
                () = sleep_until(due) => true,
            };
            if leave.is_some() {
                continue;
            }
            if look || due.is_some_and(|at| at <= tokio::time::Instant::now()) {
                due = self.other_work_due();
                // The job's own work comes first.
                leave = self.other_work().map(Leave::Work);
            }
            // Help is given with connections nobody else needs: when the manager has none
            // left, one helper gives its own back.
            if leave.is_none()
                && self.ctx.conns.available_permits() == 0
                && !self.ctx.yielding.swap(true, Ordering::AcqRel)
            {
                leave = Some(Leave::Yield(Yielding(self.ctx.clone())));
            }
            if leave.is_some() {
                due = None;
                lane.leave();
            }
        }
    }

    /// Ask for `[from, size)` in the order of the file — as many reads as the lanes have room
    /// for — and write each answer where the file ends: the local file only ever holds the
    /// first bytes of the remote one, without gaps.
    async fn write_in_order(
        &self,
        reads: &Reads,
        chunk: u32,
        file: &mut tokio::fs::File,
        from: u64,
        size: u64,
        active: &Arc<Active>,
    ) -> Result<(), Failure> {
        let stall = self.ctx.opts.stall_timeout;
        let mut at = from;
        let mut next = from;
        let mut waiting = FuturesOrdered::new();
        let mut heard = tokio::time::Instant::now();
        while at < size {
            let room = reads.room();
            while waiting.len() < room && next < size {
                let len = u32::try_from(size - next).map_or(chunk, |left| left.min(chunk));
                waiting.push_back(reads.ask(next, len));
                next += u64::from(len);
            }
            let Reply {
                offset,
                len,
                answer,
            } = tokio::select! {
                () = self.cancel.cancelled() => return Err(Failure::Cancelled),
                () = reads.grown() => continue,
                () = tokio::time::sleep_until(heard + stall) => return Err(Failure::Attempt {
                    message: {
                        let secs = stall.as_secs();
                        tr!(
                            "Nothing arrived for {secs} s",
                            "{secs} 秒沒有收到任何資料",
                            "{secs} 秒間データを何も受信していません"
                        )
                    },
                    lost: true,
                }),
                Some(reply) = waiting.next() => reply,
            };
            let data = match answer {
                Some(Ok(data)) => data,
                Some(Err(e)) => return Err(read_failure(e, Doing::Read)),
                None => {
                    waiting.push_front(reads.ask_first(offset, len));
                    continue;
                }
            };
            if data.is_empty() {
                return Err(Failure::Attempt {
                    message: tr!(
                        "The remote file is shorter than expected (it ends at {at} bytes instead of {size})",
                        "遠端檔案比預期短（在 {at} bytes 結束，應有 {size}）",
                        "リモートファイルが予想より短くなっています（{at} bytes で終わっていますが、{size} あるはずです）"
                    ),
                    lost: false,
                });
            }
            // Every answer is written at the place it was read from. Anything else would put
            // bytes where they do not belong: the attempt ends instead.
            if offset != at || data.len() as u64 > u64::from(len) {
                let got = data.len();
                return Err(Failure::Attempt {
                    message: tr!(
                        "The server's answer does not match the request (offset {offset}, {got} bytes, instead of offset {at}, at most {len} bytes)",
                        "伺服器的回答和要求的不符（位置 {offset}、{got} bytes，應為位置 {at}、最多 {len} bytes）",
                        "サーバーの応答が要求と一致しません（位置 {offset}、{got} bytes。正しくは位置 {at}、最大 {len} bytes）"
                    ),
                    lost: false,
                });
            }
            file.write_all(&data).await.map_err(|e| local_error(&e))?;
            at += data.len() as u64;
            active.add(data.len() as u64);
            self.cell.touch();
            heard = tokio::time::Instant::now();
            if (data.len() as u64) < u64::from(len) {
                // A short read: the reads after it start again at the gap.
                reads.forget();
                waiting = FuturesOrdered::new();
                next = at;
            }
        }
        Ok(())
    }

    /// Give the complete partial file its local name, never replacing anything. `Ok(false)`:
    /// the partial file is gone, so nothing proves a file of that name to be this download
    /// (download it again).
    async fn finalize(
        &self,
        local: &Arc<LocalDir>,
        row: &mut SshDownloadTransferRow,
    ) -> Result<bool, Failure> {
        let mut name = if let Some(p) = row.final_path.as_deref() {
            // Recorded before a crash: the same name again.
            std::path::Path::new(p).file_name().map_or_else(
                || unique_name(&row.name, &row.id),
                |n| n.to_string_lossy().into_owned(),
            )
        } else {
            let (n, cut) = local_name(&row.name, &row.id);
            let (dir, probe) = (local.clone(), n.clone());
            if cut || blocking(move || dir.exists(&probe)).await? {
                unique_name(&row.name, &row.id)
            } else {
                n
            }
        };
        for _ in 0..3 {
            // Chosen and recorded before the rename, so a crash after it is recognised.
            let path = local.final_path(&name);
            if row.final_path.as_deref() != Some(path.as_str()) {
                row.final_path = Some(path);
                self.save(row).await.map_err(Failure::Local)?;
            }
            let (dir, id, to) = (local.clone(), row.id.clone(), name.clone());
            let placed = tokio::task::spawn_blocking(move || {
                match dir.place(&id, &to) {
                    Ok(()) => {}
                    // Linked before a crash: the name is the partial file itself. A file that
                    // only has the name and the size is someone else's.
                    Err(PlaceError::Exists)
                        if dir.is_placed(&id, &to).map_err(PlaceError::Io)? => {}
                    Err(e) => return Err(e),
                }
                dir.sync().map_err(PlaceError::Io)
            })
            .await
            .map_err(|_| interrupted())?;
            match placed {
                Ok(()) => return Ok(true),
                Err(PlaceError::Exists) => {
                    let unique = unique_name(&row.name, &row.id);
                    if name == unique {
                        // No name here: the reason is shown and logged, also for a job that
                        // does not record names (the log line says which file).
                        return Err(Failure::Local(tr!(
                            "The local folder already has a file of that name (and the numbered name is taken too), so the downloaded file cannot be placed",
                            "本機資料夾已有同名的檔案（加上編號的名稱也被佔用），無法放入下載的檔案",
                            "ローカルフォルダーに同じ名前のファイルがすでにあり（番号付きの名前も使われています）、ダウンロードしたファイルを配置できません"
                        )));
                    }
                    name = unique;
                }
                Err(PlaceError::Io(e)) => return Err(local_error(&e)),
                Err(PlaceError::PartialMissing) => return Ok(false),
            }
        }
        Err(Failure::Local(tr!(
            "Cannot decide on a local file name",
            "無法決定本機檔名",
            "ローカルのファイル名を決められません"
        )))
    }

    /// The local file is complete and in place, and the record says so: the partial name, a
    /// second link to it until now, goes, and only now is the remote copy deleted.
    async fn complete(
        &self,
        c: &Conn,
        local: &Arc<LocalDir>,
        row: &mut SshDownloadTransferRow,
    ) -> Step {
        let local_retry = self.local_retry_token(&row.id);
        let (dir, id) = (local.clone(), row.id.clone());
        if blocking(move || dir.remove_partial(&id)).await.is_err() {
            tracing::warn!(job = %self.job.id, transfer = %row.id, "partial file not removed");
        }
        let removed = c
            .session
            .sftp
            .remove(row.work_path.clone())
            .await
            .map_err(remote_error);
        match removed {
            Ok(_) | Err(RemoteError::Missing) => row.error = None,
            Err(RemoteError::Lost(_)) => {
                self.later(row.clone(), Duration::ZERO);
                return Step::Done { keep: false };
            }
            Err(RemoteError::Refused(m)) => row.error = Some(undeleted(&row.work_path, m)),
        }
        row.state = SshDownloadTransferState::Completed;
        row.finished_ms = Some(now_ms());
        if let Err(e) = self.save(row).await {
            // The record on disk still says "local file in place": the retry starts there and
            // ends the record (a record waiting as completed would never be written).
            row.state = SshDownloadTransferState::LocalDone;
            row.finished_ms = None;
            return self.unsaved(row.clone(), e).await;
        }
        self.recover_local_retry(&row.id, local_retry, None);
        let size = row.size.unwrap_or(0);
        self.cell.update(|b| {
            b.completed += 1;
            b.bytes += size;
        });
        self.release(&row.name);
        let took = row.started_ms.map(|s| {
            Duration::from_millis(
                row.finished_ms
                    .unwrap_or(s)
                    .saturating_sub(s)
                    .max(0)
                    .cast_unsigned(),
            )
            .as_secs_f64()
        });
        let (level, message) = row.error.as_ref().map_or_else(
            || {
                let path = self
                    .job
                    .record_names
                    .then(|| row.final_path.as_deref().unwrap_or_default());
                (SshDownloadLogLevel::Info, downloaded(path, size, took))
            },
            |e| {
                (
                    SshDownloadLogLevel::Warning,
                    record::scrub(&self.job, row, e),
                )
            },
        );
        self.ctx
            .log(
                self.job.id,
                level,
                "DOWNLOADED",
                message,
                Some(record::file_ref(&self.job, row)),
            )
            .await;
        Step::Done { keep: true }
    }

    /// A failed attempt: again later, or — after `retries` attempts without progress — to the
    /// failed folder.
    async fn attempt_failed(
        &self,
        c: &Conn,
        local: &Arc<LocalDir>,
        mut row: SshDownloadTransferRow,
        progressed: bool,
        message: Text,
        lost: bool,
    ) -> bool {
        row.attempts = if progressed { 0 } else { row.attempts + 1 };
        row.error = Some(message.clone());
        if row.attempts >= self.job.retries.max(1) {
            if lost {
                // The connection went with the attempt: the move waits for the next one.
                row.state = SshDownloadTransferState::Failing;
                row.failed_path = Some(join_remote(&self.job.failed_dir, &row.name));
                if let Err(e) = self.save(&row).await {
                    self.unsaved(row, e).await;
                    return false;
                }
                self.later(row, Duration::ZERO);
                return false;
            }
            return self.give_up(c, local, row, true).await;
        }
        let base = Duration::from_secs(u64::from(self.job.retry_backoff_secs.max(1)));
        let wait = base
            .saturating_mul(1u32 << row.attempts.saturating_sub(1).min(16))
            .min(MAX_BACKOFF);
        if let Err(e) = self.save(&row).await {
            self.unsaved(row, e).await;
            return !lost;
        }
        let message = record::scrub(&self.job, &row, &message);
        let secs = wait.as_secs();
        let line = if progressed {
            tr!(
                "{message}; the part already downloaded is kept, and the download goes on in {secs} s",
                "{message}；已下載的部分保留，{secs} 秒後接著下載",
                "{message}。ダウンロード済みの部分は残し、{secs} 秒後に続きをダウンロードします";
                message = message
            )
        } else {
            let (attempts, retries) = (row.attempts, self.job.retries);
            tr!(
                "{message}; trying again in {secs} s ({attempts}/{retries} attempts in a row without progress)",
                "{message}；{secs} 秒後再試（連續 {attempts}／{retries} 次沒有進展）",
                "{message}。{secs} 秒後に再試行します（進展のない試行が連続 {attempts}／{retries} 回）";
                message = message
            )
        };
        self.ctx
            .log(
                self.job.id,
                SshDownloadLogLevel::Warning,
                "ATTEMPT_FAILED",
                line,
                Some(record::file_ref(&self.job, &row)),
            )
            .await;
        self.later(row, wait);
        !lost
    }

    /// The file is not downloaded: move the remote copy to the failed folder (when `move_it`
    /// and it is still there), remove the partial file, end the record as failed.
    async fn give_up(
        &self,
        c: &Conn,
        local: &Arc<LocalDir>,
        mut row: SshDownloadTransferRow,
        move_it: bool,
    ) -> bool {
        let local_retry = self.local_retry_token(&row.id);
        let sftp = &c.session.sftp;
        let _failing = self.cell.begin(
            &row.id,
            &row.name,
            SshDownloadStep::Failing,
            row.attempts.max(1),
        );
        if row.state != SshDownloadTransferState::Failing || row.failed_path.is_none() {
            row.state = SshDownloadTransferState::Failing;
            row.failed_path = Some(join_remote(&self.job.failed_dir, &row.name));
            if let Err(e) = self.save(&row).await {
                self.unsaved(row, e).await;
                return true;
            }
        }
        if move_it {
            for _ in 0..2 {
                let failed = row.failed_path.clone().unwrap_or_default();
                match sftp
                    .rename(row.work_path.clone(), failed.clone())
                    .await
                    .map_err(remote_error)
                {
                    Ok(_) | Err(RemoteError::Missing) => break,
                    Err(RemoteError::Lost(_)) => {
                        self.later(row, Duration::ZERO);
                        return false;
                    }
                    Err(RemoteError::Refused(m)) => {
                        // A file of the same name failed before: this one gets a unique name.
                        let unique =
                            join_remote(&self.job.failed_dir, &unique_name(&row.name, &row.id));
                        if failed != unique && sftp.stat(failed.clone()).await.is_ok() {
                            row.failed_path = Some(unique);
                            if let Err(e) = self.save(&row).await {
                                self.unsaved(row, e).await;
                                return true;
                            }
                            continue;
                        }
                        let m = record::scrub(&self.job, &row, &m);
                        self.ctx
                            .log(
                                self.job.id,
                                SshDownloadLogLevel::Error,
                                "FAIL_MOVE_REFUSED",
                                fail_move_refused(m),
                                Some(record::file_ref(&self.job, &row)),
                            )
                            .await;
                        let wait =
                            Duration::from_secs(u64::from(self.job.retry_backoff_secs.max(1)) * 4);
                        self.later(row, wait.min(MAX_BACKOFF));
                        return true;
                    }
                }
            }
        }
        let (dir, id) = (local.clone(), row.id.clone());
        if blocking(move || dir.remove_partial(&id)).await.is_err() {
            tracing::warn!(job = %self.job.id, transfer = %row.id, "partial file not removed");
        }
        row.state = SshDownloadTransferState::Failed;
        row.finished_ms = Some(now_ms());
        if let Err(e) = self.save(&row).await {
            // As in `complete`: the retry starts from what the record on disk says.
            row.state = SshDownloadTransferState::Failing;
            row.finished_ms = None;
            self.unsaved(row, e).await;
            return true;
        }
        self.recover_local_retry(&row.id, local_retry, None);
        self.cell.update(|b| b.failed += 1);
        self.release(&row.name);
        let why = row
            .error
            .clone()
            .unwrap_or_else(|| tr!("unknown reason", "原因不明", "原因不明"));
        let why = record::scrub(&self.job, &row, &why);
        let place = match (move_it, self.job.record_names) {
            (true, true) => Place::At(row.failed_path.as_deref().unwrap_or_default()),
            (true, false) => Place::FailedFolder(&self.job.failed_dir),
            (false, _) => Place::Gone,
        };
        let line = download_failed(why, &place);
        self.ctx
            .log(
                self.job.id,
                SshDownloadLogLevel::Error,
                "FAILED",
                line,
                Some(record::file_ref(&self.job, &row)),
            )
            .await;
        true
    }
}
