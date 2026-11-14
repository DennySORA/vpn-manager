//! SSH download (使用者 2026-11-06 新增): jobs that pull files from a remote folder over SFTP into a
//! local folder, only through a VPN Manager Gateway of the job's connection.
//!
//! The job is a revisioned entity (kind `ssh_download_job`); its runtime state (pause, the trusted
//! host key), the record of every file it took and its log live in the component's own tables
//! (control schema step 12). The engine that runs the jobs is `crates/ssh-download`, inside the
//! manager.
//!
//! A job only ever reaches its server through the SOCKS5 Gateway it names (the host name is
//! resolved inside the tunnel): while the connection does not carry traffic the job waits, it
//! never connects directly.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::common::{Counter, SecretRef, Timestamp};
use crate::config::EntityMeta;
use crate::ids::{GatewayId, SshDownloadJobId};
use crate::status::Operation;
use crate::text::Text;
use crate::tr;
use crate::validation::{ValidationReport, check_name, ssh_vpn_private, ssh_vpn_unreachable};

/// SSH connections one job opens at most (the original tool's `SSH_CONFIG_MAX_CONNECT`).
pub const SSH_DOWNLOAD_CONNECTIONS: std::ops::RangeInclusive<u32> = 1..=8;
/// Attempts without progress before a file goes to the failed folder.
pub const SSH_DOWNLOAD_RETRIES: std::ops::RangeInclusive<u32> = 1..=20;
/// The first wait after a failed attempt (it doubles, up to ten minutes).
pub const SSH_DOWNLOAD_BACKOFF_SECS: std::ops::RangeInclusive<u32> = 1..=3600;
/// How often the source folder is listed.
pub const SSH_DOWNLOAD_SCAN_SECS: std::ops::RangeInclusive<u32> = 5..=86_400;
/// Jobs one installation may have.
pub const SSH_DOWNLOAD_MAX_JOBS: usize = 32;
/// Longest remote folder path.
pub const SSH_DOWNLOAD_MAX_REMOTE_PATH: usize = 1024;
/// Longest local path (folder or key file).
pub const SSH_DOWNLOAD_MAX_LOCAL_PATH: usize = 4096;
/// Days a job may keep its log lines and finished records (`history_days`).
pub const SSH_DOWNLOAD_HISTORY_DAYS: std::ops::RangeInclusive<u32> = 1..=3650;
/// Folder names the working and failed folders default to, beside the source folder.
pub const SSH_DOWNLOAD_WORK_NAME: &str = "doing";
pub const SSH_DOWNLOAD_FAILED_NAME: &str = "failed";

/// Which names of the source folder a job takes. A name "contains a UUID" when any part of it
/// is a canonical UUID (8-4-4-4-12 hex digits), as the original tool matched them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshDownloadNameFilter {
    /// Every regular file.
    #[default]
    All,
    /// Skip names that contain a UUID — the original tool's `OTHER_CONFIG_IS_FILTER_UUID_FILE`:
    /// an uploader that writes under a temporary UUID name and renames when done.
    SkipUuid,
    /// Only names that contain a UUID.
    OnlyUuid,
}

/// One SSH download job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadJob {
    pub id: SshDownloadJobId,
    #[serde(flatten)]
    pub meta: EntityMeta,
    pub name: String,
    /// Every connection goes through this Gateway (SOCKS5 or Mixed): the host name is resolved
    /// inside its connection's tunnel. There is no other path.
    pub gateway_id: GatewayId,
    /// The SSH server: a DNS name or an IP literal.
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Private key file (`/…` or `~/…`), read by the manager for each connection.
    pub identity_file: Option<String>,
    /// The key's passphrase, held by the vault (never returned in plain text).
    pub key_passphrase: Option<SecretRef>,
    /// The account's password, held by the vault (never returned in plain text).
    pub password: Option<SecretRef>,
    /// Remote folder files are taken from (`todo`). A relative path starts at the login
    /// directory; `~/` means the same.
    pub source_dir: String,
    /// Remote folder a file is moved to while it downloads (`doing`), under a UUID name.
    pub work_dir: String,
    /// Remote folder a file goes to after its last failed attempt (`failed`).
    pub failed_dir: String,
    /// Local folder the finished files are put in (absolute; owned by this user, not writable by
    /// others). Partial files wait in its `.vpn-manager-partial` folder.
    pub local_dir: String,
    /// SSH connections in parallel (one file each).
    pub connections: u32,
    /// Attempts without progress before a file is moved to the failed folder.
    pub retries: u32,
    /// The first wait after a failed attempt, in seconds; it doubles, up to ten minutes.
    pub retry_backoff_secs: u32,
    /// How often the source folder is listed, in seconds.
    pub scan_interval_secs: u32,
    pub name_filter: SshDownloadNameFilter,
    /// Skip names that start with `.` (temporary files of uploaders such as rsync).
    pub skip_hidden: bool,
    /// Whether the job's log and history keep file names (and the paths that hold them). Off, a
    /// finished file is kept as its transfer number only ([`ssh_download_label`]); a file that is
    /// not finished keeps its name until it is — it resumes with it.
    #[serde(default = "yes")]
    pub record_names: bool,
    /// Log lines and finished records older than this many days are deleted (looked at every
    /// hour); `None`: only the newest are kept (500 lines, 1,000 records).
    #[serde(default)]
    pub history_days: Option<u32>,
}

/// `POST /v1/ssh-downloads`, `PUT /v1/ssh-downloads/{id}`.
///
/// Secrets come in plain text once and go into the vault; leaving `password` / `key_passphrase` out
/// (null) keeps the stored one on an update, `clear_*` removes it.
#[derive(Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "HTTP wire shape: each flag is an independent user choice exported to the frontend"
)]
pub struct SshDownloadInput {
    pub name: String,
    pub gateway_id: GatewayId,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub identity_file: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    #[serde(default)]
    pub clear_key_passphrase: bool,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub clear_password: bool,
    pub source_dir: String,
    /// Empty: the `doing` folder beside the source folder.
    #[serde(default)]
    pub work_dir: Option<String>,
    /// Empty: the `failed` folder beside the source folder.
    #[serde(default)]
    pub failed_dir: Option<String>,
    pub local_dir: String,
    #[serde(default = "default_connections")]
    pub connections: u32,
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_backoff")]
    pub retry_backoff_secs: u32,
    #[serde(default = "default_scan")]
    pub scan_interval_secs: u32,
    #[serde(default)]
    pub name_filter: SshDownloadNameFilter,
    #[serde(default = "yes")]
    pub skip_hidden: bool,
    #[serde(default = "yes")]
    pub record_names: bool,
    #[serde(default)]
    pub history_days: Option<u32>,
    /// Create only: the job starts paused.
    #[serde(default)]
    pub paused: bool,
}

/// `Debug` never prints the plain-text secrets (`password`, `key_passphrase`), only whether one was
/// given; every other field is shown. The destructuring makes a new field a compile error here.
impl std::fmt::Debug for SshDownloadInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            gateway_id,
            host,
            port,
            user,
            identity_file,
            key_passphrase,
            clear_key_passphrase,
            password,
            clear_password,
            source_dir,
            work_dir,
            failed_dir,
            local_dir,
            connections,
            retries,
            retry_backoff_secs,
            scan_interval_secs,
            name_filter,
            skip_hidden,
            record_names,
            history_days,
            paused,
        } = self;
        let redacted = |secret: &Option<String>| secret.as_ref().map(|_| "<redacted>");
        f.debug_struct("SshDownloadInput")
            .field("name", name)
            .field("gateway_id", gateway_id)
            .field("host", host)
            .field("port", port)
            .field("user", user)
            .field("identity_file", identity_file)
            .field("key_passphrase", &redacted(key_passphrase))
            .field("clear_key_passphrase", clear_key_passphrase)
            .field("password", &redacted(password))
            .field("clear_password", clear_password)
            .field("source_dir", source_dir)
            .field("work_dir", work_dir)
            .field("failed_dir", failed_dir)
            .field("local_dir", local_dir)
            .field("connections", connections)
            .field("retries", retries)
            .field("retry_backoff_secs", retry_backoff_secs)
            .field("scan_interval_secs", scan_interval_secs)
            .field("name_filter", name_filter)
            .field("skip_hidden", skip_hidden)
            .field("record_names", record_names)
            .field("history_days", history_days)
            .field("paused", paused)
            .finish()
    }
}

const fn default_port() -> u16 {
    22
}
const fn default_connections() -> u32 {
    3
}
const fn default_retries() -> u32 {
    3
}
const fn default_backoff() -> u32 {
    5
}
const fn default_scan() -> u32 {
    60
}
const fn yes() -> bool {
    true
}

/// What a job does right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshDownloadState {
    /// Paused by the user: nothing runs; unfinished files continue when it is resumed.
    Paused,
    /// The Gateway cannot carry traffic now (its connection is not running or not ready, or it
    /// refused): the job waits and tries again — it never connects any other way.
    WaitingVpn,
    /// Opening SSH connections through the Gateway.
    Connecting,
    /// Listing the source folder.
    Scanning,
    /// At least one file is being downloaded.
    Downloading,
    /// Nothing to do until the next listing.
    Idle,
    /// A failure that may pass (the server did not answer, a connection broke): trying again at
    /// `next_retry_at`.
    Retrying,
    /// Stopped until the user acts (the host key changed, the server refused the login, the local
    /// folder cannot be used): `reason` says what to do.
    Error,
}

/// A server host key as the job saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadHostKey {
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-512`…
    pub algorithm: String,
    /// OpenSSH form, `SHA256:` and base64.
    pub fingerprint: String,
    pub seen_at: Timestamp,
}

/// Where a file being worked on is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshDownloadStep {
    /// Moving it from the source folder to the working folder.
    Claiming,
    Downloading,
    /// Putting the finished file in the local folder and deleting the remote copy.
    Finalizing,
    /// Moving it to the failed folder after its last failed attempt.
    Failing,
}

/// A file a job works on now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadActive {
    pub transfer_id: String,
    pub name: String,
    pub step: SshDownloadStep,
    pub bytes_done: Counter,
    /// `None` until the remote size is known.
    pub bytes_total: Option<Counter>,
    /// Where this attempt started (more than 0: it resumed a partial file).
    pub resumed_from: Counter,
    /// Bytes per second over the last seconds (`None` until measured).
    pub rate_bps: Option<f64>,
    /// Seconds left at that rate (`None` while unknown).
    #[ts(type = "number | null")]
    pub eta_secs: Option<u64>,
    /// The attempt (1 = first) since the file last made progress.
    pub attempt: u32,
    /// SSH connections that fetch it now: more than 1 while the job's other connections help
    /// with a large file.
    pub connections: u32,
    pub started_at: Timestamp,
}

/// What the manager observes about a job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadStatus {
    pub job_id: SshDownloadJobId,
    pub state: SshDownloadState,
    /// Why it waits, retries or stopped.
    pub reason: Option<Text>,
    /// Stable code of `reason` (`VPN_NOT_READY`, `GATEWAY_REFUSED`, `HOST_KEY_CHANGED`,
    /// `AUTH_REJECTED`, `LOCAL_DIR_UNUSABLE`, …).
    pub reason_code: Option<String>,
    /// SSH connections open now, and the most the job opens.
    pub connections: u32,
    pub connections_max: u32,
    /// Files found in the source folder that wait for a connection.
    pub queued: u32,
    /// The last listing stopped at its limit: more files wait than were counted.
    pub queue_truncated: bool,
    /// Files taken earlier that are not finished (they continue first).
    pub unfinished: u32,
    pub active: Vec<SshDownloadActive>,
    pub last_scan_at: Option<Timestamp>,
    pub next_scan_at: Option<Timestamp>,
    /// Entries the last listing left alone (folders, links, filtered or unusable names).
    pub last_scan_skipped: u32,
    pub next_retry_at: Option<Timestamp>,
    /// Since the manager started.
    pub completed: u32,
    pub failed: u32,
    pub bytes: Counter,
    /// The trusted host key (trust on first use).
    pub host_key: Option<SshDownloadHostKey>,
    /// A different key the server offered: the job stopped until the user trusts it.
    pub offered_host_key: Option<SshDownloadHostKey>,
    /// Bytes the job's SSH connections received from the server since the manager started the
    /// job, as they cross the stream to the Gateway (SSH framing and encryption included): the
    /// same bytes that Gateway counts in its connection's traffic.
    #[serde(default)]
    pub wire_rx_bytes: Counter,
    /// The same towards the server.
    #[serde(default)]
    pub wire_tx_bytes: Counter,
    /// Bytes per second of `wire_rx_bytes` over the last one to two seconds (`None` until
    /// measured).
    #[serde(default)]
    pub wire_rx_bps: Option<f64>,
    #[serde(default)]
    pub wire_tx_bps: Option<f64>,
    /// When this run of the job started; `None` while it is paused or stopped.
    #[serde(default)]
    pub running_since: Option<Timestamp>,
    pub observed_at: Timestamp,
}

/// One job with what the manager observes about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadView {
    pub job: SshDownloadJob,
    /// `None` while the manager cannot say — never guessed.
    pub status: Option<SshDownloadStatus>,
}

/// Where one file is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshDownloadTransferState {
    /// Being moved from the source to the working folder.
    Claiming,
    Downloading,
    /// Complete: being put in the local folder.
    Finalizing,
    /// In the local folder; the remote copy is being deleted.
    LocalDone,
    /// Being moved to the failed folder.
    Failing,
    Completed,
    Failed,
}

/// The record of one file a job took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadTransfer {
    pub id: String,
    pub job_id: SshDownloadJobId,
    /// Its name in the source folder.
    pub name: String,
    pub state: SshDownloadTransferState,
    pub size: Option<Counter>,
    /// Bytes in the local file when it finished (or failed).
    pub bytes_done: Option<Counter>,
    /// Where the finished file is.
    pub local_path: Option<String>,
    /// Where the remote file is now: the working folder, or the failed folder.
    pub remote_path: String,
    /// `false`: the job does not record names, and `name` is the transfer number
    /// ([`ssh_download_label`]); there is no local path.
    #[serde(default = "yes")]
    pub name_recorded: bool,
    pub attempts: u32,
    pub error: Option<Text>,
    pub created_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    /// From the first byte to the local file in place.
    #[ts(type = "number | null")]
    pub duration_ms: Option<u64>,
}

/// `GET /v1/ssh-downloads/{id}/transfers`: newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadTransfers {
    pub items: Vec<SshDownloadTransfer>,
    /// Cursor of the next (older) page (`before=`), `None` at the end.
    pub next: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshDownloadLogLevel {
    Info,
    Warning,
    Error,
}

/// One line of a job's log (public facts only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadLogEntry {
    #[ts(type = "number")]
    pub seq: i64,
    pub at: Timestamp,
    pub level: SshDownloadLogLevel,
    pub code: String,
    pub message: Text,
    /// The file it is about, if any.
    pub file: Option<String>,
}

/// `GET /v1/ssh-downloads/{id}/log`: newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadLog {
    pub items: Vec<SshDownloadLogEntry>,
}

/// `DELETE /v1/ssh-downloads/{id}/log`, `DELETE /v1/ssh-downloads/{id}/transfers`: how many log
/// lines or finished records were deleted (unfinished records stay: their files resume).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadCleared {
    pub removed: u32,
}

/// How a job that does not record names refers to a file: its transfer number (`#3f2a9c1d`, the
/// start of the record's id), which says nothing about the file.
#[must_use]
pub fn ssh_download_label(transfer_id: &str) -> String {
    let short: String = transfer_id.chars().take(8).collect();
    format!("#{short}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshDownloadAction {
    Pause,
    Resume,
    /// List the source folder now.
    Scan,
    /// Trust the key the server offered instead of the recorded one (`fingerprint`: the one
    /// shown to the user, refused when the server now offers another).
    TrustHostKey,
}

/// `POST /v1/ssh-downloads/{id}/actions`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct SshDownloadActionRequest {
    pub action: SshDownloadAction,
    /// `trust_host_key`: the offered key's fingerprint as shown.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Answer of a job action: the recorded operation and the job's status after it.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadActionResult {
    pub operation: Operation,
    pub status: Option<SshDownloadStatus>,
}

/// `GET /v1/ssh-downloads/dir-check?path=`: whether a local folder can take downloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshDownloadDirCheck {
    pub path: String,
    pub exists: bool,
    /// It would be created on save.
    pub would_create: bool,
    /// Why it cannot be used (`None`: it can).
    pub problem: Option<Text>,
}

// ---------------------------------------------------------------------------------------------
// Rules (pure)
// ---------------------------------------------------------------------------------------------

/// `dir` without trailing slashes (`/` stays `/`).
#[must_use]
pub fn trim_dir(dir: &str) -> &str {
    let t = dir.trim();
    let trimmed = t.trim_end_matches('/');
    if trimmed.is_empty() && t.starts_with('/') {
        "/"
    } else {
        trimmed
    }
}

/// The folder named `name` beside `source` (`/data/todo` → `/data/doing`; `todo` → `doing`), or
/// `None` when the source has no parent (`/`).
#[must_use]
pub fn sibling_dir(source: &str, name: &str) -> Option<String> {
    let s = trim_dir(source);
    let s = s.trim_prefix("~/");
    if s.is_empty() || s == "/" || s == "~" {
        return None;
    }
    Some(match s.rsplit_once('/') {
        Some(("", _)) => format!("/{name}"),
        Some((parent, _)) => format!("{parent}/{name}"),
        None => name.to_string(),
    })
}

/// A remote path as the server reads it: `~/x` is `x` (SFTP paths start at the login folder).
#[must_use]
pub fn remote_path(dir: &str) -> &str {
    let d = trim_dir(dir);
    match d.strip_prefix("~/") {
        Some(rest) => rest,
        None if d == "~" => ".",
        None => d,
    }
}

fn path_chars_ok(p: &str) -> bool {
    !p.chars().any(char::is_control)
}

fn has_dot_segment(p: &str) -> bool {
    p.split('/').any(|seg| seg == ".." || seg == ".")
}

/// `what` names the folder, as it reads inside a sentence (“source folder”).
fn check_remote_dir(r: &mut ValidationReport, path: &str, dir: &str, what: Text) {
    let d = dir.trim();
    if d.is_empty() {
        r.error(
            "SSH_DL_REMOTE_DIR_REQUIRED",
            path,
            tr!(
                "Enter the {what}",
                "請輸入{what}",
                "{what}を入力してください";
                what = what
            ),
        );
    } else if d.len() > SSH_DOWNLOAD_MAX_REMOTE_PATH {
        r.error(
            "SSH_DL_REMOTE_DIR",
            path,
            tr!(
                "The {what} is at most {SSH_DOWNLOAD_MAX_REMOTE_PATH} bytes",
                "{what}最多 {SSH_DOWNLOAD_MAX_REMOTE_PATH} 個位元組",
                "{what}は最大 {SSH_DOWNLOAD_MAX_REMOTE_PATH} バイトです";
                what = what
            ),
        );
    } else if !path_chars_ok(d) || has_dot_segment(d) {
        r.error(
            "SSH_DL_REMOTE_DIR",
            path,
            tr!(
                "The {what} cannot contain control characters or segments such as . or ..",
                "{what}不能含有控制字元，也不能有 . 或 .. 這樣的段落",
                "{what}に制御文字や、. や .. のような部分は使えません";
                what = what
            ),
        );
    }
}

/// `/…` or `~/…`, no control characters, no `.`/`..` segment.
#[must_use]
pub fn local_path_ok(p: &str) -> bool {
    (p.starts_with('/') || p.starts_with("~/"))
        && p.len() <= SSH_DOWNLOAD_MAX_LOCAL_PATH
        && path_chars_ok(p)
        && !has_dot_segment(p)
}

/// The job's three remote folders: each valid, and no two the same.
fn check_remote_dirs(r: &mut ValidationReport, job: &SshDownloadJob) {
    check_remote_dir(
        r,
        "/source_dir",
        &job.source_dir,
        tr!("source folder", "來源資料夾", "取得元フォルダー"),
    );
    check_remote_dir(
        r,
        "/work_dir",
        &job.work_dir,
        tr!("working folder", "處理中資料夾", "処理中フォルダー"),
    );
    check_remote_dir(
        r,
        "/failed_dir",
        &job.failed_dir,
        tr!("failed folder", "失敗資料夾", "失敗フォルダー"),
    );
    let (s, w, f) = (
        remote_path(&job.source_dir),
        remote_path(&job.work_dir),
        remote_path(&job.failed_dir),
    );
    if !s.is_empty() && s == w {
        r.error(
            "SSH_DL_SAME_DIR",
            "/work_dir",
            tr!(
                "The working folder cannot be the same as the source folder",
                "處理中資料夾不能和來源資料夾相同",
                "処理中フォルダーは取得元フォルダーと別にしてください"
            ),
        );
    }
    if !s.is_empty() && s == f {
        r.error(
            "SSH_DL_SAME_DIR",
            "/failed_dir",
            tr!(
                "The failed folder cannot be the same as the source folder",
                "失敗資料夾不能和來源資料夾相同",
                "失敗フォルダーは取得元フォルダーと別にしてください"
            ),
        );
    }
    if !w.is_empty() && w == f {
        r.error(
            "SSH_DL_SAME_DIR",
            "/failed_dir",
            tr!(
                "The failed folder cannot be the same as the working folder",
                "失敗資料夾不能和處理中資料夾相同",
                "失敗フォルダーは処理中フォルダーと別にしてください"
            ),
        );
    }
}

/// The job's numbers within their ranges.
fn check_ranges(r: &mut ValidationReport, job: &SshDownloadJob) {
    for (path, value, range, what) in [
        (
            "/connections",
            job.connections,
            SSH_DOWNLOAD_CONNECTIONS,
            tr!("Concurrent connections", "同時連線數", "同時接続数"),
        ),
        (
            "/retries",
            job.retries,
            SSH_DOWNLOAD_RETRIES,
            tr!("Attempts", "嘗試次數", "試行回数"),
        ),
        (
            "/retry_backoff_secs",
            job.retry_backoff_secs,
            SSH_DOWNLOAD_BACKOFF_SECS,
            tr!("Retry interval", "重試間隔", "再試行の間隔"),
        ),
        (
            "/scan_interval_secs",
            job.scan_interval_secs,
            SSH_DOWNLOAD_SCAN_SECS,
            tr!("Scan interval", "掃描間隔", "スキャン間隔"),
        ),
        (
            "/history_days",
            job.history_days
                .unwrap_or(*SSH_DOWNLOAD_HISTORY_DAYS.start()),
            SSH_DOWNLOAD_HISTORY_DAYS,
            tr!("Days of history kept", "紀錄保留天數", "履歴の保存日数"),
        ),
    ] {
        if !range.contains(&value) {
            let (min, max) = (range.start(), range.end());
            r.error(
                "SSH_DL_RANGE",
                path,
                tr!(
                    "{what} must be between {min} and {max}",
                    "{what}必須介於 {min} 與 {max}",
                    "{what}は {min} から {max} の間にしてください";
                    what = what
                ),
            );
        }
    }
}

/// Field rules of a job (the manager also checks the local folder, the key file and the
/// Gateway against the host).
#[must_use]
pub fn check_ssh_download(job: &SshDownloadJob) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &job.name);
    let host = job.host.trim();
    if host.is_empty() {
        r.error(
            "SSH_DL_HOST_REQUIRED",
            "/host",
            tr!(
                "Enter the address of the SSH server",
                "請輸入 SSH 伺服器位址",
                "SSH サーバーのアドレスを入力してください"
            ),
        );
    } else if !crate::validation::valid_ssh_host_name(host) {
        r.error(
            "SSH_DL_HOST",
            "/host",
            tr!("The server address must be a domain name or a complete IP address (short forms such as 127.1 are not accepted)", "伺服器位址必須是網域名稱或完整的 IP 位址（不接受 127.1 這類簡寫）", "サーバーのアドレスはドメイン名か完全な IP アドレスにしてください（127.1 のような省略形は使えません）"),
        );
    } else if let Some(why) = ssh_vpn_unreachable(host) {
        r.error("SSH_DL_NOT_VIA_VPN", "/host", why);
    } else if ssh_vpn_private(host) {
        r.warning(
            "SSH_DL_PRIVATE_VIA_VPN",
            "/host",
            tr!("A private address can be reached through the VPN only when this connection's security profile allows that network; otherwise the Gateway refuses it (it never falls back to the ordinary network)", "私有位址只有在這條連線的安全設定允許該網段時才能經 VPN 到達；否則代理埠會拒絕（不會改走一般網路）", "プライベートアドレスには、この接続のセキュリティ設定がそのネットワークを許可している場合にだけ VPN 経由で到達できます。許可されていなければゲートウェイが拒否します（通常のネットワークには切り替わりません）"),
        );
    }
    if job.port == 0 {
        r.error(
            "SSH_DL_PORT",
            "/port",
            tr!(
                "The port must be between 1 and 65535",
                "埠號必須介於 1 與 65535",
                "ポート番号は 1 から 65535 の間にしてください"
            ),
        );
    }
    let user = job.user.as_str();
    if user.is_empty() {
        r.error(
            "SSH_DL_USER_REQUIRED",
            "/user",
            tr!(
                "Enter the user name to log in as",
                "請輸入登入的使用者名稱",
                "ログインするユーザー名を入力してください"
            ),
        );
    } else if user.len() > 128 || user.chars().any(|c| c.is_control() || c.is_whitespace()) {
        r.error(
            "SSH_DL_USER",
            "/user",
            tr!("The user name is at most 128 bytes and cannot contain spaces or control characters", "使用者名稱最多 128 個位元組，不能含有空白或控制字元", "ユーザー名は最大 128 バイトで、空白や制御文字は使えません"),
        );
    }
    match &job.identity_file {
        Some(f) if !local_path_ok(f) => r.error(
            "SSH_DL_IDENTITY_FILE",
            "/identity_file",
            tr!("The key file path must start with / or ~/ and cannot contain control characters or . or .. segments", "金鑰檔路徑必須以 / 或 ~/ 開頭，不能含有控制字元或 . 、.. 段落", "鍵ファイルのパスは / または ~/ で始め、制御文字や . 、.. の部分を含めないでください"),
        ),
        None if job.password.is_none() => r.error(
            "SSH_DL_AUTH_REQUIRED",
            "/identity_file",
            tr!("Choose a private key file or enter a password (at least one way to log in)", "請指定私鑰檔或輸入密碼（至少一種登入方式）", "秘密鍵ファイルを指定するか、パスワードを入力してください（ログイン方法が 1 つ以上必要です）"),
        ),
        None if job.key_passphrase.is_some() => r.error(
            "SSH_DL_PASSPHRASE_WITHOUT_KEY",
            "/key_passphrase",
            tr!("A key passphrase needs a private key file", "金鑰密碼要搭配私鑰檔", "鍵のパスフレーズには秘密鍵ファイルが必要です"),
        ),
        _ => {}
    }
    check_remote_dirs(&mut r, job);
    let local = job.local_dir.trim();
    if local.is_empty() {
        r.error(
            "SSH_DL_LOCAL_DIR_REQUIRED",
            "/local_dir",
            tr!(
                "Enter the local folder",
                "請輸入本機資料夾",
                "ローカルフォルダーを入力してください"
            ),
        );
    } else if !local_path_ok(local) || trim_dir(local) == "/" {
        r.error(
            "SSH_DL_LOCAL_DIR",
            "/local_dir",
            tr!("The local folder must be a full path that starts with / or ~/ (and is not /), without control characters or . or .. segments", "本機資料夾必須是以 / 或 ~/ 開頭的完整路徑（不能是 /），不能含有控制字元或 . 、.. 段落", "ローカルフォルダーは / または ~/ で始まる完全なパスにしてください（/ は使えません）。制御文字や . 、.. の部分は使えません"),
        );
    }
    check_ranges(&mut r, job);
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretId;

    fn job() -> SshDownloadJob {
        let now = Timestamp::now();
        SshDownloadJob {
            id: SshDownloadJobId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: now,
                updated_at: now,
            },
            name: "下載".into(),
            gateway_id: GatewayId::new(),
            host: "files.example.net".into(),
            port: 22,
            user: "ubuntu".into(),
            identity_file: Some("~/.ssh/id_ed25519".into()),
            key_passphrase: None,
            password: None,
            source_dir: "/data/todo".into(),
            work_dir: "/data/doing".into(),
            failed_dir: "/data/failed".into(),
            local_dir: "/home/me/Downloads/incoming".into(),
            connections: 3,
            retries: 3,
            retry_backoff_secs: 5,
            scan_interval_secs: 60,
            name_filter: SshDownloadNameFilter::All,
            skip_hidden: true,
            record_names: true,
            history_days: None,
        }
    }

    fn codes(r: &ValidationReport) -> Vec<String> {
        r.issues.iter().map(|i| i.code.clone()).collect()
    }

    #[test]
    fn a_complete_job_passes_and_each_rule_names_its_field() {
        assert!(check_ssh_download(&job()).valid);

        let mut j = job();
        j.host = "localhost".into();
        assert_eq!(codes(&check_ssh_download(&j)), ["SSH_DL_NOT_VIA_VPN"]);
        j.host = "127.1".into();
        assert_eq!(codes(&check_ssh_download(&j)), ["SSH_DL_HOST"]);
        j.host = "10.0.0.5".into();
        let r = check_ssh_download(&j);
        assert!(r.valid, "a private address is a warning");
        assert_eq!(codes(&r), ["SSH_DL_PRIVATE_VIA_VPN"]);

        let mut j = job();
        j.identity_file = None;
        assert_eq!(codes(&check_ssh_download(&j)), ["SSH_DL_AUTH_REQUIRED"]);
        j.password = Some(SecretRef(SecretId::new()));
        assert!(check_ssh_download(&j).valid, "a password alone is enough");
        j.identity_file = Some("keys/id".into());
        assert_eq!(codes(&check_ssh_download(&j)), ["SSH_DL_IDENTITY_FILE"]);

        let mut j = job();
        j.work_dir = "/data/todo/".into();
        let r = check_ssh_download(&j);
        assert_eq!(codes(&r), ["SSH_DL_SAME_DIR"]);
        assert_eq!(r.issues[0].path, "/work_dir");
        let mut j = job();
        j.failed_dir = "~/../doing".into();
        assert_eq!(codes(&check_ssh_download(&j)), ["SSH_DL_REMOTE_DIR"]);
        j.failed_dir = "/data/doing".into();
        let r = check_ssh_download(&j);
        assert_eq!(codes(&r), ["SSH_DL_SAME_DIR"]);
        assert_eq!(r.issues[0].path, "/failed_dir");

        let mut j = job();
        j.source_dir = "/data/../etc".into();
        j.local_dir = "relative/dir".into();
        j.connections = 9;
        j.scan_interval_secs = 1;
        j.user = "a b".into();
        assert_eq!(
            codes(&check_ssh_download(&j)),
            [
                "SSH_DL_USER",
                "SSH_DL_REMOTE_DIR",
                "SSH_DL_LOCAL_DIR",
                "SSH_DL_RANGE",
                "SSH_DL_RANGE"
            ]
        );
        let mut j = job();
        j.local_dir = "/".into();
        assert_eq!(codes(&check_ssh_download(&j)), ["SSH_DL_LOCAL_DIR"]);
    }

    /// Secret-handling boundary: a `{:?}` of the request (logs, error contexts) never carries the
    /// plain-text password or key passphrase, with or without each secret present.
    #[test]
    fn debug_never_prints_plain_text_secrets() {
        let cases = [
            (Some("hunter2-pass"), Some("hunter2-phrase")),
            (Some("hunter2-pass"), None),
            (None, Some("hunter2-phrase")),
            (None, None),
        ];
        for (password, passphrase) in cases {
            let input: SshDownloadInput = serde_json::from_value(serde_json::json!({
                "name": "job",
                "gateway_id": "00000000-0000-4000-8000-000000000001",
                "host": "example.net",
                "user": "u",
                "password": password,
                "key_passphrase": passphrase,
                "source_dir": "/src",
                "local_dir": "/dst",
            }))
            .expect("valid input");
            let shown = format!("{input:?}");
            assert!(!shown.contains("hunter2"), "{shown}");
            assert_eq!(
                shown.contains("<redacted>"),
                password.is_some() || passphrase.is_some()
            );
            assert!(shown.contains("example.net"));
        }
    }
}
