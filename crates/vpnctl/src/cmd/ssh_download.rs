//! `vpnctl ssh-download list|clear-log|clear-history|records`: SSH download jobs through the same
//! API as the web UI. Creating and editing a job (folders, credentials) stays in the web UI;
//! `records` saves the job with only its record settings changed (If-Match on its revision).
//!
//! A job's log and history name remote files: `clear-log` and `clear-history` delete them for
//! good (nothing is left in the database), `records --names off` stops recording names, and
//! `records --keep-days` deletes what is older. Unfinished files keep their records — they resume
//! from them — and no file is ever touched.

use clap::{Subcommand, ValueEnum};
use hyper::Method;
use vpn_domain::{
    SSH_DOWNLOAD_HISTORY_DAYS, SshDownloadCleared, SshDownloadInput, SshDownloadJob,
    SshDownloadState, SshDownloadView,
};

use super::{CmdResult, Ctx, Exit, Failure};
use crate::client::Mutation;
use crate::output::table;

#[derive(Subcommand, Debug)]
pub enum SshDownloadCmd {
    /// 列出所有 SSH 下載工作與它們的紀錄設定
    List,
    /// 清除一個工作的日誌（永久刪除，資料庫裡不留內容；之後只有一行說明已清除）
    #[command(after_help = "例：vpnctl ssh-download clear-log 備份同步 --yes")]
    ClearLog {
        /// 名稱、ID 或 ID 開頭
        job: String,
        /// 確認要清除（沒有這個旗標只會說明後果）
        #[arg(long)]
        yes: bool,
    },
    /// 清除一個工作已完成與失敗的傳輸紀錄（未完成的保留，會接著下載；不動任何檔案）
    ClearHistory {
        /// 名稱、ID 或 ID 開頭
        job: String,
        /// 確認要清除（沒有這個旗標只會說明後果）
        #[arg(long)]
        yes: bool,
    },
    /// 檢視或修改一個工作的紀錄設定：是否記錄檔名、紀錄保留天數
    #[command(
        after_help = "例：vpnctl ssh-download records 備份同步 --names off --keep-days 7
不加旗標時只顯示目前的設定。--keep-days off：只保留最新的 500 行日誌與 1,000 筆紀錄。"
    )]
    Records {
        /// 名稱、ID 或 ID 開頭
        job: String,
        /// 記錄檔名（off：日誌與傳輸紀錄只留傳輸編號；未完成的檔案在完成前保留檔名以便接續）
        #[arg(long, value_enum)]
        names: Option<Switch>,
        /// 超過這個天數的日誌與傳輸紀錄每小時刪除一次（1–3650），或 off
        #[arg(long)]
        keep_days: Option<String>,
    },
}

/// `on` / `off` of a setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Switch {
    /// 開啟
    On,
    /// 關閉
    Off,
}

pub async fn run(ctx: &Ctx, cmd: SshDownloadCmd) -> CmdResult {
    match cmd {
        SshDownloadCmd::List => list(ctx).await,
        SshDownloadCmd::ClearLog { job, yes } => clear(ctx, &job, Clear::Log, yes).await,
        SshDownloadCmd::ClearHistory { job, yes } => clear(ctx, &job, Clear::History, yes).await,
        SshDownloadCmd::Records {
            job,
            names,
            keep_days,
        } => records(ctx, &job, names, keep_days.as_deref()).await,
    }
}

async fn jobs(ctx: &Ctx) -> Result<Vec<SshDownloadView>, Failure> {
    ctx.client.get("/v1/ssh-downloads").await
}

/// The job a command names (unique name, id or id prefix).
async fn job(ctx: &Ctx, query: &str) -> Result<SshDownloadView, Failure> {
    let all = jobs(ctx).await?;
    crate::resolve::pick(
        &all,
        query,
        "SSH 下載工作",
        |v| v.job.id.to_string(),
        |v| v.job.name.clone(),
    )
    .cloned()
}

const fn state(s: SshDownloadState) -> &'static str {
    match s {
        SshDownloadState::Paused => "已暫停",
        SshDownloadState::WaitingVpn => "等待 VPN",
        SshDownloadState::Connecting => "連線中",
        SshDownloadState::Scanning => "掃描中",
        SshDownloadState::Downloading => "下載中",
        SshDownloadState::Idle => "閒置",
        SshDownloadState::Retrying => "稍後重試",
        SshDownloadState::Error => "已停止",
    }
}

/// The job's record settings in words.
fn records_text(j: &SshDownloadJob) -> String {
    let names = if j.record_names {
        "記錄檔名"
    } else {
        "不記錄檔名（只留傳輸編號）"
    };
    let keep = j.history_days.map_or_else(
        || "保留最新的 500 行日誌與 1,000 筆紀錄".to_string(),
        |d| format!("保留 {d} 天（最多 500 行日誌與 1,000 筆紀錄）"),
    );
    format!("{names}；{keep}")
}

async fn list(ctx: &Ctx) -> CmdResult {
    let all = jobs(ctx).await?;
    if ctx.out.json {
        ctx.out.json(&all);
        return Ok(Exit::Ok);
    }
    if all.is_empty() {
        ctx.out.line("還沒有任何 SSH 下載工作。");
        return Ok(Exit::Ok);
    }
    let rows: Vec<Vec<String>> = all
        .iter()
        .map(|v| {
            let j = &v.job;
            vec![
                j.name.clone(),
                format!("{}@{}:{}", j.user, j.host, j.port),
                v.status
                    .as_ref()
                    .map_or("未知", |s| state(s.state))
                    .to_string(),
                records_text(j),
            ]
        })
        .collect();
    ctx.out
        .line(table(&["名稱", "伺服器", "狀態", "紀錄"], &rows));
    Ok(Exit::Ok)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Clear {
    Log,
    History,
}

async fn clear(ctx: &Ctx, q: &str, what: Clear, yes: bool) -> CmdResult {
    let v = job(ctx, q).await?;
    let name = &v.job.name;
    let (path, label) = match what {
        Clear::Log => ("log", "日誌"),
        Clear::History => ("transfers", "傳輸紀錄"),
    };
    if !yes {
        let mut why = match what {
            Clear::Log => format!("會永久刪除「{name}」的所有日誌（資料庫裡不留內容）。"),
            Clear::History => format!(
                "會永久刪除「{name}」已完成與失敗的傳輸紀錄（資料庫裡不留內容）；未完成的檔案保留紀錄，會接著下載。"
            ),
        };
        why.push_str("\n不會刪除或移動任何檔案。確定要清除，請加上 --yes");
        return Err(Failure::Usage(why));
    }
    let done: Mutation<SshDownloadCleared> = ctx
        .client
        .mutate(
            Method::DELETE,
            &format!("/v1/ssh-downloads/{}/{path}", v.job.id),
            None::<&()>,
            None,
        )
        .await?;
    match done {
        Mutation::Done(Some(c)) => {
            ctx.out.json(&c);
            ctx.out.line(match what {
                Clear::Log => format!("已清除「{name}」的日誌（{} 行）。", c.removed),
                Clear::History => format!(
                    "已清除「{name}」的傳輸紀錄（{} 筆）；未完成的檔案保留紀錄。",
                    c.removed
                ),
            });
        }
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示「{name}」的{label}已清除（operation {}）。",
                op.id
            ));
        }
    }
    Ok(Exit::Ok)
}

/// `--keep-days`: a number of days in range, or `off`.
fn keep_days(v: &str) -> Result<Option<u32>, Failure> {
    let v = v.trim();
    if v.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    v.parse::<u32>()
        .ok()
        .filter(|d| SSH_DOWNLOAD_HISTORY_DAYS.contains(d))
        .map(Some)
        .ok_or_else(|| {
            Failure::Usage(format!(
                "--keep-days 必須是 {} 到 {} 的天數，或 off",
                SSH_DOWNLOAD_HISTORY_DAYS.start(),
                SSH_DOWNLOAD_HISTORY_DAYS.end()
            ))
        })
}

/// The job as it is saved: the body of a `PUT` that changes nothing (secrets stay as stored).
fn input_of(j: &SshDownloadJob) -> SshDownloadInput {
    SshDownloadInput {
        name: j.name.clone(),
        gateway_id: j.gateway_id,
        host: j.host.clone(),
        port: j.port,
        user: j.user.clone(),
        identity_file: j.identity_file.clone(),
        key_passphrase: None,
        clear_key_passphrase: false,
        password: None,
        clear_password: false,
        source_dir: j.source_dir.clone(),
        work_dir: Some(j.work_dir.clone()),
        failed_dir: Some(j.failed_dir.clone()),
        local_dir: j.local_dir.clone(),
        connections: j.connections,
        retries: j.retries,
        retry_backoff_secs: j.retry_backoff_secs,
        scan_interval_secs: j.scan_interval_secs,
        name_filter: j.name_filter,
        skip_hidden: j.skip_hidden,
        record_names: j.record_names,
        history_days: j.history_days,
        paused: false,
    }
}

async fn records(ctx: &Ctx, q: &str, names: Option<Switch>, keep: Option<&str>) -> CmdResult {
    let keep = keep.map(keep_days).transpose()?;
    let v = job(ctx, q).await?;
    let j = &v.job;
    let record_names = names.map_or(j.record_names, |s| s == Switch::On);
    let history_days = keep.unwrap_or(j.history_days);
    if record_names == j.record_names && history_days == j.history_days {
        ctx.out.json(&v);
        ctx.out
            .line(format!("「{}」：{}。", j.name, records_text(j)));
        return Ok(Exit::Ok);
    }
    let input = SshDownloadInput {
        record_names,
        history_days,
        ..input_of(j)
    };
    let done: Mutation<SshDownloadView> = ctx
        .client
        .mutate(
            Method::PUT,
            &format!("/v1/ssh-downloads/{}", j.id),
            Some(&input),
            Some(j.meta.revision),
        )
        .await?;
    match done {
        Mutation::Done(Some(view)) => {
            ctx.out.json(&view);
            ctx.out.line(format!(
                "已儲存「{}」：{}。",
                view.job.name,
                records_text(&view.job)
            ));
            if j.record_names && !record_names {
                ctx.out.line(
                    "之後完成的檔案只留傳輸編號；先前的日誌與紀錄仍有檔名，可以用 clear-log、clear-history 清除。",
                );
            }
        }
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示「{}」的紀錄設定已儲存（operation {}）。",
                j.name, op.id
            ));
        }
    }
    Ok(Exit::Ok)
}
