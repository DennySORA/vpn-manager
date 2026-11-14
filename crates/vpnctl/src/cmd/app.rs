//! `vpnctl app list|status|start|stop|restart`: managed Apps through the same API as the web UI.
//! `status` (also `inspect`) includes a strict App's local access ports.
//! The manager launches and supervises them; `vpnctl` never starts a program itself. Approving a
//! changed executable stays in the web UI, where the file's SHA-256 is shown before it is
//! approved.

use clap::Subcommand;
use hyper::Method;
use vpn_domain::{
    AccessBind, AccessState, AppAction, AppActionRequest, AppActionResult, AppExit, AppIsolation,
    AppLimits, AppRunState, AppStatus, AppView, DesiredState, InstanceView, Persistence,
};

use super::{CmdResult, Ctx, Exit, Failure, instances};
use crate::client::Mutation;
use crate::output::{Out, opt_time, resources, table, time};

#[derive(Subcommand, Debug)]
pub enum AppCmd {
    /// 列出所有受管 App
    List,
    /// 一個 App 的狀態：程序、隔離方式、代理埠、監聽的連接埠、本機存取埠與最近的錯誤
    #[command(visible_alias = "inspect")]
    Status {
        /// 名稱、ID 或 ID 開頭
        app: String,
    },
    /// 啟動（執行檔與核准時不同就不啟動；在網頁上重新核准）
    Start { app: String },
    /// 停止整個程序樹（先 SIGTERM，10 秒後 SIGKILL），停止意圖寫入磁碟
    Stop { app: String },
    /// 重新啟動（套用已儲存的設定）
    Restart { app: String },
}

pub async fn run(ctx: &Ctx, cmd: AppCmd) -> CmdResult {
    match cmd {
        AppCmd::List => list(ctx).await,
        AppCmd::Status { app: q } => status(ctx, &q).await,
        AppCmd::Start { app: q } => act(ctx, &q, AppAction::Start).await,
        AppCmd::Stop { app: q } => act(ctx, &q, AppAction::Stop).await,
        AppCmd::Restart { app: q } => act(ctx, &q, AppAction::Restart).await,
    }
}

async fn apps(ctx: &Ctx) -> Result<Vec<AppView>, Failure> {
    ctx.client.get("/v1/apps").await
}

/// The App a command names (unique name, id or id prefix).
async fn app(ctx: &Ctx, query: &str) -> Result<AppView, Failure> {
    let all = apps(ctx).await?;
    crate::resolve::pick(
        &all,
        query,
        "受管 App",
        |v| v.spec.id.to_string(),
        |v| v.spec.name.clone(),
    )
    .cloned()
}

const fn isolation(i: AppIsolation) -> &'static str {
    match i {
        AppIsolation::ProxyEnv => "環境變數",
        AppIsolation::EnforcedProxy => "強制代理",
        AppIsolation::StrictNetns => "嚴格隔離",
    }
}

const fn run_state(s: AppRunState) -> &'static str {
    match s {
        AppRunState::Stopped => "已停止",
        AppRunState::Starting => "啟動中",
        AppRunState::Running => "執行中",
        AppRunState::Stopping => "停止中",
        AppRunState::Failed => "需要處理",
    }
}

/// The state as the list shows it; unknown when the manager did not report it.
fn state(v: &AppView) -> &'static str {
    v.status.as_ref().map_or("未知", |s| run_state(s.state))
}

const fn access_state(s: AccessState) -> &'static str {
    match s {
        AccessState::Unavailable => "無法監聽",
        AccessState::AppStopped => "App 未執行，連線會被拒絕",
        AccessState::RestartNeeded => "App 重新啟動後才開放",
        AccessState::Serving => "轉送中",
    }
}

/// Where a port listens, as a client on this host would use it, and for whom.
fn access_place(port: u16, bind: AccessBind, allow: &[String]) -> String {
    match bind {
        AccessBind::Loopback => format!("http://127.0.0.1:{port}（只限本機）"),
        AccessBind::Lan => format!(
            "0.0.0.0:{port}（區網，允許 {}）",
            if allow.is_empty() {
                "—".to_string()
            } else {
                allow.join("、")
            }
        ),
    }
}

/// The App's local access ports: as configured, with what the manager reports about each.
fn access_lines(v: &AppView) -> Vec<String> {
    let mut out = Vec::new();
    for p in &v.spec.access_ports {
        let allow: Vec<String> = p.allow.iter().map(ToString::to_string).collect();
        let place = access_place(p.host_port, p.bind, &allow);
        let seen = v
            .status
            .as_ref()
            .and_then(|s| s.access.iter().find(|a| a.host_port == p.host_port));
        let Some(a) = seen else {
            out.push(format!("{place} → App 的 {}：狀態未知", p.app_port));
            continue;
        };
        let listening = match a.app_listening {
            Some(true) => "；App 在沙箱內監聽這個 port",
            Some(false) => "；App 沒有在沙箱內監聽這個 port",
            None => "",
        };
        out.push(format!(
            "{place} → App 的 {}：{}{listening}；已轉送 {}、已拒絕 {}",
            p.app_port,
            access_state(a.state),
            a.accepted,
            a.refused
        ));
        if let Some(f) = &a.last_error {
            out.push(format!(
                "  最近的錯誤：{}（{}，{}）",
                f.message.zh_tw,
                f.code,
                time(&f.at)
            ));
        }
        if let Some(f) = &a.last_refused {
            out.push(format!(
                "  最近拒絕：{}（{}）",
                f.message.zh_tw,
                time(&f.at)
            ));
        }
    }
    out
}

fn exit_text(e: &AppExit) -> String {
    match (e.code, e.signal) {
        (Some(c), _) => format!("結束碼 {c}"),
        (None, Some(s)) => format!("訊號 {s}"),
        _ => "結束狀態不明".into(),
    }
}

async fn list(ctx: &Ctx) -> CmdResult {
    let list = apps(ctx).await?;
    if ctx.out.json {
        ctx.out.json(&list);
        return Ok(Exit::Ok);
    }
    if list.is_empty() {
        ctx.out.line("還沒有任何受管 App。");
        return Ok(Exit::Ok);
    }
    // Connection names; an unreadable list only costs the names.
    let owners: Vec<InstanceView> = instances(ctx).await.unwrap_or_default();
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|v| {
            let s = v.status.as_ref();
            vec![
                v.spec.name.clone(),
                state(v).to_string(),
                isolation(v.spec.isolation).to_string(),
                owners
                    .iter()
                    .find(|o| o.spec.id == v.spec.instance_id)
                    .map_or_else(|| "—".to_string(), |o| o.spec.name.clone()),
                s.and_then(|s| s.pid)
                    .map_or_else(|| "—".to_string(), |p| p.to_string()),
                s.and_then(|s| s.process_count)
                    .map_or_else(|| "—".to_string(), |n| n.to_string()),
            ]
        })
        .collect();
    ctx.out.line(table(
        &["名稱", "狀態", "隔離", "連線", "PID", "程序"],
        &rows,
    ));
    Ok(Exit::Ok)
}

async fn status(ctx: &Ctx, q: &str) -> CmdResult {
    let v = app(ctx, q).await?;
    if ctx.out.json {
        ctx.out.json(&v);
        return Ok(Exit::Ok);
    }
    let out = &ctx.out;
    out.line(format!("{}（{}）", v.spec.name, v.spec.id));
    out.line(format!("執行檔：{}", v.spec.executable));
    match &v.spec.approval {
        Some(a) => out.line(format!(
            "核准：SHA-256 {}（{} 核准）",
            a.sha256,
            time(&a.approved_at)
        )),
        None => out.line("核准：尚未核准（在網頁上檢查並核准）"),
    }
    out.line(format!("隔離：{}", isolation(v.spec.isolation)));
    out.line(limits_line(&v.spec.limits));
    let access = access_lines(&v);
    if !access.is_empty() {
        out.line("本機存取埠：");
        for line in access {
            out.line(format!("  {line}"));
        }
    }
    let Some(s) = &v.status else {
        out.line("狀態：未知（manager 沒有回報）");
        return Ok(Exit::Failed);
    };
    status_lines(*out, s);
    Ok(Exit::Ok)
}

/// "設定的上限：…" for an App's configured limits.
fn limits_line(l: &AppLimits) -> String {
    let mut set = Vec::new();
    if let Some(m) = l.memory_mib {
        set.push(format!("記憶體 {m} MiB"));
    }
    if let Some(c) = l.cpu_percent {
        set.push(format!("CPU {c}%"));
    }
    if let Some(p) = l.processes {
        set.push(format!("程序（含執行緒） {p}"));
    }
    if let Some(f) = l.open_files {
        set.push(format!("開啟檔案 {f}"));
    }
    if set.is_empty() {
        "設定的上限：沒有".to_string()
    } else {
        format!("設定的上限：{}", set.join("、"))
    }
}

/// The lines of an App's observed status, from its state on.
fn status_lines(out: Out, s: &AppStatus) {
    out.line(format!(
        "狀態：{}，觀測於 {}",
        run_state(s.state),
        time(&s.observed_at)
    ));
    out.line(format!(
        "意圖：{}；{}",
        match s.desired {
            DesiredState::Running => "執行",
            DesiredState::Stopped => "停止",
        },
        match s.intent_persistence {
            Persistence::Durable => "已寫入磁碟",
            Persistence::Pending => "尚未寫入磁碟（重試中）",
            Persistence::Unavailable => "無法讀取",
        }
    ));
    if let Some(pid) = s.pid {
        out.line(format!(
            "根程序：pid {pid}，啟動於 {}；程序 {} 個",
            opt_time(s.started_at.as_ref()),
            s.process_count
                .map_or_else(|| "—".to_string(), |n| n.to_string())
        ));
    }
    if let Some(port) = s.gateway_port {
        out.line(format!("代理埠：127.0.0.1:{port}"));
    }
    if let Some(r) = &s.resources {
        for line in resources(r) {
            out.line(format!("資源：{line}"));
        }
    }
    match &s.listeners {
        Some(l) if !l.is_empty() => {
            let rows: Vec<String> = l
                .iter()
                .map(|l| {
                    format!(
                        "{}（pid {}{}）",
                        l.address,
                        l.pid,
                        if l.loopback { "" } else { "，非本機位址" }
                    )
                })
                .collect();
            out.line(format!("監聽：{}", rows.join("、")));
        }
        Some(_) => out.line("監聽：沒有"),
        None => {}
    }
    if s.isolation == Some(AppIsolation::EnforcedProxy) {
        out.line(s.sandbox_denials.map_or_else(
            || "Seatbelt 拒絕：無法讀取系統紀錄".to_string(),
            |n| format!("Seatbelt 拒絕：{n} 次"),
        ));
    }
    if let Some(e) = &s.last_exit {
        out.line(format!("上次結束：{}，{}", exit_text(e), time(&e.at)));
    }
    if let Some(f) = &s.last_error {
        out.line(format!(
            "最近的錯誤：{}（{}，{}）",
            f.message.zh_tw,
            f.code,
            time(&f.at)
        ));
    }
}

const fn verb(a: AppAction) -> &'static str {
    match a {
        AppAction::Start => "啟動",
        AppAction::Stop => "停止",
        AppAction::Restart => "重新啟動",
        AppAction::Approve => "核准",
    }
}

async fn act(ctx: &Ctx, q: &str, action: AppAction) -> CmdResult {
    let v = app(ctx, q).await?;
    let name = &v.spec.name;
    let body = AppActionRequest {
        action,
        sha256: None,
    };
    let done: Mutation<AppActionResult> = ctx
        .client
        .mutate(
            Method::POST,
            &format!("/v1/apps/{}/actions", v.spec.id),
            Some(&body),
            None,
        )
        .await?;
    let result = match done {
        Mutation::Done(Some(r)) => r,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        // The record only says the request was carried out: the App itself is read again and
        // judged as an answer would be; unknown (exit 3) when it cannot be read now.
        Mutation::Recovered(op) => {
            ctx.out.line(format!(
                "沒有收到回應；紀錄顯示這個請求已完成（operation {}），以下是重新讀取的「{name}」狀態。",
                op.id
            ));
            let now = app(ctx, &v.spec.id.to_string()).await;
            if let Ok(Some(status)) = now.map(|v| v.status) {
                AppActionResult {
                    operation: *op,
                    status: Some(status),
                }
            } else {
                ctx.out.json(&op);
                ctx.out.line("無法重新讀取 App 的狀態，不能確認結果。");
                return Ok(Exit::Unknown);
            }
        }
    };
    ctx.out.json(&result);
    let Some(s) = &result.status else {
        ctx.out.line(format!(
            "已{}「{name}」（operation {}）；目前狀態未知。",
            verb(action),
            result.operation.id
        ));
        return Ok(Exit::Ok);
    };
    match (action, s.state) {
        (AppAction::Stop, AppRunState::Stopped) => {
            ctx.out
                .line(format!("已停止「{name}」：整個程序樹都已結束。"));
            Ok(Exit::Ok)
        }
        (_, AppRunState::Running) => {
            ctx.out.line(format!(
                "已{}「{name}」：執行中，pid {}（{}）。",
                verb(action),
                s.pid.map_or_else(|| "—".to_string(), |p| p.to_string()),
                isolation(v.spec.isolation)
            ));
            Ok(Exit::Ok)
        }
        _ => {
            let why = s
                .last_error
                .as_ref()
                .map_or_default(|f| format!("：{}", f.message.zh_tw));
            ctx.out.line(format!(
                "已送出{}「{name}」，目前{}{why}",
                verb(action),
                run_state(s.state)
            ));
            Ok(if s.state == AppRunState::Failed {
                Exit::Failed
            } else {
                Exit::Ok
            })
        }
    }
}
