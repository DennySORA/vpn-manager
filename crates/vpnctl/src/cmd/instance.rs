//! `vpnctl instance list|inspect|start|stop|restart|clear-emergency` and `vpnctl emergency-stop`.
//! Lifecycle commands go through the same API as the web UI: an intent recorded by the Instance
//! Manager, never a worker driven directly.

use std::time::Duration;

use clap::Subcommand;
use hyper::Method;
use vpn_domain::{
    Accepted, DesiredState, Enforcement, GatewayState, InstanceId, InstanceStatus, InstanceView,
    LifecycleAction, LifecycleRequest, Operation, Persistence, Phase,
};

use super::{CmdResult, Ctx, Exit, Failure, instance, instances};
use crate::client::Mutation;
use crate::output::{
    Out, bytes, cap, gateway_kind, instance_state, opt_time, phase_label, recovery_help,
    recovery_lines, resources, table, time,
};

#[derive(Subcommand, Debug)]
pub enum InstanceCmd {
    /// 列出所有連線
    List,
    /// 一條連線的狀態與證據
    Inspect {
        /// 名稱、ID 或 ID 開頭
        instance: String,
    },
    /// 啟動（之後服務重新啟動也會自動恢復）
    Start {
        instance: String,
        /// 送出後不等待連線結果
        #[arg(long)]
        no_wait: bool,
    },
    /// 停止：立即封鎖並停止，停止意圖寫入磁碟
    Stop { instance: String },
    /// 重新啟動（套用尚未生效的設定）
    Restart {
        instance: String,
        #[arg(long)]
        no_wait: bool,
    },
    /// 解除急停（連線維持停止，之後再啟動）
    ClearEmergency { instance: String },
}

/// How long `start` and `restart` wait to see where the connection ends up.
const SETTLE_WAIT: Duration = Duration::from_secs(20);

pub async fn run(ctx: &Ctx, cmd: InstanceCmd) -> CmdResult {
    match cmd {
        InstanceCmd::List => list(ctx).await,
        InstanceCmd::Inspect { instance: q } => inspect(ctx, &q).await,
        InstanceCmd::Start {
            instance: q,
            no_wait,
        } => lifecycle(ctx, &q, LifecycleAction::Start, !no_wait).await,
        InstanceCmd::Restart {
            instance: q,
            no_wait,
        } => lifecycle(ctx, &q, LifecycleAction::Restart, !no_wait).await,
        InstanceCmd::Stop { instance: q } => lifecycle(ctx, &q, LifecycleAction::Stop, false).await,
        InstanceCmd::ClearEmergency { instance: q } => {
            lifecycle(ctx, &q, LifecycleAction::ClearEmergency, false).await
        }
    }
}

async fn list(ctx: &Ctx) -> CmdResult {
    let list = instances(ctx).await?;
    if ctx.out.json {
        ctx.out.json(&list);
    } else if list.is_empty() {
        ctx.out.line("還沒有任何連線。");
    } else {
        ctx.out.line(table(
            &super::status::INSTANCE_HEADERS,
            &super::status::instance_rows(&list),
        ));
        for l in recovery_lines(&list) {
            ctx.out.line(l);
        }
    }
    Ok(Exit::Ok)
}

const fn yes_no(b: bool) -> &'static str {
    if b { "是" } else { "否" }
}

const fn persistence(p: Persistence) -> &'static str {
    match p {
        Persistence::Durable => "已寫入磁碟",
        Persistence::Pending => "尚未寫入磁碟（重試中）",
        Persistence::Unavailable => "無法讀取",
    }
}

const fn enforcement(e: Enforcement) -> &'static str {
    match e {
        Enforcement::TunnelOnly => "只經 tunnel",
        Enforcement::Blocked => "已封鎖",
        Enforcement::Unknown => "未知",
    }
}

const fn gateway_state(s: GatewayState) -> &'static str {
    match s {
        GatewayState::Serving => "服務中",
        GatewayState::Blocked => "拒絕連線",
        GatewayState::Inactive => "未啟用",
        GatewayState::Failed => "無法啟用",
    }
}

async fn inspect(ctx: &Ctx, q: &str) -> CmdResult {
    let v = instance(ctx, q).await?;
    if ctx.out.json {
        ctx.out.json(&v);
        return Ok(Exit::Ok);
    }
    let out = &ctx.out;
    out.line(format!("{}（{}）", v.spec.name, v.spec.id));
    let Some(s) = &v.status else {
        out.line("狀態：未知（manager 沒有回報）");
        return Ok(Exit::Failed);
    };
    out.line(format!(
        "狀態：{}（{}），觀測於 {}",
        instance_state(&v),
        enforcement(s.enforcement),
        time(&s.observed_at)
    ));
    out.line(format!(
        "意圖：{}；人工停止 {}；急停 {}；{}",
        match s.intent.desired {
            DesiredState::Running => "執行",
            DesiredState::Stopped => "停止",
        },
        yes_no(s.intent.manual_stop),
        yes_no(s.intent.emergency_latched),
        // Held for the user: nothing retries that write, the user's decision ends it.
        if s.phase == Phase::RecoveryRequired && s.intent.persistence == Persistence::Pending {
            "尚未寫入磁碟（等你確認）"
        } else {
            persistence(s.intent.persistence)
        }
    ));
    if let Some(p) = &v.profile {
        out.line(format!(
            "WireGuard：{}（端點 {}{}）",
            p.name,
            p.endpoint,
            if p.ipv6 {
                "，已設定 IPv6 位址"
            } else {
                ""
            }
        ));
    }
    if let Some(r) = &s.running {
        out.line(format!(
            "執行中：第 {} 代，pid {}，啟動於 {}，就緒於 {}",
            r.generation,
            r.pid.map_or_else(|| "—".into(), |p| p.to_string()),
            time(&r.started_at),
            opt_time(r.ready_at.as_ref())
        ));
        if !r.pending_changes.is_empty() {
            out.line("已儲存但尚未套用的變更：重新啟動後生效");
        }
        if let Some(res) = &r.resources {
            for line in resources(res) {
                out.line(format!("worker 資源：{line}"));
            }
        }
    }
    // The caps the running worker confirmed; otherwise what is saved.
    let saved = &v.spec.limits;
    match s.running.as_ref().and_then(|r| r.bandwidth) {
        Some(applied) => out.line(format!(
            "頻寬上限：下載 {}、上傳 {}（worker 已套用）",
            cap(applied.download_bps),
            cap(applied.upload_bps)
        )),
        None => out.line(format!(
            "頻寬上限：下載 {}、上傳 {}（已儲存）",
            cap(saved.download_bps),
            cap(saved.upload_bps)
        )),
    }
    if let Some(t) = s.running.as_ref().and_then(|r| r.transport.as_ref()) {
        out.line(transport_line(t));
    }
    tunnel_lines(*out, &v, s);
    if let Some(f) = &s.recovery.last_fault {
        out.line(format!(
            "最近的錯誤：{}（{}，{}）",
            f.message.zh_tw,
            f.code,
            time(&f.at)
        ));
    }
    if let Some((_, how)) = recovery_help(&v) {
        out.line(format!("處理方式：{how}"));
    }
    if s.recovery.attempt > 0 {
        out.line(format!(
            "自動重試：第 {} 次，下次 {}",
            s.recovery.attempt,
            opt_time(s.recovery.next_retry_at.as_ref())
        ));
    }
    Ok(Exit::Ok)
}

/// The transport line of `inspect`: the profile, the set new connections take and why.
fn transport_line(t: &vpn_domain::TransportStatus) -> String {
    let rtt = t.rtt_ms.map_or_else(
        || "尚未量到往返時間".to_string(),
        |ms| format!("往返 {ms} 毫秒"),
    );
    let now = if t.automatic {
        format!("{}，目前套用「{}」（{rtt}）", t.profile.zh_tw, t.band.zh_tw)
    } else {
        format!("{}（{rtt}）", t.profile.zh_tw)
    };
    let size = super::transport::size;
    let mut parts = vec![format!(
        "傳輸設定：{now}；新連線送出最多 {}、接收最多 {}",
        size(t.flow.tcp_send_kib),
        size(t.flow.tcp_recv_kib)
    )];
    if t.buffers_grown > 0 {
        parts.push(format!("已放大緩衝 {} 次", t.buffers_grown));
    }
    if t.growth_refused > 0 {
        parts.push(format!("{} 次因連線緩衝預算不足沒有放大", t.growth_refused));
    }
    if let Some(k) = t.kernel_limits {
        parts.push(format!(
            "沙箱的核心 TCP 緩衝上限：接收 {}、送出 {}",
            size(k.recv_kib),
            size(k.send_kib)
        ));
    }
    parts.extend(congestion_now(t));
    parts.join("；")
}

/// The congestion control the connection's own TCP connections use, next to the one its profile
/// asks for: nothing while both are the default, the reason when they differ.
fn congestion_now(t: &vpn_domain::TransportStatus) -> Option<String> {
    use vpn_domain::{CongestionControl, CongestionFallback};
    let label = |name: &str| match name {
        "cubic" => "Cubic".to_owned(),
        "reno" => "Reno".to_owned(),
        "bbr" => "BBR".to_owned(),
        other => other.to_owned(),
    };
    let asked = match t.flow.congestion {
        CongestionControl::Cubic => "Cubic",
        CongestionControl::Reno => "Reno",
        CongestionControl::Bbr => "BBR",
    };
    let Some(now) = &t.congestion else {
        return (t.flow.congestion != CongestionControl::Cubic)
            .then(|| format!("壅塞控制：要求 {asked}，連線還沒有開過自己的 TCP 連線，尚未確認"));
    };
    match now.fallback {
        None => (now.in_use != "cubic").then(|| {
            format!(
                "壅塞控制：{} 已生效（只及於連線自己開的 TCP 連線，嚴格隔離 App 自己開的不在內）",
                label(&now.in_use)
            )
        }),
        Some(CongestionFallback::UserspaceStack) => Some(format!(
            "壅塞控制：要求 {asked}，實際是 {}（使用者態 TCP 沒有 BBR，開啟嚴格隔離才用得到）",
            label(&now.in_use)
        )),
        Some(CongestionFallback::KernelRefused) => Some(format!(
            "壅塞控制：要求 {asked}，實際是 {}（核心沒有給非特權程式用：模組沒載入，或不在 net.ipv4.tcp_allowed_congestion_control 裡）",
            label(&now.in_use)
        )),
    }
}

/// The tunnel, DNS and proxy-port lines of `inspect`.
fn tunnel_lines(out: Out, v: &InstanceView, s: &InstanceStatus) {
    if let Some(t) = &s.tunnel {
        out.line(format!(
            "tunnel：最後握手 {}；WireGuard 收 {}／送 {}",
            opt_time(t.last_handshake_at.as_ref()),
            bytes(t.wg_rx_bytes.0),
            bytes(t.wg_tx_bytes.0)
        ));
    }
    if let Some(d) = &s.dns {
        let health = if d.interrupted.is_some() {
            "已中斷：DNS 設定的伺服器都沒有回應，依設定不改問其他 DNS，名稱無法解析"
        } else if d.fallback.is_some() {
            "暫時改用 WireGuard 設定的 DNS：DNS 設定的伺服器都沒有回應"
        } else {
            match d.healthy {
                Some(true) => "探測通過",
                Some(false) => "探測失敗",
                None => "未知",
            }
        };
        // A failure says why (with the interruption's reason in it); otherwise the reason the
        // profile's servers failed.
        let why = d
            .last_error
            .as_ref()
            .or(d.interrupted.as_ref())
            .or(d.fallback.as_ref());
        out.line(format!(
            "DNS：{health}，最後探測 {}{}",
            opt_time(d.last_probe_at.as_ref()),
            why.map_or_default(|e| format!("（{}）", e.zh_tw))
        ));
    }
    if !v.gateways.is_empty() {
        let rows: Vec<Vec<String>> = v
            .gateways
            .iter()
            .map(|g| {
                let rt = s.gateways.iter().find(|r| r.gateway_id == g.id);
                vec![
                    g.name.clone(),
                    g.port.to_string(),
                    gateway_kind(g.kind).to_string(),
                    match (g.enabled, rt) {
                        (false, _) => "停用".to_string(),
                        (true, Some(r)) => gateway_state(r.state).to_string(),
                        (true, None) => "—".to_string(),
                    },
                    rt.map_or_else(
                        || "—".into(),
                        |r| format!("TCP {} / UDP {}", r.active_tcp, r.active_udp),
                    ),
                ]
            })
            .collect();
        out.line("代理埠：");
        for l in table(&["名稱", "埠", "協定", "狀態", "連線"], &rows).lines() {
            out.line(format!("  {l}"));
        }
    }
}

const fn verb(a: LifecycleAction) -> &'static str {
    match a {
        LifecycleAction::Start => "啟動",
        LifecycleAction::Stop => "停止",
        LifecycleAction::Restart => "重新啟動",
        LifecycleAction::ClearEmergency => "解除急停",
    }
}

/// Report a stop's evidence: closed, and the latch on disk.
fn stopped(ctx: &Ctx, name: &str, emergency: bool, a: &Accepted) -> Exit {
    let what = if emergency { "急停" } else { "停止" };
    match (a.sealed, a.durable) {
        (Some(true), Some(true)) => {
            ctx.out.line(format!(
                "已{what}「{name}」：資料路徑已封閉，停止意圖已寫入磁碟。"
            ));
            Exit::Ok
        }
        (Some(true), _) => {
            ctx.out.line(format!(
                "已{what}「{name}」：資料路徑已封閉；停止意圖尚未寫入磁碟，manager 會持續重試。"
            ));
            Exit::Ok
        }
        _ => {
            ctx.out.line(format!(
                "已送出{what}「{name}」，但還沒有收到封閉的證據；請用 vpnctl instance inspect 確認。"
            ));
            Exit::Unknown
        }
    }
}

/// The evidence a lost answer would have carried, read again from the Instance itself after
/// the operation lookup said the request was carried out: for a stop, whether the data path is
/// closed and the stop (or latch) is on disk; for clear-emergency, whether the latch is gone.
/// None (exit 3) when that cannot be established now.
async fn recovered(
    ctx: &Ctx,
    name: &str,
    id: InstanceId,
    op: Operation,
    what: Recovered,
) -> Result<Option<Accepted>, Failure> {
    ctx.out.line(format!(
        "沒有收到回應；紀錄顯示這個請求已完成（operation {}），以下是重新讀取的「{name}」狀態。",
        op.id
    ));
    // Some(emergency) for a stop; None for clear-emergency.
    let stop = match what {
        // Start and restart: where it ends up is read below, as after a normal answer.
        Recovered::Started => {
            return Ok(Some(Accepted {
                operation: op,
                sealed: None,
                durable: None,
            }));
        }
        Recovered::Stopped { emergency } => Some(emergency),
        Recovered::Cleared => None,
    };
    let v = match settle(ctx, id).await {
        Ok(v) => v,
        Err(e) => {
            ctx.out
                .json(&serde_json::json!({ "operation": op, "error": e.to_json() }));
            ctx.out
                .line(format!("無法重新讀取連線狀態：{}", e.to_text()));
            return Ok(None);
        }
    };
    let Some(s) = &v.status else {
        ctx.out
            .json(&serde_json::json!({ "operation": op, "instance": v }));
        ctx.out
            .line("無法重新讀取連線狀態（manager 沒有回應），不能確認結果。");
        return Ok(None);
    };
    let durable = s.intent.persistence == Persistence::Durable;
    match stop {
        Some(emergency) => {
            let sealed = s.enforcement == Enforcement::Blocked;
            let latched = !emergency || s.intent.emergency_latched;
            Ok(Some(Accepted {
                operation: op,
                sealed: Some(sealed),
                durable: Some(durable && s.intent.desired == DesiredState::Stopped && latched),
            }))
        }
        None if !s.intent.emergency_latched && durable => Ok(Some(Accepted {
            operation: op,
            sealed: None,
            durable: Some(true),
        })),
        None => {
            ctx.out
                .json(&serde_json::json!({ "operation": op, "instance": v }));
            ctx.out.line(if s.intent.emergency_latched {
                "紀錄顯示已解除，但連線現在仍是急停狀態（可能又被急停了）；請用 vpnctl instance inspect 確認。"
            } else {
                "急停已解除，但這個變更還沒有寫入磁碟；請用 vpnctl instance inspect 確認。"
            });
            Ok(None)
        }
    }
}

/// What a recovered answer must be checked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovered {
    Started,
    Stopped { emergency: bool },
    Cleared,
}

impl Recovered {
    const fn of(action: LifecycleAction) -> Self {
        match action {
            LifecycleAction::Start | LifecycleAction::Restart => Self::Started,
            LifecycleAction::Stop => Self::Stopped { emergency: false },
            LifecycleAction::ClearEmergency => Self::Cleared,
        }
    }
}

/// Wait (bounded) until the Instance is no longer on its way somewhere.
async fn settle(ctx: &Ctx, id: InstanceId) -> Result<InstanceView, Failure> {
    let deadline = tokio::time::Instant::now() + SETTLE_WAIT;
    loop {
        let v: InstanceView = ctx.client.get(&format!("/v1/instances/{id}")).await?;
        let settled = v.status.as_ref().is_none_or(|s| {
            matches!(
                s.phase,
                Phase::Ready | Phase::Failed | Phase::Stopped | Phase::RecoveryRequired
            )
        });
        if settled || tokio::time::Instant::now() >= deadline {
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn lifecycle(ctx: &Ctx, q: &str, action: LifecycleAction, wait: bool) -> CmdResult {
    let v = instance(ctx, q).await?;
    let id = v.spec.id;
    let body = LifecycleRequest { action };
    let done: Mutation<Accepted> = ctx
        .client
        .mutate(
            Method::POST,
            &format!("/v1/instances/{id}/actions"),
            Some(&body),
            None,
        )
        .await?;
    after(ctx, &v.spec.name, id, action, done, wait).await
}

async fn after(
    ctx: &Ctx,
    name: &str,
    id: InstanceId,
    action: LifecycleAction,
    done: Mutation<Accepted>,
    wait: bool,
) -> CmdResult {
    let accepted = match done {
        Mutation::Done(Some(a)) => a,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        // The same evidence as an answer would carry, read again; unknown when it cannot be.
        Mutation::Recovered(op) => {
            match recovered(ctx, name, id, *op, Recovered::of(action)).await? {
                Some(a) => a,
                None => return Ok(Exit::Unknown),
            }
        }
    };
    if action == LifecycleAction::Stop {
        ctx.out.json(&accepted);
        return Ok(stopped(ctx, name, false, &accepted));
    }
    if action == LifecycleAction::ClearEmergency {
        ctx.out.json(&accepted);
        ctx.out.line(format!(
            "已解除「{name}」的急停；連線維持停止，需要時再用 vpnctl instance start 啟動。"
        ));
        return Ok(Exit::Ok);
    }
    if !wait {
        ctx.out.json(&accepted);
        ctx.out.line(format!(
            "已送出{}「{name}」（operation {}）。",
            verb(action),
            accepted.operation.id
        ));
        return Ok(Exit::Ok);
    }
    let v = settle(ctx, id).await?;
    ctx.out
        .json(&serde_json::json!({ "accepted": accepted, "instance": v }));
    let Some(s) = &v.status else {
        ctx.out
            .line(format!("已{}「{name}」；目前狀態未知。", verb(action)));
        return Ok(Exit::Ok);
    };
    let state = phase_label(s.phase);
    match s.phase {
        Phase::Failed | Phase::RecoveryRequired => {
            let why = s
                .recovery
                .last_fault
                .as_ref()
                .map_or_default(|f| format!("：{}", f.message.zh_tw));
            ctx.out
                .line(format!("已{}「{name}」，但連線{state}{why}", verb(action)));
            Ok(Exit::Failed)
        }
        Phase::Ready | Phase::Stopped => {
            ctx.out
                .line(format!("已{}「{name}」：{state}。", verb(action)));
            Ok(Exit::Ok)
        }
        _ => {
            ctx.out.line(format!(
                "已{}「{name}」：{} 秒內仍是「{state}」，連線會繼續嘗試。",
                verb(action),
                SETTLE_WAIT.as_secs()
            ));
            Ok(Exit::Ok)
        }
    }
}

/// `vpnctl emergency-stop <instance>`: close at once and latch; only `clear-emergency` lifts it.
pub async fn emergency_stop(ctx: &Ctx, q: &str) -> CmdResult {
    let v = instance(ctx, q).await?;
    let id = v.spec.id;
    let done: Mutation<Accepted> = ctx
        .client
        .mutate(
            Method::POST,
            &format!("/v1/instances/{id}/emergency-stop"),
            Some(&serde_json::json!({})),
            None,
        )
        .await?;
    let accepted = match done {
        Mutation::Done(Some(a)) => a,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        // The same evidence as an answer would carry, read again; unknown when it cannot be.
        Mutation::Recovered(op) => {
            let what = Recovered::Stopped { emergency: true };
            match recovered(ctx, &v.spec.name, id, *op, what).await? {
                Some(a) => a,
                None => return Ok(Exit::Unknown),
            }
        }
    };
    ctx.out.json(&accepted);
    Ok(stopped(ctx, &v.spec.name, true, &accepted))
}
