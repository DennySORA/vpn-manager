//! `vpnctl forward list|status|enable|disable|proxy-protocol|udp-direct`: port forwards through
//! the same API as the web UI. Creating and editing one (with the provider's steps and the App's
//! port) stays in the web UI; enable/disable, proxy-protocol and udp-direct save the forward with
//! only that one setting changed (If-Match on its revision) — udp-direct `on --add-udp` also lets
//! a TCP-only forward carry UDP, in the same save.

use clap::{Subcommand, ValueEnum};
use hyper::Method;
use vpn_domain::{
    AppView, ForwardBinding, ForwardInput, ForwardProtocol, ForwardReachability, ForwardState,
    ForwardView, InstanceView, Reachability,
};

use super::{CmdResult, Ctx, Exit, Failure, instances};
use crate::client::Mutation;
use crate::output::{bytes, opt_time, table, time};

#[derive(Subcommand, Debug)]
pub enum ForwardCmd {
    /// 列出所有轉發
    List,
    /// 一個轉發的狀態：目標、租約、計數與外部可達證據
    Status {
        /// 名稱、ID 或 ID 開頭
        forward: String,
    },
    /// 啟用（連線執行中且目標 App 持有該 port 時開始監聽）
    Enable { forward: String },
    /// 停用（立即停止監聽並結束它的連線）
    Disable { forward: String },
    /// 把來源位址傳給 App：每條轉入的 TCP 連線開頭先送一個 PROXY protocol v2 標頭（App 必須支援，否則連線會失敗；UDP 不受影響）
    #[command(after_help = "例：vpnctl forward proxy-protocol eD2k on
改變時這個轉發的既有連線會結束，之後的連線依新的設定。")]
    ProxyProtocol {
        /// 名稱、ID 或 ID 開頭
        forward: String,
        #[arg(value_enum)]
        state: Switch,
    },
    /// UDP 直接送進沙箱：轉入的 UDP 原樣送到嚴格隔離 App 自己在 tunnel port 的 socket（App 看到真正的來源位址，例如 eMule 的 Kad、BitTorrent 的 DHT）；只用於嚴格隔離的連線與 App
    #[command(after_help = "例：vpnctl forward udp-direct eD2k on --add-udp
App 要在所有位址（0.0.0.0）或 tunnel 位址接收 UDP 的 tunnel port，App 的 port 必須等於 tunnel port。
TCP 照常經本機位址轉送。改變時這個轉發的既有連線會結束，之後的連線依新的設定。")]
    UdpDirect {
        /// 名稱、ID 或 ID 開頭
        forward: String,
        #[arg(value_enum)]
        state: Switch,
        /// 只轉發 TCP 的轉發同時開始轉發 UDP（協定改為 TCP＋UDP，在同一次儲存）
        #[arg(long)]
        add_udp: bool,
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

pub async fn run(ctx: &Ctx, cmd: ForwardCmd) -> CmdResult {
    match cmd {
        ForwardCmd::List => list(ctx).await,
        ForwardCmd::Status { forward } => status(ctx, &forward).await,
        ForwardCmd::Enable { forward } => set_enabled(ctx, &forward, true).await,
        ForwardCmd::Disable { forward } => set_enabled(ctx, &forward, false).await,
        ForwardCmd::ProxyProtocol { forward, state } => {
            set_proxy_protocol(ctx, &forward, state == Switch::On).await
        }
        ForwardCmd::UdpDirect {
            forward,
            state,
            add_udp,
        } => set_udp_direct(ctx, &forward, state == Switch::On, add_udp).await,
    }
}

async fn forwards(ctx: &Ctx) -> Result<Vec<ForwardView>, Failure> {
    ctx.client.get("/v1/forward-bindings").await
}

/// The forward a command names (unique name, id or id prefix).
async fn forward(ctx: &Ctx, query: &str) -> Result<ForwardView, Failure> {
    let all = forwards(ctx).await?;
    crate::resolve::pick(
        &all,
        query,
        "轉發",
        |v| v.binding.id.to_string(),
        |v| v.binding.name.clone(),
    )
    .cloned()
}

const fn protocol(p: ForwardProtocol) -> &'static str {
    match p {
        ForwardProtocol::Tcp => "TCP",
        ForwardProtocol::Udp => "UDP",
        ForwardProtocol::Both => "TCP＋UDP",
    }
}

/// What the App learns about who connected.
const fn source(b: &ForwardBinding) -> &'static str {
    if b.proxy_protocol {
        "以 PROXY protocol v2 傳給 App（每條 TCP 連線開頭；App 必須支援）"
    } else {
        "不傳給 App（App 看到的來源都是本機位址）"
    }
}

/// Where the forward's UDP goes, for a forward that carries UDP.
fn udp_path(b: &ForwardBinding) -> Option<&'static str> {
    b.protocol.udp().then_some(if b.udp_direct {
        "直接送進沙箱（App 自己在 tunnel port 的 socket 收到真正的來源位址）"
    } else {
        "由 worker 從本機位址轉送（App 看到的來源都是本機位址）"
    })
}

const fn state(s: ForwardState) -> &'static str {
    match s {
        ForwardState::Disabled => "已停用",
        ForwardState::ConnectionNotReady => "連線未就緒",
        ForwardState::TargetMissing => "目標未監聽",
        ForwardState::TargetNotOwned => "目標不是 App",
        ForwardState::Listening => "監聽中",
    }
}

fn reach(r: &ForwardReachability) -> String {
    match r.state {
        Reachability::Unverified => "未驗證".into(),
        Reachability::Observed => {
            let latest = [r.tcp_observed_at, r.udp_observed_at]
                .into_iter()
                .flatten()
                .max_by_key(|t| t.0);
            format!("已觀測（{}）", opt_time(latest.as_ref()))
        }
    }
}

async fn list(ctx: &Ctx) -> CmdResult {
    let list = forwards(ctx).await?;
    if ctx.out.json {
        ctx.out.json(&list);
        return Ok(Exit::Ok);
    }
    if list.is_empty() {
        ctx.out.line("還沒有任何轉發。");
        return Ok(Exit::Ok);
    }
    let owners: Vec<InstanceView> = instances(ctx).await.unwrap_or_default();
    let apps: Vec<AppView> = ctx.client.get("/v1/apps").await.unwrap_or_default();
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|v| {
            let b = &v.binding;
            let app = apps
                .iter()
                .find(|a| a.spec.id == b.target_app_id)
                .map_or_else(|| "—".to_string(), |a| a.spec.name.clone());
            vec![
                b.name.clone(),
                format!("{} {}", protocol(b.protocol), b.tunnel_port),
                format!("{app}：{}", b.target_port),
                owners
                    .iter()
                    .find(|o| o.spec.id == b.instance_id)
                    .map_or_else(|| "—".to_string(), |o| o.spec.name.clone()),
                v.status
                    .as_ref()
                    .map_or("未知", |s| state(s.state))
                    .to_string(),
                v.status
                    .as_ref()
                    .map_or_else(|| "—".to_string(), |s| reach(&s.reachability)),
            ]
        })
        .collect();
    ctx.out.line(table(
        &["名稱", "tunnel port", "目標", "連線", "狀態", "外部可達"],
        &rows,
    ));
    Ok(Exit::Ok)
}

async fn status(ctx: &Ctx, q: &str) -> CmdResult {
    let v = forward(ctx, q).await?;
    if ctx.out.json {
        ctx.out.json(&v);
        return Ok(Exit::Ok);
    }
    let out = &ctx.out;
    let b = &v.binding;
    out.line(format!("{}（{}）", b.name, b.id));
    out.line(format!(
        "{} tunnel port {}{} → App port {}；最多 {} 條連線",
        protocol(b.protocol),
        b.tunnel_port,
        b.public_port
            .map_or_default(|p| format!("（供應商公開 port {p}，手動登錄、未核實）")),
        b.target_port,
        b.max_connections
    ));
    out.line(format!("來源位址：{}", source(b)));
    if let Some(path) = udp_path(b) {
        out.line(format!("UDP：{path}"));
    }
    let Some(s) = &v.status else {
        out.line("狀態：未知（manager 沒有回報）");
        return Ok(Exit::Failed);
    };
    out.line(format!(
        "狀態：{}{}，觀測於 {}",
        state(s.state),
        s.reason
            .as_ref()
            .map_or_default(|r| format!("——{}", r.zh_tw)),
        time(&s.observed_at)
    ));
    if let Some(t) = &s.target {
        let addrs: Vec<String> = [t.tcp_address.as_ref(), t.udp_address.as_ref()]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        out.line(format!(
            "目標：{}（pid {}{}），核對於 {}",
            addrs.join("、"),
            t.pid.map_or_else(|| "—".to_string(), |p| p.to_string()),
            if t.wildcard {
                "，App 在所有位址監聽"
            } else {
                ""
            },
            time(&t.verified_at)
        ));
    }
    if let Some(l) = &s.lease {
        out.line(format!(
            "租約：{}（generation {}，{} 起）",
            l.lease_id,
            l.generation,
            time(&l.granted_at)
        ));
    }
    if let Some(c) = &s.counters {
        out.line(format!(
            "連線：已轉送 {}（TCP 進行中 {}、UDP {}）；收 {}、送 {}",
            c.accepted.0,
            c.active_tcp,
            c.active_udp,
            bytes(c.bytes_in.0),
            bytes(c.bytes_out.0)
        ));
        out.line(format!(
            "拒絕：封鎖清單 {}、自動封鎖 {}、上限 {}、未開放 {}、App 未接受 {}",
            c.refused_blocklisted.0,
            c.refused_banned.0 + c.refused_rate_limited.0,
            c.refused_limit.0,
            c.refused_closed.0,
            c.target_failed.0
        ));
    }
    out.line(format!("外部可達：{}", reach(&s.reachability)));
    Ok(Exit::Ok)
}

/// The forward as it is saved: the body of a `PUT` that changes nothing.
fn input_of(b: &ForwardBinding) -> ForwardInput {
    ForwardInput {
        instance_id: b.instance_id,
        name: b.name.clone(),
        protocol: b.protocol,
        tunnel_port: b.tunnel_port,
        public_port: b.public_port,
        target_app_id: b.target_app_id,
        target_port: b.target_port,
        enabled: b.enabled,
        max_connections: b.max_connections,
        proxy_protocol: b.proxy_protocol,
        udp_direct: b.udp_direct,
    }
}

async fn set_enabled(ctx: &Ctx, q: &str, enabled: bool) -> CmdResult {
    let v = forward(ctx, q).await?;
    let b = &v.binding;
    let verb = if enabled { "啟用" } else { "停用" };
    if b.enabled == enabled {
        ctx.out.json(&v);
        ctx.out.line(format!("轉發「{}」已經是{verb}。", b.name));
        return Ok(Exit::Ok);
    }
    let input = ForwardInput {
        enabled,
        ..input_of(b)
    };
    save(ctx, b, &input, &format!("{verb}轉發「{}」", b.name)).await
}

async fn set_proxy_protocol(ctx: &Ctx, q: &str, on: bool) -> CmdResult {
    let v = forward(ctx, q).await?;
    let b = &v.binding;
    let verb = if on { "開啟" } else { "關閉" };
    if b.proxy_protocol == on {
        ctx.out.json(&v);
        ctx.out.line(format!(
            "轉發「{}」的 PROXY protocol 已經是{verb}。",
            b.name
        ));
        return Ok(Exit::Ok);
    }
    let input = ForwardInput {
        proxy_protocol: on,
        ..input_of(b)
    };
    let done = save(
        ctx,
        b,
        &input,
        &format!("{verb}轉發「{}」的 PROXY protocol", b.name),
    )
    .await?;
    ctx.out.line(if on {
        "之後每條轉入的 TCP 連線開頭都有 PROXY protocol v2 標頭；App 必須支援，否則連線會失敗。"
    } else {
        "App 看到的來源回到本機位址；App 若要求 PROXY 標頭，也要在 App 關閉。"
    });
    Ok(done)
}

async fn set_udp_direct(ctx: &Ctx, q: &str, on: bool, add_udp: bool) -> CmdResult {
    if add_udp && !on {
        return Err(Failure::Usage(
            "--add-udp 只和 on 一起用（關閉時協定不變）".into(),
        ));
    }
    let v = forward(ctx, q).await?;
    let b = &v.binding;
    // Never opens a protocol the user did not ask for: a TCP-only forward carries UDP only
    // with --add-udp.
    if on && !b.protocol.udp() && !add_udp {
        return Err(Failure::Usage(format!(
            "轉發「{}」只轉發 TCP；要同時轉發 UDP 並直接送進沙箱，請加上 --add-udp（協定會改為 TCP＋UDP）",
            b.name
        )));
    }
    let protocol = if on && !b.protocol.udp() {
        ForwardProtocol::Both
    } else {
        b.protocol
    };
    let verb = if on { "開啟" } else { "關閉" };
    if b.udp_direct == on && protocol == b.protocol {
        ctx.out.json(&v);
        ctx.out.line(format!(
            "轉發「{}」的 UDP 直接送進沙箱已經是{verb}。",
            b.name
        ));
        return Ok(Exit::Ok);
    }
    let input = ForwardInput {
        protocol,
        udp_direct: on,
        ..input_of(b)
    };
    let what = if protocol == b.protocol {
        format!("{verb}轉發「{}」的 UDP 直接送進沙箱", b.name)
    } else {
        format!("把轉發「{}」改為 TCP＋UDP，並開啟 UDP 直接送進沙箱", b.name)
    };
    let done = save(ctx, b, &input, &what).await?;
    ctx.out.line(if on {
        "之後轉入的 UDP 原樣送到 App 自己在 tunnel port 的 socket：App 看到真正的來源位址並直接回覆。App 要在所有位址（0.0.0.0）或 tunnel 位址接收這個 port；TCP 照常轉送。"
    } else {
        "UDP 改回由 worker 從本機位址轉送：App 要在 127.0.0.1 接收這個 port（嚴格隔離時在所有位址接收會與轉發衝突），否則轉發不會監聽。"
    });
    Ok(done)
}

/// Save `input` over `b` (If-Match on its revision); `what` names the change in the answer.
async fn save(ctx: &Ctx, b: &ForwardBinding, input: &ForwardInput, what: &str) -> CmdResult {
    let done: Mutation<ForwardView> = ctx
        .client
        .mutate(
            Method::PUT,
            &format!("/v1/forward-bindings/{}", b.id),
            Some(input),
            Some(b.meta.revision),
        )
        .await?;
    match done {
        Mutation::Done(Some(view)) => {
            ctx.out.json(&view);
            let now = view.status.as_ref().map_or("未知", |s| state(s.state));
            ctx.out.line(format!("已{what}，目前：{now}。"));
        }
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示{what}已完成（operation {}）。",
                op.id
            ));
        }
    }
    Ok(Exit::Ok)
}
