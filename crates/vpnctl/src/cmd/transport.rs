//! `vpnctl transport list|show|use`: the transport profiles a connection can use — the ones
//! that are part of the program and the ones saved in the web UI — and which one a connection
//! uses. Saved profiles are created and changed in the web UI.

use clap::Subcommand;
use hyper::Method;
use vpn_domain::{
    BuiltinTransport, CongestionControl, FlowSettings, HealthSettings, InstanceInput, InstanceView,
    TransportProfile, TransportRef, TransportSettings,
};

use super::{CmdResult, Ctx, Exit, Failure, instance};
use crate::client::Mutation;
use crate::output::table;

#[derive(Subcommand, Debug)]
pub enum TransportCmd {
    /// 列出內建與自訂的傳輸設定
    List,
    /// 一個傳輸設定的所有數值
    Show {
        /// 內建設定的代號（auto、balanced…）、名稱、ID 或 ID 開頭
        profile: String,
    },
    /// 讓連線改用一個傳輸設定：立即套用到之後建立的連線，不需要重新啟動
    Use {
        /// 連線的名稱、ID 或 ID 開頭
        instance: String,
        /// 內建設定的代號（auto、balanced…）、名稱、ID 或 ID 開頭
        profile: String,
    },
}

pub async fn run(ctx: &Ctx, cmd: TransportCmd) -> CmdResult {
    match cmd {
        TransportCmd::List => list(ctx).await,
        TransportCmd::Show { profile } => show(ctx, &profile).await,
        TransportCmd::Use { instance, profile } => use_profile(ctx, &instance, &profile).await,
    }
}

/// A profile a connection can use, wherever it lives.
struct Listed {
    reference: TransportRef,
    /// What names it on the command line besides its name: a built-in's key, a saved one's id.
    handle: String,
    name: String,
    builtin: bool,
    summary: Option<String>,
    health: HealthSettings,
    settings: TransportSettings,
}

/// Every profile: the built-in ones first, as the program lists them, then the saved ones.
async fn all(ctx: &Ctx) -> Result<Vec<Listed>, Failure> {
    let builtin: Vec<BuiltinTransport> = ctx.client.get("/v1/transport-profiles/builtin").await?;
    let saved: Vec<TransportProfile> = ctx.client.get("/v1/transport-profiles").await?;
    Ok(builtin
        .into_iter()
        .map(|b| Listed {
            reference: TransportRef::Builtin { key: b.key.clone() },
            handle: b.key,
            name: b.name.zh_tw.clone(),
            builtin: true,
            summary: Some(b.summary.zh_tw.clone()),
            health: b.health,
            settings: b.settings,
        })
        .chain(saved.into_iter().map(|p| Listed {
            reference: TransportRef::Profile { id: p.id },
            handle: p.id.to_string(),
            name: p.name,
            builtin: false,
            summary: None,
            health: p.health,
            settings: p.settings,
        }))
        .collect())
}

/// The profile `query` names: a built-in key, else a unique name, id or id prefix.
fn pick<'a>(profiles: &'a [Listed], query: &str) -> Result<&'a Listed, Failure> {
    crate::resolve::pick(
        profiles,
        query,
        "傳輸設定",
        |p| p.handle.clone(),
        |p| p.name.clone(),
    )
}

const fn congestion(c: CongestionControl) -> &'static str {
    match c {
        CongestionControl::Cubic => "Cubic",
        CongestionControl::Reno => "Reno",
        CongestionControl::Bbr => "BBR（嚴格隔離且核心支援時；否則 Cubic）",
    }
}

/// A size given in KiB, in MiB when it is a whole number of them: "256 KiB", "4 MiB".
pub fn size(kib: u32) -> String {
    if kib >= 1024 && kib.is_multiple_of(1024) {
        format!("{} MiB", kib / 1024)
    } else {
        format!("{kib} KiB")
    }
}

/// A buffer's opening and upper size: one number when they are the same.
fn buffer(start_kib: u32, upper_kib: u32) -> String {
    if start_kib >= upper_kib {
        size(upper_kib)
    } else {
        format!("{} 起、最多 {}", size(start_kib), size(upper_kib))
    }
}

/// A fixed profile's values in one line.
fn flow_line(f: &FlowSettings) -> String {
    format!(
        "送出 {}；接收 {}；UDP {}；{}；連線逾時 {} 秒；keepalive {} 秒；無回應 {} 秒中止",
        buffer(f.tcp_send_start_kib, f.tcp_send_kib),
        buffer(f.tcp_recv_start_kib, f.tcp_recv_kib),
        size(f.udp_buffer_kib),
        congestion(f.congestion),
        f.connect_timeout_secs,
        f.keepalive_secs,
        f.dead_peer_secs,
    )
}

/// How the profiles' names read where one names another.
fn name_of(profiles: &[Listed], reference: &TransportRef) -> String {
    profiles
        .iter()
        .find(|p| &p.reference == reference)
        .map_or_else(|| "（已不存在）".to_string(), |p| p.name.clone())
}

/// What a profile holds, in one line for the list.
fn brief(profiles: &[Listed], p: &Listed) -> String {
    match &p.settings {
        TransportSettings::Fixed { flow } => format!(
            "送出最多 {}、接收最多 {}",
            size(flow.tcp_send_kib),
            size(flow.tcp_recv_kib)
        ),
        TransportSettings::Auto { bands } => bands
            .iter()
            .map(|b| {
                format!(
                    "{} 毫秒起「{}」",
                    b.from_rtt_ms,
                    name_of(profiles, &b.profile)
                )
            })
            .collect::<Vec<_>>()
            .join("、"),
    }
}

async fn list(ctx: &Ctx) -> CmdResult {
    if ctx.out.json {
        let builtin: Vec<BuiltinTransport> =
            ctx.client.get("/v1/transport-profiles/builtin").await?;
        let saved: Vec<TransportProfile> = ctx.client.get("/v1/transport-profiles").await?;
        ctx.out
            .json(&serde_json::json!({ "builtin": builtin, "saved": saved }));
        return Ok(Exit::Ok);
    }
    let profiles = all(ctx).await?;
    let rows: Vec<Vec<String>> = profiles
        .iter()
        .map(|p| {
            vec![
                if p.builtin {
                    p.handle.clone()
                } else {
                    crate::output::short(&p.handle)
                },
                p.name.clone(),
                if p.builtin { "內建" } else { "自訂" }.to_string(),
                match p.settings {
                    TransportSettings::Fixed { .. } => "固定",
                    TransportSettings::Auto { .. } => "自動",
                }
                .to_string(),
                brief(&profiles, p),
            ]
        })
        .collect();
    ctx.out
        .line(table(&["代號／ID", "名稱", "來源", "類型", "內容"], &rows));
    Ok(Exit::Ok)
}

async fn show(ctx: &Ctx, query: &str) -> CmdResult {
    let profiles = all(ctx).await?;
    let p = pick(&profiles, query)?;
    ctx.out.json(&serde_json::json!({
        "reference": p.reference,
        "name": p.name,
        "health": p.health,
        "settings": p.settings,
    }));
    ctx.out.line(format!(
        "{}（{}，{}）",
        p.name,
        if p.builtin { "內建" } else { "自訂" },
        p.handle
    ));
    if let Some(summary) = &p.summary {
        ctx.out.line(summary);
    }
    match &p.settings {
        TransportSettings::Fixed { flow } => {
            ctx.out.line(format!("每條連線：{}", flow_line(flow)));
            ctx.out.line(format!(
                "其他：Nagle {}、延遲 ACK {} 毫秒",
                if flow.nagle { "開" } else { "關" },
                flow.ack_delay_ms
            ));
        }
        TransportSettings::Auto { bands } => {
            ctx.out
                .line("依量到的往返時間選用（只影響之後建立的連線）：");
            for band in bands {
                ctx.out.line(format!(
                    "  {} 毫秒起：{}",
                    band.from_rtt_ms,
                    name_of(&profiles, &band.profile)
                ));
            }
        }
    }
    ctx.out.line(format!(
        "健康探測：每 {} 秒一次，連續失敗 {} 次停止接受新連線，握手逾時 {} 秒",
        p.health.probe_interval_secs, p.health.probe_failures, p.health.handshake_timeout_secs
    ));
    Ok(Exit::Ok)
}

async fn use_profile(ctx: &Ctx, instance_query: &str, profile_query: &str) -> CmdResult {
    let profiles = all(ctx).await?;
    let p = pick(&profiles, profile_query)?;
    let v = instance(ctx, instance_query).await?;
    if v.spec.transport == p.reference {
        ctx.out.json(&v);
        ctx.out.line(format!(
            "連線「{}」已經使用傳輸設定「{}」。",
            v.spec.name, p.name
        ));
        return Ok(Exit::Ok);
    }
    // Everything else stays as saved: the limits and strict mode are left out (unchanged).
    let input = InstanceInput {
        name: v.spec.name.clone(),
        profile_id: v.spec.profile_id,
        dns_profile_id: v.spec.dns_profile_id,
        security_profile_id: v.spec.security_profile_id,
        limits: None,
        strict: None,
        transport: Some(p.reference.clone()),
    };
    let done: Mutation<InstanceView> = ctx
        .client
        .mutate(
            Method::PUT,
            &format!("/v1/instances/{}", v.spec.id),
            Some(&input),
            Some(v.spec.meta.revision),
        )
        .await?;
    match done {
        Mutation::Done(Some(view)) => ctx.out.json(&view),
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => ctx.out.json(&op),
    }
    ctx.out.line(format!(
        "連線「{}」改用傳輸設定「{}」：之後建立的連線立即套用，已經建立的連線維持原樣。",
        v.spec.name, p.name
    ));
    Ok(Exit::Ok)
}
