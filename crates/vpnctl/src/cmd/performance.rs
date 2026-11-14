//! `vpnctl performance summary`: the Performance Manager's passive analysis from the command
//! line. It generates no traffic. Unknown values print as `—` with their reason, never as 0.

use clap::Subcommand;
use vpn_domain::{ByteObservation, NumericObservation, PerformanceOverview, ProcessRole};

use super::{CmdResult, Ctx, Exit};
use crate::output::{bytes, table};

#[derive(Subcommand, Debug)]
pub enum PerformanceCmd {
    /// 被動效能摘要：程序 CPU／記憶體、各連線與代理埠的速率、流量數與瓶頸線索（不產生流量）
    Summary,
}

const fn role_label(r: Option<ProcessRole>) -> &'static str {
    match r {
        None => "產品合計",
        Some(ProcessRole::Manager) => "manager",
        Some(ProcessRole::Controller) => "controller",
        Some(ProcessRole::Worker) => "連線 worker",
    }
}

/// A number with its unit, or `—（原因）`.
fn num(o: &NumericObservation, f: impl Fn(f64) -> String) -> String {
    match (o.value, &o.reason_code) {
        (Some(v), _) => f(v),
        (None, Some(r)) => format!("—（{r}）"),
        (None, None) => "—".into(),
    }
}

fn bps(v: f64) -> String {
    if v >= 1e9 {
        format!("{:.2} Gbit/s", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.1} Mbit/s", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.1} kbit/s", v / 1e3)
    } else {
        format!("{v:.0} bit/s")
    }
}

fn pct(v: f64) -> String {
    format!("{v:.2} %")
}

fn byte_obs(o: &ByteObservation) -> String {
    match (&o.value, &o.reason_code) {
        (Some(v), _) => bytes(v.0),
        (None, Some(r)) => format!("—（{r}）"),
        (None, None) => "—".into(),
    }
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "—".into(), |v| v.to_string())
}

pub async fn run(ctx: &Ctx, cmd: PerformanceCmd) -> CmdResult {
    match cmd {
        PerformanceCmd::Summary => summary(ctx).await,
    }
}

async fn summary(ctx: &Ctx) -> CmdResult {
    let s: PerformanceOverview = ctx.client.get("/v1/performance/summary").await?;
    ctx.out.json(&s);
    ctx.out.line(format!(
        "被動效能摘要（不產生流量）：{} 個邏輯 CPU；速率看最近 {} 秒，延遲看最近 {} 秒",
        s.system.logical_cpu_count, s.rate_window_secs, s.latency_window_secs
    ));
    let mut rows = Vec::new();
    for r in std::iter::once(&s.system.product).chain(s.system.roles.iter()) {
        rows.push(vec![
            role_label(r.role).to_string(),
            r.processes.to_string(),
            num(&r.cpu_core_pct, pct),
            num(&r.cpu_host_pct, pct),
            byte_obs(&r.rss_bytes),
        ]);
    }
    ctx.out.line(table(
        &[
            "程序",
            "數量",
            "CPU（單核 %）",
            "CPU（整機 %）",
            "記憶體 RSS",
        ],
        &rows,
    ));
    ctx.out.line("（RSS 為各程序相加，共用頁面會重複計算）");
    if !s.instances.is_empty() {
        let rows: Vec<Vec<String>> = s
            .instances
            .iter()
            .map(|i| {
                vec![
                    i.name.clone(),
                    format!("{:?}", i.phase).to_lowercase(),
                    num(&i.summary.payload_download_bps, bps),
                    num(&i.summary.payload_upload_bps, bps),
                    format!("{} / {}", opt(i.data_flows.tcp), opt(i.data_flows.udp)),
                    opt(i.summary.active_probe_flows),
                    opt(i.summary.active_control_flows),
                    num(&i.summary.cpu_core_pct, pct),
                ]
            })
            .collect();
        ctx.out.line(table(
            &[
                "連線",
                "狀態",
                "下載",
                "上傳",
                "資料流量 TCP / UDP",
                "探測",
                "控制",
                "worker CPU",
            ],
            &rows,
        ));
    }
    for h in &s.hints {
        ctx.out.line(format!("推論：{}", h.message.zh_tw));
    }
    ctx.out.line(format!(
        "參考規模（規格的工作量，不是即時值）：{} 條連線／{} 個代理埠／{} 條資料流量；目前就緒 {} 條，其中 {} 條有至少 {} 個代理埠在服務",
        s.reference.instances,
        s.reference.gateways,
        s.reference.data_flows,
        s.reference.ready_instances,
        s.reference.eligible_instances,
        s.reference.gateways_per_instance
    ));
    Ok(Exit::Ok)
}
