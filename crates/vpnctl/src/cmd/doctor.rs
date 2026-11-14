//! `vpnctl doctor`: the diagnostics report — checks first, then the facts behind them. Exits 1
//! when a check failed or could not be determined: unknown is never reported as healthy.

use vpn_domain::{
    BinaryDigest, CheckStatus, DiagnosticReport, ManagerReport, ProcessReport, VaultKeyState,
};

use super::{CmdResult, Ctx, Exit};
use crate::output::{Out, bytes, check_label, duration, opt_bytes, opt_time, short, table, time};

fn process_line(p: &ProcessReport) -> String {
    let up = p
        .uptime_secs
        .map_or_default(|s| format!("，已執行 {}", duration(s)));
    let rss = p
        .rss_bytes
        .map_or_default(|b| format!("，記憶體 {}", bytes(b)));
    format!(
        "{:<10} pid {}，build {}{up}{rss}",
        p.role, p.pid, p.build_id
    )
}

fn digest_line(name: &str, d: &BinaryDigest) -> String {
    d.sha256.as_ref().map_or_else(
        || {
            format!(
                "  {name:<7} （{}）  {}",
                d.error.as_ref().map_or("無法讀取", |t| t.zh_tw.as_str()),
                d.path
            )
        },
        |sha| format!("  {name:<7} {}  {}", short_sha(sha), d.path),
    )
}

/// The first 16 hex digits (all of a shorter text).
fn short_sha(s: &str) -> String {
    format!("sha256:{}…", s.get(..16).unwrap_or(s))
}

pub async fn run(ctx: &Ctx) -> CmdResult {
    let r: DiagnosticReport = ctx.client.get("/v1/system/diagnostics").await?;
    let failed = r
        .checks
        .iter()
        .any(|c| matches!(c.status, CheckStatus::Failed | CheckStatus::Unknown));
    if ctx.out.json {
        ctx.out.json(&r);
        return Ok(if failed { Exit::Failed } else { Exit::Ok });
    }
    let out = &ctx.out;
    out.line(format!(
        "VPN Manager 診斷（{}，{} {}）",
        time(&r.generated_at),
        r.os,
        r.arch
    ));
    out.line("");
    for c in &r.checks {
        out.line(format!("[{}] {}", check_label(c.status), c.message.zh_tw));
    }
    out.line("");
    out.line("程序");
    out.line(format!("  {}", process_line(&r.controller)));
    match &r.manager {
        Some(m) => out.line(format!("  {}", process_line(&m.process))),
        None => out.line(format!(
            "  manager    無法連線：{}",
            r.manager_error
                .as_ref()
                .map_or("沒有回應", |t| t.zh_tw.as_str())
        )),
    }
    out.line(format!(
        "元件  GotaTun {}，smoltcp {}，SQLite {}",
        r.components.gotatun,
        r.components.smoltcp,
        r.components.sqlite.as_deref().unwrap_or("未知")
    ));
    out.line("程式");
    out.line(digest_line("vpnd", &r.controller.binary));
    let Some(m) = &r.manager else {
        return Ok(Exit::Failed);
    };
    manager_lines(*out, m);
    Ok(if failed { Exit::Failed } else { Exit::Ok })
}

/// The manager's part of the report: its binary, directories, databases and resources.
fn manager_lines(out: Out, m: &ManagerReport) {
    out.line(digest_line("vpnctl", &m.vpnctl));
    out.line(format!("資料目錄  {}", m.data_dir));
    out.line(format!("socket 目錄  {}", m.run_dir));
    out.line("資料庫");
    let rows: Vec<Vec<String>> = m
        .databases
        .iter()
        .map(|d| {
            vec![
                d.name.clone(),
                opt_bytes(d.size_bytes),
                opt_bytes(d.wal_bytes),
                d.schema_version
                    .map_or_else(|| "—".into(), |v| format!("{v}/{}", d.supported_version)),
                d.quick_check.clone().zh_tw.clone(),
                format!(
                    "{}/{}（拒絕 {}）",
                    d.queue.depth, d.queue.capacity, d.queue.busy_refusals
                ),
            ]
        })
        .collect();
    for l in table(
        &["資料庫", "大小", "WAL", "schema", "quick_check", "寫入佇列"],
        &rows,
    )
    .lines()
    {
        out.line(format!("  {l}"));
    }
    let key = match m.vault_key.state {
        VaultKeyState::Matches => "與資料庫相符".to_string(),
        _ => (m
            .vault_key
            .detail
            .clone()
            .unwrap_or_else(|| "有問題".into()))
        .zh_tw
        .clone(),
    };
    out.line(format!("vault.key  {key}"));
    let ing = &m.metrics_ingress;
    out.line(format!(
        "指標寫入  已寫入 {}、佇列中 {}、丟棄 {}、失敗 {}",
        ing.written, ing.queued_now, ing.dropped, ing.write_failures
    ));
    let res = &m.resources;
    let listeners = if res.unanswered.is_empty() {
        res.listeners.len().to_string()
    } else {
        format!(
            "{} 以上（{} 條連線沒有回應，未列出）",
            res.listeners.len(),
            res.unanswered.len()
        )
    };
    out.line(format!(
        "擁有的資源  worker {}、代理埠 {listeners}、金鑰鎖 {}、connector {}、sandbox {}；遺留項目 {}{}",
        res.workers.len(),
        res.key_locks.len(),
        res.connector_sockets.len(),
        res.sandboxes.len(),
        m.recovery_items,
        if m.recovery_gaps.is_empty() {
            String::new()
        } else {
            format!("（另有 {} 處無法檢查）", m.recovery_gaps.len())
        }
    ));
    for g in &m.recovery_gaps {
        out.line(format!(
            "  無法檢查：{}{}：{}",
            g.what.zh_tw,
            g.path.as_deref().map_or_default(|p| format!("（{p}）")),
            g.reason.zh_tw
        ));
    }
    for w in &res.workers {
        out.line(format!(
            "  worker pid {}  連線 {} 第 {} 代  啟動於 {}",
            w.pid,
            short(&w.instance_id),
            w.generation,
            opt_time(w.process_started_at.as_ref())
        ));
    }
    if let Some(e) = &m.logs_error {
        out.line(format!("日誌  {}", e.zh_tw));
    }
    if !m.logs.is_empty() {
        let logs: Vec<String> = m
            .logs
            .iter()
            .map(|l| format!("{} {}", l.name, opt_bytes(l.size_bytes)))
            .collect();
        out.line(format!("日誌  {}", logs.join("、")));
    }
}
