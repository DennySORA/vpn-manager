//! `vpnctl blocklist list|show|refresh|delete`: IP blocklists. A list's content is created or
//! replaced through a preview in the web UI (`/security/blocklists`); here a list can be read,
//! downloaded again (URL sources, through the Provider egress connection) and deleted.

use clap::Subcommand;
use hyper::Method;
use vpn_domain::{BlocklistSource, BlocklistStats, BlocklistView};

use super::{CmdResult, Ctx, Exit, Failure};
use crate::client::Mutation;
use crate::output::{bytes, short, table, time};

/// Invalid lines `show` prints (every kept one is in `--json`).
const INVALID_SHOWN: usize = 10;

#[derive(Subcommand, Debug)]
pub enum BlocklistCmd {
    /// 列出 IP 封鎖清單：來源、內容、使用中的安全設定、最近一次更新
    List,
    /// 一份清單的內容統計、無效行、更新狀態與使用它的安全設定
    Show {
        /// 名稱、ID 或 ID 開頭
        list: String,
    },
    /// 立即重新下載網址來源的清單（經 Provider 出口連線）；失敗時保留先前的內容
    Refresh {
        /// 名稱、ID 或 ID 開頭
        list: String,
    },
    /// 刪除清單（仍有安全設定使用時會被拒絕）
    Delete {
        /// 名稱、ID 或 ID 開頭
        list: String,
        /// 確認要刪除（沒有這個旗標只會說明後果）
        #[arg(long)]
        yes: bool,
    },
}

pub async fn run(ctx: &Ctx, cmd: BlocklistCmd) -> CmdResult {
    match cmd {
        BlocklistCmd::List => list(ctx).await,
        BlocklistCmd::Show { list } => show(ctx, &list).await,
        BlocklistCmd::Refresh { list } => refresh(ctx, &list).await,
        BlocklistCmd::Delete { list, yes } => delete(ctx, &list, yes).await,
    }
}

async fn lists(ctx: &Ctx) -> Result<Vec<BlocklistView>, Failure> {
    ctx.client.get("/v1/blocklists").await
}

async fn find(ctx: &Ctx, q: &str) -> Result<BlocklistView, Failure> {
    let all = lists(ctx).await?;
    crate::resolve::pick(
        &all,
        q,
        "IP 封鎖清單",
        |v| v.blocklist.id.to_string(),
        |v| v.blocklist.name.clone(),
    )
    .cloned()
}

fn source(s: &BlocklistSource) -> String {
    match s {
        BlocklistSource::Upload => "上傳或貼上的文字".into(),
        BlocklistSource::Url {
            url,
            refresh_hours: None,
        } => format!("網址 {url}（只在手動時更新）"),
        BlocklistSource::Url {
            url,
            refresh_hours: Some(h),
        } => format!("網址 {url}（每 {h} 小時自動更新）"),
    }
}

/// "6 筆 · IPv4 4 段 · IPv6 1 段".
fn size(s: &BlocklistStats) -> String {
    let mut parts = vec![format!("{} 筆", s.entries)];
    if s.v4_ranges > 0 {
        parts.push(format!("IPv4 {} 段", s.v4_ranges));
    }
    if s.v6_ranges > 0 {
        parts.push(format!("IPv6 {} 段", s.v6_ranges));
    }
    parts.join(" · ")
}

/// The latest refresh, for URL sources ("—" for uploaded text, which is never downloaded).
fn refresh_state(v: &BlocklistView) -> String {
    if !v.blocklist.enabled {
        return "已停用".into();
    }
    if v.awaiting_content {
        return match (&v.waiting, &v.refresh) {
            (Some(why), _) => format!("等待下載：{}", why.zh_tw),
            (None, Some(r)) if !r.ok => format!("首次下載失敗（{}）", time(&r.attempted_at)),
            (None, _) => "等待下載".into(),
        };
    }
    match (&v.blocklist.source, &v.refresh) {
        (BlocklistSource::Upload, _) => "—".into(),
        (BlocklistSource::Url { .. }, None) => "尚未更新".into(),
        (BlocklistSource::Url { .. }, Some(r)) if v.stale => {
            format!("更新失敗（{}），使用先前的內容", time(&r.attempted_at))
        }
        (BlocklistSource::Url { .. }, Some(r)) => format!("成功（{}）", time(&r.attempted_at)),
    }
}

fn users(v: &BlocklistView) -> String {
    let mut who: Vec<String> = v
        .used_by
        .iter()
        .map(|p| format!("「{}」", p.name))
        .collect();
    if v.default_policy {
        who.insert(0, "預設安全政策（沒有指定安全設定的連線）".into());
    }
    if who.is_empty() {
        "沒有安全設定使用".into()
    } else {
        who.join("、")
    }
}

/// The name, marked when the list is built in or disabled.
fn title(v: &BlocklistView) -> String {
    let mut t = v.blocklist.name.clone();
    if v.builtin.is_some() {
        t.push_str("（內建）");
    }
    if !v.blocklist.enabled {
        t.push_str("（已停用）");
    }
    t
}

async fn list(ctx: &Ctx) -> CmdResult {
    let all = lists(ctx).await?;
    if ctx.out.json {
        ctx.out.json(&all);
    } else if all.is_empty() {
        ctx.out
            .line("還沒有 IP 封鎖清單（在網頁的「IP 封鎖清單」上傳、貼上或從網址下載）。");
    } else {
        let rows: Vec<Vec<String>> = all
            .iter()
            .map(|v| {
                let b = &v.blocklist;
                vec![
                    short(&b.id),
                    title(v),
                    match b.source {
                        BlocklistSource::Upload => "上傳".into(),
                        BlocklistSource::Url { .. } => "網址".into(),
                    },
                    size(&b.stats),
                    match (v.default_policy, v.used_by.len()) {
                        (false, 0) => "—".into(),
                        (true, 0) => "預設政策".into(),
                        (false, n) => format!("{n} 份安全設定"),
                        (true, n) => format!("預設政策、{n} 份安全設定"),
                    },
                    refresh_state(v),
                ]
            })
            .collect();
        ctx.out.line(table(
            &["ID", "名稱", "來源", "內容", "使用中", "最近更新"],
            &rows,
        ));
    }
    Ok(Exit::Ok)
}

fn describe(ctx: &Ctx, v: &BlocklistView) {
    let b = &v.blocklist;
    let s = &b.stats;
    ctx.out
        .line(format!("IP 封鎖清單「{}」 {}", title(v), b.id));
    if let Some(info) = &v.builtin {
        ctx.out
            .line(format!("  內建清單：{}", info.description.zh_tw));
        ctx.out.line(format!(
            "  使用條款：{}（{}）",
            info.terms.zh_tw, info.terms_url
        ));
    }
    ctx.out.line(format!("  來源：{}", source(&b.source)));
    if let Some(why) = &v.waiting {
        ctx.out.line(format!("  等待 Provider 出口：{}", why.zh_tw));
    }
    if v.awaiting_content {
        ctx.out
            .line("  內容：尚未下載（第一次下載前不封鎖任何位址）");
    }
    ctx.out.line(format!(
        "  內容：{}；IPv4 {} 個位址、IPv6 {} 個位址；{} → {}",
        size(s),
        s.v4_addresses,
        s.v6_addresses,
        bytes(u64::from(s.raw_bytes)),
        bytes(u64::from(s.parsed_bytes))
    ));
    ctx.out.line(format!(
        "  內容更新於 {}，SHA-256 {}",
        time(&b.content_updated_at),
        b.content_sha256
    ));
    if let BlocklistSource::Url { .. } = b.source {
        match &v.refresh {
            Some(r) => {
                ctx.out.line(format!(
                    "  最近更新：{}（{}）{}",
                    if r.ok { "成功" } else { "失敗" },
                    time(&r.attempted_at),
                    r.message
                        .as_ref()
                        .map_or_default(|m| format!("：{}", m.zh_tw))
                ));
                if v.stale {
                    ctx.out.line(format!(
                        "  使用先前下載的內容{}",
                        r.stale_since
                            .as_ref()
                            .map_or_default(|t| format!("（自 {} 起更新失敗）", time(t)))
                    ));
                }
            }
            None => ctx.out.line("  最近更新：尚未更新"),
        }
        if let Some(next) = &v.next_refresh_at {
            ctx.out.line(format!("  下次自動更新：{}", time(next)));
        }
    }
    ctx.out.line(format!("  使用中：{}", users(v)));
    if s.special_filtered > 0 {
        ctx.out.line(format!(
            "  略過的私有或特殊用途位址：{} 筆（不封鎖：私網由安全設定的私網允許規則管理）",
            s.special_filtered
        ));
    }
    if s.invalid > 0 {
        ctx.out.line(format!(
            "  無效的行：{} 行（不會生效）{}",
            s.invalid,
            if b.invalid_lines.len() > INVALID_SHOWN {
                format!("，列出前 {INVALID_SHOWN} 行")
            } else {
                String::new()
            }
        ));
        for l in b.invalid_lines.iter().take(INVALID_SHOWN) {
            ctx.out.line(format!(
                "    第 {} 行  {}  {}",
                l.line, l.content, l.reason.zh_tw
            ));
        }
    }
}

async fn show(ctx: &Ctx, q: &str) -> CmdResult {
    let v = find(ctx, q).await?;
    if ctx.out.json {
        ctx.out.json(&v);
    } else {
        describe(ctx, &v);
    }
    Ok(Exit::Ok)
}

async fn refresh(ctx: &Ctx, q: &str) -> CmdResult {
    let v = find(ctx, q).await?;
    let done: Mutation<BlocklistView> = ctx
        .client
        .mutate(
            Method::POST,
            &format!("/v1/blocklists/{}/refresh", v.blocklist.id),
            Some(&serde_json::json!({})),
            None,
        )
        .await?;
    let after = match done {
        Mutation::Done(Some(after)) => after,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        // The answer was lost but the refresh went through: read what it left.
        Mutation::Recovered(_) => find(ctx, &v.blocklist.id.to_string()).await?,
    };
    ctx.out.json(&after);
    let message = after
        .refresh
        .as_ref()
        .and_then(|r| r.message.as_ref().map(|m| m.zh_tw.clone()))
        .unwrap_or_else(|| "已更新".into());
    ctx.out.line(format!(
        "「{}」：{message}（{}）",
        after.blocklist.name,
        size(&after.blocklist.stats)
    ));
    if !after.used_by.is_empty() {
        ctx.out
            .line("使用它的執行中連線會立即套用新的內容，不需要重新啟動。");
    }
    Ok(Exit::Ok)
}

async fn delete(ctx: &Ctx, q: &str, yes: bool) -> CmdResult {
    let v = find(ctx, q).await?;
    let b = &v.blocklist;
    if !yes {
        let mut why = vec![format!(
            "會永久刪除 IP 封鎖清單「{}」（{}）。",
            b.name,
            size(&b.stats)
        )];
        if !v.used_by.is_empty() {
            why.push(format!(
                "它仍被安全設定{}使用：先在安全設定中取消選取，否則刪除會被拒絕。",
                users(&v)
            ));
        }
        why.push("確定要刪除，請加上 --yes".into());
        return Err(Failure::Usage(why.join("\n")));
    }
    let done: Mutation<serde_json::Value> = ctx
        .client
        .mutate(
            Method::DELETE,
            &format!("/v1/blocklists/{}", b.id),
            None::<&()>,
            Some(b.meta.revision),
        )
        .await?;
    if let Mutation::Recovered(op) = &done {
        ctx.out.json(op);
    } else {
        ctx.out.json(&serde_json::json!({ "deleted": b.id }));
    }
    ctx.out.line(format!("已刪除 IP 封鎖清單「{}」。", b.name));
    Ok(Exit::Ok)
}
