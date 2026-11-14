//! `vpnctl recovery inspect|reconcile`: what the manager owns and what a crash left behind;
//! a reconcile cleans only what is provably ours and stale — exactly the items just shown, after
//! `--yes`.

use clap::Subcommand;
use hyper::Method;
use vpn_domain::{ReconcileInput, ReconcileOutcome, ReconcileResult, RecoveryItem, RecoveryReport};

use super::{CmdResult, Ctx, Exit, Failure};
use crate::client::Mutation;

#[derive(Subcommand, Debug)]
pub enum RecoveryCmd {
    /// 列出擁有的資源與遺留的項目（不改變任何東西）
    Inspect,
    /// 清理可以證明屬於我們、已失效的項目（不會啟動任何東西）
    Reconcile {
        /// 確認清理列出的項目（沒有這個旗標只會列出）
        #[arg(long)]
        yes: bool,
    },
}

pub async fn run(ctx: &Ctx, cmd: RecoveryCmd) -> CmdResult {
    match cmd {
        RecoveryCmd::Inspect => inspect(ctx).await,
        RecoveryCmd::Reconcile { yes } => reconcile(ctx, yes).await,
    }
}

fn print_item(ctx: &Ctx, i: &RecoveryItem) {
    ctx.out.line(format!(
        "[{}] {}",
        if i.cleanable {
            "可清理"
        } else {
            "只回報"
        },
        i.title.zh_tw
    ));
    ctx.out.line(format!("    {}", i.detail.zh_tw));
    if let Some(p) = &i.path {
        ctx.out.line(format!("    {p}"));
    }
    if let Some(a) = &i.action {
        ctx.out.line(format!("    清理時：{}", a.zh_tw));
    }
}

async fn report(ctx: &Ctx) -> Result<RecoveryReport, Failure> {
    ctx.client.get("/v1/recovery").await
}

async fn inspect(ctx: &Ctx) -> CmdResult {
    let r = report(ctx).await?;
    if ctx.out.json {
        ctx.out.json(&r);
        return Ok(Exit::Ok);
    }
    let res = &r.resources;
    ctx.out.line(format!(
        "擁有的資源：worker {}、代理埠 {}、金鑰鎖 {}、connector socket {}、嚴格隔離 sandbox {}",
        res.workers.len(),
        res.listeners.len(),
        res.key_locks.len(),
        res.connector_sockets.len(),
        res.sandboxes.len()
    ));
    for w in &res.workers {
        ctx.out.line(format!(
            "  worker pid {}  連線 {}  第 {} 代",
            w.pid, w.instance_id, w.generation
        ));
    }
    for s in &res.sandboxes {
        ctx.out.line(format!(
            "  sandbox holder pid {}  連線 {}  epoch {}",
            s.holder_pid, s.instance_id, s.epoch
        ));
    }
    if !res.unanswered.is_empty() {
        ctx.out.line(format!(
            "  另有 {} 條連線沒有在時限內回應：它們持有的代理埠沒有列出",
            res.unanswered.len()
        ));
    }
    for g in &r.gaps {
        ctx.out.line(format!(
            "無法檢查：{}{}：{}",
            g.what.zh_tw,
            g.path.as_deref().map_or_default(|p| format!("（{p}）")),
            g.reason.zh_tw
        ));
    }
    if r.items.is_empty() && r.gaps.is_empty() {
        ctx.out.line("沒有遺留的程序、紀錄、鎖、socket 或暫存檔。");
    } else if r.items.is_empty() {
        ctx.out
            .line("在檢查得到的地方沒有找到遺留項目；上面列出的地方無法檢查。");
    } else {
        ctx.out.line(format!("{} 個項目：", r.items.len()));
        for i in &r.items {
            print_item(ctx, i);
        }
    }
    Ok(Exit::Ok)
}

const fn outcome(o: ReconcileOutcome) -> &'static str {
    match o {
        ReconcileOutcome::Done => "完成",
        ReconcileOutcome::Skipped => "略過",
        ReconcileOutcome::Failed => "失敗",
    }
}

async fn reconcile(ctx: &Ctx, yes: bool) -> CmdResult {
    let r = report(ctx).await?;
    let cleanable: Vec<&RecoveryItem> = r.items.iter().filter(|i| i.cleanable).collect();
    if cleanable.is_empty() {
        ctx.out
            .json(&serde_json::json!({ "actions": [], "remaining": r.items }));
        ctx.out.line("沒有需要清理的項目。");
        return Ok(Exit::Ok);
    }
    if !yes {
        let mut lines = vec![format!("會清理這 {} 個項目：", cleanable.len())];
        lines.extend(cleanable.iter().map(|i| {
            format!(
                "  {}：{}",
                i.title.zh_tw,
                i.action.as_ref().map_or("清理", |t| t.zh_tw.as_str())
            )
        }));
        lines.push("確定要清理，請加上 --yes".into());
        return Err(Failure::Usage(lines.join("\n")));
    }
    let input = ReconcileInput {
        items: Some(cleanable.iter().map(|i| i.id.clone()).collect()),
    };
    let done: Mutation<ReconcileResult> = ctx
        .client
        .mutate(Method::POST, "/v1/recovery/reconcile", Some(&input), None)
        .await?;
    let result = match done {
        Mutation::Done(Some(r)) => r,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        // What each item came to is lost with the answer: look again. A confirmed item still
        // there may or may not have been tried (exit 3).
        Mutation::Recovered(op) => {
            ctx.out.line(format!(
                "沒有收到回應；紀錄顯示這個請求已完成（operation {}），以下是重新檢查的結果。",
                op.id
            ));
            let now = report(ctx).await.map_err(|e| Failure::Unknown {
                key: None,
                operation: Some(op.clone()),
                why: format!("無法重新檢查：{}", e.to_text()),
            })?;
            let confirmed = input.items.unwrap_or_default();
            let left: Vec<&RecoveryItem> = now
                .items
                .iter()
                .filter(|i| confirmed.contains(&i.id))
                .collect();
            ctx.out.json(
                &serde_json::json!({ "operation": op, "remaining": now.items, "gaps": now.gaps }),
            );
            if left.is_empty() {
                ctx.out.line("確認的項目都已不在。");
                return Ok(Exit::Ok);
            }
            ctx.out.line(format!("仍有 {} 個確認的項目：", left.len()));
            for i in left {
                print_item(ctx, i);
            }
            return Ok(Exit::Unknown);
        }
    };
    ctx.out.json(&result);
    for a in &result.actions {
        ctx.out.line(format!(
            "[{}] {}：{}",
            outcome(a.outcome),
            a.title.zh_tw,
            a.detail.zh_tw
        ));
    }
    if !result.remaining.is_empty() {
        ctx.out
            .line(format!("仍有 {} 個項目：", result.remaining.len()));
        for i in &result.remaining {
            print_item(ctx, i);
        }
    }
    let failed = result
        .actions
        .iter()
        .any(|a| a.outcome == ReconcileOutcome::Failed);
    Ok(if failed { Exit::Failed } else { Exit::Ok })
}
