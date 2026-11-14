//! `vpnctl ban list|remove`: sources the auto-ban engine banned. Only new connections forwarded
//! in through a port forward are counted; a banned source can neither connect in nor be reached
//! through a Gateway until the ban expires or is lifted. Lifting a ban does not lift IP
//! blocklists or the security profile's rules.

use std::collections::HashMap;

use clap::Subcommand;
use hyper::Method;
use vpn_domain::validation::ban_label;
use vpn_domain::{Ban, InstanceId, Timestamp, UnbanEffect, UnbanResult};

use super::{CmdResult, Ctx, Exit, Failure};
use crate::client::Mutation;
use crate::output::{duration, short, table, time};

#[derive(Subcommand, Debug)]
pub enum BanCmd {
    /// 列出封鎖中的來源：連線、原因、封鎖時間、剩餘時間
    List {
        /// 只列這條連線的封鎖（名稱、ID 或 ID 開頭）
        #[arg(long)]
        instance: Option<String>,
    },
    /// 解除一筆封鎖：這個來源可以再次經 port forward 連入，經代理埠連到它也不再被拒絕
    Remove {
        /// 封鎖紀錄的 ID（或開頭），或被封鎖的來源位址
        ban: String,
        /// 只在這條連線的封鎖中找（同一個來源被多條連線封鎖時）
        #[arg(long)]
        instance: Option<String>,
        /// 確認要解除（沒有這個旗標只會說明後果）
        #[arg(long)]
        yes: bool,
    },
}

pub async fn run(ctx: &Ctx, cmd: BanCmd) -> CmdResult {
    match cmd {
        BanCmd::List { instance } => list(ctx, instance.as_deref()).await,
        BanCmd::Remove { ban, instance, yes } => remove(ctx, &ban, instance.as_deref(), yes).await,
    }
}

/// Active bans (of the named connection only, when given), with every connection's name.
async fn bans(
    ctx: &Ctx,
    instance: Option<&str>,
) -> Result<(Vec<Ban>, HashMap<InstanceId, String>), Failure> {
    let views = super::instances(ctx).await?;
    let path = match instance {
        Some(q) => {
            let v = crate::resolve::pick(
                &views,
                q,
                "連線",
                |v| v.spec.id.to_string(),
                |v| v.spec.name.clone(),
            )?;
            format!("/v1/bans?instance={}", v.spec.id)
        }
        None => "/v1/bans".to_string(),
    };
    let names = views
        .into_iter()
        .map(|v| (v.spec.id, v.spec.name))
        .collect();
    Ok((ctx.client.get(&path).await?, names))
}

fn connection(names: &HashMap<InstanceId, String>, id: InstanceId) -> String {
    names
        .get(&id)
        .cloned()
        .unwrap_or_else(|| "已刪除的連線".into())
}

/// Time left until `expires_at`, or "已到期" (the next sweep deletes it).
fn left(expires_at: &Timestamp, now: &Timestamp) -> String {
    let ms = expires_at.unix_millis() - now.unix_millis();
    if ms <= 0 {
        "已到期".into()
    } else {
        // Round up: "1 秒" until it is really over.
        duration(ms.unsigned_abs().div_ceil(1000))
    }
}

async fn list(ctx: &Ctx, instance: Option<&str>) -> CmdResult {
    let (all, names) = bans(ctx, instance).await?;
    if ctx.out.json {
        ctx.out.json(&all);
    } else if all.is_empty() {
        ctx.out.line(if instance.is_some() {
            "這條連線沒有封鎖中的來源。"
        } else {
            "沒有封鎖中的來源。"
        });
    } else {
        let now = Timestamp::now();
        let rows: Vec<Vec<String>> = all
            .iter()
            .map(|b| {
                vec![
                    short(&b.id),
                    ban_label(b.source),
                    connection(&names, b.instance_id),
                    b.reason.clone().zh_tw.clone(),
                    time(&b.created_at),
                    left(&b.expires_at, &now),
                ]
            })
            .collect();
        ctx.out.line(table(
            &["ID", "來源", "連線", "原因", "封鎖於", "剩餘"],
            &rows,
        ));
    }
    Ok(Exit::Ok)
}

async fn remove(ctx: &Ctx, q: &str, instance: Option<&str>, yes: bool) -> CmdResult {
    let (all, names) = bans(ctx, instance).await?;
    let b = crate::resolve::pick(
        &all,
        q,
        "封鎖紀錄",
        |b| b.id.to_string(),
        |b| ban_label(b.source),
    )?
    .clone();
    let conn = connection(&names, b.instance_id);
    if !yes {
        return Err(Failure::Usage(format!(
            "會解除 {} 在「{conn}」的封鎖（原因：{}，剩餘 {}）：它可以再次經 port forward 連入，經代理埠連到它也不再被拒絕。\nIP 封鎖清單與安全設定的規則仍然適用；它再次超過門檻時會重新被封鎖。\n確定要解除，請加上 --yes",
            ban_label(b.source),
            b.reason.zh_tw,
            left(&b.expires_at, &Timestamp::now())
        )));
    }
    let done: Mutation<UnbanResult> = ctx
        .client
        .mutate(
            Method::DELETE,
            &format!("/v1/bans/{}", b.id),
            None::<&()>,
            None,
        )
        .await?;
    match done {
        Mutation::Done(Some(r)) => {
            ctx.out.json(&r);
            ctx.out.line(match r.worker {
                UnbanEffect::Applied => format!(
                    "已解除 {} 的封鎖：「{conn}」執行中的 worker 已確認不再封鎖它。",
                    ban_label(b.source)
                ),
                UnbanEffect::NotRunning => format!(
                    "已解除 {} 的封鎖：「{conn}」目前沒有執行，下次啟動時不會再帶入這筆封鎖。",
                    ban_label(b.source)
                ),
                UnbanEffect::Unconfirmed => format!(
                    "已移除 {} 的封鎖紀錄；「{conn}」執行中的 worker 沒有及時確認，連線重新建立後一定不再生效。",
                    ban_label(b.source)
                ),
            });
        }
        // A replay of a lift that went through, or a lost answer the record says succeeded.
        Mutation::Done(None) => {
            ctx.out.json(&serde_json::json!({ "removed": b.id }));
            ctx.out
                .line(format!("已解除 {} 的封鎖。", ban_label(b.source)));
        }
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示 {} 的封鎖已解除。",
                ban_label(b.source)
            ));
        }
    }
    Ok(Exit::Ok)
}
