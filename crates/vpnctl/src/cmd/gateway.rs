//! `vpnctl gateway list`: every proxy port, its connection and whether it serves right now.

use clap::Subcommand;
use vpn_domain::{GatewaySpec, GatewayState};

use super::{CmdResult, Ctx, Exit, instances};
use crate::output::{gateway_kind, short, table};

#[derive(Subcommand, Debug)]
pub enum GatewayCmd {
    /// 列出所有代理埠
    List,
}

pub async fn run(ctx: &Ctx, cmd: GatewayCmd) -> CmdResult {
    match cmd {
        GatewayCmd::List => list(ctx).await,
    }
}

async fn list(ctx: &Ctx) -> CmdResult {
    let gateways: Vec<GatewaySpec> = ctx.client.get("/v1/gateways").await?;
    if ctx.out.json {
        ctx.out.json(&gateways);
        return Ok(Exit::Ok);
    }
    if gateways.is_empty() {
        ctx.out.line("還沒有任何代理埠。");
        return Ok(Exit::Ok);
    }
    let views = instances(ctx).await?;
    let mut rows: Vec<Vec<String>> = gateways
        .iter()
        .map(|g| {
            let owner = views.iter().find(|v| v.spec.id == g.instance_id);
            let runtime = owner
                .and_then(|v| v.status.as_ref())
                .and_then(|s| s.gateways.iter().find(|r| r.gateway_id == g.id));
            let state = match (g.enabled, runtime) {
                (false, _) => "停用".to_string(),
                (true, Some(r)) => match r.state {
                    GatewayState::Serving => format!("服務中（TCP {}）", r.active_tcp),
                    GatewayState::Blocked => "拒絕連線".into(),
                    GatewayState::Inactive => "未啟用".into(),
                    GatewayState::Failed => {
                        format!(
                            "無法啟用{}",
                            r.error
                                .as_ref()
                                .map_or_default(|e| format!("：{}", e.zh_tw))
                        )
                    }
                },
                (true, None) => "—".into(),
            };
            vec![
                format!("127.0.0.1:{}", g.port),
                g.name.clone(),
                gateway_kind(g.kind).to_string(),
                owner.map_or_else(|| short(&g.instance_id), |v| v.spec.name.clone()),
                state,
            ]
        })
        .collect();
    rows.sort();
    ctx.out
        .line(table(&["位址", "名稱", "協定", "連線", "狀態"], &rows));
    Ok(Exit::Ok)
}
