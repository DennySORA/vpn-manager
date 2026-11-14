//! `vpnctl secret list`: what the vault holds, by metadata only (nothing reads a secret back).

use clap::Subcommand;
use vpn_domain::SecretMetadata;

use super::{CmdResult, Ctx, Exit};
use crate::output::{table, time};

#[derive(Subcommand, Debug)]
pub enum SecretCmd {
    /// 列出保管庫裡的秘密（只有中繼資料）
    List,
}

fn kind(k: &str) -> &str {
    match k {
        "wireguard_private_key" => "WireGuard 私鑰",
        "wireguard_preshared_key" => "WireGuard 預共享金鑰",
        "provider_credential" => "供應商帳號憑證",
        other => other,
    }
}

pub async fn run(ctx: &Ctx, cmd: SecretCmd) -> CmdResult {
    match cmd {
        SecretCmd::List => {
            let list: Vec<SecretMetadata> = ctx.client.get("/v1/secrets").await?;
            if ctx.out.json {
                ctx.out.json(&list);
            } else if list.is_empty() {
                ctx.out.line("保管庫是空的。");
            } else {
                let rows: Vec<Vec<String>> = list
                    .iter()
                    .map(|s| {
                        vec![
                            kind(&s.kind).to_string(),
                            s.label.clone().unwrap_or_else(|| "—".into()),
                            s.public_fingerprint
                                .as_ref()
                                .map_or_else(|| "—".into(), |f| f.chars().take(16).collect()),
                            time(&s.created_at),
                            s.secret_ref.to_string(),
                        ]
                    })
                    .collect();
                ctx.out.line(table(
                    &["種類", "標籤", "公鑰指紋", "建立時間", "參照"],
                    &rows,
                ));
            }
            Ok(Exit::Ok)
        }
    }
}
