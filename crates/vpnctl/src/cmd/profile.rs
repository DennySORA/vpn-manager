//! `vpnctl profile import --file <absolute path> [--name] --preview|--commit`: a `WireGuard`
//! configuration file is read from disk (never from argv or the environment) and sent once;
//! its private key is never printed.

use std::path::{Path, PathBuf};

use clap::{ArgGroup, Subcommand};
use hyper::Method;
use vpn_domain::{ImportMode, ImportRequest, ImportResult, Severity};

use super::{CmdResult, Ctx, Exit, Failure};
use crate::client::Mutation;

/// Largest configuration file read (a `WireGuard` config is a few hundred bytes).
const CONFIG_MAX: u64 = 64 * 1024;

#[derive(Subcommand, Debug)]
pub enum ProfileCmd {
    /// 匯入 `WireGuard` 設定檔：先 --preview 檢查，再 --commit 建立
    #[command(group(ArgGroup::new("mode").required(true).args(["preview", "commit"])))]
    Import {
        /// 設定檔的絕對路徑
        #[arg(long, value_name = "ABSOLUTE_PATH")]
        file: PathBuf,
        /// 設定名稱（預設：檔名）
        #[arg(long)]
        name: Option<String>,
        /// 只解析與檢查，不儲存任何東西
        #[arg(long)]
        preview: bool,
        /// 把金鑰存進保管庫並建立設定
        #[arg(long)]
        commit: bool,
    },
}

pub async fn run(ctx: &Ctx, cmd: ProfileCmd) -> CmdResult {
    match cmd {
        ProfileCmd::Import {
            file,
            name,
            preview,
            commit: _,
        } => import(ctx, &file, name, preview).await,
    }
}

/// The configuration text: an absolute path to a regular file of at most [`CONFIG_MAX`] bytes.
pub fn read_config(file: &Path) -> Result<String, Failure> {
    if !file.is_absolute() {
        return Err(Failure::Usage(format!(
            "--file 必須是絕對路徑（收到 {}）",
            file.display()
        )));
    }
    let meta = std::fs::metadata(file)
        .map_err(|e| Failure::Usage(format!("無法讀取 {}：{e}", file.display())))?;
    if !meta.is_file() {
        return Err(Failure::Usage(format!("{} 不是一般檔案", file.display())));
    }
    if meta.len() > CONFIG_MAX {
        return Err(Failure::Usage(format!(
            "{} 超過 {} KiB，不像 WireGuard 設定檔",
            file.display(),
            CONFIG_MAX / 1024
        )));
    }
    std::fs::read_to_string(file)
        .map_err(|e| Failure::Usage(format!("無法讀取 {}：{e}", file.display())))
}

fn default_name(file: &Path) -> String {
    file.file_stem()
        .map_or_else(|| "WireGuard".into(), |s| s.to_string_lossy().into_owned())
}

const fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Error => "錯誤",
        Severity::Warning => "警告",
    }
}

fn print_result(ctx: &Ctx, r: &ImportResult) {
    if let Some(c) = &r.candidate {
        ctx.out.line(format!("公鑰：{}", c.public_key));
        let addresses: Vec<String> = c
            .addresses
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        ctx.out.line(format!("位址：{}", addresses.join(", ")));
        ctx.out.line(format!("端點：{}", c.endpoint));
        let allowed: Vec<String> = c
            .allowed_ips
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        ctx.out.line(format!("AllowedIPs：{}", allowed.join(", ")));
        let dns: Vec<String> = c.dns.iter().map(std::string::ToString::to_string).collect();
        ctx.out.line(format!(
            "DNS：{}",
            if dns.is_empty() {
                "（沒有）".into()
            } else {
                dns.join(", ")
            }
        ));
        ctx.out.line(format!(
            "MTU {}，預共享金鑰：{}",
            c.mtu,
            if c.has_preshared_key { "有" } else { "沒有" }
        ));
    }
    for i in &r.report.issues {
        ctx.out.line(format!(
            "[{}] {}（{}）",
            severity(i.severity),
            i.message.zh_tw,
            i.path
        ));
    }
}

async fn import(ctx: &Ctx, file: &Path, name: Option<String>, preview: bool) -> CmdResult {
    let config = read_config(file)?;
    let request = ImportRequest {
        mode: if preview {
            ImportMode::Preview
        } else {
            ImportMode::Commit
        },
        name: name.unwrap_or_else(|| default_name(file)),
        config,
        provider: None,
        location: None,
    };
    let done: Mutation<ImportResult> = ctx
        .client
        .mutate(Method::POST, "/v1/profiles/import", Some(&request), None)
        .await?;
    drop(request);
    match done {
        Mutation::Done(Some(r)) => {
            ctx.out.json(&r);
            print_result(ctx, &r);
            let errors = r
                .report
                .issues
                .iter()
                .any(|i| i.severity == Severity::Error);
            match &r.profile {
                Some(p) => {
                    ctx.out
                        .line(format!("已建立 WireGuard 設定「{}」（{}）。", p.name, p.id));
                    Ok(Exit::Ok)
                }
                None if errors => {
                    ctx.out.line("設定檔有錯誤，不能匯入。");
                    Ok(Exit::Failed)
                }
                None => {
                    ctx.out.line("檢查通過；加上 --commit 匯入。");
                    Ok(Exit::Ok)
                }
            }
        }
        Mutation::Done(None) => Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示匯入已完成（operation {}，設定 {}）。",
                op.id,
                op.result_refs.first().map_or("—", String::as_str)
            ));
            Ok(Exit::Ok)
        }
    }
}
