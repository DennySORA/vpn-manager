//! `vpnctl ssh status|apply`, and `vpnctl ssh-proxy`: the `ProxyCommand` written into the SSH
//! configuration for hosts that go through a Gateway.
//!
//! `vpnctl ssh-proxy --gateway 127.0.0.1:<port> --key-file <key> %h %p` makes the Gateway prove
//! it belongs to this installation (another program could hold the port), opens a SOCKS5
//! CONNECT (the name is resolved inside the tunnel) and relays stdin/stdout. Every refusal ends
//! with a reason on stderr and a non-zero exit, so ssh fails instead of connecting another way.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use hyper::Method;
use vpn_domain::{SshActionResult, SshFileState, SshHost, SshIncludeState, SshStatus};

use super::{CmdResult, Ctx, Exit, Failure};
use crate::client::Mutation;
use crate::output::stderr_line;

#[derive(Subcommand, Debug)]
pub enum SshCmd {
    /// SSH 設定的狀態：Include、vpn-manager.conf、主機數
    Status,
    /// 立刻依目前的主機寫入 vpn-manager.conf（被手動改過的檔案不會被覆寫）
    Apply,
}

const fn include(s: SshIncludeState) -> &'static str {
    match s {
        SshIncludeState::Present => "在 ~/.ssh/config 的最前面（生效）",
        SshIncludeState::Late => "在 ~/.ssh/config 裡，但不在最前面（可能被前面的設定蓋過）",
        SshIncludeState::Missing => "~/.ssh/config 沒有 Include",
        SshIncludeState::NoConfig => "沒有 ~/.ssh/config",
        SshIncludeState::Unsafe => "~/.ssh/config 不安全，不會修改",
    }
}

const fn file(s: SshFileState) -> &'static str {
    match s {
        SshFileState::Ok => "與 VPN Manager 寫入的一致",
        SshFileState::Absent => "還沒寫入",
        SshFileState::Modified => "被手動修改過（不會覆寫）",
        SshFileState::Unsafe => "不安全（符號連結或權限），不會寫入",
    }
}

fn describe(ctx: &Ctx, s: &SshStatus, hosts: Option<usize>) {
    if !s.available {
        ctx.out.line(format!(
            "SSH Manager 無法使用：{}",
            s.unavailable_reason
                .as_ref()
                .map_or("原因不明", |t| t.zh_tw.as_str())
        ));
    }
    ctx.out.line(format!("SSH 目錄：{}", s.ssh_dir));
    ctx.out.line(format!("Include：{}", include(s.include)));
    ctx.out
        .line(format!("{}：{}", s.managed_path, file(s.file)));
    if let Some(n) = hosts {
        ctx.out.line(format!("主機：{n} 台"));
    }
    if s.pending {
        ctx.out.line("儲存的主機與檔案內容還不一致。");
    }
    if let Some(p) = &s.config_problem {
        ctx.out.line(format!("~/.ssh/config：{}", p.zh_tw));
    }
    if let Some(e) = &s.last_error {
        ctx.out.line(format!("上次寫入失敗：{}", e.zh_tw));
    }
}

pub async fn run(ctx: &Ctx, cmd: SshCmd) -> CmdResult {
    match cmd {
        SshCmd::Status => {
            let s: SshStatus = ctx.client.get("/v1/ssh").await?;
            let hosts: Vec<SshHost> = ctx.client.get("/v1/ssh-hosts").await?;
            ctx.out
                .json(&serde_json::json!({ "status": s, "hosts": hosts.len() }));
            describe(ctx, &s, Some(hosts.len()));
            Ok(Exit::Ok)
        }
        SshCmd::Apply => {
            let done: Mutation<SshActionResult> = ctx
                .client
                .mutate(
                    Method::POST,
                    "/v1/ssh/apply",
                    Some(&serde_json::json!({})),
                    None,
                )
                .await?;
            let status = match done {
                Mutation::Done(Some(r)) => {
                    ctx.out.json(&r);
                    r.status
                }
                Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
                // What the file is now decides, as after an answer; unknown when unreadable.
                Mutation::Recovered(op) => {
                    ctx.out.line(format!(
                        "沒有收到回應；紀錄顯示這個請求已完成（operation {}），以下是重新讀取的狀態。",
                        op.id
                    ));
                    match ctx.client.get::<SshStatus>("/v1/ssh").await {
                        Ok(s) => {
                            ctx.out
                                .json(&serde_json::json!({ "operation": op, "status": s }));
                            s
                        }
                        Err(e) => {
                            ctx.out.json(
                                &serde_json::json!({ "operation": op, "error": e.to_json() }),
                            );
                            ctx.out
                                .line(format!("無法讀取 SSH 設定的狀態：{}", e.to_text()));
                            return Ok(Exit::Unknown);
                        }
                    }
                }
            };
            ctx.out.line(match status.file {
                SshFileState::Ok => "vpn-manager.conf 已是目前主機的內容。",
                SshFileState::Absent => {
                    "沒有 SSH 主機，不需要 vpn-manager.conf（不會建立空檔案）。"
                }
                SshFileState::Modified => {
                    "vpn-manager.conf 被手動修改過，沒有覆寫；請在網頁的 SSH 主機頁決定是否覆寫。"
                }
                SshFileState::Unsafe => "vpn-manager.conf 不安全，沒有寫入。",
            });
            describe(ctx, &status, None);
            Ok(match status.file {
                SshFileState::Ok | SshFileState::Absent => Exit::Ok,
                _ => Exit::Failed,
            })
        }
    }
}

/// `vpnctl ssh-proxy`: relay one SSH connection through a Gateway of this installation.
pub async fn proxy(gateway: SocketAddr, key_file: PathBuf, host: String, port: u16) -> ExitCode {
    if !gateway.ip().is_loopback() {
        stderr_line(&format!(
            "vpn-manager: 代理埠必須在 127.0.0.1（收到 {gateway}）"
        ));
        return ExitCode::FAILURE;
    }
    let key = match vpn_ssh::socks::read_key_file(&key_file) {
        Ok(k) => k,
        Err(e) => {
            stderr_line(&format!("vpn-manager: {}", e.zh_tw));
            return ExitCode::FAILURE;
        }
    };
    let carries = vpn_ssh::socks::Carries::SshSession;
    let remote = match vpn_ssh::socks::connect(gateway, &host, port, Some(&*key), carries).await {
        Ok(s) => s,
        Err(e) => {
            stderr_line(&format!(
                "vpn-manager: 無法經 VPN 連到 {host}:{port}：{}",
                e.text().zh_tw
            ));
            return ExitCode::FAILURE;
        }
    };
    // The Gateway connection waits out a host short of buffer space (`ENOBUFS`), as the
    // Gateway's own side does.
    let mut remote = vpn_platform::nobufs::Patient::new(remote);
    let mut local = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    match tokio::io::copy_bidirectional(&mut local, &mut remote).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            stderr_line(&format!("vpn-manager: 連線中斷：{e}"));
            ExitCode::FAILURE
        }
    }
}
