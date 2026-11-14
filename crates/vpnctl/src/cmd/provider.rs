//! `vpnctl provider-egress inspect|switch|disable|enable|bootstrap|rebootstrap`,
//! `vpnctl provider check <account>`, `vpnctl provider account add|remove` and
//! `vpnctl provider ports list|reserve|delete|edit|test|ddns|free <account>` (`AirVPN`'s forwarded
//! ports, everything its Client Area's Ports page does). Every provider request leaves through
//! the one egress the user chose (the controller's provider API, the same as the web form's);
//! only the user switches or disables it, and the one-time direct bootstrap as well as a manual
//! rebootstrap (only while the egress cannot come back by itself) need an explicit flag.
//!
//! A credential is read from standard input only (never from arguments or the environment;
//! without echo on a terminal), goes once to the controller over `api.sock`, is verified with the
//! provider and kept only in the vault: nothing `vpnctl` prints contains it.

use clap::{Subcommand, ValueEnum};
use hyper::Method;
use serde::Serialize;
use vpn_domain::{
    AIRDNS_SUFFIX, ApiError, BootstrapKind, EgressMode, EgressPhase, ErrorCode, ForwardProtocol,
    ForwardedPort, ForwardedPortDdns, ForwardedPortInput, ForwardedPortSearch,
    ForwardedPortSession, ForwardedPortTest, ForwardedPortUpdate, ForwardedPorts, GateStatus,
    IpCheckStatus, IpFamily, PortIpLayer, PortTestState, ProviderAccount, ProviderEgressInput,
    ProviderEgressStatus, ProviderGateKind, ProviderKind, ProviderMatch, ProviderRebootstrapInput,
};

use super::{CmdResult, Ctx, Exit, Failure, instance};
use crate::client::Mutation;
use crate::output::{opt_time, short, table};

#[derive(Subcommand, Debug)]
pub enum EgressCmd {
    /// 目前的 Provider 出口與最近一次出口檢查
    Inspect,
    /// 把 Provider 出口改為指定的連線
    Switch {
        /// 名稱、ID 或 ID 開頭
        instance: String,
    },
    /// 停用 Provider 出口（之後不送出任何供應商請求）
    Disable,
    /// 啟用 Provider 出口
    Enable {
        /// 同時選擇出口連線
        #[arg(long)]
        instance: Option<String>,
    },
    /// 開啟一次性的首次直連（10 分鐘，只能連到供應商的固定網址）
    Bootstrap {
        /// 確認這次會經這台電腦的一般網路（不經 VPN）連到供應商
        #[arg(long)]
        allow_direct: bool,
    },
    /// 出口無法自行恢復時（金鑰遺失、伺服器一直沒有回應），以一般網路重新建立出口（10 分鐘，只限恢復出口的供應商操作）
    Rebootstrap {
        /// 確認這段時間供應商請求會經這台電腦的一般網路（不經 VPN）送出
        #[arg(long, conflicts_with = "cancel")]
        confirm_direct: bool,
        /// 取消進行中的重新直連（直連立即關閉，新連線不會成為出口）
        #[arg(long)]
        cancel: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProviderCmd {
    /// 經 Provider 出口重新向供應商確認帳號（到期日等）
    Check {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
    },
    /// 供應商帳號：add、remove
    #[command(subcommand)]
    Account(AccountCmd),
    /// `AirVPN` 的連入埠（forwarded ports）：list、reserve、delete、edit、test、ddns、free
    #[command(subcommand)]
    Ports(PortsCmd),
}

#[derive(Subcommand, Debug)]
pub enum PortsCmd {
    /// 列出 `AirVPN` 帳號保留的連入埠（經 Provider 出口登入 `AirVPN` 網站讀取）
    List {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
    },
    /// 保留一個連入埠：不指定 --port 時由 `AirVPN` 挑選（每個帳號最多 5 個）
    Reserve {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
        /// 指定的 port（2049–65535）
        #[arg(long)]
        port: Option<u16>,
    },
    /// 刪除一個連入埠：AirVPN 立即釋出，使用它的轉發不再收得到外部連入
    Delete {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
        port: u16,
        /// 確認刪除
        #[arg(long)]
        yes: bool,
    },
    /// 修改一個連入埠在 `AirVPN` 的設定：只送出有改變的項目，之後重新讀取確認
    #[command(
        after_help = "例：vpnctl provider ports edit 我的帳號 40000 --protocol tcp --ddns my-box --note 種子機
    清除備註或 DDNS 名稱：--note \"\" 或 --ddns \"\""
    )]
    Edit(PortEdit),
    /// 請 `AirVPN` 從每條使用這個埠的連線的伺服器測試它（只測 TCP，和 `AirVPN` 網站相同）
    Test {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
        port: u16,
    },
    /// `AirVPN` 的 DDNS 檢查：每個 DDNS 名稱指向幾條連線、應該解析到的位址
    Ddns {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
    },
    /// 請 `AirVPN` 找連續 n 個沒有人使用的埠（2–10；只是查詢，不會保留）
    Free {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
        #[arg(value_parser = clap::value_parser!(u8).range(2..=10))]
        count: u8,
    },
}

/// `vpnctl provider ports edit`: the settings to change; one left out stays as it is.
#[derive(clap::Args, Debug)]
pub struct PortEdit {
    /// 帳號名稱、ID 或 ID 開頭
    pub account: String,
    pub port: u16,
    /// 備註（一行，最多 200 字；空字串清除）
    #[arg(long)]
    pub note: Option<String>,
    /// 啟用這個埠
    #[arg(long, conflicts_with = "disabled")]
    pub enabled: bool,
    /// 停用這個埠（AirVPN 不再轉送它）
    #[arg(long)]
    pub disabled: bool,
    /// 只轉給哪台裝置：all（全部裝置）、裝置名稱或 ID
    #[arg(long)]
    pub device: Option<String>,
    /// 協定
    #[arg(long, value_enum)]
    pub protocol: Option<PortProtocol>,
    /// IP 版本
    #[arg(long, value_enum)]
    pub layer: Option<PortLayer>,
    /// Local port（1–65535）：VPN Manager 的轉發與 P2P 程式需要和公開的 port 相同
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub local: Option<u16>,
    /// DDNS 名稱（.airdns.org 之前的部分：英文字母、數字、連字號，最多 60 字；空字串清除）
    #[arg(long)]
    pub ddns: Option<String>,
}

/// `--protocol` of `ports edit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PortProtocol {
    /// TCP＋UDP
    Both,
    /// 只有 TCP
    Tcp,
    /// 只有 UDP
    Udp,
}

/// `--layer` of `ports edit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PortLayer {
    /// IPv4＋IPv6
    Both,
    /// 只有 IPv4
    #[value(alias = "ipv4")]
    V4,
    /// 只有 IPv6
    #[value(alias = "ipv6")]
    V6,
}

/// Providers whose accounts can be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AccountProvider {
    Mullvad,
    Airvpn,
}

#[derive(Subcommand, Debug)]
pub enum AccountCmd {
    /// 加入供應商帳號：憑證只從標準輸入讀取（終端機上不回顯），經 Provider 出口向供應商驗證後只存入金鑰保管庫
    #[command(
        after_help = "憑證不接受命令列參數或環境變數（其他程式與 shell 紀錄看得到）。
例：vpnctl provider account add --provider mullvad --label 家裡 < 帳號號碼檔
    AirVPN：第一行使用者名稱、第二行密碼"
    )]
    Add {
        /// 供應商
        #[arg(long, value_enum)]
        provider: AccountProvider,
        /// 顯示名稱（預設為供應商名稱）
        #[arg(long)]
        label: Option<String>,
    },
    /// 移除供應商帳號：只刪除這台電腦上的帳號與憑證，供應商那邊的帳號與裝置不受影響
    Remove {
        /// 帳號名稱、ID 或 ID 開頭
        account: String,
        /// 確認移除
        #[arg(long)]
        yes: bool,
    },
}

/// `POST /v1/provider-accounts`, borrowing the credential (serialized once, into the request).
#[derive(Serialize)]
struct AccountBody<'a> {
    label: &'a str,
    credential: CredentialBody<'a>,
}

#[derive(Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
enum CredentialBody<'a> {
    Mullvad {
        account_number: &'a str,
    },
    Airvpn {
        username: &'a str,
        password: &'a str,
    },
}

const fn phase(p: EgressPhase) -> &'static str {
    match p {
        EgressPhase::Unconfigured => "還沒有 Provider 出口",
        EgressPhase::BootstrapDirect => "首次直連中（不經 VPN）",
        EgressPhase::StartingInstance => "出口連線啟動中",
        EgressPhase::Switching => "等待新連線成為出口",
        EgressPhase::VpnReady => "經 VPN 出口",
        EgressPhase::Blocked => "出口連線無法使用",
        EgressPhase::RecoveryRequired => "出口需要恢復（無法自行恢復）",
        EgressPhase::Disabled => "Provider 出口已停用",
    }
}

const fn matched(m: ProviderMatch) -> &'static str {
    match m {
        ProviderMatch::Match => "供應商確認是它的出口",
        ProviderMatch::Other => "供應商確認不是它的出口",
        ProviderMatch::Unknown => "無法確認屬於哪個供應商",
    }
}

fn describe(ctx: &Ctx, s: &ProviderEgressStatus) {
    let selected = match (&s.selected_instance_name, s.egress.selected_instance_id) {
        (Some(n), Some(id)) => format!("{n}（{}）", short(&id)),
        (None, Some(id)) => short(&id),
        _ => "未選擇".into(),
    };
    ctx.out.line(format!("Provider 出口：{}", phase(s.phase)));
    ctx.out.line(format!(
        "  出口連線：{selected}{}",
        s.selected_generation
            .map_or_default(|g| format!("，第 {g} 代"))
    ));
    let rebootstrap = s
        .bootstrap
        .as_ref()
        .filter(|r| r.kind == BootstrapKind::Rebootstrap && r.stage.is_active());
    match (rebootstrap, &s.bootstrap_expires_at) {
        (Some(_), Some(t)) => ctx.out.line(format!(
            "  重新直連：開放中，到 {}（只限恢復出口的供應商操作，不經 VPN）",
            opt_time(Some(t))
        )),
        _ => ctx.out.line(format!(
            "  首次直連：{}",
            if s.egress.bootstrap_consumed {
                "已用過，不會再開放".to_string()
            } else {
                s.bootstrap_expires_at.as_ref().map_or_else(
                    || "尚未使用".into(),
                    |t| format!("開放中，到 {}", opt_time(Some(t))),
                )
            }
        )),
    }
    if let Some(r) = &s.reason {
        ctx.out.line(format!("  {}", r.zh_tw));
    }
    if let Some(r) = &s.recovery
        && s.reason.as_ref() != Some(&r.reason)
    {
        ctx.out.line(format!("  {}", r.reason.zh_tw));
    }
    if let Some(r) = &s.recovery {
        ctx.out.line(if r.rebootstrap_eligible {
            "  可以重新直連：vpnctl provider-egress rebootstrap --confirm-direct".to_string()
        } else {
            format!("  不能重新直連（{}）", r.reason_code)
        });
    }
    if let Some(c) = &s.last_check {
        match c.status {
            IpCheckStatus::Ok => ctx.out.line(format!(
                "  最近檢查：{} {}，{}（{}，{}）",
                c.observed_ip.as_deref().unwrap_or("—"),
                [c.country.as_deref(), c.city.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" "),
                matched(c.provider_match),
                if c.tunnel_verified {
                    "經 tunnel"
                } else {
                    "未經 VPN"
                },
                opt_time(c.checked_at.as_ref())
            )),
            _ => ctx.out.line(format!(
                "  最近檢查失敗：{}",
                c.reason_code.as_deref().unwrap_or("無法完成")
            )),
        }
        // Each function of that provider on its own: one passing says nothing of another.
        let gates: Vec<String> = s
            .gates
            .iter()
            .filter(|g| g.provider == c.provider)
            .map(|g| format!("{} {}", gate_name(g.gate), gate_status(g.status)))
            .collect();
        if !gates.is_empty() {
            ctx.out.line(format!("  功能檢查：{}", gates.join("、")));
        }
    }
}

const fn gate_name(g: ProviderGateKind) -> &'static str {
    match g {
        ProviderGateKind::ExitCheck => "出口檢查",
        ProviderGateKind::Membership => "出口歸屬",
        ProviderGateKind::Ipv6 => "IPv6 出口",
        ProviderGateKind::ConfigGenerator => "產生連線設定",
        ProviderGateKind::Forward => "轉發 port 保留",
    }
}

const fn gate_status(s: GateStatus) -> &'static str {
    match s {
        GateStatus::Passed => "通過",
        GateStatus::Failed => "未通過",
        GateStatus::Blocked => "無法代辦",
        GateStatus::NotApplicable => "不適用",
        GateStatus::Unverified => "尚未確認",
    }
}

async fn status(ctx: &Ctx) -> Result<ProviderEgressStatus, Failure> {
    ctx.client.get("/v1/provider-egress").await
}

async fn put(ctx: &Ctx, input: ProviderEgressInput, what: &str) -> CmdResult {
    let current = status(ctx).await?;
    let done: Mutation<ProviderEgressStatus> = ctx
        .client
        .mutate(
            Method::PUT,
            "/v1/provider-egress",
            Some(&input),
            Some(current.egress.revision),
        )
        .await?;
    match done {
        Mutation::Done(Some(s)) => {
            ctx.out.json(&s);
            ctx.out.line(format!("已{what}。"));
            describe(ctx, &s);
            Ok(Exit::Ok)
        }
        Mutation::Done(None) => Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示已{what}（operation {}）。",
                op.id
            ));
            Ok(Exit::Ok)
        }
    }
}

pub async fn run_egress(ctx: &Ctx, cmd: EgressCmd) -> CmdResult {
    match cmd {
        EgressCmd::Inspect => {
            let s = status(ctx).await?;
            ctx.out.json(&s);
            describe(ctx, &s);
            Ok(Exit::Ok)
        }
        EgressCmd::Switch { instance: q } => {
            let v = instance(ctx, &q).await?;
            put(
                ctx,
                ProviderEgressInput {
                    desired_mode: EgressMode::ViaInstance,
                    selected_instance_id: Some(v.spec.id),
                },
                &format!("把 Provider 出口改為「{}」", v.spec.name),
            )
            .await
        }
        EgressCmd::Disable => {
            put(
                ctx,
                ProviderEgressInput {
                    desired_mode: EgressMode::Disabled,
                    selected_instance_id: None,
                },
                "停用 Provider 出口",
            )
            .await
        }
        EgressCmd::Enable { instance: q } => {
            let selected = match q {
                Some(q) => Some(instance(ctx, &q).await?.spec.id),
                None => None,
            };
            put(
                ctx,
                ProviderEgressInput {
                    desired_mode: EgressMode::ViaInstance,
                    selected_instance_id: selected,
                },
                "啟用 Provider 出口",
            )
            .await
        }
        EgressCmd::Bootstrap { allow_direct } => {
            if !allow_direct {
                return Err(Failure::Usage(
                    "首次直連會經這台電腦的一般網路（不經 VPN）連到供應商的固定網址，最多 10 分鐘，而且只能用一次。確定要開啟，請加上 --allow-direct".into(),
                ));
            }
            let done: Mutation<ProviderEgressStatus> = ctx
                .client
                .mutate(
                    Method::POST,
                    "/v1/provider-egress/bootstrap",
                    Some(&serde_json::json!({})),
                    None,
                )
                .await?;
            egress_changed(ctx, done, "已開啟首次直連。", "首次直連已開啟")
        }
        EgressCmd::Rebootstrap {
            confirm_direct: _,
            cancel: true,
        } => {
            let done: Mutation<ProviderEgressStatus> = ctx
                .client
                .mutate(
                    Method::DELETE,
                    "/v1/provider-egress/rebootstrap",
                    None::<&()>,
                    None,
                )
                .await?;
            egress_changed(ctx, done, "已取消重新直連；直連已關閉。", "已取消重新直連")
        }
        EgressCmd::Rebootstrap {
            confirm_direct,
            cancel: false,
        } => rebootstrap(ctx, confirm_direct).await,
    }
}

/// `provider-egress rebootstrap`: open the direct path again, when the egress is eligible.
async fn rebootstrap(ctx: &Ctx, confirm_direct: bool) -> CmdResult {
    let current = status(ctx).await?;
    if let Some(r) = current
        .recovery
        .as_ref()
        .filter(|r| !r.rebootstrap_eligible)
    {
        return Err(Failure::Api(ApiError::new(
            ErrorCode::RebootstrapNotEligible,
            format!("不能重新直連：{}", r.reason.zh_tw),
        )));
    }
    if !confirm_direct {
        return Err(Failure::Usage(
            "重新直連會讓供應商請求（帳號、裝置、伺服器清單、建立一條新的出口連線）經這台電腦的一般網路（不經 VPN）送出，最多 10 分鐘。確定要開啟，請加上 --confirm-direct".into(),
        ));
    }
    let done: Mutation<ProviderEgressStatus> = ctx
        .client
        .mutate(
            Method::POST,
            "/v1/provider-egress/rebootstrap",
            Some(&ProviderRebootstrapInput {
                confirm_direct: true,
            }),
            Some(current.egress.revision),
        )
        .await?;
    egress_changed(
        ctx,
        done,
        "已開啟重新直連：10 分鐘內可以用供應商帳號建立一條新的出口連線，它連上後自動成為出口，直連隨即關閉。",
        "重新直連已開啟",
    )
}

/// Reports a change of the Provider egress: `done` (then the status), or, when the answer was
/// lost, that the operation's record shows `recorded`.
fn egress_changed(
    ctx: &Ctx,
    done: Mutation<ProviderEgressStatus>,
    done_line: &str,
    recorded: &str,
) -> CmdResult {
    match done {
        Mutation::Done(Some(s)) => {
            ctx.out.json(&s);
            ctx.out.line(done_line);
            describe(ctx, &s);
            Ok(Exit::Ok)
        }
        Mutation::Done(None) => Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示{recorded}（operation {}）。",
                op.id
            ));
            Ok(Exit::Ok)
        }
    }
}

const fn provider_name(p: ProviderKind) -> &'static str {
    match p {
        ProviderKind::Mullvad => "Mullvad",
        ProviderKind::Airvpn => "AirVPN",
        ProviderKind::Generic => "一般",
    }
}

async fn accounts(ctx: &Ctx) -> Result<Vec<ProviderAccount>, Failure> {
    ctx.client.get("/v1/provider-accounts").await
}

fn expiry(a: &ProviderAccount) -> String {
    format!("到期日：{}", opt_time(a.expires_at.as_ref()))
}

/// `vpnctl provider account add`: the credential from standard input, through the controller.
async fn add(ctx: &Ctx, provider: AccountProvider, label: Option<String>) -> CmdResult {
    let kind = match provider {
        AccountProvider::Mullvad => ProviderKind::Mullvad,
        AccountProvider::Airvpn => ProviderKind::Airvpn,
    };
    let label = label.unwrap_or_else(|| provider_name(kind).to_string());
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 64 || label.chars().any(char::is_control) {
        return Err(Failure::Usage("--label 需要 1–64 個字元".into()));
    }
    let typed = match provider {
        AccountProvider::Mullvad => {
            crate::prompt::secrets(&[("Mullvad 帳號號碼（不會顯示）：", "Mullvad 帳號號碼")])?
        }
        AccountProvider::Airvpn => crate::prompt::secrets(&[
            ("AirVPN 使用者名稱（不會顯示）：", "AirVPN 使用者名稱"),
            ("AirVPN 密碼（不會顯示）：", "AirVPN 密碼"),
        ])?,
    };
    let credential = match (provider, typed.as_slice()) {
        (AccountProvider::Mullvad, [number]) if !number.trim().is_empty() => {
            CredentialBody::Mullvad {
                account_number: number.trim(),
            }
        }
        (AccountProvider::Airvpn, [user, password])
            if !user.trim().is_empty() && !password.is_empty() =>
        {
            CredentialBody::Airvpn {
                username: user.trim(),
                password: password.as_str(),
            }
        }
        _ => return Err(Failure::Usage("沒有輸入憑證，沒有送出".into())),
    };
    if crate::prompt::stdin_is_terminal() {
        eprintln!("經 Provider 出口向 {} 驗證中…", provider_name(kind));
    }
    let body = AccountBody { label, credential };
    let done: Mutation<ProviderAccount> = ctx
        .client
        .mutate(Method::POST, "/v1/provider-accounts", Some(&body), None)
        .await?;
    drop(typed);
    let a = match done {
        Mutation::Done(Some(a)) => a,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        // The answer was lost, but the operation says it was added: read it back.
        Mutation::Recovered(op) => {
            let id = op
                .result_refs
                .first()
                .ok_or_else(|| Failure::Invalid("操作紀錄沒有帳號 ID".into()))?;
            ctx.client
                .get(&format!("/v1/provider-accounts/{id}"))
                .await?
        }
    };
    ctx.out.json(&a);
    ctx.out.line(format!(
        "已加入 {} 帳號「{}」（{}）：供應商已確認，憑證只存在金鑰保管庫",
        provider_name(a.provider),
        a.label,
        short(&a.id)
    ));
    ctx.out.line(format!("  {}", expiry(&a)));
    Ok(Exit::Ok)
}

/// `vpnctl provider account remove`: this computer's account and credential only.
async fn remove(ctx: &Ctx, q: &str, yes: bool) -> CmdResult {
    let all = accounts(ctx).await?;
    let a = crate::resolve::pick(
        &all,
        q,
        "供應商帳號",
        |a| a.id.to_string(),
        |a| a.label.clone(),
    )?;
    if !yes {
        return Err(Failure::Usage(format!(
            "會移除 {} 帳號「{}」與它在這台電腦保存的憑證；供應商那邊的帳號與裝置不受影響，用它建立的 WireGuard 設定仍在時會被拒絕。\n確定要移除，請加上 --yes",
            provider_name(a.provider),
            a.label
        )));
    }
    let done: Mutation<serde_json::Value> = ctx
        .client
        .mutate(
            Method::DELETE,
            &format!("/v1/provider-accounts/{}", a.id),
            None::<&()>,
            Some(a.meta.revision),
        )
        .await?;
    match &done {
        Mutation::Recovered(op) => ctx.out.json(op),
        Mutation::Done(_) => ctx.out.json(&serde_json::json!({ "deleted": a.id })),
    }
    ctx.out.line(format!(
        "已移除 {} 帳號「{}」（這台電腦上的帳號與憑證）",
        provider_name(a.provider),
        a.label
    ));
    Ok(Exit::Ok)
}

const fn port_protocol(p: ForwardProtocol) -> &'static str {
    match p {
        ForwardProtocol::Tcp => "TCP",
        ForwardProtocol::Udp => "UDP",
        ForwardProtocol::Both => "TCP＋UDP",
    }
}

fn ip_layer(l: &str) -> String {
    match l {
        "both" => "IPv4＋IPv6".into(),
        "ipv4" => "IPv4".into(),
        "ipv6" => "IPv6".into(),
        other => other.into(),
    }
}

/// The columns of [`port_row`].
const PORT_COLUMNS: [&str; 6] = ["port", "協定", "IP", "裝置", "狀態", "備註"];

/// One port as a table row: where it arrives, for which device, and what is unusual about it.
fn port_row(p: &ForwardedPort) -> Vec<String> {
    let mut notes = Vec::new();
    if p.local_port != p.port {
        notes.push(format!("轉到 local port {}", p.local_port));
    }
    if let Some(d) = &p.dns_name {
        notes.push(format!("DDNS {d}{AIRDNS_SUFFIX}"));
    }
    if let Some(n) = &p.notes {
        notes.push(n.clone());
    }
    vec![
        p.port.to_string(),
        port_protocol(p.protocol).into(),
        ip_layer(&p.ip_layer),
        match (&p.device_id, &p.device_name) {
            (None, _) => "全部裝置".into(),
            (Some(_), Some(name)) => name.clone(),
            (Some(id), None) => short(id),
        },
        if p.enabled { "啟用" } else { "停用" }.into(),
        if notes.is_empty() {
            "—".into()
        } else {
            notes.join("；")
        },
    ]
}

/// The `AirVPN` account a command names; any other provider is a usage error with the reason.
async fn airvpn_account(ctx: &Ctx, q: &str) -> Result<ProviderAccount, Failure> {
    let all = accounts(ctx).await?;
    let a = crate::resolve::pick(
        &all,
        q,
        "供應商帳號",
        |a| a.id.to_string(),
        |a| a.label.clone(),
    )?
    .clone();
    if a.provider != ProviderKind::Airvpn {
        return Err(Failure::Usage(format!(
            "「{}」是 {} 帳號：只有 AirVPN 帳號有可以保留的連入埠{}",
            a.label,
            provider_name(a.provider),
            if a.provider == ProviderKind::Mullvad {
                "（Mullvad 已停止提供 port forwarding）"
            } else {
                ""
            }
        )));
    }
    Ok(a)
}

/// The account's forwarded ports in the API.
fn ports_path(a: &ProviderAccount) -> String {
    format!("/v1/provider-accounts/{}/forwarded-ports", a.id)
}

/// `ip:port`, an IPv6 address in brackets.
fn endpoint(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// What `AirVPN`'s test of one session said, in words (never "open" for a word it did not say).
fn test_state(s: &ForwardedPortSession) -> String {
    match s.state {
        PortTestState::Open => "連得進來".into(),
        PortTestState::Closed => "連不進來".into(),
        PortTestState::Warning => "有警告".into(),
        PortTestState::Unknown => {
            format!("結果不明（AirVPN：{}）", s.word.as_deref().unwrap_or("—"))
        }
        PortTestState::NotTested => "沒有測試".into(),
    }
}

/// One session of a port test as a table row.
fn session_row(s: &ForwardedPortSession) -> Vec<String> {
    let place: Vec<String> = [
        s.server_location.clone(),
        s.server_country.as_deref().map(str::to_ascii_uppercase),
    ]
    .into_iter()
    .flatten()
    .collect();
    let server = match (&s.server_name, place.is_empty()) {
        (Some(name), false) => format!("{name}（{}）", place.join(" ")),
        (Some(name), true) => name.clone(),
        (None, false) => place.join(" "),
        (None, true) => "—".into(),
    };
    vec![
        server,
        endpoint(&s.server_ip, s.port),
        s.client_ip.as_deref().map_or_else(
            || format!("port {}", s.local_port),
            |ip| endpoint(ip, s.local_port),
        ),
        format!(
            "{} {}",
            port_protocol(s.protocol),
            match s.ip_layer {
                IpFamily::Ipv4 => "IPv4",
                IpFamily::Ipv6 => "IPv6",
            }
        ),
        test_state(s),
        (s.message.clone().unwrap_or_else(|| "—".into()))
            .zh_tw
            .clone(),
    ]
}

/// What a DDNS name's number of sessions means.
fn ddns_reach(sessions: u32) -> String {
    match sessions {
        0 => "沒有連線使用它的埠：名稱目前不指向任何地方".into(),
        1 => "指向 1 條連線".into(),
        n => format!("有 {n} 條連線使用它的埠：名稱有多個目的地"),
    }
}

/// `vpnctl provider ports edit`: only the settings named, each saved at `AirVPN` and read back.
async fn edit_port(ctx: &Ctx, e: PortEdit) -> CmdResult {
    let a = airvpn_account(ctx, &e.account).await?;
    let device = match e.device.as_deref().map(str::trim) {
        None => None,
        Some(d) if d.eq_ignore_ascii_case("all") => Some("all".to_owned()),
        Some(d) => {
            let list: ForwardedPorts = ctx.client.get(&ports_path(&a)).await?;
            let picked = crate::resolve::pick(
                &list.devices,
                d,
                "裝置",
                |d| d.id.clone(),
                |d| d.name.clone(),
            )?;
            Some(picked.id.clone())
        }
    };
    let update = ForwardedPortUpdate {
        notes: e.note,
        enabled: (e.enabled || e.disabled).then_some(e.enabled),
        device,
        protocol: e.protocol.map(|p| match p {
            PortProtocol::Both => ForwardProtocol::Both,
            PortProtocol::Tcp => ForwardProtocol::Tcp,
            PortProtocol::Udp => ForwardProtocol::Udp,
        }),
        ip_layer: e.layer.map(|l| match l {
            PortLayer::Both => PortIpLayer::Both,
            PortLayer::V4 => PortIpLayer::Ipv4,
            PortLayer::V6 => PortIpLayer::Ipv6,
        }),
        local_port: e.local,
        dns_name: e.ddns,
    };
    if update.is_empty() {
        return Err(Failure::Usage(
            "沒有要修改的設定：加上 --note、--enabled／--disabled、--device、--protocol、--layer、--local 或 --ddns".into(),
        ));
    }
    let port = e.port;
    let done: Mutation<ForwardedPort> = ctx
        .client
        .mutate(
            Method::PATCH,
            &format!("{}/{port}", ports_path(&a)),
            Some(&update),
            None,
        )
        .await?;
    let p = match done {
        Mutation::Done(Some(p)) => p,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示已修改連入埠 {port} 的設定（operation {}）；用 vpnctl provider ports list {} 查看",
                op.id, a.label
            ));
            return Ok(Exit::Ok);
        }
    };
    ctx.out.json(&p);
    ctx.out.line(format!(
        "已在 AirVPN 修改連入埠 {port} 的設定，重新讀取的結果："
    ));
    ctx.out.line(table(&PORT_COLUMNS, &[port_row(&p)]));
    if p.local_port != p.port {
        ctx.out.line(format!(
            "  注意：AirVPN 會把 {0} 轉到 local port {1}。VPN Manager 的轉發與 P2P 程式需要和公開的 port 相同；要改回請用 --local {0}",
            p.port, p.local_port
        ));
    }
    Ok(Exit::Ok)
}

/// `vpnctl provider ports test`: `AirVPN`'s own test from each session's server.
async fn test_port(ctx: &Ctx, account: &str, port: u16) -> CmdResult {
    let a = airvpn_account(ctx, account).await?;
    if crate::prompt::stdin_is_terminal() {
        eprintln!("請 AirVPN 從伺服器測試連入埠 {port}（每條連線最多約 15 秒）…");
    }
    let t: ForwardedPortTest = ctx
        .client
        .post(&format!("{}/{port}/test", ports_path(&a)))
        .await?;
    ctx.out.json(&t);
    if t.sessions.is_empty() {
        ctx.out.line(format!(
            "目前沒有 AirVPN 連線使用連入埠 {port}，沒有東西可以測試。\n  先用帳號「{}」建立並啟動一條連線，讓程式在 {port} 監聽（或建立轉發到受管 App），再測一次。",
            a.label
        ));
        return Ok(Exit::Ok);
    }
    let rows: Vec<Vec<String>> = t.sessions.iter().map(session_row).collect();
    ctx.out.line(format!(
        "AirVPN 從伺服器測試連入埠 {port}（{}）：",
        opt_time(Some(&t.observed_at))
    ));
    ctx.out.line(table(
        &[
            "伺服器",
            "外部連到",
            "送到",
            "協定",
            "結果",
            "AirVPN 的說明",
        ],
        &rows,
    ));
    Ok(Exit::Ok)
}

/// `vpnctl provider ports list|reserve|delete|edit|test|ddns|free`: `AirVPN`'s forwarded ports
/// through the controller, which signs in to `AirVPN`'s website over the Provider egress.
/// `ports ddns`: `AirVPN`'s DDNS check of the account's ports.
async fn ddns(ctx: &Ctx, account: &str) -> CmdResult {
    let a = airvpn_account(ctx, account).await?;
    let report: ForwardedPortDdns = ctx.client.get(&format!("{}/ddns", ports_path(&a))).await?;
    ctx.out.json(&report);
    if report.names.is_empty() {
        ctx.out.line(format!(
            "帳號「{0}」的連入埠都沒有 DDNS 名稱：用 vpnctl provider ports edit {0} <port> --ddns <名稱> 設定",
            a.label
        ));
        return Ok(Exit::Ok);
    }
    let rows: Vec<Vec<String>> = report
        .names
        .iter()
        .map(|n| {
            vec![
                format!("{}{AIRDNS_SUFFIX}", n.name),
                ddns_reach(n.sessions),
                n.ipv4.clone().unwrap_or_else(|| "—".into()),
                n.ipv6.clone().unwrap_or_else(|| "—".into()),
            ]
        })
        .collect();
    ctx.out.line(format!(
        "AirVPN 的 DDNS 檢查（{}）：",
        opt_time(Some(&report.observed_at))
    ));
    ctx.out.line(table(
        &["名稱", "指向", "應解析到的 IPv4", "應解析到的 IPv6"],
        &rows,
    ));
    Ok(Exit::Ok)
}

/// `ports reserve`: reserve `port`, or one `AirVPN` picks.
async fn reserve(ctx: &Ctx, account: &str, port: Option<u16>) -> CmdResult {
    let a = airvpn_account(ctx, account).await?;
    if port.is_some_and(|p| p < 2049) {
        return Err(Failure::Usage(
            "--port 必須是 2049–65535（AirVPN 不接受更小的 port）".into(),
        ));
    }
    let done: Mutation<ForwardedPort> = ctx
        .client
        .mutate(
            Method::POST,
            &ports_path(&a),
            Some(&ForwardedPortInput { port }),
            None,
        )
        .await?;
    let reserved = match done {
        Mutation::Done(Some(p)) => p,
        Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
        Mutation::Recovered(op) => {
            ctx.out.json(&op);
            ctx.out.line(format!(
                "沒有收到回應，但紀錄顯示已保留連入埠 {}（operation {}）；用 vpnctl provider ports list {} 查看",
                op.result_refs.first().map_or("—", String::as_str),
                op.id,
                a.label
            ));
            return Ok(Exit::Ok);
        }
    };
    ctx.out.json(&reserved);
    ctx.out.line(format!(
        "已在 AirVPN 保留連入埠 {}（{}）：轉發的 tunnel port 填 {}、公開 port 填 {}，App 也要在 {} 監聽",
        reserved.port,
        port_protocol(reserved.protocol),
        reserved.local_port,
        reserved.port,
        reserved.port
    ));
    Ok(Exit::Ok)
}

async fn run_ports(ctx: &Ctx, cmd: PortsCmd) -> CmdResult {
    match cmd {
        PortsCmd::Edit(e) => edit_port(ctx, e).await,
        PortsCmd::Test { account, port } => test_port(ctx, &account, port).await,
        PortsCmd::Ddns { account } => ddns(ctx, &account).await,
        PortsCmd::Free { account, count } => {
            let a = airvpn_account(ctx, &account).await?;
            let found: ForwardedPortSearch = ctx
                .client
                .get(&format!("{}/free?count={count}", ports_path(&a)))
                .await?;
            ctx.out.json(&found);
            ctx.out.line(format!(
                "AirVPN（找 {count} 個連續的空閒埠）：{}",
                found.message
            ));
            ctx.out.line(format!(
                "  只是查詢，沒有保留；要保留請用 vpnctl provider ports reserve {} --port <port>（每個帳號最多 5 個）",
                a.label
            ));
            Ok(Exit::Ok)
        }
        PortsCmd::List { account } => {
            let a = airvpn_account(ctx, &account).await?;
            let list: ForwardedPorts = ctx.client.get(&ports_path(&a)).await?;
            ctx.out.json(&list);
            ctx.out.line(format!(
                "AirVPN 帳號「{}」的連入埠：已用 {}／{} 個（所有 AirVPN 伺服器相同；P2P 程式要在同一個 port 監聽）",
                a.label,
                list.ports.len(),
                list.limit
            ));
            if list.ports.is_empty() {
                ctx.out.line(format!(
                    "  還沒有保留任何連入埠：vpnctl provider ports reserve {} [--port {}–65535]",
                    a.label, list.min_port
                ));
            } else {
                let rows: Vec<Vec<String>> = list.ports.iter().map(port_row).collect();
                ctx.out.line(table(&PORT_COLUMNS, &rows));
            }
            Ok(Exit::Ok)
        }
        PortsCmd::Reserve { account, port } => reserve(ctx, &account, port).await,
        PortsCmd::Delete { account, port, yes } => {
            let a = airvpn_account(ctx, &account).await?;
            if !yes {
                return Err(Failure::Usage(format!(
                    "會在 AirVPN 刪除帳號「{}」的連入埠 {port}：AirVPN 立即釋出它，使用它的轉發不再收得到外部連入，之後也不一定能再保留到同一個 port。\n確定要刪除，請加上 --yes",
                    a.label
                )));
            }
            let done: Mutation<serde_json::Value> = ctx
                .client
                .mutate(
                    Method::DELETE,
                    &format!("{}/{port}", ports_path(&a)),
                    None::<&()>,
                    None,
                )
                .await?;
            match &done {
                Mutation::Recovered(op) => ctx.out.json(op),
                Mutation::Done(_) => ctx.out.json(&serde_json::json!({ "deleted": port })),
            }
            ctx.out.line(format!(
                "已在 AirVPN 刪除帳號「{}」的連入埠 {port}",
                a.label
            ));
            Ok(Exit::Ok)
        }
    }
}

pub async fn run_provider(ctx: &Ctx, cmd: ProviderCmd) -> CmdResult {
    match cmd {
        ProviderCmd::Ports(c) => run_ports(ctx, c).await,
        ProviderCmd::Account(AccountCmd::Add { provider, label }) => {
            add(ctx, provider, label).await
        }
        ProviderCmd::Account(AccountCmd::Remove { account, yes }) => {
            remove(ctx, &account, yes).await
        }
        ProviderCmd::Check { account } => {
            let all = accounts(ctx).await?;
            let a = crate::resolve::pick(
                &all,
                &account,
                "供應商帳號",
                |a| a.id.to_string(),
                |a| a.label.clone(),
            )?;
            let done: Mutation<ProviderAccount> = ctx
                .client
                .mutate(
                    Method::POST,
                    &format!("/v1/provider-accounts/{}/refresh", a.id),
                    Some(&serde_json::json!({})),
                    None,
                )
                .await?;
            let checked = match done {
                Mutation::Done(Some(a)) => a,
                Mutation::Done(None) => return Err(Failure::Invalid("沒有回應內容".into())),
                Mutation::Recovered(_) => {
                    ctx.client
                        .get(&format!("/v1/provider-accounts/{}", a.id))
                        .await?
                }
            };
            ctx.out.json(&checked);
            ctx.out.line(format!(
                "{} 帳號「{}」：已向供應商確認（{}）",
                provider_name(checked.provider),
                checked.label,
                opt_time(checked.observed_at.as_ref())
            ));
            ctx.out.line(format!("  {}", expiry(&checked)));
            Ok(Exit::Ok)
        }
    }
}
