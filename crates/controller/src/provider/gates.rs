//! Each provider's function gates (spec AC-114), each recorded on its own.
//!
//! The gates are the exit checker's answer, membership, IPv6, settings generated from the
//! account, and port forwards. One gate
//! passing never moves another — an `IPLeak` observation (a generic profile's exit check) passing
//! leaves every `AirVPN` gate where it was, and an IPv4 check says nothing about IPv6.
//!
//! Kept in memory like the latest check (the controller holds no durable state); a gate never
//! observed shows what this build knows about it, as `unverified`, `blocked` or
//! `not_applicable` with the reason.

use std::collections::HashMap;

use vpn_domain::{
    GateStatus, InstanceId, IpCheckStatus, ProviderGate, ProviderGateKind, ProviderIpCheck,
    ProviderKind, ProviderMatch, RouteMode, Text, Timestamp, tr,
};

pub const PROVIDERS: [ProviderKind; 3] = [
    ProviderKind::Airvpn,
    ProviderKind::Mullvad,
    ProviderKind::Generic,
];
pub const KINDS: [ProviderGateKind; 5] = [
    ProviderGateKind::ExitCheck,
    ProviderGateKind::Membership,
    ProviderGateKind::Ipv6,
    ProviderGateKind::ConfigGenerator,
    ProviderGateKind::Forward,
];

const fn name(p: ProviderKind) -> &'static str {
    match p {
        ProviderKind::Airvpn => "AirVPN",
        ProviderKind::Mullvad => "Mullvad",
        ProviderKind::Generic => "IPLeak",
    }
}

/// The exit checker of a provider's profiles, as the user knows it.
#[must_use]
pub const fn checker_name(p: ProviderKind) -> &'static str {
    match p {
        ProviderKind::Airvpn => "AirVPN whatismyip",
        ProviderKind::Mullvad => "Mullvad am.i.mullvad.net",
        ProviderKind::Generic => "IPLeak",
    }
}

/// Why a generic profile's exit is not checked over IPv6: `IPLeak` has no verified IPv6 check.
#[must_use]
pub fn ipleak_ipv6() -> Text {
    tr!(
        "IPLeak's IPv6 check is not verified yet (AIR-IPV6-01); the IPv6 exit of a generic configuration file is not checked",
        "IPLeak 的 IPv6 檢查尚未驗證（AIR-IPV6-01），一般設定檔的 IPv6 出口不檢查",
        "IPLeak の IPv6 チェックはまだ検証されていません（AIR-IPV6-01）。汎用設定ファイルの IPv6 出口はチェックしません"
    )
}

/// A check that did not pass and says nothing more.
fn cannot_connect() -> Text {
    tr!("cannot connect", "無法連線", "接続できません")
}

/// What this build knows about a gate nobody has observed yet.
fn known(provider: ProviderKind, gate: ProviderGateKind) -> (GateStatus, Text) {
    use GateStatus::{NotApplicable, Unverified};
    use ProviderGateKind::{ConfigGenerator, ExitCheck, Forward, Ipv6, Membership};
    match (provider, gate) {
        (ProviderKind::Generic, Membership) => (
            NotApplicable,
            tr!(
                "IPLeak reports only the address and the place, not which provider the exit belongs to; it is never guessed from the country or the ISP",
                "IPLeak 只回報位址與地點，不提供供應商歸屬；不以國家或 ISP 推測",
                "IPLeak が報告するのはアドレスと場所だけで、プロバイダーへの帰属は示しません。国や ISP から推測することはありません"
            ),
        ),
        (ProviderKind::Generic, Ipv6) => (NotApplicable, ipleak_ipv6()),
        (ProviderKind::Generic, ConfigGenerator) => (
            NotApplicable,
            tr!(
                "A generic configuration file comes from an imported .conf, not from a provider",
                "一般設定檔來自匯入的 .conf，不由供應商產生",
                "汎用設定ファイルはインポートした .conf から作られ、プロバイダーが生成したものではありません"
            ),
        ),
        (ProviderKind::Generic, Forward) => (
            NotApplicable,
            tr!(
                "A generic configuration file has no port reservation at a provider; register a port you already reserved under “Port forwards”",
                "一般設定檔沒有供應商端的 port 保留；已保留的 port 在「轉發」登錄",
                "汎用設定ファイルにはプロバイダー側のポート予約がありません。予約済みのポートは「ポート転送」で登録します"
            ),
        ),
        (ProviderKind::Airvpn, Forward) => (
            Unverified,
            tr!(
                "The inbound ports have not been read from AirVPN's website yet: when you list or reserve them under “Inbound ports” on the account page, VPN Manager signs in to AirVPN's website with the account and does it for you; whether they are reachable from outside still depends on inbound connections actually observed",
                "還沒有經 AirVPN 網站讀取連入埠：在帳號頁的「連入埠」列出或保留時，VPN Manager 以帳號登入 AirVPN 網站代為操作；外部可達仍以實際觀測到的連入為準",
                "まだ AirVPN の Web サイトから着信ポートを読み取っていません。アカウントページの「着信ポート」で一覧表示や予約をすると、VPN Manager がそのアカウントで AirVPN の Web サイトにログインして代わりに操作します。外部から到達できるかどうかは、実際に観測された着信で判断します"
            ),
        ),
        (ProviderKind::Mullvad, Forward) => (
            NotApplicable,
            tr!(
                "Mullvad no longer offers port forwarding",
                "Mullvad 已停止提供 port forwarding",
                "Mullvad は port forwarding の提供を終了しました"
            ),
        ),
        (_, ExitCheck) => (
            Unverified,
            tr!(
                "Not checked by this provider's exit check yet",
                "尚未經這個供應商的出口檢查",
                "このプロバイダーの出口チェックはまだ行われていません"
            ),
        ),
        (_, Membership) => (
            Unverified,
            tr!(
                "Ownership has not been confirmed through this provider's exit yet",
                "尚未經這個供應商的出口確認歸屬",
                "このプロバイダーの出口で帰属をまだ確認していません"
            ),
        ),
        (_, Ipv6) => (
            Unverified,
            tr!(
                "The IPv6 exit has not been checked yet (it is checked separately when you choose “Check exit”)",
                "尚未檢查 IPv6 出口（按「檢查出口」時另外檢查）",
                "IPv6 出口はまだチェックしていません（「出口を確認」を押すと別途チェックします）"
            ),
        ),
        (_, ConfigGenerator) => (
            Unverified,
            tr!(
                "No connection settings have been generated from this account yet",
                "還沒有從這個帳號產生過連線設定",
                "このアカウントから接続設定をまだ生成していません"
            ),
        ),
    }
}

/// The latest record of every gate.
#[derive(Default)]
pub struct GateBook(HashMap<(ProviderKind, ProviderGateKind), ProviderGate>);

impl GateBook {
    pub fn record(
        &mut self,
        provider: ProviderKind,
        gate: ProviderGateKind,
        status: GateStatus,
        reason: impl Into<Text>,
        instance_id: Option<InstanceId>,
    ) {
        self.0.insert(
            (provider, gate),
            ProviderGate {
                provider,
                gate,
                status,
                reason: Some(reason.into()),
                observed_at: Some(Timestamp::now()),
                instance_id,
            },
        );
    }

    /// One record per provider and gate, observed or as this build knows it.
    #[must_use]
    pub fn all(&self) -> Vec<ProviderGate> {
        PROVIDERS
            .iter()
            .flat_map(|p| KINDS.iter().map(move |k| self.get(*p, *k)))
            .collect()
    }

    /// The gate as last observed, or as this build knows it.
    #[must_use]
    pub fn get(&self, provider: ProviderKind, gate: ProviderGateKind) -> ProviderGate {
        self.0.get(&(provider, gate)).cloned().unwrap_or_else(|| {
            let (status, reason) = known(provider, gate);
            ProviderGate {
                provider,
                gate,
                status,
                reason: Some(reason),
                observed_at: None,
                instance_id: None,
            }
        })
    }

    /// An IPv4 exit check: the checker's gate, and membership when the route is a provider's
    /// tunnel (the direct bootstrap is nobody's exit; `IPLeak` has no membership to record).
    /// `why`: why the check did not pass, in the three languages (its `reason_code` is plain
    /// text).
    pub fn ipv4_check(&mut self, c: &ProviderIpCheck, why: Option<&Text>) {
        let p = c.provider;
        let at = c.instance_id;
        let checker = checker_name(p);
        if c.status == IpCheckStatus::Ok {
            let ip = c.observed_ip.as_deref().unwrap_or("—");
            self.record(
                p,
                ProviderGateKind::ExitCheck,
                GateStatus::Passed,
                tr!(
                    "{checker} answered with exit {ip}",
                    "{checker} 回答了出口 {ip}",
                    "{checker} が出口 {ip} を返しました"
                ),
                at,
            );
        } else {
            self.record(
                p,
                ProviderGateKind::ExitCheck,
                GateStatus::Failed,
                tr!(
                    "{checker} did not answer: {why}",
                    "{checker} 沒有回答：{why}",
                    "{checker} から応答がありません：{why}";
                    why = why.cloned().unwrap_or_else(cannot_connect)
                ),
                at,
            );
        }
        if c.route_mode != RouteMode::ViaInstance || p == ProviderKind::Generic {
            return;
        }
        let provider = name(p);
        let (status, reason) = match (c.status, c.provider_match) {
            (IpCheckStatus::Ok, ProviderMatch::Match) => (
                GateStatus::Passed,
                tr!(
                    "{provider} confirms this exit is its own",
                    "{provider} 確認這個出口是它的",
                    "{provider} がこの出口は自社のものだと確認しました"
                ),
            ),
            (IpCheckStatus::Ok, ProviderMatch::Other) => (
                GateStatus::Failed,
                tr!(
                    "{provider} answers that this exit is not its own",
                    "{provider} 回答這個出口不是它的",
                    "{provider} はこの出口が自社のものではないと回答しました"
                ),
            ),
            (IpCheckStatus::Ok, ProviderMatch::Unknown) => (
                GateStatus::Unverified,
                tr!(
                    "{provider} did not say whom the exit belongs to",
                    "{provider} 沒有說明出口歸屬",
                    "{provider} は出口の帰属を示しませんでした"
                ),
            ),
            _ => (
                GateStatus::Unverified,
                tr!(
                    "The exit check did not finish, so ownership cannot be told this time",
                    "出口檢查沒有完成，這次無法判定歸屬",
                    "出口チェックが完了しなかったため、今回は帰属を判定できません"
                ),
            ),
        };
        self.record(p, ProviderGateKind::Membership, status, reason, at);
    }

    /// The IPv6 check of a connection, on its own: `None` when the connection has no IPv6
    /// address (then it does not apply), else that check's result and, when it did not pass,
    /// why (`why`, in the three languages).
    pub fn ipv6_check(
        &mut self,
        provider: ProviderKind,
        instance_id: Option<InstanceId>,
        check: Option<&ProviderIpCheck>,
        why: Option<&Text>,
    ) {
        let said = |c: &ProviderIpCheck| {
            why.cloned()
                .or_else(|| c.reason_code.clone().map(Text::from))
        };
        let (status, reason) = match check {
            None => (
                GateStatus::NotApplicable,
                tr!(
                    "This connection's settings have no IPv6 address; nothing is sent over IPv6",
                    "這條連線的設定沒有 IPv6 位址，不經 IPv6 送出",
                    "この接続の設定には IPv6 アドレスがないため、IPv6 では送信しません"
                ),
            ),
            Some(c) if c.status == IpCheckStatus::NotApplicable => {
                (GateStatus::NotApplicable, said(c).unwrap_or_default())
            }
            Some(c) if c.status != IpCheckStatus::Ok => (
                GateStatus::Failed,
                tr!(
                    "The IPv6 exit check failed: {why}",
                    "IPv6 出口檢查失敗：{why}",
                    "IPv6 の出口チェックに失敗しました：{why}";
                    why = said(c).unwrap_or_else(cannot_connect)
                ),
            ),
            Some(c) => {
                let ip = c.observed_ip.as_deref().unwrap_or("—");
                let provider = name(provider);
                match c.provider_match {
                    ProviderMatch::Match => (
                        GateStatus::Passed,
                        tr!(
                            "IPv6 exit {ip}, which {provider} confirms is its own",
                            "IPv6 出口 {ip}，{provider} 確認是它的",
                            "IPv6 出口 {ip}。{provider} が自社のものだと確認しました"
                        ),
                    ),
                    ProviderMatch::Other => (
                        GateStatus::Failed,
                        tr!(
                            "IPv6 exit {ip} is not {provider}'s",
                            "IPv6 出口 {ip} 不是 {provider} 的",
                            "IPv6 出口 {ip} は {provider} のものではありません"
                        ),
                    ),
                    ProviderMatch::Unknown => (
                        GateStatus::Unverified,
                        tr!(
                            "IPv6 exit {ip}; which provider it belongs to cannot be told",
                            "IPv6 出口 {ip}，無法判定屬於哪家供應商",
                            "IPv6 出口 {ip}。どのプロバイダーのものか判定できません"
                        ),
                    ),
                }
            }
        };
        self.record(
            provider,
            ProviderGateKind::Ipv6,
            status,
            reason,
            instance_id,
        );
    }
}
