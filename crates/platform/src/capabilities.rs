//! Honest capability detection for this host. Nothing is reported as supported unless this
//! build implements it and the host provides what it needs.

use vpn_domain::{Capability, CapabilityState, Text, tr};

fn cap(name: &str, state: CapabilityState, reason: Option<Text>) -> Capability {
    Capability {
        name: name.into(),
        state,
        reason,
    }
}

/// What this host offers. `strict`: the result of [`strict_netns`] (Linux), which also decides
/// whether managed Apps can run in a strict sandbox.
#[must_use]
pub fn detect(strict: Option<&Capability>) -> Vec<Capability> {
    let mut v = vec![
        cap("explicit_proxy", CapabilityState::Supported, None),
        cap("ipv6_tunnel", CapabilityState::Supported, None),
        cap(
            "secret_keystore",
            CapabilityState::Supported,
            Some(tr!(
                "VPN Manager keeps the master key itself: a key file in the data directory that only this user can read, independent of the system keychain",
                "主金鑰由 VPN Manager 自己保管：資料目錄內只有本使用者能讀的金鑰檔，不依賴系統鑰匙圈",
                "マスターキーは VPN Manager 自身が保管します。データディレクトリ内の、このユーザーだけが読める鍵ファイルで、システムのキーチェーンには依存しません"
            )),
        ),
        cap(
            "network_rate_limit",
            CapabilityState::Supported,
            Some(tr!(
                "The Gateway traffic of each connection can have download and upload limits (a token bucket in the worker, shared by every Gateway): TCP waits under the limit (backpressure, no data lost), and UDP packets over it are dropped and counted; DNS and management connections do not count",
                "每條連線的代理埠流量可設下載與上傳上限（worker 內的 token bucket，所有代理埠共用）：TCP 在上限下等待（背壓，不丟資料），超過上限的 UDP 封包會被丟棄並計數；DNS 與管理連線不計入",
                "接続ごとのゲートウェイのトラフィックに、ダウンロードとアップロードの上限を設定できます（worker 内のトークンバケットで、すべてのゲートウェイで共有）。TCP は上限内で待機し（バックプレッシャー、データは失われません）、上限を超えた UDP パケットは破棄されてカウントされます。DNS と管理用の接続は含まれません"
            )),
        ),
    ];
    #[cfg(target_os = "macos")]
    {
        v.push(cap(
            "managed_process_network",
            CapabilityState::Blocked,
            Some(tr!(
                "Enforced isolation with NetworkExtension needs a Developer ID signature and an entitlement (MAC-G1–G3)",
                "NetworkExtension 強制隔離需要 Developer ID 簽章與 entitlement（MAC-G1～G3）",
                "NetworkExtension による強制的な分離には、Developer ID の署名と entitlement が必要です（MAC-G1～G3）"
            )),
        ));
    }
    // Linux: managed Apps run in their connection's strict sandbox exactly when one can be
    // built here (measured, not assumed).
    let strict_apps =
        cfg!(target_os = "linux") && strict.is_some_and(|c| c.state == CapabilityState::Supported);
    #[cfg(target_os = "linux")]
    {
        let (state, reason): (CapabilityState, Text) = match strict {
            Some(c) if c.state == CapabilityState::Supported => (
                CapabilityState::Supported,
                tr!(
                    "Managed apps can use strict isolation: they run in their connection's rootless network namespace, with the tunnel as the only network interface",
                    "受管 App 可用嚴格隔離：在所屬連線的 rootless network namespace 內執行，只有 tunnel 一個網路介面",
                    "管理対象アプリで厳格な分離を使えます。所属する接続の rootless network namespace 内で実行され、ネットワークインターフェースはトンネルだけです"
                ),
            ),
            Some(c) => (
                c.state,
                c.reason.clone().unwrap_or_else(|| {
                    tr!(
                        "This host cannot build a strict isolation sandbox",
                        "此主機無法建立嚴格隔離 sandbox",
                        "このホストでは厳格な分離のサンドボックスを作成できません"
                    )
                }),
            ),
            None => (
                CapabilityState::Unverified,
                match linux_userns_available() {
                    Ok(()) => tr!(
                        "Whether this host can build a strict isolation sandbox has not been tested yet",
                        "尚未實測此主機能否建立嚴格隔離 sandbox",
                        "このホストで厳格な分離のサンドボックスを作成できるかは、まだ実際に確認していません"
                    ),
                    Err(r) => r,
                },
            ),
        };
        v.push(Capability {
            name: "managed_process_network".into(),
            state,
            reason: Some(reason),
        });
    }
    // Managed App isolation modes, one capability each (the App form is driven by them).
    let mut apps = crate::apps::capabilities(strict_apps);
    // A strict sandbox that cannot be built here: the App mode says why, as measured.
    if let Some(c) = strict.filter(|c| c.state != CapabilityState::Supported)
        && cfg!(target_os = "linux")
        && let Some(app) = apps.iter_mut().find(|a| a.name == "app_strict_netns")
    {
        app.state = c.state;
        app.reason.clone_from(&c.reason);
    }
    v.extend(apps);
    v.extend(forwards());
    v
}

/// Port forwards: where they may go, and the provider-side port reservation.
fn forwards() -> [Capability; 2] {
    [
        // Port forwards: the target check is the process table, not kernel bind enforcement.
        cap(
            "forwarded_app_endpoint",
            CapabilityState::Degraded,
            Some(tr!(
                "A port forward goes only to a managed app of the same connection: on every change of the app's state, and every 2 seconds, the manager checks that the app's process tree holds the target port on a local address, and revokes the forward when it does not. This is a continuous check of the process table, not bind enforcement in the kernel: it cannot see other users' programs, and forwarding stops within about 2 seconds after the app loses the port. For a strictly isolated connection (Linux netns) the check runs in the sandbox (the app's socket and any program holding the same port are judged by the sandbox's network namespace)",
                "轉發只送到同一條連線的受管 App：每次 App 狀態變化、以及每 2 秒，manager 核對 App 的程序樹在本機位址持有目標 port，不符就撤銷；這是程序表的持續核對，不是核心層的 bind 強制，看不到其他使用者的程式，App 失去 port 後約 2 秒內停止轉發；嚴格隔離（Linux netns）的連線在 sandbox 內核對（App 的 socket 與占用同一 port 的程式都以 sandbox 的網路命名空間判斷）",
                "ポート転送は同じ接続の管理対象アプリにだけ送られます。アプリの状態が変わるたびと 2 秒ごとに、manager はアプリのプロセスツリーがローカルアドレスで対象ポートを保持しているかを確認し、一致しなければ取り消します。これはプロセス表の継続的な確認で、カーネルによる bind の強制ではありません。ほかのユーザーのプログラムは見えず、アプリがポートを失ってから約 2 秒以内に転送を止めます。厳格な分離（Linux netns）の接続ではサンドボックス内で確認します（アプリのソケットと、同じポートを使うプログラムは、どちらもサンドボックスのネットワーク名前空間で判断します）"
            )),
        ),
        // Provider-side port reservation: AirVPN's website (it has no API for it), signed in with the
        // account's own credential over the Provider egress.
        cap(
            "forward_reservation",
            CapabilityState::Supported,
            Some(tr!(
                "AirVPN: on the provider account page, “Inbound ports” lists, reserves (random or chosen) and deletes ports. AirVPN's API has no inbound port service, so VPN Manager signs in to the Client Area of the AirVPN website (the Ports page) with the account's own credentials and acts there; every request goes out through the Provider egress, and the website session stays in memory only. Rules: at most 5 per account, a port must be ≥ 2049, the same on every server, released 10 days after the premium plan expires; a P2P program must listen on the same port that is forwarded (do not change it to a different local port). When the website asks for a CAPTCHA or two-step verification, VPN Manager cannot sign in for you; do it on the website instead. Mullvad no longer offers port forwarding",
                "AirVPN：在供應商帳號頁的「連入埠」列出、保留（隨機或指定）與刪除——AirVPN 的 API 沒有連入埠服務，VPN Manager 以帳號自己的帳密登入 AirVPN 網站的 Client Area（Ports 頁）代為操作，請求都經 Provider 出口送出，網站的 session 只留在記憶體。規則：每個帳號最多 5 個、port 需 ≥ 2049、所有伺服器相同、premium 方案到期 10 天後釋出；P2P 程式必須監聽與轉發相同的 port（不要改成不同的 local port）。網站要求驗證碼或兩步驟驗證時無法代為登入，請改在網站操作。Mullvad 已停止提供 port forwarding",
                "AirVPN：プロバイダーのアカウントページの「着信ポート」で、一覧、予約（ランダムまたは指定）、削除ができます。AirVPN の API には着信ポートのサービスがないため、VPN Manager はアカウント自身の認証情報で AirVPN の Web サイトの Client Area（Ports ページ）にログインし、代わりに操作します。リクエストはすべて Provider 出口を通って送られ、Web サイトのセッションはメモリにだけ保持されます。ルール：アカウントごとに最大 5 個、ポートは 2049 以上、すべてのサーバーで共通、プレミアムプランの期限切れから 10 日後に解放されます。P2P プログラムは転送されるのと同じポートで待ち受ける必要があります（別のローカルポートに変えないでください）。Web サイトが CAPTCHA や 2 段階認証を求める場合は代わりにログインできないため、Web サイトで操作してください。Mullvad はポート転送の提供を終了しました"
            )),
        ),
    ]
}

/// Linux strict mode (an Instance's rootless sandbox): `supported` only after a throw-away
/// sandbox was really built on this host with `exe sandbox-holder`; otherwise the concrete reason
/// it cannot be.
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        clippy::unused_async,
        reason = "one signature for every system: on Linux it awaits the sandbox probe"
    )
)]
pub async fn strict_netns(exe: &std::path::Path) -> Capability {
    const NAME: &str = "strict_netns";
    #[cfg(target_os = "linux")]
    {
        if let Err(reason) = crate::sandbox::detect() {
            return cap(NAME, CapabilityState::Blocked, Some(reason));
        }
        match crate::sandbox::probe(exe).await {
            Ok(()) => cap(
                NAME,
                CapabilityState::Supported,
                Some(tr!(
                    "Tested on this host: unprivileged user + network + mount + pid namespaces and the TUN device are available",
                    "已在此主機實測：非特權 user＋network＋mount＋pid namespace 與 TUN 裝置可用",
                    "このホストで実際に確認済み：特権のない user＋network＋mount＋pid namespace と TUN デバイスを使用できます"
                )),
            ),
            Err(e) if e.is_blocked() => cap(NAME, CapabilityState::Blocked, Some(e.text())),
            Err(e) => cap(
                NAME,
                CapabilityState::Unverified,
                Some(tr!(
                    "Cannot confirm whether this host can build a sandbox: {e}",
                    "無法確認此主機是否可建立 sandbox：{e}",
                    "このホストでサンドボックスを作成できるか確認できません：{e}";
                    e = e.text()
                )),
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = exe;
        cap(
            NAME,
            CapabilityState::Unsupported,
            Some(crate::sandbox::unsupported()),
        )
    }
}

/// Why this host cannot run a rootless network-namespace sandbox (`None`: it can, or this is
/// not Linux).
#[cfg(target_os = "linux")]
pub(crate) fn linux_host_problem() -> Option<Text> {
    linux_userns_available().err()
}

/// Why this host cannot run a rootless network-namespace sandbox: `None`, this is not Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) const fn linux_host_problem() -> Option<Text> {
    None
}

#[cfg(target_os = "linux")]
fn linux_userns_available() -> Result<(), Text> {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    if read("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return Err(tr!(
            "This host has turned off unprivileged user namespaces (kernel.unprivileged_userns_clone=0)",
            "此主機停用了非特權 user namespace（kernel.unprivileged_userns_clone=0）",
            "このホストでは特権のない user namespace が無効になっています（kernel.unprivileged_userns_clone=0）"
        ));
    }
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return Err(tr!(
            "AppArmor restricts unprivileged user namespaces (apparmor_restrict_unprivileged_userns=1)",
            "AppArmor 限制了非特權 user namespace（apparmor_restrict_unprivileged_userns=1）",
            "AppArmor が特権のない user namespace を制限しています（apparmor_restrict_unprivileged_userns=1）"
        ));
    }
    if read("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        return Err(Text::verbatim("user.max_user_namespaces=0"));
    }
    if !std::path::Path::new("/dev/net/tun").exists() {
        return Err(tr!(
            "/dev/net/tun is missing",
            "缺少 /dev/net/tun",
            "/dev/net/tun がありません"
        ));
    }
    Ok(())
}
