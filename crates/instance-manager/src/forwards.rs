//! Port forwards, manager side: whether a forward's target is what it claims to be, and what the
//! forward shows.
//!
//! A forward's target is a managed App of the same connection and the loopback port it listens
//! on. The connection's actor checks every enabled forward on every App event and after every
//! watcher pass (2 s; [`crate::apps::Apps::changes`]): the App must be running for this
//! connection, its process tree must hold the target port (TCP listening, UDP bound) on a
//! loopback or wildcard address, and — when it holds only a wildcard — no other process of this
//! user may hold the loopback address itself (that process would receive the connections). Only
//! then does the worker get a lease naming the loopback address to connect to; when any of it
//! stops holding, the lease is revoked and the worker closes the forward's connections.
//!
//! What this cannot see: processes of other users, and the moment between two checks (a port
//! released and taken by another program within those ~2 s). It is a continuous check of the
//! process table, not kernel bind enforcement; the capability is reported as degraded.
//!
//! A forward whose UDP goes straight into a strict sandbox (`udp_direct`) is connected to nothing
//! for UDP: the datagrams arrive for the tunnel address, so the App's tree must hold the tunnel
//! port on an address that receives them — every address of a family, or a non-loopback one (in
//! the sandbox only the tunnel address is one) — and no other program in the sandbox may hold it
//! on such an address. Only a strict App can be the target.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use vpn_domain::{
    ApiError, AppIsolation, AppSpec, ErrorCode, FORWARDS_PER_INSTANCE, FieldError, ForwardBinding,
    ForwardProtocol, ForwardReachability, ForwardState, GatewaySpec, InstanceSpec, ProviderKind,
    Reachability, RuntimeProfile, Text, Timestamp, tr,
};
use vpn_platform::apps::proc::Holder;

use crate::apps::TargetView;

/// A socket list older than this no longer verifies anything (the watcher passes every 2 s).
pub const STALE_SCAN: Duration = Duration::from_secs(10);

/// Why a forward does not listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotReady {
    pub state: ForwardState,
    pub code: &'static str,
    pub reason: Text,
}

fn not_ready(state: ForwardState, code: &'static str, reason: impl Into<Text>) -> NotReady {
    NotReady {
        state,
        code,
        reason: reason.into(),
    }
}

/// A verified target: where the worker connects, per protocol the forward carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub run_id: String,
    pub pid: u32,
    pub tcp: Option<SocketAddr>,
    pub udp: Option<SocketAddr>,
    /// Held on a wildcard address (also reachable from other hosts).
    pub wildcard: bool,
}

/// Where the tree holds a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// On a loopback address: connect exactly there.
    Loopback(SocketAddr),
    /// Only on a wildcard address: connect to the loopback address of its family.
    Wildcard(SocketAddr),
    /// Only on another address (not reachable through loopback).
    Elsewhere(SocketAddr),
    Not,
}

fn held(list: &[SocketAddr], port: u16) -> Held {
    let on: Vec<SocketAddr> = list
        .iter()
        .filter(|a| a.port() == port)
        .map(|a| SocketAddr::new(a.ip().to_canonical(), port))
        .collect();
    let lo4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let lo6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
    if on.contains(&lo4) {
        return Held::Loopback(lo4);
    }
    if on.contains(&lo6) {
        return Held::Loopback(lo6);
    }
    if let Some(other) = on.iter().find(|a| a.ip().is_loopback()) {
        return Held::Loopback(*other);
    }
    if on
        .iter()
        .any(|a| a.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    {
        return Held::Wildcard(lo4);
    }
    if on
        .iter()
        .any(|a| a.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    {
        // Whether it also takes IPv4 is the socket's own setting; `[::1]` always reaches it.
        return Held::Wildcard(lo6);
    }
    on.first().map_or(Held::Not, |a| Held::Elsewhere(*a))
}

/// What a check knows about one protocol.
pub struct ProtocolFacts<'a> {
    /// The tree's sockets of this protocol.
    pub tree: &'a [SocketAddr],
    /// This user's processes holding the target port (`None`: not looked up, or unreadable).
    pub holders: Option<&'a [Holder]>,
    /// The tree's processes when its sockets were read.
    pub tree_pids: &'a [u32],
}

const fn label(udp: bool) -> &'static str {
    if udp { "UDP" } else { "TCP" }
}

/// Check one protocol of a running target. `Ok(address to connect to, wildcard)`.
fn check_protocol(
    app_name: &str,
    port: u16,
    udp: bool,
    facts: &ProtocolFacts<'_>,
) -> Result<(SocketAddr, bool), NotReady> {
    let proto = label(udp);
    match held(facts.tree, port) {
        Held::Loopback(addr) => Ok((addr, false)),
        Held::Wildcard(addr) => {
            // A more specific bind of the loopback address by another program wins over the
            // App's wildcard one.
            let Some(holders) = facts.holders else {
                return Err(not_ready(
                    ForwardState::TargetMissing,
                    "APP_NOT_CHECKED",
                    tr!(
                        "Cannot read the process table, so it cannot confirm that only the app “{app_name}” holds {addr} ({proto}); forwarding is paused",
                        "無法讀取程序表，無法確認 {addr}（{proto}）只由 App「{app_name}」持有；暫停轉發",
                        "プロセステーブルを読み取れないため、{addr}（{proto}）をアプリ「{app_name}」だけが保持していることを確認できません。転送を一時停止します"
                    ),
                ));
            };
            if let Some(h) = holders
                .iter()
                .find(|h| h.address == addr && !facts.tree_pids.contains(&h.pid))
            {
                let (holder, pid) = (&h.name, h.pid);
                return Err(not_ready(
                    ForwardState::TargetNotOwned,
                    "PORT_SHADOWED",
                    tr!(
                        "The app “{app_name}” listens on port {port} ({proto}) on every address, but “{holder}” (pid {pid}) holds {addr}, so connections would go to it; not forwarded",
                        "App「{app_name}」在所有位址監聽 port {port}（{proto}），但「{holder}」（pid {pid}）占用了 {addr}，連線會送到它；不轉發",
                        "アプリ「{app_name}」はすべてのアドレスでポート {port}（{proto}）を待ち受けていますが、「{holder}」（pid {pid}）が {addr} を使用しているため、接続はそちらに届きます。転送しません"
                    ),
                ));
            }
            Ok((addr, true))
        }
        Held::Elsewhere(addr) => Err(not_ready(
            ForwardState::TargetMissing,
            "APP_NOT_ON_LOOPBACK",
            tr!(
                "The app “{app_name}” listens only on {addr} ({proto}), not on a loopback address; port forwards connect only to a loopback address (127.0.0.1 or ::1)",
                "App「{app_name}」只在 {addr}（{proto}）監聽，沒有在本機位址；轉發只連到本機位址（127.0.0.1 或 ::1）",
                "アプリ「{app_name}」は {addr}（{proto}）でのみ待ち受けており、ループバックアドレスでは待ち受けていません。ポート転送はループバックアドレス（127.0.0.1 または ::1）にのみ接続します"
            ),
        )),
        Held::Not => {
            let foreign = facts.holders.and_then(|hs| {
                hs.iter().find(|h| {
                    let ip = h.address.ip().to_canonical();
                    ip.is_loopback() || ip.is_unspecified()
                })
            });
            match foreign {
                // One of the App's own processes bound the port after the tree's sockets were
                // read: the next watcher pass sees it (within seconds).
                Some(h) if facts.tree_pids.contains(&h.pid) => Err(not_ready(
                    ForwardState::TargetMissing,
                    "APP_NOT_CHECKED",
                    tr!(
                        "Checking that the app “{app_name}” listens on port {port} ({proto})",
                        "正在確認 App「{app_name}」在 port {port}（{proto}）的監聽",
                        "アプリ「{app_name}」がポート {port}（{proto}）で待ち受けているか確認しています"
                    ),
                )),
                Some(h) => {
                    let (holder, pid) = (&h.name, h.pid);
                    Err(not_ready(
                        ForwardState::TargetNotOwned,
                        "PORT_HELD_BY_OTHER",
                        tr!(
                            "port {port} ({proto}) is held by “{holder}” (pid {pid}), not by the app “{app_name}”; not forwarded",
                            "port {port}（{proto}）由「{holder}」（pid {pid}）占用，不是 App「{app_name}」；不轉發",
                            "ポート {port}（{proto}）はアプリ「{app_name}」ではなく「{holder}」（pid {pid}）が使用しています。転送しません"
                        ),
                    ))
                }
                None => Err(not_ready(
                    ForwardState::TargetMissing,
                    "APP_NOT_LISTENING",
                    tr!(
                        "The app “{app_name}” does not listen on port {port} ({proto})",
                        "App「{app_name}」沒有在 port {port}（{proto}）監聽",
                        "アプリ「{app_name}」はポート {port}（{proto}）で待ち受けていません"
                    ),
                )),
            }
        }
    }
}

/// Everything one check looks at.
pub struct Facts<'a> {
    pub binding: &'a ForwardBinding,
    /// The stored target App (`None`: it does not exist).
    pub app: Option<&'a AppSpec>,
    pub view: &'a TargetView,
    pub tcp_holders: Option<&'a [Holder]>,
    pub udp_holders: Option<&'a [Holder]>,
    pub now: Instant,
}

/// Whether the forward's target is its App's process tree on a loopback port.
///
/// # Errors
///
/// The reason the forward is not ready: its App is missing, belongs to another connection, does
/// not run, cannot receive its protocol, was not checked recently, or does not hold its port.
pub fn verify(f: &Facts<'_>) -> Result<Verified, NotReady> {
    let b = f.binding;
    let (name, direct) = check_app(b, f.app)?;
    let TargetView::Running {
        run_id,
        pid,
        instance_id,
        isolation,
        sockets,
    } = f.view
    else {
        return Err(not_ready(
            ForwardState::TargetMissing,
            "APP_NOT_RUNNING",
            tr!(
                "The app “{name}” is not running",
                "App「{name}」未執行",
                "アプリ「{name}」は実行されていません"
            ),
        ));
    };
    if *instance_id != b.instance_id {
        return Err(not_ready(
            ForwardState::TargetNotOwned,
            "APP_OTHER_CONNECTION",
            tr!(
                "The app “{name}” is running for another connection",
                "App「{name}」正在為另一條連線執行",
                "アプリ「{name}」は別の接続のために実行されています"
            ),
        ));
    }
    let Some(found) = sockets.as_ref() else {
        return Err(not_ready(
            ForwardState::TargetMissing,
            "APP_NOT_CHECKED",
            tr!(
                "Checking which ports the app “{name}” listens on",
                "正在確認 App「{name}」監聽的 port",
                "アプリ「{name}」が待ち受けているポートを確認しています"
            ),
        ));
    };
    let (tcp, udp, pids, at) = (&found.tcp, &found.udp, &found.pids, &found.at);
    if f.now.saturating_duration_since(*at) > STALE_SCAN {
        let secs = STALE_SCAN.as_secs();
        return Err(not_ready(
            ForwardState::TargetMissing,
            "APP_NOT_CHECKED",
            tr!(
                "The process table of the app “{name}” has not been updated for over {secs} s; forwarding is paused",
                "App「{name}」的程序表已超過 {secs} 秒沒有更新；暫停轉發",
                "アプリ「{name}」のプロセステーブルが {secs} 秒以上更新されていません。転送を一時停止します"
            ),
        ));
    }
    let port = b.target_port;
    // A strict App shares the sandbox's network with the connection's worker, which listens on
    // the tunnel address. With the same port on both sides, an App holding it on every address
    // also holds the tunnel address's port, and an App started after the worker took it cannot
    // bind every address at all: either way the forward cannot work.
    let shared = *isolation == AppIsolation::StrictNetns && b.tunnel_port == port;
    let hint = |e: NotReady| {
        if shared {
            strict_listen_hint(e, port)
        } else {
            e
        }
    };
    let mut out = Verified {
        run_id: run_id.clone(),
        pid: *pid,
        tcp: None,
        udp: None,
        wildcard: false,
    };
    if b.protocol.tcp() {
        let facts = ProtocolFacts {
            tree: tcp,
            holders: f.tcp_holders,
            tree_pids: pids,
        };
        let (addr, wildcard) = check_protocol(name, port, false, &facts).map_err(hint)?;
        out.tcp = Some(addr);
        out.wildcard |= wildcard;
    }
    if b.protocol.udp() {
        let facts = ProtocolFacts {
            tree: udp,
            holders: f.udp_holders,
            tree_pids: pids,
        };
        if direct {
            // Where the App receives them itself; nothing is connected to, and holding every
            // address is what it takes.
            out.udp = Some(check_direct_udp(name, port, &facts)?);
        } else {
            let (addr, wildcard) = check_protocol(name, port, true, &facts).map_err(hint)?;
            out.udp = Some(addr);
            out.wildcard |= wildcard;
        }
    }
    if shared && out.wildcard {
        return Err(wildcard_tunnel_port(name, port, direct));
    }
    Ok(out)
}

/// A strict App that does not listen on the forward's port, which is also its tunnel port: how
/// it has to listen.
fn strict_listen_hint(mut e: NotReady, port: u16) -> NotReady {
    if e.code == "APP_NOT_LISTENING" {
        e.reason = tr!(
            "{why}. With strict isolation the app must listen on 127.0.0.1 port {port}: listening on every address (0.0.0.0) conflicts with the same port the port forward reserves on the tunnel address, and binding fails",
            "{why}。嚴格隔離時 App 要在 127.0.0.1 監聽 {port}：在所有位址（0.0.0.0）監聽會與轉發在 tunnel 位址保留的同一個 port 衝突，綁定會失敗",
            "{why}。厳格な分離では、アプリは 127.0.0.1 のポート {port} で待ち受ける必要があります。すべてのアドレス（0.0.0.0）で待ち受けると、ポート転送が tunnel アドレスで確保している同じポートと競合し、バインドに失敗します";
            why = std::mem::take(&mut e.reason)
        );
    }
    e
}

/// A strict App holding the forward's port, which is also its tunnel port, on every address:
/// that takes the tunnel address's port too.
fn wildcard_tunnel_port(name: &str, port: u16, direct: bool) -> NotReady {
    // With UDP straight into the sandbox only the TCP side can be it.
    let which = if direct {
        tr!(" (TCP)", "（TCP）", "（TCP）")
    } else {
        Text::default()
    };
    not_ready(
        ForwardState::TargetMissing,
        "APP_WILDCARD_TUNNEL_PORT",
        tr!(
            "The app “{name}” listens on port {port}{which} on every address (0.0.0.0 / ::): an app with strict isolation shares its network with this connection, so this also takes the same port the port forward receives on at the tunnel address. Make the app listen on 127.0.0.1 only (the port forward connects to the app's 127.0.0.1)",
            "App「{name}」在所有位址（0.0.0.0／::）監聽 port {port}{which}：嚴格隔離的 App 與這條連線共用網路，這也占住了轉發要在 tunnel 位址接收的同一個 port。請讓 App 只在 127.0.0.1 監聽（轉發連到 App 的 127.0.0.1）",
            "アプリ「{name}」はすべてのアドレス（0.0.0.0／::）でポート {port}{which} を待ち受けています。厳格な分離のアプリはこの接続とネットワークを共有するため、ポート転送が tunnel アドレスで受信する同じポートも占有してしまいます。アプリが 127.0.0.1 でのみ待ち受けるようにしてください（ポート転送はアプリの 127.0.0.1 に接続します）";
            which = which
        ),
    )
}

/// The stored target App's own rules for `verify`: `Ok((its name, whether UDP goes straight
/// into the sandbox))`.
fn check_app<'a>(
    b: &ForwardBinding,
    app: Option<&'a AppSpec>,
) -> Result<(&'a str, bool), NotReady> {
    let Some(app) = app else {
        return Err(not_ready(
            ForwardState::TargetMissing,
            "APP_MISSING",
            tr!(
                "The target app does not exist",
                "目標 App 不存在",
                "転送先のアプリが存在しません"
            ),
        ));
    };
    let name = app.name.as_str();
    if app.instance_id != b.instance_id {
        return Err(not_ready(
            ForwardState::TargetNotOwned,
            "APP_OTHER_CONNECTION",
            other_connection(name),
        ));
    }
    if b.protocol.udp() && app.isolation == AppIsolation::EnforcedProxy {
        return Err(not_ready(
            ForwardState::TargetMissing,
            "APP_NO_UDP",
            tr!(
                "The app “{name}” uses an enforced proxy (Seatbelt) and cannot receive UDP; use TCP instead, or another isolation mode",
                "App「{name}」使用強制代理（Seatbelt），不能接收 UDP；請改用 TCP，或改用其他隔離方式",
                "アプリ「{name}」は強制プロキシ（Seatbelt）を使用しているため、UDP を受信できません。TCP にするか、別の分離方式にしてください"
            ),
        ));
    }
    let direct = b.protocol.udp() && b.udp_direct;
    if direct && app.isolation != AppIsolation::StrictNetns {
        return Err(not_ready(
            ForwardState::TargetMissing,
            "UDP_DIRECT_NOT_STRICT",
            tr!(
                "UDP straight into the sandbox goes only to an app with strict isolation; the app “{name}” does not run in this connection's sandbox (use an ordinary UDP port forward, or switch the app to strict isolation)",
                "UDP 直接送進沙箱只送到嚴格隔離的 App；App「{name}」不在這條連線的沙箱裡執行（改用一般的 UDP 轉送，或把 App 改為嚴格隔離）",
                "サンドボックスへの UDP の直接送信は、厳格な分離のアプリにのみ届きます。アプリ「{name}」はこの接続のサンドボックスで実行されていません（通常の UDP ポート転送にするか、アプリを厳格な分離に変更してください）"
            ),
        ));
    }
    Ok((name, direct))
}

/// Check the UDP side of a forward whose UDP goes straight into the sandbox. The datagrams are
/// for the tunnel address: the tree must hold `port` on an address that receives them (every
/// address of a family, or a non-loopback one — in the sandbox only the tunnel address is one),
/// and no other program may hold it on such an address (it could take them). `Ok(the address
/// the tree holds)`.
fn check_direct_udp(
    app_name: &str,
    port: u16,
    facts: &ProtocolFacts<'_>,
) -> Result<SocketAddr, NotReady> {
    let canonical = |a: &SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    let on: Vec<SocketAddr> = facts
        .tree
        .iter()
        .filter(|a| a.port() == port)
        .map(canonical)
        .collect();
    let reached = |a: &SocketAddr| !a.ip().to_canonical().is_loopback();
    let held = on.iter().copied().find(reached);
    let other = facts.holders.and_then(|hs| {
        hs.iter()
            .find(|h| reached(&h.address) && !facts.tree_pids.contains(&h.pid))
    });
    match (held, facts.holders) {
        (Some(_), None) => Err(not_ready(
            ForwardState::TargetMissing,
            "APP_NOT_CHECKED",
            tr!(
                "Cannot read the process table, so it cannot confirm that only the app “{app_name}” holds port {port} (UDP); forwarding is paused",
                "無法讀取程序表，無法確認 port {port}（UDP）只由 App「{app_name}」持有；暫停轉發",
                "プロセステーブルを読み取れないため、ポート {port}（UDP）をアプリ「{app_name}」だけが保持していることを確認できません。転送を一時停止します"
            ),
        )),
        (Some(addr), Some(_)) => other.map_or(Ok(addr), |h| {
            let (holder, pid, also) = (&h.name, h.pid, h.address);
            Err(not_ready(
                ForwardState::TargetNotOwned,
                "PORT_SHADOWED",
                tr!(
                    "The app “{app_name}” receives on {addr} (UDP), but “{holder}” (pid {pid}) also holds {also}, so datagrams sent straight into the sandbox could reach it; not forwarded",
                    "App「{app_name}」在 {addr}（UDP）接收，但「{holder}」（pid {pid}）也持有 {also}，直接送進沙箱的 datagram 可能被它收到；不轉發",
                    "アプリ「{app_name}」は {addr}（UDP）で受信していますが、「{holder}」（pid {pid}）も {also} を保持しているため、サンドボックスに直接送られたデータグラムがそちらに届く可能性があります。転送しません"
                ),
            ))
        }),
        (None, _) if !on.is_empty() => {
            let only = on[0];
            Err(not_ready(
                ForwardState::TargetMissing,
                "APP_UDP_LOOPBACK_ONLY",
                tr!(
                    "The app “{app_name}” receives only on {only} (UDP): with UDP straight into the sandbox, datagrams arrive at the tunnel address, so the app must receive port {port} on every address (0.0.0.0) or on the tunnel address",
                    "App「{app_name}」只在 {only}（UDP）接收：UDP 直接送進沙箱時 datagram 送到 tunnel 位址，App 要在所有位址（0.0.0.0）或 tunnel 位址接收 port {port}",
                    "アプリ「{app_name}」は {only}（UDP）でのみ受信しています。サンドボックスに UDP を直接送る場合、データグラムは tunnel アドレスに届くため、アプリはすべてのアドレス（0.0.0.0）または tunnel アドレスでポート {port} を受信する必要があります"
                ),
            ))
        }
        (None, _) => {
            // Not held by the tree: one of its own processes bound it after the scan, or another
            // program holds it.
            let any = facts
                .holders
                .and_then(|hs| hs.iter().find(|h| reached(&h.address)));
            match any {
                Some(h) if facts.tree_pids.contains(&h.pid) => Err(not_ready(
                    ForwardState::TargetMissing,
                    "APP_NOT_CHECKED",
                    tr!(
                        "Checking that the app “{app_name}” receives on port {port} (UDP)",
                        "正在確認 App「{app_name}」在 port {port}（UDP）的接收",
                        "アプリ「{app_name}」がポート {port}（UDP）で受信しているか確認しています"
                    ),
                )),
                Some(h) => {
                    let (holder, pid) = (&h.name, h.pid);
                    Err(not_ready(
                        ForwardState::TargetNotOwned,
                        "PORT_HELD_BY_OTHER",
                        tr!(
                            "port {port} (UDP) is held by “{holder}” (pid {pid}), not by the app “{app_name}”; not forwarded",
                            "port {port}（UDP）由「{holder}」（pid {pid}）占用，不是 App「{app_name}」；不轉發",
                            "ポート {port}（UDP）はアプリ「{app_name}」ではなく「{holder}」（pid {pid}）が使用しています。転送しません"
                        ),
                    ))
                }
                None => Err(not_ready(
                    ForwardState::TargetMissing,
                    "APP_NOT_LISTENING",
                    tr!(
                        "The app “{app_name}” does not receive on port {port} (UDP). With UDP straight into the sandbox, the app must receive this port on every address (0.0.0.0) or on the tunnel address",
                        "App「{app_name}」沒有在 port {port}（UDP）接收。UDP 直接送進沙箱時，App 要在所有位址（0.0.0.0）或 tunnel 位址接收這個 port",
                        "アプリ「{app_name}」はポート {port}（UDP）で受信していません。サンドボックスに UDP を直接送る場合、アプリはすべてのアドレス（0.0.0.0）または tunnel アドレスでこのポートを受信する必要があります"
                    ),
                )),
            }
        }
    }
}

/// The holders that can take the App's loopback address: those in the App's network namespace
/// (a strict App's sandbox has a loopback of its own). One whose namespace is unknown counts.
pub fn same_namespace(holders: Vec<Holder>, app: Option<u64>) -> Vec<Holder> {
    holders
        .into_iter()
        .filter(|h| app.is_none() || h.netns.is_none() || h.netns == app)
        .collect()
}

/// Whether a check needs this user's holders of the target port for `udp`: the tree holds the
/// port only on a wildcard address, or not at all — or, for UDP straight into the sandbox
/// (`direct`), whenever the App runs (any other holder on an address the datagrams reach could
/// take them).
pub fn needs_holders(view: &TargetView, port: u16, udp: bool, direct: bool) -> bool {
    match view {
        TargetView::Running {
            sockets: Some(s), ..
        } => {
            let list = if udp { &s.udp } else { &s.tcp };
            direct || matches!(held(list, port), Held::Wildcard(_) | Held::Not)
        }
        _ => false,
    }
}

fn field(code: ErrorCode, path: &str, field_code: &str, message: impl Into<Text>) -> ApiError {
    let message = message.into();
    ApiError::new(code, message.clone()).with_fields(vec![FieldError {
        path: path.into(),
        code: field_code.into(),
        message,
    }])
}

/// Why a port forward cannot go to the App `name`: it belongs to another connection.
fn other_connection(name: &str) -> Text {
    tr!(
        "The app “{name}” belongs to another connection; port forwards go only to apps of the same connection",
        "App「{name}」屬於另一條連線；轉發只送到同一條連線的 App",
        "アプリ「{name}」は別の接続のものです。ポート転送は同じ接続のアプリにのみ送られます"
    )
}

/// Rules of a forward that need the Store: its connection exists and can forward (Mullvad
/// cannot), its App belongs to that connection and can receive its protocols, its target is
/// not one of VPN Manager's own proxy ports, and its tunnel port is its own on the connection.
pub async fn check_binding(store: &vpn_store::Store, f: &ForwardBinding) -> Result<(), ApiError> {
    let api = |e: vpn_store::StoreError| e.to_api();
    let Some(instance) = store
        .get::<InstanceSpec>(f.instance_id.to_string())
        .await
        .map_err(api)?
    else {
        return Err(field(
            ErrorCode::ValidationFailed,
            "/instance_id",
            "FORWARD_INSTANCE",
            tr!(
                "Cannot find this connection",
                "找不到這條連線",
                "この接続が見つかりません"
            ),
        ));
    };
    let profile: Option<RuntimeProfile> = store
        .get(instance.profile_id.to_string())
        .await
        .map_err(api)?;
    if profile.is_some_and(|p| p.provider == ProviderKind::Mullvad) {
        return Err(field(
            ErrorCode::UnsupportedCapability,
            "/instance_id",
            "FORWARD_UNSUPPORTED_PROVIDER",
            tr!(
                "Mullvad no longer offers port forwarding, so this connection cannot have port forwards",
                "Mullvad 已停止提供 port forwarding，這條連線不能設定轉發",
                "Mullvad はポートフォワーディングの提供を終了したため、この接続にはポート転送を設定できません"
            ),
        ));
    }
    // Only a strict connection has a sandbox to take the UDP straight into.
    if f.udp_direct && !instance.strict {
        let name = &instance.name;
        return Err(field(
            ErrorCode::ValidationFailed,
            "/udp_direct",
            "FORWARD_UDP_DIRECT_NOT_STRICT",
            tr!(
                "“UDP straight into the sandbox” is only for connections with strict isolation; “{name}” does not have strict isolation turned on",
                "「UDP 直接送進沙箱」只用於嚴格隔離的連線；「{name}」沒有啟用嚴格隔離",
                "「サンドボックスへ UDP を直接送る」は厳格な分離の接続でのみ使えます。「{name}」は厳格な分離が有効になっていません"
            ),
        ));
    }
    let Some(app) = store
        .get::<AppSpec>(f.target_app_id.to_string())
        .await
        .map_err(api)?
    else {
        return Err(field(
            ErrorCode::ValidationFailed,
            "/target_app_id",
            "FORWARD_APP",
            tr!(
                "Cannot find this managed app",
                "找不到這個受管 App",
                "この管理対象アプリが見つかりません"
            ),
        ));
    };
    check_app_rules(f, &app)?;
    check_ports(store, f).await
}

/// [`check_binding`]'s rules about the target App: it belongs to the forward's connection and
/// can receive its protocols.
fn check_app_rules(f: &ForwardBinding, app: &AppSpec) -> Result<(), ApiError> {
    let name = &app.name;
    if app.instance_id != f.instance_id {
        return Err(field(
            ErrorCode::ValidationFailed,
            "/target_app_id",
            "FORWARD_APP_INSTANCE",
            other_connection(name),
        ));
    }
    if f.protocol.udp() && app.isolation == AppIsolation::EnforcedProxy {
        return Err(field(
            ErrorCode::ValidationFailed,
            "/protocol",
            "FORWARD_APP_NO_UDP",
            tr!(
                "The app “{name}” uses an enforced proxy (Seatbelt) and cannot receive UDP; choose TCP",
                "App「{name}」使用強制代理（Seatbelt），不能接收 UDP；請選 TCP",
                "アプリ「{name}」は強制プロキシ（Seatbelt）を使用しているため、UDP を受信できません。TCP を選んでください"
            ),
        ));
    }
    // ...and only an App inside it receives what goes in.
    if f.udp_direct && app.isolation != AppIsolation::StrictNetns {
        return Err(field(
            ErrorCode::ValidationFailed,
            "/udp_direct",
            "FORWARD_UDP_DIRECT_APP_NOT_STRICT",
            tr!(
                "“UDP straight into the sandbox” goes only to an app with strict isolation; the app “{name}” is not in the connection's sandbox (change its isolation mode to strict isolation)",
                "「UDP 直接送進沙箱」只送到嚴格隔離的 App；App「{name}」不在連線的沙箱裡（請把它的隔離方式改為嚴格隔離）",
                "「サンドボックスへ UDP を直接送る」は厳格な分離のアプリにのみ届きます。アプリ「{name}」は接続のサンドボックス内にありません（分離方式を厳格な分離に変更してください）"
            ),
        ));
    }
    Ok(())
}

/// [`check_binding`]'s rules about ports: the target is not a proxy port, the tunnel port is the
/// forward's own on the connection, and the connection has room for one more forward.
async fn check_ports(store: &vpn_store::Store, f: &ForwardBinding) -> Result<(), ApiError> {
    let api = |e: vpn_store::StoreError| e.to_api();
    let gateways: Vec<GatewaySpec> = store.list().await.map_err(api)?;
    if let Some(g) = gateways.iter().find(|g| g.port == f.target_port) {
        let (port, name) = (f.target_port, &g.name);
        return Err(field(
            ErrorCode::ValidationFailed,
            "/target_port",
            "FORWARD_TARGET_GATEWAY",
            tr!(
                "port {port} is the Gateway “{name}”; a port forward goes only to a port the app itself listens on, never into a Gateway",
                "port {port} 是代理埠「{name}」；轉發只送到 App 自己監聽的 port，不送進代理埠",
                "ポート {port} はゲートウェイ「{name}」です。ポート転送はアプリ自身が待ち受けるポートにのみ送られ、ゲートウェイには送られません"
            ),
        ));
    }
    let others: Vec<ForwardBinding> = store
        .list::<ForwardBinding>()
        .await
        .map_err(api)?
        .into_iter()
        .filter(|o| o.instance_id == f.instance_id && o.id != f.id)
        .collect();
    if let Some(o) = others.iter().find(|o| {
        o.tunnel_port == f.tunnel_port
            && ((o.protocol.tcp() && f.protocol.tcp()) || (o.protocol.udp() && f.protocol.udp()))
    }) {
        let (port, name) = (f.tunnel_port, &o.name);
        return Err(field(
            ErrorCode::ListenerConflict,
            "/tunnel_port",
            "FORWARD_TUNNEL_PORT_IN_USE",
            tr!(
                "tunnel port {port} is used by the port forward “{name}”",
                "tunnel port {port} 已由轉發「{name}」使用",
                "tunnel port {port} はポート転送「{name}」が使用しています"
            ),
        ));
    }
    if others.len() >= FORWARDS_PER_INSTANCE {
        return Err(field(
            ErrorCode::ValidationFailed,
            "/instance_id",
            "FORWARD_LIMIT",
            tr!(
                "A connection has at most {FORWARDS_PER_INSTANCE} port forwards",
                "一條連線最多 {FORWARDS_PER_INSTANCE} 個轉發",
                "1 つの接続に設定できるポート転送は最大 {FORWARDS_PER_INSTANCE} 件です"
            ),
        ));
    }
    Ok(())
}

/// Evidence that a forward was reached from outside, per protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Evidence {
    pub tcp: Option<Timestamp>,
    pub udp: Option<Timestamp>,
}

impl Evidence {
    pub fn reachability(&self, protocol: ForwardProtocol) -> ForwardReachability {
        let tcp = self.tcp.filter(|_| protocol.tcp());
        let udp = self.udp.filter(|_| protocol.udp());
        ForwardReachability {
            state: if tcp.is_some() || udp.is_some() {
                Reachability::Observed
            } else {
                Reachability::Unverified
            },
            tcp_observed_at: tcp,
            udp_observed_at: udp,
        }
    }

    /// Take the later of each. A worker reports "milliseconds ago" once a second, so the same
    /// arrival comes back a few milliseconds apart: only a time more than a second later is a
    /// newer arrival (the known one is kept otherwise, so it does not creep forward).
    pub fn merge(&mut self, tcp: Option<Timestamp>, udp: Option<Timestamp>) {
        let later = |a: Option<Timestamp>, b: Option<Timestamp>| match (a, b) {
            (Some(a), Some(b)) => Some(if b.unix_millis() - a.unix_millis() > 1_000 {
                b
            } else {
                a
            }),
            (a, b) => a.or(b),
        };
        self.tcp = later(self.tcp, tcp);
        self.udp = later(self.udp, udp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::TreeSockets;
    use vpn_domain::{
        AppId, AppLimits, AppRunState, AssignmentSource, EntityMeta, ForwardBindingId, InstanceId,
    };

    fn meta() -> EntityMeta {
        EntityMeta {
            revision: 1,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        }
    }

    fn binding(instance: InstanceId, app: AppId, protocol: ForwardProtocol) -> ForwardBinding {
        ForwardBinding {
            id: ForwardBindingId::new(),
            meta: meta(),
            instance_id: instance,
            name: "BT".into(),
            protocol,
            tunnel_port: 51234,
            public_port: None,
            assignment_source: AssignmentSource::Manual,
            target_app_id: app,
            target_port: 6881,
            enabled: true,
            max_connections: 64,
            proxy_protocol: false,
            udp_direct: false,
        }
    }

    fn app(instance: InstanceId, isolation: AppIsolation) -> AppSpec {
        AppSpec {
            id: AppId::new(),
            meta: meta(),
            instance_id: instance,
            name: "qBittorrent".into(),
            executable: "/Applications/qBittorrent.app".into(),
            args: Vec::new(),
            working_dir: None,
            env: Vec::new(),
            isolation,
            gateway_id: None,
            restart_on_recovery: false,
            writable_paths: Vec::new(),
            confine_writes: false,
            stop_grace_secs: 10,
            approval: None,
            limits: AppLimits::default(),
            access_ports: Vec::new(),
        }
    }

    fn running(instance: InstanceId, tcp: &[&str], udp: &[&str], age: Duration) -> TargetView {
        running_as(AppIsolation::ProxyEnv, instance, tcp, udp, age)
    }

    fn running_as(
        isolation: AppIsolation,
        instance: InstanceId,
        tcp: &[&str],
        udp: &[&str],
        age: Duration,
    ) -> TargetView {
        let parse = |l: &[&str]| l.iter().map(|a| a.parse().unwrap()).collect::<Vec<_>>();
        TargetView::Running {
            run_id: "r1".into(),
            pid: 4242,
            instance_id: instance,
            isolation,
            sockets: Some(TreeSockets {
                tcp: parse(tcp),
                udp: parse(udp),
                pids: vec![4242],
                ports: Vec::new(),
                at: Instant::now().checked_sub(age).unwrap(),
            }),
        }
    }

    #[test]
    fn only_holders_in_the_apps_network_namespace_can_take_its_loopback() {
        let host = Holder {
            netns: Some(1),
            ..holder(10, "host-server", "127.0.0.1:8080")
        };
        let sandbox = Holder {
            netns: Some(2),
            ..holder(20, "other-app", "127.0.0.1:8080")
        };
        let unknown = holder(30, "unreadable", "127.0.0.1:8080");
        let all = vec![host, sandbox.clone(), unknown.clone()];
        assert_eq!(
            same_namespace(all.clone(), Some(2)),
            vec![sandbox, unknown],
            "a strict App's sandbox has its own loopback"
        );
        assert_eq!(same_namespace(all.clone(), None), all);
    }

    fn holder(pid: u32, name: &str, addr: &str) -> Holder {
        Holder {
            pid,
            name: name.into(),
            address: addr.parse().unwrap(),
            netns: None,
        }
    }

    fn check(
        b: &ForwardBinding,
        a: Option<&AppSpec>,
        view: &TargetView,
        tcp: Option<&[Holder]>,
        udp: Option<&[Holder]>,
    ) -> Result<Verified, NotReady> {
        verify(&Facts {
            binding: b,
            app: a,
            view,
            tcp_holders: tcp,
            udp_holders: udp,
            now: Instant::now(),
        })
    }

    fn code(r: Result<Verified, NotReady>) -> (ForwardState, &'static str) {
        let e = r.unwrap_err();
        (e.state, e.code)
    }

    #[test]
    fn a_tree_holding_the_port_on_loopback_is_the_target() {
        let i = InstanceId::new();
        let a = app(i, AppIsolation::ProxyEnv);
        let b = binding(i, a.id, ForwardProtocol::Both);
        let v = running(
            i,
            &["127.0.0.1:6881", "0.0.0.0:8080"],
            &["127.0.0.1:6881", "0.0.0.0:53000"],
            Duration::ZERO,
        );
        let ok = check(&b, Some(&a), &v, Some(&[]), Some(&[])).unwrap();
        assert_eq!(ok.tcp, Some("127.0.0.1:6881".parse().unwrap()));
        assert_eq!(ok.udp, Some("127.0.0.1:6881".parse().unwrap()));
        assert!(!ok.wildcard);
        assert_eq!(ok.pid, 4242);
        // IPv6 loopback only: connect there.
        let v6 = running(i, &["[::1]:6881"], &["[::1]:6881"], Duration::ZERO);
        let ok = check(&b, Some(&a), &v6, None, None).unwrap();
        assert_eq!(ok.tcp, Some("[::1]:6881".parse().unwrap()));
        // A loopback hold needs no look at other processes.
        assert!(!needs_holders(&v, 6881, false, false));
    }

    #[test]
    fn a_wildcard_hold_counts_unless_another_program_holds_the_loopback_address() {
        let i = InstanceId::new();
        let a = app(i, AppIsolation::ProxyEnv);
        let b = binding(i, a.id, ForwardProtocol::Tcp);
        let v = running(i, &["0.0.0.0:6881"], &[], Duration::ZERO);
        assert!(needs_holders(&v, 6881, false, false));
        // The App's own wildcard socket is among the holders; that is fine.
        let own = [holder(4242, "qbittorrent", "0.0.0.0:6881")];
        let ok = check(&b, Some(&a), &v, Some(&own), None).unwrap();
        assert_eq!(ok.tcp, Some("127.0.0.1:6881".parse().unwrap()));
        assert!(ok.wildcard);
        let shadow = [own[0].clone(), holder(77, "python3", "127.0.0.1:6881")];
        let err = check(&b, Some(&a), &v, Some(&shadow), None).unwrap_err();
        assert_eq!(
            (err.state, err.code),
            (ForwardState::TargetNotOwned, "PORT_SHADOWED")
        );
        assert!(
            err.reason.zh_tw.contains("python3") && err.reason.zh_tw.contains("77"),
            "{}",
            err.reason.zh_tw
        );
        // Cannot tell: stop rather than guess.
        assert_eq!(
            code(check(&b, Some(&a), &v, None, None)),
            (ForwardState::TargetMissing, "APP_NOT_CHECKED")
        );
        // `[::]` is reached through `[::1]`.
        let v6 = running(i, &["[::]:6881"], &[], Duration::ZERO);
        let ok = check(&b, Some(&a), &v6, Some(&[]), None).unwrap();
        assert_eq!(ok.tcp, Some("[::1]:6881".parse().unwrap()));
    }

    #[test]
    fn missing_foreign_and_unreachable_targets_are_named() {
        let i = InstanceId::new();
        let a = app(i, AppIsolation::ProxyEnv);
        let b = binding(i, a.id, ForwardProtocol::Tcp);
        let nothing = running(i, &["127.0.0.1:9999"], &[], Duration::ZERO);
        assert_eq!(
            code(check(&b, Some(&a), &nothing, Some(&[]), None)),
            (ForwardState::TargetMissing, "APP_NOT_LISTENING")
        );
        let held = [holder(500, "nc", "127.0.0.1:6881")];
        let err = check(&b, Some(&a), &nothing, Some(&held), None).unwrap_err();
        assert_eq!(
            (err.state, err.code),
            (ForwardState::TargetNotOwned, "PORT_HELD_BY_OTHER")
        );
        assert!(err.reason.zh_tw.contains("nc"));
        // The App itself bound the port after the tree's sockets were read: not another
        // program, just not seen yet.
        let late = [holder(4242, "echo-app", "127.0.0.1:6881")];
        assert_eq!(
            code(check(&b, Some(&a), &nothing, Some(&late), None)),
            (ForwardState::TargetMissing, "APP_NOT_CHECKED")
        );
        // Nor does its own more specific bind shadow its wildcard one.
        let wildcard = running(i, &["0.0.0.0:6881"], &[], Duration::ZERO);
        let ok = check(&b, Some(&a), &wildcard, Some(&late), None).unwrap();
        assert_eq!(ok.tcp, Some("127.0.0.1:6881".parse().unwrap()));
        // A holder on another interface does not take loopback connections.
        let lan = [holder(500, "nc", "192.168.1.5:6881")];
        assert_eq!(
            code(check(&b, Some(&a), &nothing, Some(&lan), None)),
            (ForwardState::TargetMissing, "APP_NOT_LISTENING")
        );
        let elsewhere = running(i, &["192.168.1.5:6881"], &[], Duration::ZERO);
        assert_eq!(
            code(check(&b, Some(&a), &elsewhere, Some(&[]), None)),
            (ForwardState::TargetMissing, "APP_NOT_ON_LOOPBACK")
        );
        // Not running, gone, stale or for another connection.
        assert_eq!(
            code(check(
                &b,
                Some(&a),
                &TargetView::NotRunning(AppRunState::Stopped),
                None,
                None
            )),
            (ForwardState::TargetMissing, "APP_NOT_RUNNING")
        );
        assert_eq!(
            code(check(&b, None, &TargetView::Unknown, None, None)),
            (ForwardState::TargetMissing, "APP_MISSING")
        );
        let stale = running(
            i,
            &["127.0.0.1:6881"],
            &[],
            STALE_SCAN + Duration::from_secs(1),
        );
        assert_eq!(
            code(check(&b, Some(&a), &stale, None, None)),
            (ForwardState::TargetMissing, "APP_NOT_CHECKED")
        );
        let other = running(InstanceId::new(), &["127.0.0.1:6881"], &[], Duration::ZERO);
        assert_eq!(
            code(check(&b, Some(&a), &other, None, None)),
            (ForwardState::TargetNotOwned, "APP_OTHER_CONNECTION")
        );
        let moved = app(InstanceId::new(), AppIsolation::ProxyEnv);
        assert_eq!(
            code(check(&b, Some(&moved), &nothing, None, None)),
            (ForwardState::TargetNotOwned, "APP_OTHER_CONNECTION")
        );
    }

    #[test]
    fn both_protocols_must_hold_and_seatbelt_apps_take_no_udp() {
        let i = InstanceId::new();
        let a = app(i, AppIsolation::ProxyEnv);
        let both = binding(i, a.id, ForwardProtocol::Both);
        let tcp_only = running(i, &["127.0.0.1:6881"], &["0.0.0.0:51000"], Duration::ZERO);
        let err = check(&both, Some(&a), &tcp_only, Some(&[]), Some(&[])).unwrap_err();
        assert_eq!(
            (err.state, err.code),
            (ForwardState::TargetMissing, "APP_NOT_LISTENING")
        );
        assert!(err.reason.zh_tw.contains("UDP"), "{}", err.reason.zh_tw);
        let sandboxed = app(i, AppIsolation::EnforcedProxy);
        let b = binding(i, sandboxed.id, ForwardProtocol::Udp);
        assert_eq!(
            code(check(&b, Some(&sandboxed), &tcp_only, None, None)),
            (ForwardState::TargetMissing, "APP_NO_UDP")
        );
    }

    #[test]
    fn udp_straight_into_the_sandbox_needs_the_strict_app_on_every_address_or_the_tunnel_address() {
        let i = InstanceId::new();
        let a = app(i, AppIsolation::StrictNetns);
        let b = ForwardBinding {
            tunnel_port: 6881,
            udp_direct: true,
            ..binding(i, a.id, ForwardProtocol::Both)
        };
        let strict = |tcp: &[&str], udp: &[&str]| {
            running_as(AppIsolation::StrictNetns, i, tcp, udp, Duration::ZERO)
        };
        let own = [
            holder(4242, "p2pd", "0.0.0.0:6881"),
            holder(4242, "p2pd", "127.0.0.1:6881"),
        ];
        // TCP on loopback (relayed), UDP on every address (straight in): the target. The UDP
        // address is where the App receives; the wildcard is what it takes, not a concern.
        let kad = strict(&["127.0.0.1:6881"], &["0.0.0.0:6881"]);
        let ok = check(&b, Some(&a), &kad, Some(&[]), Some(&own)).unwrap();
        assert_eq!(ok.tcp, Some("127.0.0.1:6881".parse().unwrap()));
        assert_eq!(ok.udp, Some("0.0.0.0:6881".parse().unwrap()));
        assert!(!ok.wildcard);
        // On the tunnel address itself, or IPv6's every address, likewise.
        for udp in ["10.99.0.2:6881", "[::]:6881"] {
            let v = strict(&["127.0.0.1:6881"], &[udp]);
            let ok = check(&b, Some(&a), &v, Some(&[]), Some(&[])).unwrap();
            assert_eq!(ok.udp, Some(udp.parse().unwrap()), "{udp}");
        }
        // The holders are always looked up, even for a hold that needs no look when relayed:
        // another program could take the datagrams.
        let on_tunnel = strict(&["127.0.0.1:6881"], &["10.99.0.2:6881"]);
        assert!(needs_holders(&on_tunnel, 6881, true, true));
        assert!(!needs_holders(&on_tunnel, 6881, true, false));
        // Only on loopback: what goes in would never reach it.
        let lo = strict(&["127.0.0.1:6881"], &["127.0.0.1:6881"]);
        let err = check(&b, Some(&a), &lo, Some(&[]), Some(&[])).unwrap_err();
        assert_eq!(
            (err.state, err.code),
            (ForwardState::TargetMissing, "APP_UDP_LOOPBACK_ONLY")
        );
        assert!(err.reason.zh_tw.contains("0.0.0.0"), "{}", err.reason.zh_tw);
        // Another program on an address the datagrams reach.
        let thief = [own[0].clone(), holder(77, "nc", "10.99.0.2:6881")];
        let err = check(&b, Some(&a), &kad, Some(&[]), Some(&thief)).unwrap_err();
        assert_eq!(
            (err.state, err.code),
            (ForwardState::TargetNotOwned, "PORT_SHADOWED")
        );
        assert!(
            err.reason.zh_tw.contains("nc") && err.reason.zh_tw.contains("77"),
            "{}",
            err.reason.zh_tw
        );
        // ...or on loopback, which takes none of them: fine.
        let local = [own[0].clone(), holder(77, "nc", "127.0.0.1:6881")];
        assert!(check(&b, Some(&a), &kad, Some(&[]), Some(&local)).is_ok());
        // Cannot tell: stop rather than guess.
        assert_eq!(
            code(check(&b, Some(&a), &kad, Some(&[]), None)),
            (ForwardState::TargetMissing, "APP_NOT_CHECKED")
        );
        // Not held at all: by another program, by the App since the scan, or by nobody (and the
        // reason says where the App must receive).
        let none = strict(&["127.0.0.1:6881"], &[]);
        let other = [holder(77, "nc", "0.0.0.0:6881")];
        assert_eq!(
            code(check(&b, Some(&a), &none, Some(&[]), Some(&other))),
            (ForwardState::TargetNotOwned, "PORT_HELD_BY_OTHER")
        );
        assert_eq!(
            code(check(&b, Some(&a), &none, Some(&[]), Some(&own))),
            (ForwardState::TargetMissing, "APP_NOT_CHECKED")
        );
        let err = check(&b, Some(&a), &none, Some(&[]), Some(&[])).unwrap_err();
        assert_eq!(err.code, "APP_NOT_LISTENING");
        assert!(err.reason.zh_tw.contains("0.0.0.0"), "{}", err.reason.zh_tw);
        // TCP on every address is still the TCP side's problem, and the reason says TCP.
        let both_wild = strict(&["0.0.0.0:6881"], &["0.0.0.0:6881"]);
        let tcp_own = [holder(4242, "p2pd", "0.0.0.0:6881")];
        let err = check(&b, Some(&a), &both_wild, Some(&tcp_own), Some(&own)).unwrap_err();
        assert_eq!(err.code, "APP_WILDCARD_TUNNEL_PORT");
        assert!(err.reason.zh_tw.contains("（TCP）"), "{}", err.reason.zh_tw);
        // UDP alone straight in: no TCP side at all.
        let udp_only = ForwardBinding {
            protocol: ForwardProtocol::Udp,
            ..b.clone()
        };
        let ok = check(
            &udp_only,
            Some(&a),
            &strict(&[], &["0.0.0.0:6881"]),
            None,
            Some(&own),
        )
        .unwrap();
        assert_eq!(
            (ok.tcp, ok.udp),
            (None, Some("0.0.0.0:6881".parse().unwrap()))
        );
        // Only a strict App receives what goes into the sandbox, running or not.
        let proxied = app(i, AppIsolation::ProxyEnv);
        let b2 = ForwardBinding {
            target_app_id: proxied.id,
            ..b
        };
        for view in [
            running(i, &["127.0.0.1:6881"], &["0.0.0.0:6881"], Duration::ZERO),
            TargetView::NotRunning(AppRunState::Stopped),
        ] {
            assert_eq!(
                code(check(&b2, Some(&proxied), &view, Some(&[]), Some(&[]))),
                (ForwardState::TargetMissing, "UDP_DIRECT_NOT_STRICT")
            );
        }
    }
}
