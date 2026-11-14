//! Host ports for Gateways and the Apps' local access ports. The manager owns every such
//! listener, so it is the one that can tell whether a port is free: the controller never binds or
//! dials.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};

use vpn_domain::{ApiError, AppSpec, ErrorCode, FieldError, GatewaySpec, tr};
use vpn_platform::listener::bind_loopback;
use vpn_store::Store;

use crate::Manager;

/// At most this many ports are tried for one question.
const SCAN: u16 = 200;
/// Gateways and access ports take unprivileged ports only.
const MIN_PORT: u16 = 1024;

/// Bind `127.0.0.1:port` as a Gateway would, and close it again at once.
fn try_bind(port: u16) -> std::io::Result<()> {
    bind_loopback(port).map(drop)
}

/// Whether `port` can be taken on every address (`0.0.0.0`) — what an access port open to the
/// LAN binds — as well as on loopback: a free port fits either use.
fn free_everywhere(port: u16) -> bool {
    try_bind(port).is_ok()
        && std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).is_ok()
}

/// Host ports configured for something already: every Gateway's and every App's access ports.
async fn configured(store: &Store) -> Result<HashSet<u16>, ApiError> {
    let mut used: HashSet<u16> = store
        .list::<GatewaySpec>()
        .await
        .map_err(|e| e.to_api())?
        .into_iter()
        .map(|g| g.port)
        .collect();
    used.extend(
        store
            .list::<AppSpec>()
            .await
            .map_err(|e| e.to_api())?
            .into_iter()
            .flat_map(|a| a.access_ports.into_iter().map(|p| p.host_port)),
    );
    Ok(used)
}

/// The first port from `from` on (at most [`SCAN`] tried) that no Gateway or access port uses
/// and that can be bound on 127.0.0.1 and on every address right now.
pub async fn free(store: &Store, from: u16) -> Result<u16, ApiError> {
    let used = configured(store).await?;
    let from = from.max(MIN_PORT);
    let last = from.saturating_add(SCAN - 1);
    (from..=last)
        .find(|p| !used.contains(p) && free_everywhere(*p))
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ListenerConflict,
                tr!(
                    "Ports {from}–{last} are all used by Gateways or other programs; start the search from another port",
                    "port {from}–{last} 都已被 Gateway 或其他程式使用；請從其他 port 開始找",
                    "ポート {from}–{last} はすべてゲートウェイかほかのプログラムが使用しています。別のポートから探してください"
                ),
            )
        })
}

/// A Gateway may not take a port another program holds: the port is test-bound on 127.0.0.1
/// as the Gateway would bind it, unless VPN Manager itself holds it for this Gateway. A disabled
/// Gateway binds nothing, so it is checked once it is enabled. Nor may it take an App's access
/// port, enabled or not.
pub async fn check_gateway(manager: &Manager, g: &GatewaySpec) -> Result<(), ApiError> {
    if let Some(app) = manager
        .ctx
        .store
        .list::<AppSpec>()
        .await
        .map_err(|e| e.to_api())?
        .into_iter()
        .find(|a| a.access_ports.iter().any(|p| p.host_port == g.port))
    {
        let (port, name) = (g.port, &app.name);
        let message = tr!(
            "Port {port} is used by a local access port of the app “{name}”",
            "port {port} 已被 App「{name}」的本機存取埠使用",
            "ポート {port} はアプリ「{name}」のローカルアクセスポートが使用しています"
        );
        return Err(
            ApiError::new(ErrorCode::ListenerConflict, message.clone()).with_fields(vec![
                FieldError {
                    path: "/port".into(),
                    code: "PORT_IN_USE".into(),
                    message,
                },
            ]),
        );
    }
    if !g.enabled || manager.holds_gateway_port(g).await {
        return Ok(());
    }
    try_bind(g.port).map_err(|e| {
        let port = g.port;
        let (message, field) = if e.kind() == ErrorKind::AddrInUse {
            (
                tr!(
                    "Port {port} is taken by another program; choose another port, or close the program that holds it first",
                    "port {port} 已被其他程式占用；請換一個 port，或先關閉占用它的程式",
                    "ポート {port} はほかのプログラムが使用しています。別のポートにするか、先にそのプログラムを終了してください"
                ),
                tr!(
                    "This port is taken by another program",
                    "這個 port 已被其他程式占用",
                    "このポートはほかのプログラムが使用しています"
                ),
            )
        } else {
            let m = tr!(
                "Cannot use 127.0.0.1:{port} ({e}); choose another port",
                "無法使用 127.0.0.1:{port}（{e}）；請換一個 port",
                "127.0.0.1:{port} を使用できません（{e}）。別のポートにしてください"
            );
            (m.clone(), m)
        };
        ApiError::new(ErrorCode::ListenerConflict, message).with_fields(vec![FieldError {
            path: "/port".into(),
            code: "PORT_HELD".into(),
            message: field,
        }])
    })
}
