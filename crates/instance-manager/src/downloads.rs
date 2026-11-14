//! The manager's side of SSH download (`crates/ssh-download`): the component's narrow Gateway
//! lookup answered from the Instances' live state, and its status events put into the manager's
//! event stream. The component itself owns its jobs, records and connections.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use futures_util::future::BoxFuture;
use tokio::sync::{broadcast, watch};
use vpn_domain::{
    GatewayId, GatewayKind, GatewaySpec, GatewayState, InstanceId, InstanceSpec, Phase, Text, tr,
};
use vpn_ssh_download::{Gateway, Route, Routes};
use vpn_store::Store;
use zeroize::Zeroizing;

use crate::{Manager, ManagerEvent};

/// Why a job waits for the connection `name`: its phase, in the words of a waiting job.
fn waiting_for(name: &Text, p: Phase) -> Text {
    let name = name.clone();
    match p {
        Phase::Stopped => tr!(
            "The connection “{name}” is stopped",
            "連線「{name}」已停止",
            "接続「{name}」は停止しています";
            name = name
        ),
        Phase::Starting => tr!(
            "The connection “{name}” is starting",
            "連線「{name}」啟動中",
            "接続「{name}」は開始中です";
            name = name
        ),
        Phase::Connecting => tr!(
            "The connection “{name}” is handshaking",
            "連線「{name}」握手中",
            "接続「{name}」はハンドシェイク中です";
            name = name
        ),
        Phase::Verifying => tr!(
            "The connection “{name}” is verifying DNS",
            "連線「{name}」正在驗證 DNS",
            "接続「{name}」は DNS を検証しています";
            name = name
        ),
        Phase::Ready => tr!(
            "The connection “{name}” is connected",
            "連線「{name}」已連線",
            "接続「{name}」は接続済みです";
            name = name
        ),
        Phase::Degraded => tr!(
            "The connection “{name}” is unstable and has paused new connections",
            "連線「{name}」不穩定，暫停接受新連線",
            "接続「{name}」は不安定なため、新しい接続の受け付けを一時停止しています";
            name = name
        ),
        Phase::Reconnecting => tr!(
            "The connection “{name}” is reconnecting",
            "連線「{name}」重新連線中",
            "接続「{name}」は再接続中です";
            name = name
        ),
        Phase::Stopping => tr!(
            "The connection “{name}” is stopping",
            "連線「{name}」停止中",
            "接続「{name}」は停止中です";
            name = name
        ),
        Phase::Failed => tr!(
            "The connection “{name}” needs attention",
            "連線「{name}」需要處理",
            "接続「{name}」は要対応です";
            name = name
        ),
        Phase::RecoveryRequired => tr!(
            "The connection “{name}” needs a manual decision",
            "連線「{name}」需人工確認",
            "接続「{name}」には手動での確認が必要です";
            name = name
        ),
    }
}

/// Which loopback port carries a Gateway's traffic now, from the Store (its settings) and the
/// Instance's actor (its live state). Only a Ready, not latched Instance whose Gateway serves
/// gives a route; the Gateway still refuses on its own whenever its gate closes.
pub struct ManagerRoutes {
    manager: Weak<Manager>,
    store: Arc<Store>,
    key: Option<Arc<Zeroizing<[u8; 32]>>>,
    changes: watch::Sender<u64>,
}

impl ManagerRoutes {
    pub(crate) fn new(
        manager: Weak<Manager>,
        store: Arc<Store>,
        key: Option<Arc<Zeroizing<[u8; 32]>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            manager,
            store,
            key,
            changes: watch::Sender::new(0),
        })
    }

    /// Bump `changes` whenever an Instance's phase or a Gateway's state changes (not on every
    /// status): a job waiting for the VPN tries again at once.
    pub(crate) fn follow(self: &Arc<Self>, mut events: broadcast::Receiver<ManagerEvent>) {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut seen: HashMap<InstanceId, (Phase, Vec<(GatewayId, GatewayState)>)> =
                HashMap::new();
            loop {
                let ev = match events.recv().await {
                    Ok(ev) => ev,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        seen.clear();
                        continue;
                    }
                    Err(_) => return,
                };
                let ManagerEvent::Status(s) = ev else {
                    continue;
                };
                let now = (
                    s.phase,
                    s.gateways
                        .iter()
                        .map(|g| (g.gateway_id, g.state))
                        .collect::<Vec<_>>(),
                );
                if seen.get(&s.instance_id) == Some(&now) {
                    continue;
                }
                seen.insert(s.instance_id, now);
                let Some(me) = me.upgrade() else { return };
                me.changes.send_modify(|n| *n = n.wrapping_add(1));
            }
        });
    }
}

const fn waiting(code: &'static str, reason: Text) -> Route {
    Route::Waiting { code, reason }
}

impl ManagerRoutes {
    /// The Gateway `id` and the key it proves itself with, when it can carry SSH at all;
    /// otherwise the route to answer instead.
    async fn usable_gateway(
        &self,
        id: GatewayId,
    ) -> Result<(GatewaySpec, Arc<Zeroizing<[u8; 32]>>), Route> {
        let g: GatewaySpec = match self.store.get(id.to_string()).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                return Err(Route::Invalid {
                    code: "GATEWAY_MISSING",
                    reason: tr!(
                        "This Gateway no longer exists",
                        "這個代理埠已不存在",
                        "このゲートウェイはもう存在しません"
                    ),
                });
            }
            Err(e) => {
                return Err(waiting(
                    "STORE_UNAVAILABLE",
                    tr!(
                        "Cannot read the Gateway: {e}",
                        "無法讀取代理埠：{e}",
                        "ゲートウェイを読み取れません：{e}"
                    ),
                ));
            }
        };
        let gateway_name = &g.name;
        if g.kind == GatewayKind::Http {
            return Err(Route::Invalid {
                code: "GATEWAY_NOT_SOCKS",
                reason: tr!(
                    "The Gateway “{gateway_name}” is HTTP only; SSH needs a SOCKS5 or Mixed Gateway",
                    "代理埠「{gateway_name}」只有 HTTP；SSH 需要 SOCKS5 或 Mixed 代理埠",
                    "ゲートウェイ「{gateway_name}」は HTTP 専用です。SSH には SOCKS5 または Mixed のゲートウェイが必要です"
                ),
            });
        }
        let Some(key) = self.key.clone() else {
            return Err(Route::Invalid {
                code: "GATEWAY_KEY_MISSING",
                reason: tr!(
                    "The Gateway key file is missing, so the Gateway cannot be proven to be VPN Manager's",
                    "找不到代理埠金鑰檔，無法證明代理埠屬於 VPN Manager",
                    "ゲートウェイの鍵ファイルが見つからないため、ゲートウェイが VPN Manager のものだと証明できません"
                ),
            });
        };
        if !g.enabled {
            return Err(waiting(
                "GATEWAY_DISABLED",
                tr!(
                    "The Gateway “{gateway_name}” is disabled",
                    "代理埠「{gateway_name}」已停用",
                    "ゲートウェイ「{gateway_name}」は無効です"
                ),
            ));
        }
        Ok((g, key))
    }
}

impl Routes for ManagerRoutes {
    fn route(&self, gateway: GatewayId) -> BoxFuture<'_, Route> {
        Box::pin(async move {
            let (g, key) = match self.usable_gateway(gateway).await {
                Ok(usable) => usable,
                Err(route) => return route,
            };
            let Some(manager) = self.manager.upgrade() else {
                return waiting(
                    "VPN_NOT_READY",
                    tr!(
                        "The manager is stopping",
                        "manager 正在停止",
                        "manager を停止しています"
                    ),
                );
            };
            let name = match self
                .store
                .get::<InstanceSpec>(g.instance_id.to_string())
                .await
            {
                Ok(Some(i)) => Text::verbatim(i.name),
                _ => tr!("(unknown)", "（未知）", "（不明）"),
            };
            let Ok(status) = manager.status(g.instance_id).await else {
                return waiting(
                    "VPN_UNKNOWN",
                    tr!(
                        "Cannot get the status of the connection “{name}”",
                        "無法取得連線「{name}」的狀態",
                        "接続「{name}」の状態を取得できません";
                        name = name
                    ),
                );
            };
            if status.intent.emergency_latched {
                return waiting(
                    "VPN_EMERGENCY",
                    tr!(
                        "The connection “{name}” is in emergency stop",
                        "連線「{name}」已急停",
                        "接続「{name}」は緊急停止しています";
                        name = name
                    ),
                );
            }
            if status.phase != Phase::Ready {
                return waiting("VPN_NOT_READY", waiting_for(&name, status.phase));
            }
            match status.gateways.iter().find(|r| r.gateway_id == g.id) {
                Some(r) if r.state == GatewayState::Serving => {
                    Route::Ready(Gateway { port: g.port, key })
                }
                _ => {
                    let gateway_name = &g.name;
                    waiting(
                        "GATEWAY_NOT_SERVING",
                        tr!(
                            "The Gateway “{gateway_name}” is not serving",
                            "代理埠「{gateway_name}」沒有在服務",
                            "ゲートウェイ「{gateway_name}」はサービスを提供していません"
                        ),
                    )
                }
            }
        })
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}
