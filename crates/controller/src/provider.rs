//! Provider operations (architecture §7).
//!
//! Every byte to a provider goes through a relay socket of the manager: the selected egress Instance's connector (inside its tunnel), or the grant of
//! a run of the direct exception (direct, allowlisted, and only for building an egress: see
//! `crate::egress`). The controller never dials and never resolves names.
//!
//! Every provider HTTP request goes through the operation's [`guard::Guard`]: its own budget,
//! its own fresh exit check over the same route, a single-use permit checked right before the
//! request's first byte. A route that cannot reach the checker sends nothing to the provider.
//! Credentials are leased from the vault for one operation and zeroized; tokens live in memory
//! only.

pub mod budget;
pub mod gates;
pub mod guard;
mod route;

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use vpn_domain::validation::check_profile;
use vpn_domain::{
    ApiError, BootstrapKind, BootstrapRun, BootstrapStage, EgressMode, EgressPhase, EgressRecovery,
    ErrorCode, FieldError, ForwardedPort, ForwardedPortDdns, ForwardedPortDevice,
    ForwardedPortSearch, ForwardedPortTest, ForwardedPortUpdate, ForwardedPorts, GateStatus,
    GatewayId, GatewayKind, GatewaySpec, InstanceId, InstanceLimits, InstancePurpose, InstanceSpec,
    InstanceStatus, InterfaceSpec, IpCheckStatus, IpFamily, OperationId, PeerSpec, Phase,
    ProfileId, ProfileLocation, ProfileSource, ProviderAccount, ProviderAccountId,
    ProviderAccountInput, ProviderConnectInput, ProviderConnectResult, ProviderCredentialInput,
    ProviderDevice, ProviderEgress, ProviderEgressStatus, ProviderEntryInput, ProviderGate,
    ProviderGateKind, ProviderIpCheck, ProviderKind, ProviderMatch, ProviderServer,
    ProviderServerChangeInput, RouteMode, RuntimeProfile, SecretRef, Text, Timestamp,
    ValidationReport, WgKey, tr,
};
use vpn_ipc::SecretBytes;
use vpn_ipc::control::{
    BootstrapGrantWire, Call, ChildClaimWire, Entity, EntityKind, Lifecycle, Reply,
};
use vpn_ipc::relay::{self, RelayAnswer, RelayEpochs, RelayFamily, RelayLine, RelayRoute};
use vpn_providers::airvpn::{self, AirVpn, Credentials, InvalidCredentials, ServerWarning};
use vpn_providers::https::{BoxedStream, Connect, Family, HttpsClient};
use vpn_providers::mullvad::{
    self, AccessToken, AccountNumber, Mullvad, MultihopPorts, RelayCatalog,
};
use vpn_providers::{ProviderError, Refusal, Tls, ipcheck};
use vpn_sync::Mutex;
use zeroize::Zeroizing;

use self::budget::Budget;
use self::gates::GateBook;
use self::guard::{Guard, Probe, RouteProfile};
use crate::link::ManagerLink;

/// Public catalogs are reused this long.
const CATALOG_TTL: Duration = Duration::from_mins(15);
/// A cached access token is used only with this much validity left.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);
const REPLY_MAX: usize = 1024;

// -------------------------------------------------------------------------------------------
// Relay sockets
// -------------------------------------------------------------------------------------------

/// [`Connect`] over one of the manager's relay sockets.
///
/// The socket is an Instance generation's connector or the bootstrap grant. Same request line for both (`vpn_ipc::relay`, version 2): every line carries
/// a fresh single-use nonce and the route it is meant for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    path: Arc<PathBuf>,
    route: RelayRoute,
}

/// Why a relay connection was not opened.
pub(crate) enum RelayError {
    Io(io::Error),
    /// The connector refused what the guard checks — the nonce, the route, the epochs — on its
    /// own check before dialing.
    Refused(Refusal),
}

impl RelayError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Io(e) => e,
            Self::Refused(r) => io::Error::other(r),
        }
    }
}

/// An I/O failure of the provider channel whose message a person reads: carried as a
/// [`Refusal`] (nothing reached the provider), which `HttpError::text` shows in the three
/// languages.
fn channel_error(kind: io::ErrorKind, message: Text) -> io::Error {
    io::Error::new(kind, Refusal::new(ErrorCode::ProviderUnavailable, message))
}

/// The provider channel's answer is not the relay protocol's.
fn malformed_answer() -> Text {
    tr!(
        "The provider channel's answer is malformed",
        "供應商通道回覆格式錯誤",
        "プロバイダーチャネルの応答の形式が正しくありません"
    )
}

impl Relay {
    /// The connector of `instance_id`'s generation `generation`, as the manager handed it out.
    #[must_use]
    pub fn instance(path: String, instance_id: InstanceId, generation: u64) -> Self {
        Self {
            path: Arc::new(PathBuf::from(path)),
            route: RelayRoute::Instance {
                instance_id,
                generation,
            },
        }
    }

    /// The bootstrap grant's relay socket.
    #[must_use]
    pub fn bootstrap(path: String) -> Self {
        Self {
            path: Arc::new(PathBuf::from(path)),
            route: RelayRoute::Bootstrap,
        }
    }

    /// One relay connection to `host:port` over `family`: the line with a fresh nonce (and
    /// `expect`, the epochs of the check that authorized this request), then the answer. The
    /// stream and the connector's epochs.
    pub(crate) async fn open(
        &self,
        host: &str,
        port: u16,
        family: Family,
        expect: Option<RelayEpochs>,
    ) -> Result<(UnixStream, RelayEpochs), RelayError> {
        let family = match family {
            Family::V4 => RelayFamily::V4,
            Family::V6 => RelayFamily::V6,
        };
        let mut line = RelayLine::new(host, port, family, self.route);
        line.expect = expect;
        let io = |m: Text| RelayError::Io(channel_error(io::ErrorKind::Other, m));
        let mut s = UnixStream::connect(&*self.path).await.map_err(|e| {
            RelayError::Io(channel_error(
                e.kind(),
                tr!(
                    "The provider channel is closed (the egress connection reconnected, or the direct-connection grant ended)",
                    "供應商通道已關閉（出口連線已重新連線，或直連授權已結束）",
                    "プロバイダーチャネルは閉じています（出口接続が再接続したか、直接接続の許可が終了しました）"
                ),
            ))
        })?;
        s.write_all(&line.to_bytes())
            .await
            .map_err(RelayError::Io)?;
        // Read only the reply line: what follows belongs to TLS.
        let mut reply = Vec::with_capacity(160);
        let mut byte = [0u8; 1];
        loop {
            if s.read(&mut byte).await.map_err(RelayError::Io)? == 0 {
                return Err(RelayError::Io(channel_error(
                    io::ErrorKind::UnexpectedEof,
                    tr!(
                        "The provider channel closed before it answered",
                        "供應商通道在回覆前關閉",
                        "プロバイダーチャネルが応答前に閉じました"
                    ),
                )));
            }
            if byte[0] == b'\n' {
                break;
            }
            reply.push(byte[0]);
            if reply.len() > REPLY_MAX {
                return Err(io(tr!(
                    "The provider channel's answer is too long",
                    "供應商通道回覆過長",
                    "プロバイダーチャネルの応答が長すぎます"
                )));
            }
        }
        let answer: RelayAnswer =
            serde_json::from_slice(&reply).map_err(|_| io(malformed_answer()))?;
        // The connector's own words, as it wrote them.
        let message = || {
            answer.message.clone().map_or_else(
                || {
                    tr!(
                        "The provider channel refused the connection",
                        "供應商通道拒絕連線",
                        "プロバイダーチャネルが接続を拒否しました"
                    )
                },
                Text::from,
            )
        };
        match (answer.ok, answer.epochs, answer.code.as_deref()) {
            (true, Some(epochs), _) => Ok((s, epochs)),
            (true, None, _) => Err(io(malformed_answer())),
            (false, _, Some(relay::WRONG_ROUTE)) => Err(RelayError::Refused(Refusal::new(
                ErrorCode::ProviderEgressBlocked,
                message(),
            ))),
            (false, _, Some(relay::NONCE_REUSED | relay::EPOCH_CHANGED | relay::BAD_VERSION)) => {
                Err(RelayError::Refused(Refusal::new(
                    ErrorCode::ProviderPreflightFailed,
                    message(),
                )))
            }
            (false, _, _) => Err(io(message())),
        }
    }
}

impl Connect for Relay {
    async fn connect(&self, host: &str, port: u16, family: Family) -> io::Result<BoxedStream> {
        let (stream, _) = self
            .open(host, port, family, None)
            .await
            .map_err(RelayError::into_io)?;
        Ok(Box::new(stream))
    }
}

// -------------------------------------------------------------------------------------------
// Route
// -------------------------------------------------------------------------------------------

/// Where provider traffic leaves right now: what an exit check, and the request it authorizes,
/// are bound to. Two routes are the same only when all of it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub mode: RouteMode,
    pub instance_id: Option<InstanceId>,
    pub generation: Option<u64>,
    /// The egress fence (`ProviderEgress::route_revision`): advanced by every switch, by
    /// turning the egress off and by the bootstrap's use-up.
    pub egress_epoch: u64,
    pub relay: Relay,
}

/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn egress(
    link: &ManagerLink,
) -> Result<(ProviderEgress, Option<BootstrapGrantWire>), ApiError> {
    let s = binding(link).await?;
    Ok((s.egress, s.grant))
}

/// [`egress_state`] without the recovery assessment (what a route is made of).
async fn binding(link: &ManagerLink) -> Result<EgressState, ApiError> {
    state_of(link.call(Call::ProviderBinding).await?)
}

fn state_of(reply: Reply) -> Result<EgressState, ApiError> {
    match reply {
        Reply::ProviderEgress(w) => Ok(EgressState {
            egress: w.egress,
            grant: w.bootstrap,
            run: w.run,
            recovery: w.recovery,
        }),
        _ => Err(ApiError::internal()),
    }
}

/// The egress as the manager answers for it: the binding, the open grant, the active (else
/// latest) run of the direct exception, and whether the selected egress needs recovery.
pub struct EgressState {
    pub egress: ProviderEgress,
    pub grant: Option<BootstrapGrantWire>,
    pub run: Option<BootstrapRun>,
    pub recovery: Option<EgressRecovery>,
}

/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn egress_state(link: &ManagerLink) -> Result<EgressState, ApiError> {
    state_of(link.call(Call::ProviderEgress).await?)
}

fn blocked(message: impl Into<Text>) -> ApiError {
    ApiError::new(ErrorCode::ProviderEgressBlocked, message)
}

/// Where provider traffic of the current operation leaves.
///
/// A direct grant carries only the
/// operations that build an egress (see [`crate::egress::recovery`]); everything else waits for a
/// VPN egress. A rebootstrap grant is used only while the selected egress cannot carry them.
///
/// # Errors
///
/// `PROVIDER_EGRESS_BLOCKED` when the egress is disabled or cannot carry this operation
/// (none selected, not ready, or only a direct grant outside its scope), and the manager's
/// error.
pub async fn route(link: &ManagerLink) -> Result<Route, ApiError> {
    let EgressState { egress, grant, .. } = binding(link).await?;
    if egress.desired_mode == EgressMode::Disabled {
        return Err(blocked(tr!(
            "The Provider egress is disabled; choose an egress connection first",
            "Provider 出口已停用；請先選擇出口連線",
            "Provider 出口は無効です。先に出口接続を選んでください"
        )));
    }
    let direct = |b: BootstrapGrantWire| Route {
        mode: RouteMode::BootstrapDirect,
        instance_id: None,
        generation: None,
        egress_epoch: egress.route_revision,
        relay: Relay::bootstrap(b.connector),
    };
    let in_scope = crate::egress::direct_allowed();
    let out_of_scope = || {
        blocked(tr!(
            "Only building an egress is open over the direct connection now (the account, devices, the server list, creating one connection); this operation waits until the egress connection can be used",
            "目前只開放以直連建立出口（帳號、裝置、伺服器清單、建立一條連線）；這個操作要等出口連線可以使用後才能進行",
            "現在、直接接続で許可されているのは出口の作成（アカウント、デバイス、サーバー一覧、接続 1 つの作成）だけです。この操作は出口接続が使えるようになるまで待つ必要があります"
        ))
    };
    if let Some(id) = egress.selected_instance_id {
        return match link.call(Call::ProviderRoute(id)).await {
            Ok(Reply::ProviderRoute {
                generation,
                connector,
            }) => Ok(Route {
                mode: RouteMode::ViaInstance,
                instance_id: Some(id),
                generation: Some(generation),
                egress_epoch: egress.route_revision,
                relay: Relay::instance(connector, id, generation),
            }),
            Ok(_) => Err(ApiError::internal()),
            Err(_)
                if grant
                    .as_ref()
                    .is_some_and(|g| g.kind == BootstrapKind::Rebootstrap) =>
            {
                match grant {
                    Some(g) if in_scope => Ok(direct(g)),
                    _ => Err(out_of_scope()),
                }
            }
            Err(e) => Err(blocked(tr!(
                "The egress connection cannot be used right now: {why}; provider operations pause and never take another path",
                "出口連線目前無法使用：{why}；供應商操作暫停，不會改走其他路徑",
                "出口接続は現在使用できません：{why}。プロバイダーの操作は一時停止し、ほかの経路に切り替わることはありません";
                why = e.message
            ))),
        };
    }
    if let Some(b) = grant {
        return if in_scope {
            Ok(direct(b))
        } else {
            Err(out_of_scope())
        };
    }
    Err(blocked(if egress.bootstrap_consumed {
        tr!(
            "No Provider egress connection is chosen yet",
            "還沒有選擇 Provider 出口連線",
            "Provider 出口接続がまだ選ばれていません"
        )
    } else {
        tr!(
            "There is no Provider egress yet: choose a VPN connection, or open the first direct connection",
            "還沒有 Provider 出口：請選擇一條 VPN 連線，或開啟首次直連",
            "Provider 出口がまだありません。VPN 接続を選ぶか、初回の直接接続を開始してください"
        )
    }))
}

/// The profile behind `route`: whose checker answers for it — Mullvad's own when the exit is a
/// Mullvad profile or direct (it then truthfully says "not Mullvad"), `IPLeak` otherwise — and
/// whether the connection has an IPv6 address (the direct bootstrap checks IPv4 only, with
/// Mullvad's checker).
pub(crate) async fn route_profile(link: &ManagerLink, route: &Route) -> RouteProfile {
    let unknown = RouteProfile {
        provider: ProviderKind::Generic,
        ipv6: false,
    };
    let Some(id) = route.instance_id else {
        return RouteProfile {
            provider: ProviderKind::Mullvad,
            ipv6: false,
        };
    };
    let profile = match link
        .call(Call::Get(EntityKind::Instance, id.to_string()))
        .await
    {
        Ok(Reply::Entity(e)) => match *e {
            Entity::Instance(spec) => link
                .call(Call::Get(EntityKind::Profile, spec.profile_id.to_string()))
                .await
                .ok(),
            _ => None,
        },
        _ => None,
    };
    match profile {
        Some(Reply::Entity(e)) => match *e {
            Entity::Profile(p) => RouteProfile {
                provider: p.provider,
                ipv6: p
                    .interface
                    .addresses
                    .iter()
                    .any(ipnetwork::IpNetwork::is_ipv6),
            },
            _ => unknown,
        },
        _ => unknown,
    }
}

/// One exit check over `relay` (IPv4).
pub async fn check(
    relay: &Relay,
    provider: ProviderKind,
    mode: RouteMode,
    instance_id: Option<InstanceId>,
    generation: Option<u64>,
) -> ProviderIpCheck {
    let http = HttpsClient::new(Probe::new(relay.clone()));
    observe(&http, provider, Family::V4, mode, instance_id, generation)
        .await
        .0
}

/// One exit check over `http`'s connector and `family`. Each provider's own checker carries its
/// membership evidence; `IPLeak` (generic profiles) only gives the place, and only over IPv4. The
/// second value is why the check did not pass, in the three languages; the third the checker's
/// `Retry-After` when it answered 429. No credential is involved.
async fn observe<C: Connect>(
    http: &HttpsClient<C>,
    provider: ProviderKind,
    family: Family,
    mode: RouteMode,
    instance_id: Option<InstanceId>,
    generation: Option<u64>,
) -> (ProviderIpCheck, Option<Text>, Option<Option<Duration>>) {
    let started = Instant::now();
    let result = match (provider, family) {
        (ProviderKind::Mullvad, f) => Some(ipcheck::mullvad(http, f).await),
        (ProviderKind::Airvpn, f) => Some(ipcheck::airvpn(http, f).await),
        (ProviderKind::Generic, Family::V4) => Some(ipcheck::ipleak_v4(http).await),
        (ProviderKind::Generic, Family::V6) => None,
    };
    let base = ProviderIpCheck {
        provider,
        family: match family {
            Family::V4 => IpFamily::Ipv4,
            Family::V6 => IpFamily::Ipv6,
        },
        status: IpCheckStatus::Ok,
        route_mode: mode,
        instance_id,
        generation,
        tunnel_verified: mode == RouteMode::ViaInstance,
        provider_match: ProviderMatch::Unknown,
        observed_ip: None,
        country: None,
        city: None,
        checked_at: Some(Timestamp::now()),
        latency_ms: Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
        reason_code: None,
        reason: None,
        exit_server: None,
    };
    match result {
        None => {
            let why = gates::ipleak_ipv6();
            (
                ProviderIpCheck {
                    status: IpCheckStatus::NotApplicable,
                    reason: Some(why.clone()),
                    latency_ms: None,
                    ..base
                },
                Some(why),
                None,
            )
        }
        Some(Ok(o)) => (
            ProviderIpCheck {
                provider_match: o.provider_match,
                observed_ip: Some(o.ip.to_string()),
                country: o.country,
                city: o.city,
                exit_server: o.server,
                ..base
            },
            None,
            None,
        ),
        Some(Err(e)) => {
            let limited = match &e {
                ProviderError::RateLimited { retry_after } => Some(*retry_after),
                _ => None,
            };
            let why = e.text();
            (
                ProviderIpCheck {
                    status: match e {
                        ProviderError::ContractDrift(_) => IpCheckStatus::ContractDrift,
                        ProviderError::RateLimited { .. } => IpCheckStatus::Blocked,
                        _ => IpCheckStatus::Unavailable,
                    },
                    reason: Some(why.clone()),
                    latency_ms: None,
                    ..base
                },
                Some(why),
                limited,
            )
        }
    }
}

/// The selected egress Instance's name and status (`None`: not known).
async fn selected_egress(
    link: &ManagerLink,
    id: InstanceId,
) -> (Option<String>, Option<InstanceStatus>) {
    let name = if let Ok(Reply::Entity(e)) = link
        .call(Call::Get(EntityKind::Instance, id.to_string()))
        .await
        && let Entity::Instance(spec) = *e
    {
        Some(spec.name)
    } else {
        None
    };
    let status = match link.call(Call::InstanceStatus(id)).await {
        Ok(Reply::Status(s)) => Some(*s),
        _ => None,
    };
    (name, status)
}

/// The egress phase from the selected Instance's status (`None`: not known), with its reason
/// code and reason when it is not ready.
fn selected_phase(
    status: Option<&InstanceStatus>,
    recovery: Option<&EgressRecovery>,
) -> (EgressPhase, Option<String>, Option<Text>) {
    let required = recovery.is_some_and(|r| r.required);
    let mut reason_code = None;
    let mut reason = None;
    let phase = match status.map(|s| s.phase) {
        Some(Phase::Ready) => EgressPhase::VpnReady,
        _ if required => {
            if let Some(r) = recovery {
                reason_code = Some(r.reason_code.clone());
                reason = Some(r.reason.clone());
            }
            EgressPhase::RecoveryRequired
        }
        Some(Phase::Starting | Phase::Connecting | Phase::Verifying) => {
            EgressPhase::StartingInstance
        }
        Some(_) => {
            if let Some(r) = recovery {
                reason_code = Some(r.reason_code.clone());
                reason = Some(r.reason.clone());
            } else {
                reason_code = Some("EGRESS_NOT_READY".into());
                reason = Some(tr!(
                    "The egress connection is not running; provider operations pause until it recovers (it is never switched automatically)",
                    "出口連線沒有在執行；供應商操作會暫停，直到它恢復（不會自動換線）",
                    "出口接続が実行されていません。復旧するまでプロバイダーの操作は一時停止します（自動では切り替わりません）"
                ));
            }
            EgressPhase::Blocked
        }
        None => {
            reason_code = Some("EGRESS_UNKNOWN".into());
            reason = Some(tr!(
                "Cannot get the egress connection's status",
                "無法取得出口連線的狀態",
                "出口接続の状態を取得できません"
            ));
            EgressPhase::Blocked
        }
    };
    (phase, reason_code, reason)
}

/// Store the generated `profile` when `report` has no errors; otherwise, or when the manager
/// refuses it, delete the key material stored for it (`fresh`) and fail.
async fn store_profile(
    link: &ManagerLink,
    profile: RuntimeProfile,
    report: &ValidationReport,
    fresh: Vec<SecretRef>,
) -> Result<RuntimeProfile, ApiError> {
    let created = if report.has_errors() {
        Err(crate::http::report_error(report).0)
    } else {
        match link.call(Call::Create(Entity::Profile(profile))).await {
            Ok(Reply::Entity(e)) => {
                if let Entity::Profile(p) = *e {
                    Ok(p)
                } else {
                    Err(ApiError::internal())
                }
            }
            Ok(_) => Err(ApiError::internal()),
            Err(e) => Err(e),
        }
    };
    if created.is_err() {
        for r in fresh {
            let _ = link.call(Call::DeleteSecret(r)).await;
        }
    }
    created
}

/// Create a connection that is not a run's: the Instance, its Gateway if any (a refused
/// Gateway is left out), and its start when `start`.
async fn create_connection(
    link: &ManagerLink,
    spec: InstanceSpec,
    gateway: Option<GatewaySpec>,
    start: bool,
) -> Result<(InstanceSpec, Option<GatewayId>), ApiError> {
    let instance = match link.call(Call::Create(Entity::Instance(spec))).await? {
        Reply::Entity(e) => match *e {
            Entity::Instance(s) => s,
            _ => return Err(ApiError::internal()),
        },
        _ => return Err(ApiError::internal()),
    };
    let gateway_id = match gateway {
        Some(g) => match link.call(Call::Create(Entity::Gateway(g))).await? {
            Reply::Entity(e) => match *e {
                Entity::Gateway(g) => Some(g.id),
                _ => None,
            },
            _ => None,
        },
        None => None,
    };
    if start {
        link.call(Call::Lifecycle(instance.id, Lifecycle::Start))
            .await?;
    }
    Ok((instance, gateway_id))
}

/// An imported profile whose key is none of the account's devices.
fn not_a_device() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidState,
        tr!(
            "The key of this imported profile is not one of this account's devices; only the account's devices can change servers. For other profiles, import a new .conf",
            "這份匯入設定的金鑰不是這個帳號的裝置；只有帳號裡的裝置可以更換伺服器，其他設定請重新匯入新的 .conf",
            "このインポートした設定の鍵は、このアカウントのデバイスのものではありません。サーバーを変更できるのはアカウントのデバイスだけです。それ以外の設定は新しい .conf をインポートし直してください"
        ),
    )
}

/// The device's public key is not the profile's.
fn key_changed() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidState,
        tr!(
            "The device's public key differs from this profile's; use a new connection instead",
            "裝置的公開金鑰與這份設定不同；請改用新的連線",
            "デバイスの公開鍵がこの設定と異なります。新しい接続を使ってください"
        ),
    )
}

/// The Mullvad device of a new connection: `input.device_id` when this host holds its private
/// key, otherwise a new device with a key generated and stored for it (`name` labels it).
async fn mullvad_device(
    link: &ManagerLink,
    api: &MullvadApi<'_>,
    token: &AccessToken,
    input: &ProviderConnectInput,
    name: &str,
) -> Result<(mullvad::Device, SecretRef), ApiError> {
    if let Some(id) = &input.device_id {
        let devices = api.devices(token).await.map_err(|e| provider_error(&e))?;
        let device = devices
            .into_iter()
            .find(|d| d.id.as_str() == id)
            .ok_or_else(|| {
                field_error(
                    "/device_id",
                    tr!(
                        "This device was not found",
                        "找不到這個裝置",
                        "このデバイスが見つかりません"
                    ),
                )
            })?;
        let secret = local_keys(link)
            .await?
            .get(&key_fingerprint(&device.pubkey))
            .copied()
            .ok_or_else(|| {
                field_error(
                    "/device_id",
                    tr!(
                        "This computer does not have this device's private key; use a new device instead",
                        "這台電腦沒有這個裝置的私鑰；請改用新裝置",
                        "このコンピューターにはこのデバイスの秘密鍵がありません。新しいデバイスを使ってください"
                    ),
                )
            })?;
        Ok((device, secret))
    } else {
        let (secret, public_key) = match link
            .call(Call::GenerateKey {
                label: Some(name.to_string()),
            })
            .await?
        {
            Reply::GeneratedKey { secret, public_key } => (secret.secret_ref, public_key),
            _ => return Err(ApiError::internal()),
        };
        match api.create_device(token, &public_key).await {
            Ok(d) => Ok((d, secret)),
            Err(e) if e.outcome_unknown() => {
                // Never resend: find out whether it was created.
                match api.reconcile_device(token, &public_key).await {
                    Ok(mullvad::Reconciled::Bound(d)) => Ok((d, secret)),
                    _ => Err(ApiError::new(
                        ErrorCode::OutcomeUnknown,
                        tr!(
                            "Whether the new device was created is unknown; the key is kept. Refresh the device list later",
                            "新裝置的建立結果未知；金鑰已保留，請稍後重新整理裝置清單",
                            "新しいデバイスが作成されたかどうか不明です。鍵は保持しています。しばらくしてからデバイス一覧を更新してください"
                        ),
                    )),
                }
            }
            Err(e) => {
                let _ = link.call(Call::DeleteSecret(secret)).await;
                Err(provider_error(&e))
            }
        }
    }
}

/// The vault references of `device`'s private key (the stored one when this host has it) and
/// preshared key, and those stored by this call (to delete again if no profile keeps them).
async fn store_airvpn_keys(
    link: &ManagerLink,
    device: &airvpn::Device,
    name: &str,
) -> Result<(SecretRef, SecretRef, Vec<SecretRef>), ApiError> {
    let mut fresh = Vec::new();
    let fingerprint = key_fingerprint(&device.public_key);
    let private_key = if let Some(r) = local_keys(link).await?.get(&fingerprint).copied() {
        r
    } else {
        let r = put_secret(
            link,
            "wireguard_private_key",
            name,
            device.private_key.bytes().to_vec(),
            Some(fingerprint),
        )
        .await?;
        fresh.push(r);
        r
    };
    let preshared = match put_secret(
        link,
        "wireguard_preshared_key",
        name,
        device.preshared_key.bytes().to_vec(),
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            for r in fresh {
                let _ = link.call(Call::DeleteSecret(r)).await;
            }
            return Err(e);
        }
    };
    fresh.push(preshared);
    Ok((private_key, preshared, fresh))
}

fn provider_error(e: &ProviderError) -> ApiError {
    ApiError::new(e.code(), e.text())
}

/// A website failure as the API reports it; what the request named carries its field: the port,
/// a setting the page would not take, each setting `AirVPN` did not keep.
fn site_error(e: &airvpn::site::SiteError) -> ApiError {
    use airvpn::site::SiteError;
    let message = e.text();
    let field = |path: &str, code: &str, message: Text| FieldError {
        path: path.into(),
        code: code.into(),
        message,
    };
    let fields = match e {
        SiteError::PortOutOfRange(_) => vec![field("/port", "PORT_RANGE", message.clone())],
        SiteError::AlreadyReserved(_) => {
            vec![field("/port", "PORT_ALREADY_RESERVED", message.clone())]
        }
        SiteError::Invalid {
            field: Some(path),
            reason,
        } => vec![field(path, "INVALID", reason.clone())],
        SiteError::NotSaved { unsaved, .. } => unsaved
            .iter()
            .map(|u| field(u.setting.path(), "NOT_SAVED", u.why.text()))
            .collect(),
        _ => Vec::new(),
    };
    ApiError::new(e.code(), message).with_fields(fields)
}

/// Forwarded ports are reserved only at `AirVPN` (its website): Mullvad discontinued port
/// forwarding, and generic profiles have no provider account.
///
/// # Errors
///
/// `UNSUPPORTED_CAPABILITY` for a Mullvad or generic account.
pub fn reservations(account: &ProviderAccount) -> Result<(), ApiError> {
    match account.provider {
        ProviderKind::Airvpn => Ok(()),
        ProviderKind::Mullvad => Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            tr!(
                "Mullvad no longer offers port forwarding: a Mullvad account has no inbound ports to reserve (forward_reservation supports AirVPN only)",
                "Mullvad 已停止提供 port forwarding：Mullvad 帳號沒有可以保留的連入埠（forward_reservation 只支援 AirVPN）",
                "Mullvad は port forwarding の提供を終了しました。Mullvad アカウントには予約できる着信ポートがありません（forward_reservation は AirVPN のみ対応）"
            ),
        )),
        ProviderKind::Generic => Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            tr!(
                "This provider has no inbound ports that can be reserved here (forward_reservation supports AirVPN only)",
                "這個供應商沒有可以在這裡保留的連入埠（forward_reservation 只支援 AirVPN）",
                "このプロバイダーには、ここで予約できる着信ポートがありません（forward_reservation は AirVPN のみ対応）"
            ),
        )),
    }
}

/// A port that may be asked for (2049–65535); `None` lets `AirVPN` pick one.
///
/// # Errors
///
/// A validation error naming `/port` when it is below `AirVPN`'s minimum.
pub fn reservable(port: Option<u16>) -> Result<(), ApiError> {
    port.map_or(Ok(()), |p| {
        airvpn::site::check_port(p).map_err(|e| site_error(&e))
    })
}

/// A settings change `AirVPN`'s page takes: something to change, each value in its range.
///
/// # Errors
///
/// A validation error naming the setting `AirVPN`'s page would not take.
pub fn changeable(update: &ForwardedPortUpdate) -> Result<(), ApiError> {
    airvpn::site::check_update(update).map_err(|e| site_error(&e))
}

/// A search for `count` consecutive free ports `AirVPN`'s page takes (2–10).
///
/// # Errors
///
/// A validation error naming `/count` when it is outside 2–10.
pub fn searchable(count: u8) -> Result<(), ApiError> {
    airvpn::site::check_count(count).map_err(|e| site_error(&e))
}

/// One `AirVPN` port in the API's terms; `list` names its device when it is limited to one.
fn forwarded_port(p: &airvpn::site::Port, list: Option<&airvpn::site::PortList>) -> ForwardedPort {
    ForwardedPort {
        port: p.port,
        pool: p.pool,
        enabled: p.enabled,
        protocol: p.protocol,
        ip_layer: p.ip_layer.clone(),
        device_id: p.device.clone(),
        device_name: p
            .device
            .as_deref()
            .and_then(|d| list.and_then(|l| l.device_name(d)))
            .map(str::to_owned),
        local_port: p.local_port(),
        dns_name: p.dns.clone(),
        notes: p.notes.clone(),
    }
}

fn still_used() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidState,
        tr!(
            "A WireGuard profile still uses this device's key; delete the connections and profiles that use it first",
            "仍有 WireGuard 設定使用這個裝置的金鑰；請先刪除使用它的連線與設定",
            "このデバイスの鍵をまだ使っている WireGuard 設定があります。先に、それを使っている接続と設定を削除してください"
        ),
    )
}

/// A provider this flow does not support.
fn unsupported() -> ApiError {
    ApiError::new(
        ErrorCode::UnsupportedCapability,
        tr!(
            "This provider is not supported yet",
            "這個供應商尚未支援",
            "このプロバイダーにはまだ対応していません"
        ),
    )
}

/// The rule of a name the user gives.
fn name_rule() -> Text {
    tr!(
        "The name needs 1–64 characters",
        "名稱需要 1–64 個字元",
        "名前は 1〜64 文字にしてください"
    )
}

/// The server has no entry address of the family asked for.
fn no_entry_for_family() -> ApiError {
    field_error(
        "/endpoint_family",
        tr!(
            "This server has no entry for this IP version",
            "這台伺服器沒有這個 IP 版本的入口",
            "このサーバーにはこの IP バージョンの入口がありません"
        ),
    )
}

/// An `AirVPN` server that is not listed, or whose entry the status list does not confirm.
fn unknown_air_server() -> ApiError {
    field_error(
        "/server_id",
        tr!(
            "This server was not found, or its entry is not confirmed by AirVPN's official list",
            "找不到這台伺服器，或它的入口沒有經 AirVPN 官方清單確認",
            "このサーバーが見つからないか、その入口が AirVPN の公式一覧で確認されていません"
        ),
    )
}

/// An `AirVPN` server that is closed.
fn closed_air_server() -> ApiError {
    field_error(
        "/server_id",
        tr!(
            "This server is closed right now",
            "這台伺服器目前關閉",
            "このサーバーは現在閉鎖されています"
        ),
    )
}

/// The connection a run of the direct exception builds becomes the egress: it starts at once.
fn must_start() -> ApiError {
    field_error(
        "/start",
        tr!(
            "This connection becomes the Provider egress: it must connect as soon as it is created",
            "這條連線會成為 Provider 出口：必須建立後立即連線",
            "この接続は Provider 出口になるため、作成後すぐに接続する必要があります"
        ),
    )
}

/// A new Gateway's port is outside 1024–65535.
fn gateway_port_range() -> ApiError {
    field_error(
        "/gateway_port",
        tr!(
            "The Gateway needs a port from 1024 to 65535",
            "代理埠需要 1024–65535",
            "ゲートウェイのポートは 1024–65535 にしてください"
        ),
    )
}

/// The name of the Gateway the provider flow creates: the one the request gives (the web UI names it
/// in its own language), else English. A name is the user's to change afterwards.
fn gateway_name(given: Option<&str>, port: u16) -> String {
    given
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map_or_else(|| format!("Gateway {port}"), str::to_owned)
}

fn field_error(path: &str, message: impl Into<Text>) -> ApiError {
    let message = message.into();
    ApiError::new(ErrorCode::ValidationFailed, message.clone()).with_fields(vec![FieldError {
        path: path.into(),
        code: "INVALID".into(),
        message,
    }])
}

// -------------------------------------------------------------------------------------------
// Service
// -------------------------------------------------------------------------------------------

/// The Mullvad client of one operation: every request through its guard.
type MullvadApi<'a> = Mullvad<Guard<'a, ManagerLink>>;

/// `AirVPN` servers whose entry addresses `AirVPN`'s TLS-verified status list confirmed.
pub struct AirCatalog {
    pub servers: Vec<airvpn::Server>,
    /// The manifest's UDP `WireGuard` modes, the default first.
    pub modes: Vec<airvpn::EntryMode>,
    /// Servers left out because no entry address could be confirmed.
    pub excluded: usize,
}

#[derive(Default)]
pub struct Providers {
    /// The TLS trust of every provider request and exit check.
    tls: Tls,
    /// Provider requests per origin, shared by every route (switching does not reset it).
    budget: Budget,
    /// Each provider's function gates, each as last observed (AC-114).
    gates: Mutex<GateBook>,
    /// How long an exit check authorizes its request ([`guard::PERMIT_TTL`]).
    permit_ttl: guard::PermitTtl,
    tokens: Mutex<HashMap<ProviderAccountId, Arc<AccessToken>>>,
    mullvad_catalog: Mutex<Option<(Instant, Arc<RelayCatalog>)>>,
    /// Each Mullvad relay's multihop port (the website's relay list).
    mullvad_multihop: Mutex<Option<(Instant, Arc<MultihopPorts>)>>,
    air_catalogs: Mutex<HashMap<ProviderAccountId, (Instant, Arc<AirCatalog>)>>,
    /// The `WireGuard` key every `AirVPN` server of the account answers with (public).
    air_peer: Mutex<HashMap<ProviderAccountId, WgKey>>,
    /// Each `AirVPN` account's website session (cookies and the Ports page token): in memory
    /// only, never persisted or shown. Its lock makes one website operation per account at a
    /// time, so two requests never sign in twice.
    air_sites: Mutex<HashMap<ProviderAccountId, Arc<tokio::sync::Mutex<airvpn::site::Session>>>>,
    /// One mutation at a time per account.
    locks: Mutex<HashMap<ProviderAccountId, Arc<tokio::sync::Mutex<()>>>>,
    last_check: Mutex<Option<ProviderIpCheck>>,
}

impl Providers {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// With another TLS trust, budget and permit lifetime: for test fixtures (a throwaway CA
    /// needs `vpn-providers/testing`). Products use [`Providers::new`].
    #[must_use]
    pub fn with(tls: Tls, limits: budget::Limits, permit_ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            tls,
            budget: Budget::new(limits),
            permit_ttl: guard::PermitTtl(permit_ttl),
            ..Self::default()
        })
    }

    fn lock_for(&self, id: ProviderAccountId) -> Arc<tokio::sync::Mutex<()>> {
        self.locks.lock().entry(id).or_default().clone()
    }

    pub fn last_check(&self) -> Option<ProviderIpCheck> {
        self.last_check.lock().clone()
    }

    /// Every provider's function gates, as last observed.
    pub fn gates(&self) -> Vec<ProviderGate> {
        self.gates.lock().all()
    }

    /// The per-origin request budget.
    pub const fn budget(&self) -> &Budget {
        &self.budget
    }

    /// A client over `connector` with the providers' TLS trust.
    pub fn client<C: Connect>(&self, connector: C) -> HttpsClient<C> {
        self.tls.client(connector)
    }

    /// The guard of an operation starting now: every request of it goes through this, pinned
    /// to the route in force (see [`guard`]).
    ///
    /// # Errors
    ///
    /// As for [`Guard::new`].
    pub async fn guard<'a, E: guard::Egress>(
        &'a self,
        egress: &'a E,
    ) -> Result<Guard<'a, E>, ApiError> {
        Guard::new(egress, self).await
    }

    /// One exit check over `route` for a request of `family`, recorded as the latest check (and
    /// in the gates, over IPv4). A 429 holds the checker's origin. The connector's epochs the
    /// check saw come along. Never through a guard, never with a credential.
    async fn probe(
        &self,
        route: &Route,
        provider: ProviderKind,
        family: Family,
    ) -> (ProviderIpCheck, Option<Text>, Option<RelayEpochs>) {
        let relay = Probe::new(route.relay.clone());
        let http = self.tls.client(relay.clone());
        let (c, why, limited) = observe(
            &http,
            provider,
            family,
            route.mode,
            route.instance_id,
            route.generation,
        )
        .await;
        if let (Some(retry_after), Some(origin)) = (limited, guard::checker_host(provider, family))
        {
            self.budget.hold(origin, retry_after);
        }
        if family == Family::V4 {
            self.gates.lock().ipv4_check(&c, why.as_ref());
            *self.last_check.lock() = Some(c.clone());
        }
        (c, why, relay.epochs())
    }

    /// The explicit check of a route: IPv4, then — on its own — IPv6 when the connection has an
    /// IPv6 address (the IPv6 gate is never implied by the IPv4 check). Within the budget. The
    /// IPv4 check, and why it did not pass in the three languages.
    pub(crate) async fn check_route(
        &self,
        route: &Route,
        profile: RouteProfile,
    ) -> Result<(ProviderIpCheck, Option<Text>), ApiError> {
        let v4 = guard::checker_host(profile.provider, Family::V4).unwrap_or_default();
        self.budget
            .reserve(&[v4])
            .await
            .map_err(|r| ApiError::new(r.code, r.message))?;
        let (c, why, _) = self.probe(route, profile.provider, Family::V4).await;
        if route.mode != RouteMode::ViaInstance {
            return Ok((c, why));
        }
        let unverified = |reason: Text| {
            self.gates.lock().record(
                profile.provider,
                ProviderGateKind::Ipv6,
                GateStatus::Unverified,
                reason,
                route.instance_id,
            );
        };
        let v6 = match guard::checker_host(profile.provider, Family::V6) {
            // No IPv6 address: IPv6 does not apply to this connection.
            _ if !profile.ipv6 => None,
            // No IPv6 checker (IPLeak, AIR-IPV6-01): the check says why it does not apply.
            None => {
                let (c6, why6, _) = observe(
                    &self.tls.client(Probe::new(route.relay.clone())),
                    profile.provider,
                    Family::V6,
                    route.mode,
                    route.instance_id,
                    route.generation,
                )
                .await;
                Some((c6, why6))
            }
            Some(_) if c.status != IpCheckStatus::Ok => {
                unverified(tr!(
                    "The IPv4 exit check did not pass, so IPv6 was not checked this time",
                    "IPv4 出口檢查沒有通過，這次沒有檢查 IPv6",
                    "IPv4 の出口チェックに合格しなかったため、今回は IPv6 をチェックしていません"
                ));
                return Ok((c, why));
            }
            Some(host) => match self.budget.reserve(&[host]).await {
                Ok(_) => {
                    let (c6, why6, _) = self.probe(route, profile.provider, Family::V6).await;
                    Some((c6, why6))
                }
                // No budget for it now: this attempt could not tell, and says so.
                Err(r) => {
                    unverified(r.message);
                    return Ok((c, why));
                }
            },
        };
        self.gates.lock().ipv6_check(
            profile.provider,
            route.instance_id,
            v6.as_ref().map(|(c6, _)| c6),
            v6.as_ref().and_then(|(_, why6)| why6.as_ref()),
        );
        Ok((c, why))
    }

    /// Check the exit of the current egress now (no reuse), and its IPv6 exit on its own.
    ///
    /// # Errors
    ///
    /// As for [`Providers::check_via`].
    pub async fn check_egress(&self, link: &ManagerLink) -> Result<ProviderIpCheck, ApiError> {
        self.check_via(link).await
    }

    /// [`Providers::check_egress`] for the route `egress` names.
    ///
    /// # Errors
    ///
    /// The Provider egress error when there is no usable route, and the manager's error.
    pub async fn check_via<E: guard::Egress>(
        &self,
        egress: &E,
    ) -> Result<ProviderIpCheck, ApiError> {
        let route = egress.route().await?;
        let profile = egress.profile(&route).await;
        self.check_route(&route, profile).await.map(|(c, _)| c)
    }

    /// The exit of one running Instance, through its own tunnel (it need not be the egress).
    ///
    /// # Errors
    ///
    /// The manager's error when the Instance has no running route, or an internal error when
    /// it answers out of contract.
    pub async fn check_instance(
        &self,
        link: &ManagerLink,
        id: InstanceId,
    ) -> Result<ProviderIpCheck, ApiError> {
        let Reply::ProviderRoute {
            generation,
            connector,
        } = link.call(Call::ProviderRoute(id)).await?
        else {
            return Err(ApiError::internal());
        };
        let egress = egress(link).await.ok().map(|(e, _)| e);
        let route = Route {
            mode: RouteMode::ViaInstance,
            instance_id: Some(id),
            generation: Some(generation),
            egress_epoch: egress.as_ref().map_or(0, |e| e.route_revision),
            relay: Relay::instance(connector, id, generation),
        };
        let profile = route_profile(link, &route).await;
        let last = self.last_check();
        let c = self.check_route(&route, profile).await.map(|(c, _)| c);
        // Another connection's exit is not the egress's latest check.
        if egress.and_then(|e| e.selected_instance_id) != Some(id) {
            *self.last_check.lock() = last;
        }
        c
    }

    /// `result` of reading what settings are generated from (devices, servers): a contract
    /// drift there is the generator gate failing.
    fn source<T>(
        &self,
        provider: ProviderKind,
        result: Result<T, ProviderError>,
    ) -> Result<T, ApiError> {
        let result = result.map_err(|e| provider_error(&e));
        if let Err(e) = &result {
            self.generated(provider, Err(e));
        }
        result
    }

    /// Settings were generated from `provider`'s account data (or could not be, because of it).
    fn generated(&self, provider: ProviderKind, result: Result<&RuntimeProfile, &ApiError>) {
        let (status, reason) = match result {
            Ok(p) => {
                let at = p
                    .location
                    .as_ref()
                    .and_then(|l| l.server.clone())
                    .unwrap_or_else(|| p.name.clone());
                (
                    GateStatus::Passed,
                    tr!(
                        "Settings were generated from the account's devices and servers confirmed by the official list ({at})",
                        "已由帳號的裝置與經官方清單確認的伺服器產生設定（{at}）",
                        "アカウントのデバイスと公式一覧で確認されたサーバーから設定を生成しました（{at}）"
                    ),
                )
            }
            Err(e) if e.code == ErrorCode::ProviderContractDrift => (
                GateStatus::Failed,
                tr!(
                    "The provider's data does not match the format needed to generate settings: {why}",
                    "供應商資料與產生設定所需的格式不符：{why}",
                    "プロバイダーのデータが設定の生成に必要な形式と一致しません：{why}";
                    why = e.message.clone()
                ),
            ),
            Err(_) => return,
        };
        self.gates.lock().record(
            provider,
            ProviderGateKind::ConfigGenerator,
            status,
            reason,
            None,
        );
    }

    /// # Errors
    ///
    /// The manager's error, or an internal error when it answers out of contract.
    pub async fn status(&self, link: &ManagerLink) -> Result<ProviderEgressStatus, ApiError> {
        let EgressState {
            egress,
            grant,
            run,
            recovery,
        } = egress_state(link).await?;
        let mut name = None;
        let mut generation = None;
        let mut reason_code = None;
        let mut reason = None;
        let active = run.as_ref().filter(|r| r.stage.is_active());
        // The selected egress: its name, and its status (`Some(None)`: not known).
        let selected = match egress.selected_instance_id {
            Some(id) => {
                let (n, status) = selected_egress(link, id).await;
                name = n;
                generation = status
                    .as_ref()
                    .and_then(|s| s.running.as_ref().map(|r| r.generation));
                Some(status)
            }
            None => None,
        };
        let selected_ready = selected
            .as_ref()
            .is_some_and(|s| s.as_ref().is_some_and(|s| s.phase == Phase::Ready));
        let direct = grant.as_ref().is_some_and(|g| {
            egress.selected_instance_id.is_none() || g.kind == BootstrapKind::Rebootstrap
        });
        let phase = if egress.desired_mode == EgressMode::Disabled {
            EgressPhase::Disabled
        } else if let Some(r) = active.filter(|r| {
            matches!(
                r.stage,
                BootstrapStage::InstanceRequested | BootstrapStage::Sealing
            )
        }) {
            reason = Some(if r.stage == BootstrapStage::Sealing {
                tr!(
                    "Closing the direct connection and making the new connection the egress",
                    "正在關閉直連，並把新連線設為出口",
                    "直接接続を閉じて、新しい接続を出口にしています"
                )
            } else {
                tr!(
                    "Once the new connection is up and the exit is confirmed through it, it becomes the egress by itself",
                    "新連線連上、並經它確認出口後，會自動成為出口",
                    "新しい接続が確立し、その接続経由で出口が確認されると、自動的に出口になります"
                )
            });
            EgressPhase::Switching
        } else if direct && !selected_ready {
            // Why the run's last connection did not come up, if it did not.
            if let Some(r) = active {
                reason_code = r.reason_code.clone();
                reason = r.reason.clone();
            }
            EgressPhase::BootstrapDirect
        } else if let Some(status) = selected {
            let (phase, code, why) = selected_phase(status.as_ref(), recovery.as_ref());
            reason_code = code;
            reason = why;
            phase
        } else {
            // No egress: why the last run ended without one, if it did.
            if let Some(r) = run
                .as_ref()
                .filter(|r| !r.stage.is_active() && r.stage != BootstrapStage::Sealed)
            {
                reason_code = r.reason_code.clone();
                reason = r.reason.clone();
            }
            EgressPhase::Unconfigured
        };
        // A check made on another route (before a switch) says nothing about this one.
        let child = active.and_then(|r| r.child_instance_id);
        let last_check = self.last_check().filter(|c| match phase {
            EgressPhase::BootstrapDirect => c.route_mode == RouteMode::BootstrapDirect,
            EgressPhase::Switching => child.is_some_and(|i| c.instance_id == Some(i)),
            _ => egress.selected_instance_id.map_or_else(
                || c.route_mode == RouteMode::BootstrapDirect,
                |id| c.instance_id == Some(id),
            ),
        });
        Ok(ProviderEgressStatus {
            egress,
            phase,
            selected_instance_name: name,
            selected_generation: generation,
            reason_code,
            reason,
            bootstrap_expires_at: grant.map(|b| b.expires_at),
            bootstrap: run,
            recovery,
            last_check,
            gates: self.gates(),
            observed_at: Timestamp::now(),
        })
    }

    // ---------------------------------------------------------------------------------------
    // Accounts
    // ---------------------------------------------------------------------------------------

    /// Verify the credential with the provider, store it in the vault and create the account.
    ///
    /// # Errors
    ///
    /// A validation error for the input or the credential's form, the provider's refusal of
    /// the credential, and otherwise as for an operation (route, guard, manager).
    pub async fn add_account(
        &self,
        link: &ManagerLink,
        input: &ProviderAccountInput,
    ) -> Result<ProviderAccount, ApiError> {
        let label = input.label.trim();
        if label.is_empty() || label.chars().count() > 64 || label.chars().any(char::is_control) {
            return Err(field_error("/label", name_rule()));
        }
        match &input.credential {
            ProviderCredentialInput::Mullvad { account_number } => {
                let number = AccountNumber::parse(account_number)
                    .map_err(|e| field_error("/credential/account_number", e.text()))?;
                let digits = Zeroizing::new(
                    account_number
                        .chars()
                        .filter(char::is_ascii_digit)
                        .collect::<String>()
                        .into_bytes(),
                );
                let fingerprint = keyed(link, b"mullvad-account:", &digits).await?;
                self.refuse_duplicate(link, &fingerprint).await?;
                let guard = self.guard(link).await?;
                let api = Mullvad::new(self.tls.client(guard), Family::V4);
                let token = api.token(&number).await.map_err(|e| provider_error(&e))?;
                let account = api.account(&token).await.map_err(|e| provider_error(&e))?;
                let secret = put_secret(
                    link,
                    "provider_credential",
                    label,
                    digits.to_vec(),
                    Some(fingerprint),
                )
                .await?;
                let created = self
                    .create_account(
                        link,
                        ProviderKind::Mullvad,
                        label,
                        secret,
                        Some(account.expiry),
                    )
                    .await?;
                self.tokens.lock().insert(created.id, Arc::new(token));
                Ok(created)
            }
            ProviderCredentialInput::Airvpn { username, password } => {
                let creds = Credentials::new(username, password).map_err(|e| match e {
                    InvalidCredentials::Username => field_error("/credential/username", e.text()),
                    InvalidCredentials::Password => field_error("/credential/password", e.text()),
                })?;
                let fingerprint = keyed(
                    link,
                    b"airvpn-account:",
                    creds.username().to_lowercase().as_bytes(),
                )
                .await?;
                self.refuse_duplicate(link, &fingerprint).await?;
                let guard = self.guard(link).await?;
                let user = AirVpn::new(guard)
                    .user(&creds)
                    .await
                    .map_err(|e| provider_error(&e))?;
                // Neither part can hold a line break (checked above).
                let mut stored = Zeroizing::new(Vec::with_capacity(
                    creds.username().len() + 1 + password.len(),
                ));
                stored.extend_from_slice(creds.username().as_bytes());
                stored.push(b'\n');
                stored.extend_from_slice(password.as_bytes());
                let secret = put_secret(
                    link,
                    "provider_credential",
                    label,
                    stored.to_vec(),
                    Some(fingerprint),
                )
                .await?;
                let created = self
                    .create_account(link, ProviderKind::Airvpn, label, secret, user.expires_at)
                    .await?;
                self.air_peer
                    .lock()
                    .insert(created.id, user.peer_public_key);
                Ok(created)
            }
        }
    }

    /// The account's `AirVPN` credentials, leased from the vault for one operation.
    async fn air_credentials(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<Credentials, ApiError> {
        let raw = lease(link, account.credential_ref).await?;
        let text = std::str::from_utf8(&raw).map_err(|_| ApiError::internal())?;
        let (user, pass) = text.split_once('\n').ok_or_else(ApiError::internal)?;
        Credentials::new(user, pass).map_err(|_| ApiError::internal())
    }

    /// The account's user record (devices and their keys) over the current route.
    async fn air_user(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<(Route, airvpn::UserInfo), ApiError> {
        let creds = self.air_credentials(link, account).await?;
        let guard = self.guard(link).await?;
        let route = guard.route().clone();
        let user = self.source(ProviderKind::Airvpn, AirVpn::new(guard).user(&creds).await)?;
        self.air_peer
            .lock()
            .insert(account.id, user.peer_public_key);
        Ok((route, user))
    }

    /// The manifest (unauthenticated Eddie answer), keeping only entry addresses that `AirVPN`'s
    /// TLS-verified status list confirms for the same server.
    async fn air_catalog(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<Arc<AirCatalog>, ApiError> {
        if let Some((at, c)) = self.air_catalogs.lock().get(&account.id).cloned()
            && at.elapsed() < CATALOG_TTL
        {
            return Ok(c);
        }
        let creds = self.air_credentials(link, account).await?;
        let guard = self.guard(link).await?;
        let air = ProviderKind::Airvpn;
        let manifest = self.source(air, AirVpn::new(guard.clone()).manifest(&creds).await)?;
        let status = self.source(
            air,
            airvpn::status::fetch(&self.tls.client(guard), Family::V4).await,
        )?;
        let mut excluded = 0;
        let servers: Vec<airvpn::Server> = manifest
            .servers
            .into_iter()
            .filter_map(|mut s| {
                // Every entry the manifest (unauthenticated) lists is used only when the status
                // list confirms it for the same server: the alternative ones too.
                for slot in &mut s.entries_v4 {
                    if slot.is_some_and(|ip| !status.confirms(&s.name, std::net::IpAddr::V4(ip))) {
                        *slot = None;
                    }
                }
                for slot in &mut s.entries_v6 {
                    if slot.is_some_and(|ip| !status.confirms(&s.name, std::net::IpAddr::V6(ip))) {
                        *slot = None;
                    }
                }
                if s.entry_v4
                    .is_some_and(|ip| !status.confirms(&s.name, std::net::IpAddr::V4(ip)))
                {
                    s.entry_v4 = None;
                }
                if s.entry_v6
                    .is_some_and(|ip| !status.confirms(&s.name, std::net::IpAddr::V6(ip)))
                {
                    s.entry_v6 = None;
                }
                if s.entry_v4.is_none() && s.entry_v6.is_none() {
                    excluded += 1;
                    None
                } else {
                    Some(s)
                }
            })
            .collect();
        if excluded > 0 {
            tracing::warn!(
                excluded,
                "AirVPN servers left out: entry not confirmed by the status list"
            );
        }
        if servers.is_empty() {
            self.gates.lock().record(
                air,
                ProviderGateKind::ConfigGenerator,
                GateStatus::Failed,
                tr!(
                    "No AirVPN server's entry is confirmed by the official status list, so settings cannot be generated",
                    "沒有任何 AirVPN 伺服器的入口經官方狀態清單確認，無法產生設定",
                    "公式のステータス一覧で入口が確認された AirVPN サーバーがないため、設定を生成できません"
                ),
                None,
            );
        }
        let catalog = Arc::new(AirCatalog {
            servers,
            modes: manifest.modes,
            excluded,
        });
        self.air_catalogs
            .lock()
            .insert(account.id, (Instant::now(), catalog.clone()));
        Ok(catalog)
    }

    async fn refuse_duplicate(
        &self,
        link: &ManagerLink,
        fingerprint: &str,
    ) -> Result<(), ApiError> {
        if let Reply::Secrets(all) = link.call(Call::Secrets).await?
            && all.iter().any(|s| {
                s.kind == "provider_credential"
                    && s.public_fingerprint.as_deref() == Some(fingerprint)
            })
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                tr!(
                    "This account has already been added",
                    "這個帳號已經加入過",
                    "このアカウントはすでに追加されています"
                ),
            ));
        }
        Ok(())
    }

    async fn create_account(
        &self,
        link: &ManagerLink,
        provider: ProviderKind,
        label: &str,
        secret: SecretRef,
        expires_at: Option<Timestamp>,
    ) -> Result<ProviderAccount, ApiError> {
        let account = ProviderAccount {
            id: ProviderAccountId::new(),
            meta: crate::routes::new_meta(),
            provider,
            label: label.to_string(),
            credential_ref: secret,
            expires_at,
            observed_at: Some(Timestamp::now()),
        };
        match link
            .call(Call::Create(Entity::ProviderAccount(account)))
            .await
        {
            Ok(Reply::Entity(e)) => match *e {
                Entity::ProviderAccount(a) => Ok(a),
                _ => Err(ApiError::internal()),
            },
            Ok(_) => Err(ApiError::internal()),
            Err(e) => {
                let _ = link.call(Call::DeleteSecret(secret)).await;
                Err(e)
            }
        }
    }

    /// A Mullvad API client on the current route (every request through the operation's guard)
    /// and a valid token (a new one is itself a guarded request).
    async fn mullvad<'a>(
        &'a self,
        link: &'a ManagerLink,
        account: &ProviderAccount,
    ) -> Result<(Route, MullvadApi<'a>, Arc<AccessToken>), ApiError> {
        let guard = self.guard(link).await?;
        let route = guard.route().clone();
        let api = Mullvad::new(self.tls.client(guard), Family::V4);
        let cached = self.tokens.lock().get(&account.id).cloned().filter(|t| {
            t.expires_at().unix_millis() - Timestamp::now().unix_millis()
                > i64::try_from(TOKEN_MARGIN.as_millis()).unwrap_or(i64::MAX)
        });
        let token = if let Some(t) = cached {
            t
        } else {
            let digits = lease(link, account.credential_ref).await?;
            let text = std::str::from_utf8(&digits).map_err(|_| ApiError::internal())?;
            let number = AccountNumber::parse(text).map_err(|_| ApiError::internal())?;
            let t = Arc::new(api.token(&number).await.map_err(|e| provider_error(&e))?);
            self.tokens.lock().insert(account.id, t.clone());
            t
        };
        Ok((route, api, token))
    }

    /// Re-read the account (paid-until) and record it, on the account and on the profiles made
    /// from it.
    ///
    /// # Errors
    ///
    /// The Provider egress error when there is no usable route, the guard's refusal (budget,
    /// exit check, permit), the provider's error under its API code, and the manager's error.
    pub async fn refresh(
        &self,
        link: &ManagerLink,
        account: ProviderAccount,
    ) -> Result<ProviderAccount, ApiError> {
        let expires_at = match account.provider {
            ProviderKind::Mullvad => {
                let (_, api, token) = self.mullvad(link, &account).await?;
                let info = match api.account(&token).await {
                    Err(ProviderError::AuthRejected) => {
                        self.tokens.lock().remove(&account.id);
                        return Err(provider_error(&ProviderError::AuthRejected));
                    }
                    r => r.map_err(|e| provider_error(&e))?,
                };
                Some(info.expiry)
            }
            ProviderKind::Airvpn => self.air_user(link, &account).await?.1.expires_at,
            ProviderKind::Generic => return Err(unsupported()),
        };
        let rev = account.meta.revision;
        let updated = ProviderAccount {
            expires_at,
            observed_at: Some(Timestamp::now()),
            ..account
        };
        let account = match link
            .call(Call::Update {
                entity: Entity::ProviderAccount(updated),
                expected_revision: rev,
            })
            .await?
        {
            Reply::Entity(e) => match *e {
                Entity::ProviderAccount(a) => a,
                _ => return Err(ApiError::internal()),
            },
            _ => return Err(ApiError::internal()),
        };
        profile_expiry(link, &account).await;
        Ok(account)
    }

    pub fn forget(&self, id: ProviderAccountId) {
        self.tokens.lock().remove(&id);
        self.locks.lock().remove(&id);
        self.air_catalogs.lock().remove(&id);
        self.air_peer.lock().remove(&id);
        // Its cookies and token are zeroized once the last operation holding it ends.
        self.air_sites.lock().remove(&id);
    }

    // ---------------------------------------------------------------------------------------
    // Devices and servers
    // ---------------------------------------------------------------------------------------

    /// # Errors
    ///
    /// The Provider egress error when there is no usable route, the guard's refusal (budget,
    /// exit check, permit), the provider's error under its API code, and the manager's error.
    pub async fn devices(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<Vec<ProviderDevice>, ApiError> {
        match account.provider {
            ProviderKind::Mullvad => {
                let (_, api, token) = self.mullvad(link, account).await?;
                let devices = api.devices(&token).await.map_err(|e| provider_error(&e))?;
                let keys = local_keys(link).await?;
                Ok(devices
                    .into_iter()
                    .map(|d| {
                        let owned = keys.contains_key(&key_fingerprint(&d.pubkey));
                        ProviderDevice {
                            id: d.id.as_str().to_string(),
                            account_id: account.id,
                            label: d.name,
                            public_key: d.pubkey.to_string(),
                            owned,
                            usable: owned,
                            ipv4_address: Some(d.ipv4_address.to_string()),
                            ipv6_address: d.ipv6_address.map(|a| a.to_string()),
                            created_at: Some(d.created),
                        }
                    })
                    .collect())
            }
            ProviderKind::Airvpn => {
                let (_, user) = self.air_user(link, account).await?;
                let keys = local_keys(link).await?;
                Ok(user
                    .devices
                    .iter()
                    .map(|d| ProviderDevice {
                        id: d.name.clone(),
                        account_id: account.id,
                        label: d.name.clone(),
                        public_key: d.public_key.to_string(),
                        owned: keys.contains_key(&key_fingerprint(&d.public_key)),
                        // AirVPN hands every device's keys to its account holder.
                        usable: true,
                        ipv4_address: Some(d.ipv4.to_string()),
                        ipv6_address: d.ipv6.map(|a| a.to_string()),
                        created_at: None,
                    })
                    .collect())
            }
            ProviderKind::Generic => Err(unsupported()),
        }
    }

    async fn mullvad_catalog(&self, api: &MullvadApi<'_>) -> Result<Arc<RelayCatalog>, ApiError> {
        if let Some((at, c)) = self.mullvad_catalog.lock().clone()
            && at.elapsed() < CATALOG_TTL
        {
            return Ok(c);
        }
        let fresh = Arc::new(self.source(ProviderKind::Mullvad, api.relays().await)?);
        *self.mullvad_catalog.lock() = Some((Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    /// Each relay's multihop port (the website's relay list), cached like the catalog.
    async fn mullvad_multihop(&self, api: &MullvadApi<'_>) -> Result<Arc<MultihopPorts>, ApiError> {
        if let Some((at, p)) = self.mullvad_multihop.lock().clone()
            && at.elapsed() < CATALOG_TTL
        {
            return Ok(p);
        }
        let fresh = Arc::new(self.source(ProviderKind::Mullvad, api.multihop_ports().await)?);
        *self.mullvad_multihop.lock() = Some((Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    /// # Errors
    ///
    /// The Provider egress error when there is no usable route, the guard's refusal (budget,
    /// exit check, permit), the provider's error under its API code, and the manager's error.
    pub async fn servers(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<Vec<ProviderServer>, ApiError> {
        match account.provider {
            ProviderKind::Mullvad => {
                let api = Mullvad::new(self.tls.client(self.guard(link).await?), Family::V4);
                let catalog = self.mullvad_catalog(&api).await?;
                // Without the multihop list the servers still list; none is a multihop exit.
                let ports = match self.mullvad_multihop(&api).await {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!(error = %e.message.en, "Mullvad multihop ports not read");
                        None
                    }
                };
                let port = catalog.network.port;
                Ok(catalog
                    .relays
                    .iter()
                    .map(|r| {
                        let endpoints = [Family::V4, Family::V6]
                            .into_iter()
                            .filter_map(|f| r.entry(f))
                            .map(|ip| std::net::SocketAddr::new(ip, port).to_string())
                            .collect();
                        ProviderServer {
                            id: r.hostname.clone(),
                            provider: ProviderKind::Mullvad,
                            country_code: r.country_code.clone(),
                            country: r.country.clone(),
                            city_code: r.city_code.clone(),
                            city: r.city.clone(),
                            hosting: Some(r.provider.clone()),
                            owned: r.owned,
                            active: r.active,
                            endpoints,
                            peer_public_key: r.public_key.to_string(),
                            load_percent: None,
                            warning: None,
                            multihop_port: ports.as_ref().and_then(|p| p.port_of(r)),
                            entries: Vec::new(),
                            exit_ips: Vec::new(),
                        }
                    })
                    .collect())
            }
            ProviderKind::Airvpn => {
                let catalog = self.air_catalog(link, account).await?;
                let peer = self
                    .air_peer
                    .lock()
                    .get(&account.id)
                    .map_or_default(std::string::ToString::to_string);
                Ok(catalog
                    .servers
                    .iter()
                    .map(|s| {
                        let endpoints = [Family::V4, Family::V6]
                            .into_iter()
                            .filter_map(|f| s.endpoint(f))
                            .map(|a| a.to_string())
                            .collect();
                        let (active, warning) = match &s.warning {
                            Some(ServerWarning::Closed(w)) => (false, Some(w.clone())),
                            Some(ServerWarning::Open(w)) => (true, Some(w.clone())),
                            None => (true, None),
                        };
                        ProviderServer {
                            id: s.name.clone(),
                            provider: ProviderKind::Airvpn,
                            country_code: s.country_code.clone(),
                            country: s.country_code.clone(),
                            city_code: s.location.clone().unwrap_or_default(),
                            city: s.location.clone().unwrap_or_default(),
                            hosting: None,
                            owned: false,
                            active,
                            endpoints,
                            peer_public_key: peer.clone(),
                            load_percent: s.load,
                            warning,
                            multihop_port: None,
                            entries: route::airvpn_entries(&catalog.modes, s),
                            exit_ips: [
                                s.exit_v4.map(std::net::IpAddr::V4),
                                s.exit_v6.map(std::net::IpAddr::V6),
                            ]
                            .into_iter()
                            .flatten()
                            .map(|ip| ip.to_string())
                            .collect(),
                        }
                    })
                    .collect())
            }
            ProviderKind::Generic => Err(unsupported()),
        }
    }

    /// Revoke a device this installation owns, then forget its key. Refused while a `WireGuard`
    /// profile still uses it (delete those connections first). The remote delete comes first:
    /// if its outcome is unknown the key is kept, so a retry can still prove ownership.
    ///
    /// # Errors
    ///
    /// A validation or state error for a device this host still uses or that is not the
    /// account's; otherwise as for an operation (route, guard, provider, manager).
    pub async fn revoke_device(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        device_id: &str,
        unowned_confirmed: bool,
    ) -> Result<(), ApiError> {
        let lock = self.lock_for(account.id);
        let _guard = lock.lock().await;
        let profiles: Vec<RuntimeProfile> = match link.call(Call::List(EntityKind::Profile)).await?
        {
            Reply::Entities(all) => all
                .into_iter()
                .filter_map(|e| match e {
                    Entity::Profile(p) => Some(p),
                    _ => None,
                })
                .collect(),
            _ => return Err(ApiError::internal()),
        };
        // Built from this device, or imported with its key: revoking would break either.
        let in_use = |key: Option<&WgKey>| {
            profiles.iter().any(|p| {
                matches!(&p.source, ProfileSource::Provider { account_id, device_id: d, .. }
                    if *account_id == account.id && d == device_id)
                    || key.is_some_and(|k| p.interface.public_key == *k)
            })
        };
        if in_use(None) {
            return Err(still_used());
        }
        match account.provider {
            ProviderKind::Mullvad => {
                let (_, api, token) = self.mullvad(link, account).await?;
                let devices = api.devices(&token).await.map_err(|e| provider_error(&e))?;
                let device = devices
                    .into_iter()
                    .find(|d| d.id.as_str() == device_id)
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::NotFound,
                            tr!("Device not found", "找不到裝置", "デバイスが見つかりません"),
                        )
                    })?;
                if in_use(Some(&device.pubkey)) {
                    return Err(still_used());
                }
                // A device whose key is not here may be in use on another computer or phone:
                // revoked only when the user confirmed exactly that.
                let secret = local_keys(link)
                    .await?
                    .get(&key_fingerprint(&device.pubkey))
                    .copied();
                if secret.is_none() && !unowned_confirmed {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "This device's key is not on this computer, so it may be in use on another device; revoking it needs explicit confirmation",
                            "這個裝置的金鑰不在這台電腦，可能正在其他設備使用；需要明確確認才能撤銷",
                            "このデバイスの鍵はこのコンピューターにないため、別の機器で使用中の可能性があります。取り消すには明示的な確認が必要です"
                        ),
                    ));
                }
                api.delete_device(&token, &device.id)
                    .await
                    .map_err(|e| provider_error(&e))?;
                if let Some(secret) = secret {
                    let _ = link.call(Call::DeleteSecret(secret)).await;
                }
                Ok(())
            }
            _ => Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                tr!(
                    "This provider's devices are managed on the provider's website",
                    "這個供應商的裝置需要在供應商網站管理",
                    "このプロバイダーのデバイスはプロバイダーの Web サイトで管理してください"
                ),
            )),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Forwarded ports (AirVPN's website)
    // ---------------------------------------------------------------------------------------

    /// The account's website session, shared by its operations one at a time.
    fn air_site(&self, id: ProviderAccountId) -> Arc<tokio::sync::Mutex<airvpn::site::Session>> {
        self.air_sites.lock().entry(id).or_default().clone()
    }

    /// The account's forwarded ports, read from `AirVPN`'s website (signed in with the account's
    /// own credential, leased for this operation) over the egress route.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_CAPABILITY` for an account that is not `AirVPN`'s, and the website's error
    /// (sign-in refused, the Ports page unavailable, an answer outside the contract) under
    /// its API code; otherwise as for an operation (route, guard, manager).
    pub async fn forwarded_ports(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<ForwardedPorts, ApiError> {
        reservations(account)?;
        let creds = self.air_credentials(link, account).await?;
        self.forwarded_ports_via(link, account.id, &creds).await
    }

    /// Reserve `port`, or one `AirVPN` picks: checked against a fresh list first (range, the
    /// account's limit, a port already held).
    ///
    /// # Errors
    ///
    /// As for [`Providers::forwarded_ports`], plus the website's own refusal with the field it
    /// names (a port out of range or already held, a setting it would not take or keep).
    pub async fn reserve_port(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        port: Option<u16>,
    ) -> Result<ForwardedPort, ApiError> {
        reservations(account)?;
        reservable(port)?;
        let creds = self.air_credentials(link, account).await?;
        self.reserve_port_via(link, account.id, &creds, port).await
    }

    /// Delete one of the account's forwarded ports at `AirVPN`.
    ///
    /// # Errors
    ///
    /// As for [`Providers::forwarded_ports`], plus the website's own refusal with the field it
    /// names (a port out of range or already held, a setting it would not take or keep).
    pub async fn delete_port(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        port: u16,
    ) -> Result<(), ApiError> {
        reservations(account)?;
        let creds = self.air_credentials(link, account).await?;
        self.delete_port_via(link, account.id, &creds, port).await
    }

    /// Change some of a forwarded port's settings at `AirVPN`: only those that differ, one request
    /// each, then the port as read back.
    ///
    /// # Errors
    ///
    /// As for [`Providers::forwarded_ports`], plus the website's own refusal with the field it
    /// names (a port out of range or already held, a setting it would not take or keep).
    pub async fn update_port(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        port: u16,
        update: &ForwardedPortUpdate,
    ) -> Result<ForwardedPort, ApiError> {
        reservations(account)?;
        changeable(update)?;
        let creds = self.air_credentials(link, account).await?;
        self.update_port_via(link, account.id, &creds, port, update)
            .await
    }

    /// `AirVPN`'s test of a forwarded port from the server of each connected session that uses it.
    ///
    /// # Errors
    ///
    /// As for [`Providers::forwarded_ports`], plus the website's own refusal with the field it
    /// names (a port out of range or already held, a setting it would not take or keep).
    pub async fn test_port(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        port: u16,
    ) -> Result<ForwardedPortTest, ApiError> {
        reservations(account)?;
        let creds = self.air_credentials(link, account).await?;
        self.test_port_via(link, account.id, &creds, port).await
    }

    /// `AirVPN`'s DDNS check of the account's forwarded ports.
    ///
    /// # Errors
    ///
    /// As for [`Providers::forwarded_ports`], plus the website's own refusal with the field it
    /// names (a port out of range or already held, a setting it would not take or keep).
    pub async fn ddns(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
    ) -> Result<ForwardedPortDdns, ApiError> {
        reservations(account)?;
        let creds = self.air_credentials(link, account).await?;
        self.ddns_via(link, account.id, &creds).await
    }

    /// `AirVPN`'s search for `count` consecutive free ports (nothing is reserved).
    ///
    /// # Errors
    ///
    /// As for [`Providers::forwarded_ports`], plus the website's own refusal with the field it
    /// names (a port out of range or already held, a setting it would not take or keep).
    pub async fn free_ports(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        count: u8,
    ) -> Result<ForwardedPortSearch, ApiError> {
        reservations(account)?;
        searchable(count)?;
        let creds = self.air_credentials(link, account).await?;
        self.free_ports_via(link, account.id, &creds, count).await
    }

    /// One website operation of `account` over the route `egress` names: its session, locked for
    /// the operation (one at a time per account, so two never sign in twice), and a client whose
    /// every request goes through the operation's guard; the egress Instance, for the gate.
    async fn website<'a, E: guard::Egress>(
        &'a self,
        egress: &'a E,
        account: ProviderAccountId,
    ) -> Result<
        (
            tokio::sync::OwnedMutexGuard<airvpn::site::Session>,
            HttpsClient<Guard<'a, E>>,
            Option<InstanceId>,
        ),
        ApiError,
    > {
        let session = self.air_site(account).lock_owned().await;
        let guard = self.guard(egress).await?;
        let at = guard.route().instance_id;
        Ok((session, self.tls.client(guard), at))
    }

    /// [`Providers::forwarded_ports`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn forwarded_ports_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
    ) -> Result<ForwardedPorts, ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .ports(&mut session, credentials)
            .await;
        self.ports_gate(
            result.as_ref().map(|l| {
                let (used, limit) = (l.ports.len(), airvpn::site::MAX_PORTS);
                tr!(
                    "Signed in to AirVPN's website and read the inbound ports ({used} of {limit} used)",
                    "已登入 AirVPN 網站讀取連入埠（已用 {used}／{limit} 個）",
                    "AirVPN の Web サイトにログインして着信ポートを読み取りました（{used}／{limit} 個を使用中）"
                )
            }),
            at,
        );
        let list = result.map_err(|e| site_error(&e))?;
        Ok(ForwardedPorts {
            account_id: account,
            ports: list
                .ports
                .iter()
                .map(|p| forwarded_port(p, Some(&list)))
                .collect(),
            devices: list
                .devices
                .iter()
                .map(|d| ForwardedPortDevice {
                    id: d.id.clone(),
                    name: d.name.clone(),
                })
                .collect(),
            limit: u32::try_from(airvpn::site::MAX_PORTS).unwrap_or(u32::MAX),
            min_port: airvpn::site::MIN_PORT,
            observed_at: Timestamp::now(),
        })
    }

    /// [`Providers::reserve_port`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn reserve_port_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
        port: Option<u16>,
    ) -> Result<ForwardedPort, ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .reserve(&mut session, credentials, port)
            .await;
        self.ports_gate(
            result.as_ref().map(|p| {
                let port = p.port;
                tr!(
                    "Reserved inbound port {port} on AirVPN's website",
                    "已在 AirVPN 網站保留連入埠 {port}",
                    "AirVPN の Web サイトで着信ポート {port} を予約しました"
                )
            }),
            at,
        );
        result
            .map(|p| forwarded_port(&p, None))
            .map_err(|e| site_error(&e))
    }

    /// [`Providers::delete_port`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn delete_port_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
        port: u16,
    ) -> Result<(), ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .delete(&mut session, credentials, port)
            .await;
        self.ports_gate(
            result.as_ref().map(|()| {
                tr!(
                    "Deleted inbound port {port} on AirVPN's website",
                    "已在 AirVPN 網站刪除連入埠 {port}",
                    "AirVPN の Web サイトで着信ポート {port} を削除しました"
                )
            }),
            at,
        );
        result.map_err(|e| site_error(&e))
    }

    /// [`Providers::update_port`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn update_port_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
        port: u16,
        update: &ForwardedPortUpdate,
    ) -> Result<ForwardedPort, ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .edit(&mut session, credentials, port, update)
            .await;
        self.ports_gate(
            result.as_ref().map(|_| {
                tr!(
                    "Changed the settings of inbound port {port} on AirVPN's website and confirmed them by reading them back",
                    "已在 AirVPN 網站修改連入埠 {port} 的設定並讀回確認",
                    "AirVPN の Web サイトで着信ポート {port} の設定を変更し、読み戻して確認しました"
                )
            }),
            at,
        );
        result
            .map(|e| forwarded_port(&e.port, Some(&e.list)))
            .map_err(|e| site_error(&e))
    }

    /// [`Providers::test_port`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn test_port_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
        port: u16,
    ) -> Result<ForwardedPortTest, ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .test(&mut session, credentials, port)
            .await;
        self.ports_gate(
            result.as_ref().map(|_| {
                tr!(
                    "Tested inbound port {port} on AirVPN's website",
                    "已在 AirVPN 網站測試連入埠 {port}",
                    "AirVPN の Web サイトで着信ポート {port} をテストしました"
                )
            }),
            at,
        );
        result.map_err(|e| site_error(&e))
    }

    /// [`Providers::ddns`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn ddns_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
    ) -> Result<ForwardedPortDdns, ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .ddns(&mut session, credentials)
            .await;
        self.ports_gate(
            result.as_ref().map(|_| {
                tr!(
                    "Completed the DDNS check on AirVPN's website",
                    "已在 AirVPN 網站完成 DDNS 檢查",
                    "AirVPN の Web サイトで DDNS チェックを完了しました"
                )
            }),
            at,
        );
        result.map_err(|e| site_error(&e))
    }

    /// [`Providers::free_ports`] over the route `egress` names, with `credentials`.
    ///
    /// # Errors
    ///
    /// As for the operation without `_via`, over the route `egress` names.
    pub async fn free_ports_via<E: guard::Egress>(
        &self,
        egress: &E,
        account: ProviderAccountId,
        credentials: &Credentials,
        count: u8,
    ) -> Result<ForwardedPortSearch, ApiError> {
        let (mut session, http, at) = self.website(egress, account).await?;
        let result = airvpn::site::Site::new(&http)
            .search(&mut session, credentials, count)
            .await;
        self.ports_gate(
            result.as_ref().map(|_| {
                tr!(
                    "Searched AirVPN's website for {count} consecutive free ports",
                    "已在 AirVPN 網站搜尋 {count} 個連續的空閒埠",
                    "AirVPN の Web サイトで連続した空きポート {count} 個を検索しました"
                )
            }),
            at,
        );
        result.map_err(|e| site_error(&e))
    }

    /// The forwarded-ports gate after a website operation: passed when it worked, failed or
    /// blocked when signing in or the site's contract failed. Transport, budget and egress
    /// failures say nothing about the gate and leave it as it was.
    fn ports_gate(&self, result: Result<Text, &airvpn::site::SiteError>, at: Option<InstanceId>) {
        let (status, reason) = match result {
            Ok(reason) => (GateStatus::Passed, reason),
            Err(e) if e.code() == ErrorCode::ProviderLoginChallenge => {
                (GateStatus::Blocked, e.text())
            }
            Err(e) if e.is_sign_in() || e.code() == ErrorCode::ProviderContractDrift => {
                (GateStatus::Failed, e.text())
            }
            Err(_) => return,
        };
        self.gates.lock().record(
            ProviderKind::Airvpn,
            ProviderGateKind::Forward,
            status,
            reason,
            at,
        );
    }

    // ---------------------------------------------------------------------------------------
    // Connections
    // ---------------------------------------------------------------------------------------

    /// Build a profile and an Instance (and optionally a local proxy port) from one device and
    /// one server, then start it. While a run of the direct exception is active (first setup,
    /// rebootstrap), the connection it builds — exactly one, claimed before any provider request —
    /// is created with its intent to run in one manager call and becomes the Provider egress once
    /// connected; a later request gets that same connection back instead of a second one.
    ///
    /// # Errors
    ///
    /// A validation error for the name, the gateway port or the server, the provider's error
    /// while the device or key is made, the profile checker's report, and the manager's error
    /// while the profile, the Instance or the run's connection is created.
    pub async fn connect(
        self: &Arc<Self>,
        link: &Arc<ManagerLink>,
        account: &ProviderAccount,
        input: &ProviderConnectInput,
        operation: OperationId,
    ) -> Result<ProviderConnectResult, ApiError> {
        let name = input.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(field_error("/name", name_rule()));
        }
        let run = match crate::egress::claim(link, operation).await? {
            ChildClaimWire::Existing {
                run,
                instance,
                profile,
            } => return crate::egress::reuse(link, run, instance, profile).await,
            ChildClaimWire::Reserved { run } => Some(run),
            ChildClaimWire::None => None,
        };
        let work = self.connect_new(link, account, input, name, operation, run.as_deref());
        let built = match &run {
            // Building the run's one connection: the reservation is renewed meanwhile, so it
            // lapses only for a request that died, never for one that is slow.
            Some(r) => {
                Box::pin(crate::egress::renewing(
                    link,
                    r,
                    operation,
                    crate::egress::RESERVATION_RENEW,
                    work,
                ))
                .await
            }
            None => work.await,
        };
        if built.is_err()
            && let Some(run) = run
        {
            // Nothing was built: the next request may build the run's connection.
            let _ = link
                .call(Call::BootstrapReleaseChild { run, operation })
                .await;
        }
        built
    }

    async fn connect_new(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        input: &ProviderConnectInput,
        name: &str,
        operation: OperationId,
        run: Option<&str>,
    ) -> Result<ProviderConnectResult, ApiError> {
        if run.is_some() && !input.start {
            return Err(must_start());
        }
        if let Some(p) = input.gateway_port {
            if p < 1024 {
                return Err(gateway_port_range());
            }
            // Before anything is created: a taken port would fail the connection halfway,
            // after its profile and Instance exist.
            port_free(link, p).await?;
        }
        let family = match input.endpoint_family {
            IpFamily::Ipv4 => Family::V4,
            IpFamily::Ipv6 => Family::V6,
        };
        let lock = self.lock_for(account.id);
        let _guard = lock.lock().await;
        // Key material stored for this connection only: removed again if no profile keeps it.
        let generated = match account.provider {
            ProviderKind::Mullvad => self
                .mullvad_profile(link, account, input, name, family)
                .await
                .map(|(p, d)| (p, d, Vec::new())),
            ProviderKind::Airvpn => {
                self.airvpn_profile(link, account, input, name, family)
                    .await
            }
            ProviderKind::Generic => return Err(unsupported()),
        };
        if let Err(e) = &generated {
            self.generated(account.provider, Err(e));
        }
        let (profile, device, fresh) = generated?;
        let report = check_profile(&profile);
        if !report.has_errors() {
            self.generated(account.provider, Ok(&profile));
        }
        let profile = store_profile(link, profile, &report, fresh).await?;
        let spec = InstanceSpec {
            id: InstanceId::new(),
            meta: crate::routes::new_meta(),
            name: name.to_string(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: vpn_domain::TransportRef::default(),
        };
        let gateway = input.gateway_port.map(|port| GatewaySpec {
            id: GatewayId::new(),
            meta: crate::routes::new_meta(),
            instance_id: spec.id,
            name: gateway_name(input.gateway_name.as_deref(), port),
            kind: GatewayKind::Mixed,
            port,
            enabled: true,
            udp: true,
            max_connections: 1024,
        });
        let (instance, gateway_id) = match run {
            // The profile passed the checker: the run's connection, its Gateway and its intent
            // to run are one durable step; it starts by itself and the manager's record of it is
            // what makes it the egress (see `crate::egress::drive`).
            Some(run) => {
                match link
                    .call(Call::BootstrapCreateChild {
                        run: run.to_string(),
                        operation,
                        instance: spec,
                        gateway,
                    })
                    .await?
                {
                    Reply::BootstrapChild { instance, gateway } => {
                        (*instance, gateway.map(|g| g.id))
                    }
                    _ => return Err(ApiError::internal()),
                }
            }
            None => create_connection(link, spec, gateway, input.start).await?,
        };
        Ok(ProviderConnectResult {
            profile_id: profile.id,
            instance_id: instance.id,
            gateway_id,
            device_id: device.id.clone(),
            device: Some(device),
            becomes_egress: run.is_some(),
            reused: false,
        })
    }

    /// Point a profile built from this account at another of its servers, keeping its device and
    /// key (the spec's template "materialize" for an identity that already exists). Only the peer,
    /// the addresses the provider assigns and the location change — the user's MTU and keepalive
    /// stay. The caller stores the result under its revision check; a running connection keeps
    /// its current server until restarted, which its status reports as a pending change.
    ///
    /// An imported profile of the same provider whose key is one of the account's devices is
    /// adopted: it takes that device's identity, so from then on it is the account's like one the
    /// provider flow built (and the device cannot be revoked under it).
    ///
    /// # Errors
    ///
    /// `INVALID_STATE` when the profile is not this account's or its device or key changed, a
    /// validation error for the name or the server, the profile checker's report, and
    /// otherwise as for an operation (route, guard, provider, manager).
    pub async fn change_server(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        mut profile: RuntimeProfile,
        input: &ProviderServerChangeInput,
    ) -> Result<RuntimeProfile, ApiError> {
        // `None`: an imported profile, matched to a device by its public key below.
        let device_id = match &profile.source {
            ProfileSource::Provider {
                account_id,
                device_id,
                ..
            } if *account_id == account.id => Some(device_id.clone()),
            ProfileSource::Imported if profile.provider == account.provider => None,
            _ => {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "This WireGuard profile was not created from this account",
                        "這份 WireGuard 設定不是由這個帳號建立的",
                        "この WireGuard 設定はこのアカウントから作成されたものではありません"
                    ),
                ));
            }
        };
        if let Some(name) = &input.name {
            let name = name.trim();
            if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
                return Err(field_error("/name", name_rule()));
            }
            profile.name = name.to_string();
        }
        let family = match input.endpoint_family {
            IpFamily::Ipv4 => Family::V4,
            IpFamily::Ipv6 => Family::V6,
        };
        let lock = self.lock_for(account.id);
        let _guard = lock.lock().await;
        match account.provider {
            ProviderKind::Mullvad => {
                self.rebind_mullvad(
                    link,
                    account,
                    &mut profile,
                    input,
                    device_id.as_deref(),
                    family,
                )
                .await?;
            }
            ProviderKind::Airvpn => {
                self.rebind_airvpn(
                    link,
                    account,
                    &mut profile,
                    input,
                    device_id.as_deref(),
                    family,
                )
                .await?;
            }
            ProviderKind::Generic => return Err(unsupported()),
        }
        let report = check_profile(&profile);
        if report.has_errors() {
            return Err(crate::http::report_error(&report).0);
        }
        self.generated(account.provider, Ok(&profile));
        Ok(profile)
    }

    /// [`Providers::change_server`] for a Mullvad profile: its device (`device_id`, or the one
    /// holding its key) on relay `input.server_id`.
    async fn rebind_mullvad(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        profile: &mut RuntimeProfile,
        input: &ProviderServerChangeInput,
        device_id: Option<&str>,
        family: Family,
    ) -> Result<(), ApiError> {
        let (_, api, token) = self.mullvad(link, account).await?;
        let catalog = self.mullvad_catalog(&api).await?;
        // The multihop list is read only for an entry at another relay.
        let ports = match &input.entry {
            Some(ProviderEntryInput::Relay { server_id }) if *server_id != input.server_id => {
                Some(self.mullvad_multihop(&api).await?)
            }
            _ => None,
        };
        let route = route::mullvad(
            &catalog,
            ports.as_deref(),
            &input.server_id,
            input.entry.as_ref(),
            family,
        )?;
        let relay = route.exit;
        let devices = api.devices(&token).await.map_err(|e| provider_error(&e))?;
        let device = match device_id {
            Some(id) => devices
                .into_iter()
                .find(|d| d.id.as_str() == id)
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "The device this profile uses is no longer in the Mullvad account; create a connection with a new device instead",
                            "這份設定使用的裝置已不在 Mullvad 帳號中；請改用新裝置建立連線",
                            "この設定が使っているデバイスは Mullvad アカウントにもうありません。新しいデバイスで接続を作成してください"
                        ),
                    )
                })?,
            None => devices
                .into_iter()
                .find(|d| d.pubkey == profile.interface.public_key)
                .ok_or_else(not_a_device)?,
        };
        if device.pubkey != profile.interface.public_key {
            return Err(key_changed());
        }
        let params = route::mullvad_params(&device, &route, &catalog.network, family)
            .ok_or_else(no_entry_for_family)?;
        profile.interface.addresses = params.addresses;
        profile.interface.dns = params.dns;
        profile.peer.public_key = params.peer_public_key;
        profile.peer.endpoint = params.endpoint;
        profile.peer.allowed_ips = params.allowed_ips;
        profile.location = Some(ProfileLocation {
            country_code: Some(relay.country_code.to_ascii_uppercase()),
            country: Some(relay.country.clone()),
            city: Some(relay.city.clone()),
            server: Some(relay.hostname.clone()),
        });
        profile.source = ProfileSource::Provider {
            account_id: account.id,
            device_id: device.id.as_str().to_string(),
            server_id: relay.hostname.clone(),
            entry: route::mullvad_entry(&route),
        };
        Ok(())
    }

    /// [`Providers::change_server`] for an `AirVPN` profile: its device (`device_id`, or the one
    /// holding its key) on server `input.server_id`.
    async fn rebind_airvpn(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        profile: &mut RuntimeProfile,
        input: &ProviderServerChangeInput,
        device_id: Option<&str>,
        family: Family,
    ) -> Result<(), ApiError> {
        let (_, user) = self.air_user(link, account).await?;
        let device = match device_id {
            Some(id) => user.devices.iter().find(|d| d.name == *id).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "The device this profile uses is no longer in the AirVPN account",
                        "這份設定使用的裝置已不在 AirVPN 帳號中",
                        "この設定が使っているデバイスは AirVPN アカウントにもうありません"
                    ),
                )
            })?,
            None => user
                .devices
                .iter()
                .find(|d| d.public_key == profile.interface.public_key)
                .ok_or_else(not_a_device)?,
        };
        if device.public_key != profile.interface.public_key {
            return Err(key_changed());
        }
        let catalog = self.air_catalog(link, account).await?;
        let server = catalog
            .servers
            .iter()
            .find(|s| s.name == input.server_id)
            .ok_or_else(unknown_air_server)?;
        if matches!(server.warning, Some(ServerWarning::Closed(_))) {
            return Err(closed_air_server());
        }
        let mode = route::airvpn(&catalog.modes, server, input.entry.as_ref(), family)?;
        let params = route::airvpn_params(device, server, &user, family, mode)
            .ok_or_else(no_entry_for_family)?;
        // The preshared key belongs to the device: the stored one stays.
        profile.interface.addresses = params.addresses;
        profile.interface.dns = params.dns;
        profile.peer.public_key = params.peer_public_key;
        profile.peer.endpoint = params.endpoint;
        profile.peer.allowed_ips = params.allowed_ips;
        profile.location = Some(ProfileLocation {
            country_code: Some(server.country_code.clone()),
            country: None,
            city: server.location.clone(),
            server: Some(server.name.clone()),
        });
        profile.source = ProfileSource::Provider {
            account_id: account.id,
            device_id: device.name.clone(),
            server_id: server.name.clone(),
            entry: route::airvpn_entry(mode),
        };
        Ok(())
    }

    async fn mullvad_profile(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        input: &ProviderConnectInput,
        name: &str,
        family: Family,
    ) -> Result<(RuntimeProfile, ProviderDevice), ApiError> {
        let (_, api, token) = self.mullvad(link, account).await?;
        let catalog = self.mullvad_catalog(&api).await?;
        // The multihop list is read only for an entry at another relay.
        let ports = match &input.entry {
            Some(ProviderEntryInput::Relay { server_id }) if *server_id != input.server_id => {
                Some(self.mullvad_multihop(&api).await?)
            }
            _ => None,
        };
        // Checked before a device is made for it.
        let route = route::mullvad(
            &catalog,
            ports.as_deref(),
            &input.server_id,
            input.entry.as_ref(),
            family,
        )?;
        let relay = route.exit;
        if route.exit.entry(family).is_none() && route.entry.is_none() {
            return Err(no_entry_for_family());
        }
        let (device, secret) = mullvad_device(link, &api, &token, input, name).await?;
        let params = route::mullvad_params(&device, &route, &catalog.network, family)
            .ok_or_else(no_entry_for_family)?;
        let profile = RuntimeProfile {
            id: ProfileId::new(),
            meta: crate::routes::new_meta(),
            name: name.to_string(),
            provider: ProviderKind::Mullvad,
            source: ProfileSource::Provider {
                account_id: account.id,
                device_id: device.id.as_str().to_string(),
                server_id: relay.hostname.clone(),
                entry: route::mullvad_entry(&route),
            },
            interface: InterfaceSpec {
                private_key: secret,
                public_key: device.pubkey,
                addresses: params.addresses,
                dns: params.dns,
                mtu: params.mtu,
            },
            peer: PeerSpec {
                public_key: params.peer_public_key,
                preshared_key: None,
                endpoint: params.endpoint,
                allowed_ips: params.allowed_ips,
                persistent_keepalive: params.persistent_keepalive,
            },
            location: Some(ProfileLocation {
                country_code: Some(relay.country_code.to_ascii_uppercase()),
                country: Some(relay.country.clone()),
                city: Some(relay.city.clone()),
                server: Some(relay.hostname.clone()),
            }),
            expires_at: account.expires_at,
        };
        let device = ProviderDevice {
            id: device.id.as_str().to_string(),
            account_id: account.id,
            label: device.name,
            public_key: device.pubkey.to_string(),
            owned: true,
            usable: true,
            ipv4_address: Some(device.ipv4_address.to_string()),
            ipv6_address: device.ipv6_address.map(|a| a.to_string()),
            created_at: Some(device.created),
        };
        Ok((profile, device))
    }
}

impl Providers {
    /// An `AirVPN` profile from one of the account's devices (keys issued by `AirVPN`, stored in the
    /// vault here) and a server whose entry the status list confirmed. Returns the key material
    /// stored for it.
    async fn airvpn_profile(
        &self,
        link: &ManagerLink,
        account: &ProviderAccount,
        input: &ProviderConnectInput,
        name: &str,
        family: Family,
    ) -> Result<(RuntimeProfile, ProviderDevice, Vec<SecretRef>), ApiError> {
        let device_id = input.device_id.as_deref().ok_or_else(|| {
            field_error(
                "/device_id",
                tr!(
                    "Choose an AirVPN device",
                    "請選擇一個 AirVPN 裝置",
                    "AirVPN のデバイスを選んでください"
                ),
            )
        })?;
        let (_, user) = self.air_user(link, account).await?;
        let device = user
            .devices
            .iter()
            .find(|d| d.name == device_id)
            .ok_or_else(|| {
                field_error(
                    "/device_id",
                    tr!(
                        "This AirVPN account has no such device",
                        "這個 AirVPN 帳號沒有這個裝置",
                        "この AirVPN アカウントにこのデバイスはありません"
                    ),
                )
            })?;
        let catalog = self.air_catalog(link, account).await?;
        let server = catalog
            .servers
            .iter()
            .find(|s| s.name == input.server_id)
            .ok_or_else(unknown_air_server)?;
        if matches!(server.warning, Some(ServerWarning::Closed(_))) {
            return Err(closed_air_server());
        }
        let mode = route::airvpn(&catalog.modes, server, input.entry.as_ref(), family)?;
        let params = route::airvpn_params(device, server, &user, family, mode)
            .ok_or_else(no_entry_for_family)?;
        let (private_key, preshared, fresh) = store_airvpn_keys(link, device, name).await?;
        let profile = RuntimeProfile {
            id: ProfileId::new(),
            meta: crate::routes::new_meta(),
            name: name.to_string(),
            provider: ProviderKind::Airvpn,
            source: ProfileSource::Provider {
                account_id: account.id,
                device_id: device.name.clone(),
                server_id: server.name.clone(),
                entry: route::airvpn_entry(mode),
            },
            interface: InterfaceSpec {
                private_key,
                public_key: device.public_key,
                addresses: params.addresses,
                dns: params.dns,
                mtu: params.mtu,
            },
            peer: PeerSpec {
                public_key: params.peer_public_key,
                preshared_key: Some(preshared),
                endpoint: params.endpoint,
                allowed_ips: params.allowed_ips,
                persistent_keepalive: params.persistent_keepalive,
            },
            location: Some(ProfileLocation {
                country_code: Some(server.country_code.clone()),
                country: None,
                city: server.location.clone(),
                server: Some(server.name.clone()),
            }),
            expires_at: account.expires_at,
        };
        let device = ProviderDevice {
            id: device.name.clone(),
            account_id: account.id,
            label: device.name.clone(),
            public_key: device.public_key.to_string(),
            owned: true,
            usable: true,
            ipv4_address: Some(device.ipv4.to_string()),
            ipv6_address: device.ipv6.map(|a| a.to_string()),
            created_at: None,
        };
        Ok((profile, device, fresh))
    }
}

/// Copy the account's paid-until date to the profiles made from it, so they show the date the
/// provider gave last. Display only: it never decides whether a profile may start. Best effort;
/// a profile left behind (e.g. edited meanwhile) is caught up by the next refresh.
async fn profile_expiry(link: &ManagerLink, account: &ProviderAccount) {
    let profiles = match link.call(Call::List(EntityKind::Profile)).await {
        Ok(Reply::Entities(all)) => all,
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(error = %e, "profiles of a refreshed account not updated");
            return;
        }
    };
    for e in profiles {
        let Entity::Profile(p) = e else { continue };
        let from_account = matches!(&p.source,
            ProfileSource::Provider { account_id, .. } if *account_id == account.id);
        if !from_account || p.expires_at == account.expires_at {
            continue;
        }
        let (id, rev) = (p.id, p.meta.revision);
        let updated = RuntimeProfile {
            expires_at: account.expires_at,
            ..p
        };
        if let Err(e) = link
            .call(Call::Update {
                entity: Entity::Profile(updated),
                expected_revision: rev,
            })
            .await
        {
            tracing::warn!(profile = %id, error = %e, "profile expiry not updated");
        }
    }
}

/// A new Gateway's port must be one no Gateway uses and no other program holds (the manager
/// test-binds it).
async fn port_free(link: &ManagerLink, port: u16) -> Result<(), ApiError> {
    // `free`: a port from it on that is free now.
    let taken = |free: Option<u16>| {
        field_error(
            "/gateway_port",
            free.map_or_else(
                || {
                    tr!(
                        "Port {port} is already used by another Gateway or program",
                        "port {port} 已被其他 Gateway 或程式使用",
                        "ポート {port} は別のゲートウェイまたはプログラムが使用しています"
                    )
                },
                |p| {
                    tr!(
                        "Port {port} is already used by another Gateway or program; {p} is free instead",
                        "port {port} 已被其他 Gateway 或程式使用；可改用 {p}",
                        "ポート {port} は別のゲートウェイまたはプログラムが使用しています。代わりに {p} を使えます"
                    )
                },
            ),
        )
    };
    match link.call(Call::FreePort { from: port }).await {
        Ok(Reply::FreePort(p)) if p == port => Ok(()),
        Ok(Reply::FreePort(p)) => Err(taken(Some(p))),
        Ok(_) => Err(ApiError::internal()),
        Err(e) if e.code == ErrorCode::ListenerConflict => Err(taken(None)),
        Err(e) => Err(e),
    }
}

// -------------------------------------------------------------------------------------------
// Vault helpers
// -------------------------------------------------------------------------------------------

fn key_fingerprint(key: &WgKey) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(key.0))
}

/// Private keys held here, by the SHA-256 of their public key.
async fn local_keys(link: &ManagerLink) -> Result<HashMap<String, SecretRef>, ApiError> {
    match link.call(Call::Secrets).await? {
        Reply::Secrets(all) => Ok(all
            .into_iter()
            .filter(|s| s.kind == "wireguard_private_key")
            .filter_map(|s| s.public_fingerprint.map(|f| (f, s.secret_ref)))
            .collect()),
        _ => Err(ApiError::internal()),
    }
}

async fn keyed(link: &ManagerLink, label: &[u8], value: &[u8]) -> Result<String, ApiError> {
    let mut input = Zeroizing::new(Vec::with_capacity(label.len() + value.len()));
    input.extend_from_slice(label);
    input.extend_from_slice(value);
    match link.call(Call::KeyedFingerprint(input.to_vec())).await? {
        Reply::Fingerprint(f) => Ok(f),
        _ => Err(ApiError::internal()),
    }
}

async fn put_secret(
    link: &ManagerLink,
    kind: &str,
    label: &str,
    plaintext: Vec<u8>,
    public_fingerprint: Option<String>,
) -> Result<SecretRef, ApiError> {
    match link
        .call(Call::PutSecret {
            kind: kind.into(),
            label: Some(label.to_string()),
            plaintext: SecretBytes::new(plaintext),
            public_fingerprint,
        })
        .await?
    {
        Reply::Secret(m) => Ok(m.secret_ref),
        _ => Err(ApiError::internal()),
    }
}

async fn lease(link: &ManagerLink, r: SecretRef) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    match link.call(Call::LeaseSecret(r)).await? {
        Reply::SecretBytes(b) => Ok(Zeroizing::new(b.expose().to_vec())),
        _ => Err(ApiError::internal()),
    }
}
