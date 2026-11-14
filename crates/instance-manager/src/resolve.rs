//! Resolve an Instance's current configuration into a worker configuration. All revisions are
//! read once and pinned for the generation; later edits apply on the next start.

use sha2::{Digest, Sha256};
use vpn_domain::validation::check_profile;
use vpn_domain::{
    AutoBanSettings, DnsCacheSettings, DnsOnFailure, DnsProfile, DnsServer, GatewaySpec,
    InstanceId, InstanceLimits, InstanceSpec, ResolvedTransport, RuntimeProfile, SecurityProfile,
    Severity, Text, Timestamp, TransportProfile, TransportRef, WgKey, tr,
};
use vpn_ipc::SecretBytes;
use vpn_ipc::worker::{BanWire, DnsSpec, GatewaySpecWire, PolicySpec, TunnelSpec};
use vpn_store::{Store, StoreError};

/// Why a start cannot proceed. `Deterministic` problems wait for a configuration change instead
/// of being retried in a loop.
#[derive(Debug)]
pub enum ResolveError {
    Deterministic {
        code: &'static str,
        message: vpn_domain::Text,
    },
    Transient(StoreError),
}

impl From<StoreError> for ResolveError {
    fn from(e: StoreError) -> Self {
        Self::Transient(e)
    }
}

/// Fault code of a start whose `WireGuard` key is not in the vault (or cannot be opened).
pub const KEY_MISSING: &str = "KEY_MISSING";

fn det(code: &'static str, message: impl Into<vpn_domain::Text>) -> ResolveError {
    ResolveError::Deterministic {
        code,
        message: message.into(),
    }
}

pub struct Resolved {
    /// What the worker takes from the configuration, to compare with later saves.
    pub inputs: crate::inputs::WorkerInputs,
    pub spec: InstanceSpec,
    pub profile: RuntimeProfile,
    pub dns_revision: Option<u64>,
    pub security: Option<SecurityProfile>,
    pub gateways: Vec<GatewaySpec>,
    pub key_fingerprint: String,
    pub worker: WorkerConfigParts,
    /// The blocklist overlay compiled now (the actor gives it a revision and sends it along).
    pub overlay: crate::policy::Compiled,
    /// What this connection needs to reach (never blocklisted, never banned).
    pub needs: Vec<crate::policy::Need>,
}

/// The revisions of the profiles a generation runs.
#[derive(Debug, Clone, Copy)]
pub struct Revisions {
    pub profile: u64,
    pub dns: Option<u64>,
    pub security: Option<u64>,
}

impl Resolved {
    #[must_use]
    pub fn revisions(&self) -> Revisions {
        Revisions {
            profile: self.profile.meta.revision,
            dns: self.dns_revision,
            security: self.security.as_ref().map(|s| s.meta.revision),
        }
    }
}

/// The worker configuration minus generation and lock path (known only after reservation).
pub struct WorkerConfigParts {
    pub tunnel: TunnelSpec,
    pub dns: DnsSpec,
    pub policy: PolicySpec,
    pub gateways: Vec<GatewaySpecWire>,
    pub limits: InstanceLimits,
    /// What each flow gets and how the health is probed: the connection's transport profile
    /// with every reference followed.
    pub transport: ResolvedTransport,
    /// Linux strict mode: the worker runs in the Instance's sandbox.
    pub strict: bool,
}

#[must_use]
pub fn key_fingerprint(public_key: &WgKey) -> String {
    hex::encode(Sha256::digest(public_key.0))
}

/// A `WireGuard` profile's announced resolvers as plain UDP servers (at most four).
fn udp_servers(dns: &[std::net::IpAddr]) -> Vec<DnsServer> {
    dns.iter()
        .take(4)
        .map(|ip| DnsServer::Udp {
            address: std::net::SocketAddr::new(*ip, 53),
        })
        .collect()
}

/// The DNS a worker uses: the DNS profile's, or the `WireGuard` profile's own resolvers over UDP.
fn dns_spec(
    profile: &RuntimeProfile,
    dns_profile: Option<&DnsProfile>,
) -> Result<DnsSpec, ResolveError> {
    if let Some(d) = dns_profile {
        return Ok(DnsSpec {
            servers: d.servers.clone(),
            cache: d.cache.clone(),
            query_timeout_ms: d.query_timeout_ms,
            attempts: d.attempts,
            fallback: match d.on_failure {
                // A DNS profile whose servers all fail must not strand the connection: the
                // WireGuard profile's own resolvers stand in meanwhile (said in the status).
                DnsOnFailure::WireguardResolvers => udp_servers(&profile.interface.dns),
                // Names fail instead: the worker is not even told of other resolvers.
                DnsOnFailure::Fail => Vec::new(),
            },
            on_failure: d.on_failure,
        });
    }
    if profile.interface.dns.is_empty() {
        return Err(det(
            "DNS_REQUIRED",
            tr!(
                "The WireGuard profile has no DNS; choose a DNS profile for the Instance",
                "WireGuard 設定沒有 DNS，請為 Instance 選擇 DNS 設定",
                "WireGuard 設定に DNS がありません。Instance に DNS 設定を選択してください"
            ),
        ));
    }
    Ok(DnsSpec {
        servers: udp_servers(&profile.interface.dns),
        cache: DnsCacheSettings::default(),
        query_timeout_ms: 3000,
        attempts: 2,
        fallback: Vec::new(),
        on_failure: DnsOnFailure::default(),
    })
}

/// The bans of earlier generations that carry over: the newest `max_bans` (the rest are
/// trimmed from the Store), with the time each has left.
async fn carried_bans(
    store: &Store,
    id: InstanceId,
    max_bans: u32,
) -> Result<Vec<BanWire>, ResolveError> {
    let mut bans = store.bans(Some(id)).await?;
    if bans.len() > max_bans as usize {
        store.trim_bans(id, max_bans).await?;
        bans.truncate(max_bans as usize);
    }
    let now = Timestamp::now().unix_millis();
    Ok(bans
        .into_iter()
        .filter_map(|b| {
            let left = b.expires_at.unix_millis() - now;
            (left > 0).then(|| BanWire {
                source: b.source,
                remaining_secs: u32::try_from((left + 999) / 1000).unwrap_or(u32::MAX),
            })
        })
        .collect())
}

/// The Instance and the configuration it uses, each checked to exist (and the profile to be
/// valid).
async fn load(
    store: &Store,
    id: InstanceId,
) -> Result<
    (
        InstanceSpec,
        RuntimeProfile,
        Option<DnsProfile>,
        Option<SecurityProfile>,
    ),
    ResolveError,
> {
    let spec: InstanceSpec = store.get(id.to_string()).await?.ok_or_else(|| {
        det(
            "INSTANCE_MISSING",
            tr!(
                "The Instance does not exist",
                "Instance 不存在",
                "Instance が存在しません"
            ),
        )
    })?;
    if spec.strict && !vpn_domain::validation::STRICT_SUPPORTED {
        // A configuration from a Linux machine: never run it as something weaker.
        return Err(det(
            "STRICT_UNSUPPORTED",
            vpn_platform::sandbox::unsupported(),
        ));
    }
    let profile: RuntimeProfile =
        store
            .get(spec.profile_id.to_string())
            .await?
            .ok_or_else(|| {
                det(
                    "PROFILE_MISSING",
                    tr!(
                        "The WireGuard profile the Instance uses does not exist",
                        "Instance 使用的 WireGuard 設定不存在",
                        "Instance が使う WireGuard 設定が存在しません"
                    ),
                )
            })?;
    let report = check_profile(&profile);
    if report.has_errors() {
        let first = report
            .issues
            .iter()
            .find(|i| i.severity == Severity::Error)
            .map_or_default(|i| i.message.clone());
        return Err(det(
            "PROFILE_INVALID",
            tr!(
                "The WireGuard profile is invalid: {why}",
                "WireGuard 設定無效：{why}",
                "WireGuard 設定が無効です：{why}";
                why = first
            ),
        ));
    }
    // `expires_at` is informational only. A local date adds no protection (the provider refuses
    // the handshake of an account that has really expired, and the tunnel then fails closed),
    // but would keep a renewed account from starting until its profiles are rewritten.

    let dns_profile: Option<DnsProfile> = match spec.dns_profile_id {
        Some(d) => Some(store.get(d.to_string()).await?.ok_or_else(|| {
            det(
                "DNS_MISSING",
                tr!(
                    "The DNS profile does not exist",
                    "DNS 設定不存在",
                    "DNS 設定が存在しません"
                ),
            )
        })?),
        None => None,
    };
    let security: Option<SecurityProfile> = match spec.security_profile_id {
        Some(s) => Some(store.get(s.to_string()).await?.ok_or_else(|| {
            det(
                "SECURITY_MISSING",
                tr!(
                    "The security profile does not exist",
                    "安全設定不存在",
                    "セキュリティ設定が存在しません"
                ),
            )
        })?),
        None => None,
    };
    Ok((spec, profile, dns_profile, security))
}

/// The transport of a connection: its profile with every reference followed. The stored
/// profiles are read only when the connection uses one.
///
/// # Errors
///
/// `Deterministic` when the profile, or one an automatic profile names, does not exist or is
/// not a fixed one where one is needed; `Transient` for a Store error.
pub async fn transport(
    store: &Store,
    spec: &InstanceSpec,
) -> Result<ResolvedTransport, ResolveError> {
    let saved: Vec<TransportProfile> = match spec.transport {
        TransportRef::Builtin { .. } => Vec::new(),
        TransportRef::Profile { .. } => store.list().await?,
    };
    vpn_domain::resolve_transport(&spec.transport, &saved)
        .map_err(|e| det("TRANSPORT_INVALID", e.message()))
}

/// The payload policy of a worker following `security` (or the default policy).
fn policy_spec(
    security: Option<&SecurityProfile>,
    auto_ban: AutoBanSettings,
    bans: Vec<BanWire>,
    needs: &[crate::policy::Need],
) -> PolicySpec {
    PolicySpec {
        allow_private: security.map_or_default(|s| s.allow_private.clone()),
        blocked_ports: security.map_or_default(|s| s.blocked_ports.clone()),
        allowed_destinations: security.map_or_default(|s| s.allowed_destinations.clone()),
        allowed_ports: security.map_or_default(|s| s.allowed_ports.clone()),
        overlay: None,
        auto_ban,
        bans,
        exempt: needs.iter().map(|n| n.ip).collect(),
    }
}

/// The fallback never reaches a resolver a list of the user's covers: the DNS controller's flows
/// would not pass through the list, and the user's rule wins over the fallback.
fn fallback_off_user_lists(id: InstanceId, dns: &mut DnsSpec, overlay: &crate::policy::Compiled) {
    dns.fallback.retain(|server| {
        let ip = crate::policy::dns_address(server).to_canonical();
        let list = overlay.user_list_covering(ip);
        if let Some(list) = list {
            tracing::info!(
                instance = %id,
                list = %list.name,
                %ip,
                "a blocklist covers a fallback DNS server: left out of the fallback"
            );
        }
        list.is_none()
    });
}

/// The tunnel a worker brings up for `profile`, with its keys.
fn tunnel_spec(
    profile: &RuntimeProfile,
    private_key: SecretBytes,
    preshared_key: Option<SecretBytes>,
) -> TunnelSpec {
    TunnelSpec {
        private_key,
        preshared_key,
        peer_public_key: profile.peer.public_key.0,
        endpoint: profile.peer.endpoint,
        allowed_ips: profile.peer.allowed_ips.clone(),
        addresses: profile.interface.addresses.clone(),
        mtu: profile.interface.mtu,
        persistent_keepalive: profile.peer.persistent_keepalive,
    }
}

/// A key that is not in the vault (or cannot be opened) does not come back by retrying: the
/// connection needs a new key or profile (and, as the Provider egress, recovery). `what`: the key.
fn missing(e: StoreError, what: Text) -> ResolveError {
    match e {
        StoreError::NotFound | StoreError::Vault(_) => det(
            KEY_MISSING,
            tr!(
                "The {what} is not in the key vault or cannot be opened; import the profile again, or create a connection with a new device key",
                "{what}不在保險庫或無法解開；請重新匯入設定，或用新的裝置金鑰建立連線",
                "{what}が鍵保管庫にないか、開けません。設定をもう一度インポートするか、新しいデバイスの鍵で接続を作成してください";
                what = what
            ),
        ),
        other => ResolveError::Transient(other),
    }
}

/// Everything a worker of Instance `id` needs, from the Store.
///
/// # Errors
///
/// `Deterministic` when the configuration cannot run as stored (an entity or key is missing,
/// the profile is invalid, the DNS or a policy conflicts); `Transient` for a Store error that a
/// retry may not see.
pub async fn resolve(store: &Store, id: InstanceId) -> Result<Resolved, ResolveError> {
    let (spec, profile, dns_profile, security) = load(store, id).await?;
    let gateways: Vec<GatewaySpec> = store
        .list::<GatewaySpec>()
        .await?
        .into_iter()
        .filter(|g| g.instance_id == id && g.enabled)
        .collect();

    let key = tr!(
        "WireGuard private key",
        "WireGuard 私鑰",
        "WireGuard 秘密鍵"
    );
    let private_key = store
        .open_secret(profile.interface.private_key)
        .await
        .map_err(|e| missing(e, key))?;
    if private_key.len() != 32 {
        return Err(det(
            "BAD_KEY",
            tr!(
                "The private key is malformed",
                "私鑰格式不正確",
                "秘密鍵の形式が正しくありません"
            ),
        ));
    }
    let psk = match profile.peer.preshared_key {
        Some(r) => Some(SecretBytes::new(
            store
                .open_secret(r)
                .await
                .map_err(|e| missing(e, tr!("preshared key", "預共享金鑰", "事前共有鍵")))?
                .to_vec(),
        )),
        None => None,
    };

    let mut dns = dns_spec(&profile, dns_profile.as_ref())?;
    // Resolvers inside the tunnel (e.g. 10.64.0.1) are private addresses; the DNS controller's
    // own upstream flows are control flows and are not subject to the payload policy.
    let needs = crate::policy::needs(&profile, dns_profile.as_ref());
    let overlay = crate::policy::compile(store, security.as_ref(), &needs)
        .await
        .map_err(|e| match e {
            crate::policy::CompileError::Store(s) => ResolveError::Transient(s),
            other => det("POLICY_INVALID", other.message()),
        })?;
    crate::policy::log_exempt(&overlay.exempt);
    fallback_off_user_lists(id, &mut dns, &overlay);
    if let Some((list, need)) = overlay.conflict(&needs) {
        let (name, ip) = (&list.name, need.ip);
        return Err(det(
            "POLICY_CONFLICT",
            tr!(
                "The IP blocklist “{name}” contains {ip} ({what}), which this connection needs; remove this address from the list",
                "IP 封鎖清單「{name}」包含這條連線需要的 {ip}（{what}）；請從清單移除這個位址",
                "IP ブロックリスト「{name}」に、この接続が必要とする {ip}（{what}）が含まれています。リストからこのアドレスを削除してください";
                what = need.kind.label()
            ),
        ));
    }
    // The profile's auto-ban, or the default policy's (on).
    let auto_ban = vpn_domain::effective_auto_ban(security.as_ref());
    // Bans of earlier generations carry over (the newest, up to the limit).
    let bans = carried_bans(store, id, auto_ban.max_bans.max(1)).await?;
    let policy = policy_spec(security.as_ref(), auto_ban, bans, &needs);
    let transport = transport(store, &spec).await?;

    let worker = WorkerConfigParts {
        tunnel: tunnel_spec(&profile, SecretBytes::new(private_key.to_vec()), psk),
        dns,
        policy,
        gateways: gateways
            .iter()
            .map(|g| GatewaySpecWire {
                id: g.id,
                kind: g.kind,
                port: g.port,
                udp: g.udp,
                max_connections: g.max_connections,
            })
            .collect(),
        limits: spec.limits.clone(),
        transport,
        strict: spec.strict,
    };
    Ok(Resolved {
        inputs: crate::inputs::WorkerInputs::of(
            &spec,
            &profile,
            dns_profile.as_ref(),
            security.as_ref(),
        ),
        key_fingerprint: key_fingerprint(&profile.interface.public_key),
        dns_revision: dns_profile.as_ref().map(|d| d.meta.revision),
        security,
        spec,
        profile,
        gateways,
        worker,
        overlay,
        needs,
    })
}
