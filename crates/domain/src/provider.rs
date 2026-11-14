//! Provider accounts, the global Provider egress and IP checks (architecture §7).
//!
//! Three facts stay separate: which Instance is selected, whether the path is protected
//! (`tunnel_verified`), and whether the exit belongs to the provider (`provider_match`). None of
//! them stands in for another; `unknown` is never shown as a match.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::common::{ProviderKind, SecretRef, Timestamp};
use crate::config::EntityMeta;
use crate::ids::{GatewayId, InstanceId, ProfileId, ProviderAccountId};
use crate::text::Text;

/// Origins the one-time direct bootstrap may reach (architecture §7): each provider API and exit
/// checker, plus `AirVPN`'s bootstrap servers (its official client protocol talks to fixed
/// addresses).
///
/// Exact `(host, port)` pairs; only these names are ever resolved by the host.
pub const BOOTSTRAP_ALLOWLIST: &[(&str, u16)] = &[
    ("api.mullvad.net", 443),
    ("ipv4.am.i.mullvad.net", 443),
    ("ipv6.am.i.mullvad.net", 443),
    ("ipv4.ipleak.net", 443),
    ("airvpn.org", 443),
    ("63.33.78.166", 80),
    ("54.93.175.114", 80),
    ("82.196.3.205", 80),
    ("63.33.116.50", 80),
];

/// A provider account. The account number (or other credential) is a vault secret; only its
/// reference is stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderAccount {
    pub id: ProviderAccountId,
    #[serde(flatten)]
    pub meta: EntityMeta,
    pub provider: ProviderKind,
    pub label: String,
    pub credential_ref: SecretRef,
    /// Paid-until date, as last observed from the provider.
    pub expires_at: Option<Timestamp>,
    pub observed_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EgressPhase {
    Unconfigured,
    BootstrapDirect,
    StartingInstance,
    Switching,
    VpnReady,
    Blocked,
    /// The selected egress cannot come back by itself: its key is missing, or its endpoint
    /// never answered over several attempts. `recovery` says what can be done.
    RecoveryRequired,
    Disabled,
}

/// Which run of the direct exception (architecture §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BootstrapKind {
    /// The first setup: at most one ever (a permanent journal row keyed by the installation).
    Initial,
    /// A manual recovery after the egress became unusable for good.
    Rebootstrap,
}

/// Where a run of the direct exception stands. Only `grant_active`, `instance_requested` and
/// `sealing` are active, and at most one run is active at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BootstrapStage {
    /// The direct grant is open; no connection has been built by this run yet.
    GrantActive,
    /// The one connection of this run exists and becomes the egress once it is connected and
    /// its exit answers through it.
    InstanceRequested,
    /// The exit was verified: direct access is being closed and the binding written. A crash
    /// from here on never reopens direct access.
    Sealing,
    /// The connection is the egress and direct access is closed for good.
    Sealed,
    /// Ended without an egress (the connection did not come up in time, was stopped, or the
    /// seal could not be completed); nothing reopens direct access by itself.
    Blocked,
    Cancelled,
    Expired,
}

impl BootstrapStage {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::GrantActive | Self::InstanceRequested | Self::Sealing
        )
    }
}

/// One run of the direct exception, as recorded (`bootstrap_journal`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BootstrapRun {
    pub id: String,
    pub kind: BootstrapKind,
    pub stage: BootstrapStage,
    /// The one connection this run built (it becomes the egress once connected).
    pub child_instance_id: Option<InstanceId>,
    pub child_profile_id: Option<ProfileId>,
    /// While the direct grant is open.
    pub grant_expires_at: Option<Timestamp>,
    /// The connection must be connected and its exit verified by then.
    pub promote_deadline: Option<Timestamp>,
    /// Why the run ended (or why it waits), in public words.
    pub reason_code: Option<String>,
    pub reason: Option<Text>,
    pub updated_at: Timestamp,
}

/// Whether the selected egress needs recovery, and whether a manual rebootstrap may be opened.
///
/// A rebootstrap opens (architecture §7) only when the selected egress is unusable for good (its
/// key is missing or its endpoint never answers), no other connection or valid profile here could
/// take over, it was not stopped by the user, and the tunnel itself is what fails (not an exit
/// checker).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EgressRecovery {
    /// The selected egress cannot come back by itself.
    pub required: bool,
    /// `POST /v1/provider-egress/rebootstrap` would be accepted now.
    pub rebootstrap_eligible: bool,
    /// Stable code of the deciding fact (`KEY_MISSING`, `ENDPOINTS_FAILED`, `EGRESS_STOPPED`,
    /// `EGRESS_USABLE`, `EGRESS_RECOVERING`, `LOCAL_EGRESS_AVAILABLE`, `LOCAL_PROFILE_AVAILABLE`,
    /// `BOOTSTRAP_ACTIVE`, …).
    pub reason_code: String,
    pub reason: Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EgressMode {
    ViaInstance,
    Disabled,
}

/// The durable part of the global Provider egress binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderEgress {
    /// CAS revision of the user's configuration.
    #[ts(type = "number")]
    pub revision: u64,
    /// Monotonic fence: advanced by every change of the binding and when the bootstrap is used
    /// up. (A new generation of the same Instance is fenced by its connector path.)
    #[ts(type = "number")]
    pub route_revision: u64,
    pub desired_mode: EgressMode,
    /// Once true, never false again: the one direct bootstrap has been used.
    pub bootstrap_consumed: bool,
    pub selected_instance_id: Option<InstanceId>,
}

/// `GET /v1/provider-egress`: the binding plus what is observed right now.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderEgressStatus {
    #[serde(flatten)]
    pub egress: ProviderEgress,
    pub phase: EgressPhase,
    pub selected_instance_name: Option<String>,
    #[ts(type = "number | null")]
    pub selected_generation: Option<u64>,
    pub reason_code: Option<String>,
    pub reason: Option<Text>,
    /// Bootstrap grant deadline while a direct bootstrap is open.
    pub bootstrap_expires_at: Option<Timestamp>,
    /// The active run of the direct exception, else the latest one (first setup or
    /// rebootstrap).
    #[serde(default)]
    pub bootstrap: Option<BootstrapRun>,
    /// Set while the selected egress is not working: whether it needs recovery and whether a
    /// manual rebootstrap is possible, with the reason.
    #[serde(default)]
    pub recovery: Option<EgressRecovery>,
    /// The latest exit check over the egress route.
    pub last_check: Option<ProviderIpCheck>,
    /// Every provider's function gates, each as last observed on its own (one per provider and
    /// [`ProviderGateKind`]). None stands in for another.
    pub gates: Vec<ProviderGate>,
    pub observed_at: Timestamp,
}

/// One function of a provider, verified on its own (spec AC-114).
///
/// An exit observation passing — `IPLeak`'s, or the provider's own checker — says nothing about
/// membership, IPv6, generating settings or port forwards; each has its own record, observation
/// time and reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderGate {
    pub provider: ProviderKind,
    pub gate: ProviderGateKind,
    pub status: GateStatus,
    /// What was observed, or what is missing, in plain words.
    pub reason: Option<Text>,
    /// When it was last observed; `None` when it never was (the status is what this build knows).
    pub observed_at: Option<Timestamp>,
    /// The connection it was observed on.
    pub instance_id: Option<InstanceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProviderGateKind {
    /// The exit checker answers in its known shape over IPv4 (`AirVPN` `whatismyip`, Mullvad
    /// `am.i.mullvad.net`, `IPLeak` for generic profiles).
    ExitCheck,
    /// The provider's own answer says the exit is its own (never inferred from country or ISP).
    Membership,
    /// The exit over IPv6, checked on its own: an IPv4 pass proves nothing about IPv6.
    Ipv6,
    /// `WireGuard` settings generated from the account's devices and the confirmed server list.
    ConfigGenerator,
    /// A port reserved at the provider for inbound connections.
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GateStatus {
    Passed,
    Failed,
    /// The provider offers no way to do it from here (e.g. no reservation API).
    Blocked,
    /// It does not apply to this provider or connection (e.g. no IPv6 address).
    NotApplicable,
    /// Not observed yet, or the last attempt could not tell.
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum IpCheckStatus {
    Ok,
    Unavailable,
    Blocked,
    ContractDrift,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum RouteMode {
    BootstrapDirect,
    ViaInstance,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProviderMatch {
    /// The provider's own answer says this is its exit.
    Match,
    /// The provider's own answer says it is not.
    Other,
    /// No membership evidence (or no answer): never shown as a match.
    Unknown,
}

/// One exit observation, per provider and address family.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderIpCheck {
    pub provider: ProviderKind,
    pub family: IpFamily,
    pub status: IpCheckStatus,
    pub route_mode: RouteMode,
    pub instance_id: Option<InstanceId>,
    #[ts(type = "number | null")]
    pub generation: Option<u64>,
    /// The request went through a Ready Instance's tunnel (false for the bootstrap exception).
    pub tunnel_verified: bool,
    pub provider_match: ProviderMatch,
    pub observed_ip: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub checked_at: Option<Timestamp>,
    #[ts(type = "number | null")]
    pub latency_ms: Option<u64>,
    pub reason_code: Option<String>,
    /// Why the check did not pass, in words (the code, when there is one, is `reason_code`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Text>,
    /// The exit server the provider's checker names (Mullvad's exit relay hostname), when it
    /// names one: compare it with the profile's exit.
    #[serde(default)]
    pub exit_server: Option<String>,
}

/// A device registered with the provider (remote identifier, not a UUID).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderDevice {
    pub id: String,
    pub account_id: ProviderAccountId,
    pub label: String,
    pub public_key: String,
    /// This installation holds the device's private key.
    pub owned: bool,
    /// A connection can be built from it now: its key is here, or the provider hands keys out
    /// (`AirVPN`).
    pub usable: bool,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub created_at: Option<Timestamp>,
}

/// One server of the provider's catalog.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderServer {
    /// The provider's server name (e.g. `jp-tyo-wg-001`).
    pub id: String,
    pub provider: ProviderKind,
    pub country_code: String,
    pub country: String,
    pub city_code: String,
    pub city: String,
    pub hosting: Option<String>,
    pub owned: bool,
    pub active: bool,
    /// Numeric `ip:port` endpoints.
    pub endpoints: Vec<String>,
    pub peer_public_key: String,
    /// Current load as the provider reports it.
    pub load_percent: Option<u8>,
    /// Provider notice for this server (maintenance, closing).
    pub warning: Option<String>,
    /// Mullvad: the port a tunnel entering at another relay reaches this one on as its exit
    /// (multihop), when the provider's list confirms it for this relay's key and address;
    /// `None`: this relay cannot be a multihop exit now.
    #[serde(default)]
    pub multihop_port: Option<u16>,
    /// `AirVPN`: the server's `WireGuard` entries (an entry address and a UDP port), the default
    /// first. Empty for providers without alternative entries.
    #[serde(default)]
    pub entries: Vec<ProviderServerEntry>,
    /// The addresses traffic leaves from, where the provider lists them (`AirVPN`); empty when
    /// unknown before connecting.
    #[serde(default)]
    pub exit_ips: Vec<String>,
}

/// One `WireGuard` entry of an `AirVPN` server: one of its entry addresses on one UDP port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderServerEntry {
    /// The entry address's index in `AirVPN`'s list (0-based: its "Entry IP 1", shown as 位址 1,
    /// is 0).
    pub index: u8,
    pub port: u16,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    /// The entry a profile gets when it names none.
    pub default: bool,
}

/// Where a connection enters the provider's network, when not at the exit server's default
/// entry (`server_id` is always the exit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[ts(export)]
pub enum ProviderEntryInput {
    /// Mullvad multihop: enter at relay `server_id`, another than the exit (IPv4 only).
    Relay { server_id: String },
    /// `AirVPN`: the exit server's entry address `index` on UDP `port` (one of its entries).
    Address { index: u8, port: u16 },
}

/// `POST /v1/provider-accounts`. The credential goes to the vault; it is never returned or
/// logged (`Debug` hides it).
#[derive(Clone, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProviderAccountInput {
    pub label: String,
    pub credential: ProviderCredentialInput,
}

// Internally tagged: serde takes the tag out before it reads the variant's fields, so
// `deny_unknown_fields` applies to those fields (tested below).
#[derive(Clone, Deserialize, TS)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
#[ts(export)]
pub enum ProviderCredentialInput {
    Mullvad { account_number: String },
    Airvpn { username: String, password: String },
}

/// Shows only which provider: the account number, user name and password stay out of logs.
impl std::fmt::Debug for ProviderCredentialInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderCredentialInput")
            .field("provider", &self.provider())
            .finish_non_exhaustive()
    }
}

impl ProviderCredentialInput {
    #[must_use]
    pub const fn provider(&self) -> ProviderKind {
        match self {
            Self::Mullvad { .. } => ProviderKind::Mullvad,
            Self::Airvpn { .. } => ProviderKind::Airvpn,
        }
    }
}

impl std::fmt::Debug for ProviderAccountInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderAccountInput")
            .field("label", &self.label)
            .field("provider", &self.credential.provider())
            .finish_non_exhaustive()
    }
}

impl Drop for ProviderCredentialInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Mullvad { account_number } => account_number.zeroize(),
            Self::Airvpn { username, password } => {
                username.zeroize();
                password.zeroize();
            }
        }
    }
}

/// `POST /v1/provider-accounts/{id}/connections`: build a `WireGuard` profile and an Instance from
/// one of the account's devices and one server.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProviderConnectInput {
    /// An existing device; `None` registers a new one (Mullvad: the key is generated here and
    /// only its public half is sent).
    pub device_id: Option<String>,
    /// The exit server.
    pub server_id: String,
    /// Where the tunnel enters; `None`: at the exit server, on its default entry.
    #[serde(default)]
    pub entry: Option<ProviderEntryInput>,
    pub name: String,
    /// Address family of the `WireGuard` endpoint.
    pub endpoint_family: IpFamily,
    /// Also open a local proxy port (SOCKS5 + HTTP) on this port.
    pub gateway_port: Option<u16>,
    /// The name of that proxy port, in the reader's language; empty or absent: `Gateway <port>`.
    #[serde(default)]
    pub gateway_name: Option<String>,
    pub start: bool,
}

/// `POST /v1/provider-accounts/{id}/profiles/{profile}/server` (If-Match): point a profile built
/// from this account at another of its servers.
///
/// The device and its key stay; a running connection keeps its current server until it is
/// restarted.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProviderServerChangeInput {
    /// The exit server.
    pub server_id: String,
    /// Where the tunnel enters; `None`: at the exit server, on its default entry.
    #[serde(default)]
    pub entry: Option<ProviderEntryInput>,
    /// Address family of the `WireGuard` endpoint.
    pub endpoint_family: IpFamily,
    /// A new profile name (e.g. one that names the new server); `None` keeps the current one.
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProviderConnectResult {
    pub profile_id: ProfileId,
    pub instance_id: InstanceId,
    pub gateway_id: Option<GatewayId>,
    pub device_id: String,
    /// The device the connection uses, as the provider described it while connecting — a new
    /// device may take a moment to appear in the provider's own device list. Absent when the
    /// answer is a replay of an earlier request.
    pub device: Option<ProviderDevice>,
    /// It becomes the Provider egress once connected (first setup, rebootstrap).
    pub becomes_egress: bool,
    /// The run of the direct exception already had its connection: it was started again and
    /// waits to become the egress — no second connection, key or device was made.
    #[serde(default)]
    pub reused: bool,
}

/// One port `AirVPN` forwards to the account's connections, as its website's Client Area lists it
/// ("Ports").
///
/// The same ports reach every `AirVPN` server; inbound traffic to the connection's exit on `port`
/// arrives on its tunnel address at `local_port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPort {
    /// The public port.
    pub port: u16,
    /// `AirVPN`'s pool of the port (a delete names it).
    pub pool: u32,
    pub enabled: bool,
    pub protocol: crate::config::ForwardProtocol,
    /// `both`, `ipv4`, `ipv6`, or `AirVPN`'s own word for another choice (shown, never acted on).
    pub ip_layer: String,
    /// The device the port is limited to; `None`: every device of the account.
    pub device_id: Option<String>,
    /// That device's name, when `AirVPN` lists it.
    pub device_name: Option<String>,
    /// Where it arrives on the tunnel address (`AirVPN`'s "local port"): `port` unless remapped on
    /// `AirVPN`'s website. A P2P program must listen on the port it announces, so it is never
    /// remapped for one.
    pub local_port: u16,
    /// `AirVPN`'s DDNS name for the port, the part before `.airdns.org`, when one is set.
    pub dns_name: Option<String>,
    /// The member's own notes on `AirVPN`'s website.
    pub notes: Option<String>,
}

/// Every DDNS name of `AirVPN` ends in this; a [`ForwardedPort::dns_name`] is the part before it.
pub const AIRDNS_SUFFIX: &str = ".airdns.org";

/// The IP versions a forwarded port is open on (`AirVPN`'s "IP layer").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PortIpLayer {
    Both,
    Ipv4,
    Ipv6,
}

impl PortIpLayer {
    /// The word [`ForwardedPort::ip_layer`] uses for it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// `PATCH /v1/provider-accounts/{id}/forwarded-ports/{port}`: change some of a forwarded port's
/// settings on the provider's website (`AirVPN`'s Client Area); a field left out stays as it is.
///
/// Each change is one request to the website, and the port is read back afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ForwardedPortUpdate {
    /// Free text, at most 200 characters on one line; `""` clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub enabled: Option<bool>,
    /// `"all"` (every device of the account) or the id of one of its devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub protocol: Option<crate::config::ForwardProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ip_layer: Option<PortIpLayer>,
    /// Where it arrives on the tunnel address (1–65535). VPN Manager's forwards and P2P programs
    /// need the port itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub local_port: Option<u16>,
    /// The DDNS name before `.airdns.org`: letters, digits and hyphens, at most 60; `""` clears
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub dns_name: Option<String>,
}

impl ForwardedPortUpdate {
    /// Nothing to change.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// What `AirVPN`'s own test from one server said about a forwarded port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PortTestState {
    /// `AirVPN` reached a program on the port through the server (its `ok`).
    Open,
    /// `AirVPN` could not reach it (its `error`).
    Closed,
    /// `AirVPN` warned about it (its `warning`).
    Warning,
    /// A word this version does not know (kept in `word`): only `AirVPN`'s message says what it
    /// means. Never a success.
    Unknown,
    /// Not tested: UDP (`AirVPN` tests TCP only), or `AirVPN` did not run or finish the test (the
    /// message says why).
    NotTested,
}

/// One connected `AirVPN` session that uses a forwarded port, for one protocol and IP version,
/// with `AirVPN`'s test of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPortSession {
    /// `tcp` or `udp`.
    pub protocol: crate::config::ForwardProtocol,
    pub ip_layer: IpFamily,
    pub server_name: Option<String>,
    /// The server's city, as `AirVPN` names it.
    pub server_location: Option<String>,
    /// ISO 3166-1 two-letter code, lower case.
    pub server_country: Option<String>,
    /// The server's exit address that the Internet connects to, with `port`.
    pub server_ip: String,
    pub port: u16,
    /// The session's own address that `AirVPN` delivers to, with `local_port`.
    pub client_ip: Option<String>,
    pub local_port: u16,
    /// The device of the session, as `AirVPN` names it.
    pub device_name: Option<String>,
    pub state: PortTestState,
    /// `AirVPN`'s word for the result, as it wrote it.
    pub word: Option<String>,
    /// `AirVPN`'s own message (a plain sentence), or why it was not tested.
    pub message: Option<Text>,
}

/// `POST /v1/provider-accounts/{id}/forwarded-ports/{port}/test`: `AirVPN` tests the port from the
/// server of every connected session that uses it (TCP only, as its website does).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPortTest {
    pub port: u16,
    /// Empty: no `AirVPN` session of the account uses the port now, so there is nothing to test.
    pub sessions: Vec<ForwardedPortSession>,
    pub observed_at: Timestamp,
}

/// One DDNS name of the account's forwarded ports, as `AirVPN`'s DDNS check reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPortDdnsName {
    /// The part before `.airdns.org`.
    pub name: String,
    /// Connected sessions that use a port with this name: 0, it leads nowhere now; more than
    /// one, it has several destinations.
    pub sessions: u32,
    /// The IPv4 address it should resolve to, as `AirVPN` reports it.
    pub ipv4: Option<String>,
    /// The IPv6 address it should resolve to, as `AirVPN` reports it.
    pub ipv6: Option<String>,
}

/// `GET /v1/provider-accounts/{id}/forwarded-ports/ddns`: `AirVPN`'s DDNS check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPortDdns {
    pub names: Vec<ForwardedPortDdnsName>,
    pub observed_at: Timestamp,
}

/// `GET /v1/provider-accounts/{id}/forwarded-ports/free?count=n`: `AirVPN`'s search for `count`
/// consecutive ports nobody holds (it reserves nothing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPortSearch {
    pub count: u8,
    /// `AirVPN`'s answer, as its website shows it.
    pub message: String,
    pub observed_at: Timestamp,
}

/// One of the account's devices as the forwarded ports name them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPortDevice {
    pub id: String,
    pub name: String,
}

/// `GET /v1/provider-accounts/{id}/forwarded-ports`: the account's forwarded ports, read from
/// the provider's website just now (`AirVPN` only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardedPorts {
    pub account_id: ProviderAccountId,
    pub ports: Vec<ForwardedPort>,
    /// The account's devices, by the ids a port may name.
    pub devices: Vec<ForwardedPortDevice>,
    /// Ports the account may hold (`AirVPN`: 5).
    pub limit: u32,
    /// The lowest port that can be reserved (`AirVPN`: 2049).
    pub min_port: u16,
    pub observed_at: Timestamp,
}

/// `POST /v1/provider-accounts/{id}/forwarded-ports`: reserve `port`, or one the provider picks
/// when it is absent or `null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ForwardedPortInput {
    #[serde(default)]
    pub port: Option<u16>,
}

/// `PUT /v1/provider-egress`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProviderEgressInput {
    pub desired_mode: EgressMode,
    pub selected_instance_id: Option<InstanceId>,
}

/// `POST /v1/provider-egress/rebootstrap` (If-Match: the egress revision).
///
/// A manual, one-time, ten-minute direct exception to build a new egress after the selected one
/// became unusable for good. `confirm_direct` must be `true`: the user acknowledges that these
/// provider requests leave through this computer's own network, not a VPN.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProviderRebootstrapInput {
    pub confirm_direct: bool,
}
