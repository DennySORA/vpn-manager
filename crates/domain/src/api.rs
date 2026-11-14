//! HTTP request/response shapes that are not stored entities: create/update inputs (the server
//! owns ids and revisions), joined views for the workbench, import previews, live rates and SSE
//! payloads.

use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::builtin_blocklists::{BlocklistFamily, BlocklistFormat};
use crate::common::{ProviderKind, Revision, SecretRef, Timestamp, WgKey};
use crate::config::{
    AppAccessPort, AppClassInfo, AppIsolation, AppLimits, AppSpec, AutoBanSettings, Blocklist,
    BlocklistSource, BlocklistStats, DnsCacheSettings, DnsOnFailure, DnsServer, EnvVar,
    ForwardBinding, ForwardProtocol, GatewayKind, GatewaySpec, InstanceLimits, InstanceSpec,
    InvalidLine, PortRange, ProfileEntry, ProfileLocation, RuntimeProfile, SshHostKind,
};
use crate::ids::{
    AppId, BlocklistId, DnsProfileId, GatewayId, InstanceId, ProfileId, SecurityProfileId,
};
use crate::status::{AppStatus, ForwardStatus, InstanceStatus, Operation};
use crate::text::Text;
use crate::transport::{HealthSettings, TransportRef, TransportSettings};
use crate::validation::ValidationReport;

// ---------------------------------------------------------------------------------------------
// Inputs (POST creates with a server-generated id; PUT updates with If-Match)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct DnsProfileInput {
    pub name: String,
    pub servers: Vec<DnsServer>,
    #[serde(default)]
    pub cache: DnsCacheSettings,
    #[serde(default = "default_dns_timeout")]
    pub query_timeout_ms: u32,
    #[serde(default = "default_dns_attempts")]
    pub attempts: u8,
    /// Absent: `wireguard_resolvers`, as before the choice existed.
    #[serde(default)]
    pub on_failure: DnsOnFailure,
}

const fn default_dns_timeout() -> u32 {
    3000
}
const fn default_dns_attempts() -> u8 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct SecurityProfileInput {
    pub name: String,
    #[serde(default)]
    #[ts(type = "Array<string>")]
    pub allow_private: Vec<IpNetwork>,
    #[serde(default)]
    pub blocked_ports: Vec<u16>,
    #[serde(default)]
    #[ts(type = "Array<string>")]
    pub allowed_destinations: Vec<IpNetwork>,
    #[serde(default)]
    pub allowed_ports: Vec<PortRange>,
    #[serde(default)]
    pub blocklists: Vec<BlocklistId>,
    #[serde(default)]
    pub auto_ban: AutoBanSettings,
}

// ---------------------------------------------------------------------------------------------
// IP blocklists and bans
// ---------------------------------------------------------------------------------------------

/// `POST /v1/blocklists/preview` with a JSON body: download a URL source (through the Provider
/// egress) and preview it. A text body previews uploaded or pasted text instead.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct BlocklistUrlPreview {
    pub url: String,
}

/// Where a previewed URL source was downloaded from, and through which connection.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlocklistFetch {
    /// The URL the content came from (after same-origin redirects).
    pub url: String,
    pub bytes: u32,
    pub content_type: Option<String>,
    /// The Provider egress connection that carried the download.
    pub via_instance_id: InstanceId,
    #[ts(type = "number")]
    pub via_generation: u64,
}

/// What a preview found; nothing is stored. A commit must name `import_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlocklistPreview {
    /// SHA-256 of the compiled content.
    pub import_hash: String,
    pub stats: BlocklistStats,
    /// The first ranges after merging (an address, a CIDR or `first – last`).
    pub sample: Vec<String>,
    /// The first invalid lines (at most 50; `stats.invalid` counts all).
    pub invalid_lines: Vec<InvalidLine>,
    /// Why this content cannot be saved (e.g. no valid entries); empty when it can.
    pub problems: Vec<Text>,
    pub fetched: Option<BlocklistFetch>,
}

/// `POST /v1/blocklists`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct BlocklistInput {
    pub name: String,
    pub source: BlocklistSource,
    /// The list text of an upload source; a URL source is downloaded again by the server.
    #[serde(default)]
    pub text: Option<String>,
    /// `import_hash` of the preview the user accepted: different content is refused.
    pub expected_import_hash: String,
}

/// `PUT /v1/blocklists/{id}` (If-Match).
///
/// New content only with `expected_import_hash` (and the `text` of an upload source); otherwise
/// only the name and source settings change. A built-in list keeps its URL (its interval and name
/// can change).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct BlocklistUpdate {
    pub name: String,
    pub source: BlocklistSource,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub expected_import_hash: Option<String>,
    /// Enable or disable the list (see `Blocklist::enabled`). Omitted: unchanged.
    #[serde(default)]
    #[ts(optional)]
    pub enabled: Option<bool>,
}

/// What the catalogue says about a built-in list (`builtin_blocklists::BUILTIN_BLOCKLISTS`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BuiltinBlocklistInfo {
    pub key: String,
    pub name: Text,
    pub url: String,
    pub homepage: String,
    pub family: BlocklistFamily,
    pub format: BlocklistFormat,
    pub refresh_hours: u32,
    pub description: Text,
    pub terms: Text,
    pub terms_url: String,
}

impl From<&crate::builtin_blocklists::BuiltinBlocklist> for BuiltinBlocklistInfo {
    fn from(b: &crate::builtin_blocklists::BuiltinBlocklist) -> Self {
        Self {
            key: b.key.into(),
            name: b.name(),
            url: b.url.into(),
            homepage: b.homepage.into(),
            family: b.family,
            format: b.format,
            refresh_hours: b.refresh_hours,
            description: b.description(),
            terms: b.terms(),
            terms_url: b.terms_url.into(),
        }
    }
}

/// `GET /v1/blocklists/builtin`: each built-in list and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BuiltinBlocklistState {
    pub info: BuiltinBlocklistInfo,
    /// The list created from it; `None` once the user deleted it (it is never created again on
    /// its own; `POST /v1/blocklists/builtin/{key}/restore` brings it back).
    pub blocklist_id: Option<BlocklistId>,
    pub deleted_at: Option<Timestamp>,
}

/// The latest refresh attempt of a URL source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlocklistRefreshState {
    pub attempted_at: Timestamp,
    pub ok: bool,
    /// Success: whether the content changed. Failure: why (the last good content stays).
    pub message: Option<Text>,
    pub succeeded_at: Option<Timestamp>,
    /// Since when refreshes fail.
    pub stale_since: Option<Timestamp>,
}

/// An entity named in a view (`id` and display name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NamedRef {
    pub id: String,
    pub name: String,
}

/// `GET /v1/blocklists`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlocklistView {
    pub blocklist: Blocklist,
    pub refresh: Option<BlocklistRefreshState>,
    /// The latest refresh failed: the content is the last good one (a list still awaiting its
    /// first content has none).
    pub stale: bool,
    /// When the next automatic refresh is due (`None` without automatic refresh, or disabled).
    pub next_refresh_at: Option<Timestamp>,
    /// Security profiles that use the list.
    pub used_by: Vec<NamedRef>,
    /// The catalogue entry of a built-in list.
    #[serde(default)]
    pub builtin: Option<BuiltinBlocklistInfo>,
    /// Part of the default security policy: every connection without a security profile
    /// enforces it (an enabled built-in list).
    #[serde(default)]
    pub default_policy: bool,
    /// No content downloaded yet: the list enforces nothing until its first download.
    #[serde(default)]
    pub awaiting_content: bool,
    /// Why an enabled URL list cannot be downloaded right now (no usable Provider egress
    /// connection); it is downloaded once there is one. `None` when it can be.
    #[serde(default)]
    pub waiting: Option<Text>,
}

/// Port forwards of one connection. Auto-ban only acts on forwarded inbound connections.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InboundCount {
    pub instance_id: InstanceId,
    pub forward_bindings: u32,
    pub enabled: u32,
}

/// `GET /v1/security/inbound`: what inbound traffic auto-ban can see at all.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InboundSummary {
    pub instances: Vec<InboundCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct InstanceInput {
    pub name: String,
    pub profile_id: ProfileId,
    #[serde(default)]
    pub dns_profile_id: Option<DnsProfileId>,
    #[serde(default)]
    pub security_profile_id: Option<SecurityProfileId>,
    #[serde(default)]
    pub limits: Option<InstanceLimits>,
    /// Linux strict mode (see `InstanceSpec::strict`). Omitted: `false` on create, unchanged on
    /// update.
    #[serde(default)]
    #[ts(optional)]
    pub strict: Option<bool>,
    /// The transport profile (see `InstanceSpec::transport`). Omitted: the built-in automatic
    /// one on create, unchanged on update.
    #[serde(default)]
    #[ts(optional)]
    pub transport: Option<TransportRef>,
}

/// `POST /v1/transport-profiles`, `PUT /v1/transport-profiles/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct TransportProfileInput {
    pub name: String,
    /// Omitted: the values every connection had before transport profiles existed.
    #[serde(default = "default_health")]
    pub health: HealthSettings,
    pub settings: TransportSettings,
}

const fn default_health() -> HealthSettings {
    HealthSettings::DEFAULT
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct GatewayInput {
    pub instance_id: InstanceId,
    pub name: String,
    pub kind: GatewayKind,
    pub port: u16,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub udp: bool,
    #[serde(default = "default_gateway_connections")]
    pub max_connections: u32,
}

const fn yes() -> bool {
    true
}
const fn default_gateway_connections() -> u32 {
    256
}

/// `POST /v1/apps`, `PUT /v1/apps/{id}`. The approval of the executable is the server's: it is
/// recorded when the App is created or its executable path changes.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct AppInput {
    pub instance_id: InstanceId,
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    pub isolation: AppIsolation,
    #[serde(default)]
    pub gateway_id: Option<GatewayId>,
    #[serde(default)]
    pub restart_on_recovery: bool,
    #[serde(default)]
    pub writable_paths: Vec<String>,
    /// The SHA-256 the user saw for `executable` (from the executable check). When given and
    /// the file now differs, saving is refused instead of approving a file nobody looked at.
    #[serde(default)]
    pub executable_sha256: Option<String>,
    #[serde(default)]
    pub limits: AppLimits,
    /// `strict_netns` only: sandbox ports published on this host.
    #[serde(default)]
    pub access_ports: Vec<AppAccessPort>,
    /// `strict_netns` only: write only under `writable_paths`, the private home and temporary
    /// directory and `/dev`. Omitted: off for a new App, unchanged for an existing one.
    #[serde(default)]
    #[ts(optional)]
    pub confine_writes: Option<bool>,
    /// Seconds to exit after SIGTERM before the App is killed. Omitted: 10 for a new App,
    /// unchanged for an existing one.
    #[serde(default)]
    #[ts(optional)]
    pub stop_grace_secs: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AppAction {
    Start,
    Stop,
    Restart,
    /// Approve the executable as it is now (its SHA-256 must be the one the user saw).
    Approve,
}

/// `POST /v1/apps/{id}/actions`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct AppActionRequest {
    pub action: AppAction,
    /// `approve`: the SHA-256 shown to the user.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Answer of an App action: the recorded operation and the App's status after it.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppActionResult {
    pub operation: Operation,
    pub status: Option<AppStatus>,
}

/// One managed App with what the manager observes about it.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppView {
    pub spec: AppSpec,
    /// `None` while the manager is unreachable — never guessed.
    pub status: Option<AppStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ExecutableKind {
    File,
    /// A macOS `.app` bundle: its main executable (from `Contents/Info.plist`) runs.
    AppBundle,
}

/// `GET /v1/apps/executable-check?path=`: whether a path can be approved, and what would run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ExecutableCheck {
    pub path: String,
    pub kind: Option<ExecutableKind>,
    /// The file that runs (symlinks resolved).
    pub resolved: Option<String>,
    pub sha256: Option<String>,
    #[ts(type = "number | null")]
    pub size: Option<u64>,
    /// Errors make the path unusable; warnings are notes.
    pub issues: Vec<crate::validation::Issue>,
    pub ok: bool,
    /// A browser (started with a data directory of its own), a macOS app or a launcher; `None`
    /// for an ordinary program.
    #[serde(default)]
    pub app_class: Option<AppClassInfo>,
}

/// `POST /v1/forward-bindings`, `PUT /v1/forward-bindings/{id}`. The assignment source is the
/// server's: every binding entered here is `manual` (never verified by a provider).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ForwardInput {
    pub instance_id: InstanceId,
    pub name: String,
    pub protocol: ForwardProtocol,
    /// The provider's "local port": where inbound traffic reaches the tunnel address.
    pub tunnel_port: u16,
    /// The public port the provider reserved (shown only).
    #[serde(default)]
    pub public_port: Option<u16>,
    pub target_app_id: AppId,
    pub target_port: u16,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "crate::config::default_forward_connections")]
    pub max_connections: u32,
    /// Start every forwarded TCP connection with a PROXY protocol v2 header (see
    /// `ForwardBinding::proxy_protocol`); off when left out. Refused for a UDP-only forward.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Take the UDP straight into the strict sandbox, to the App's own socket (see
    /// `ForwardBinding::udp_direct`); off when left out. Refused without UDP, on a connection or
    /// App that is not strict, and when the App's port is not the tunnel port.
    #[serde(default)]
    pub udp_direct: bool,
}

/// One port forward with what the manager observes about it.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardView {
    pub binding: ForwardBinding,
    /// `None` while the manager is unreachable — never guessed.
    pub status: Option<ForwardStatus>,
}

/// `GET /v1/ports/free?from=<port>`: a loopback port a new Gateway can take right now.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FreePort {
    pub port: u16,
}

/// Editable fields of a profile (keys, endpoint and addresses come only from an import or a
/// provider and are not edited by hand).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ProfileUpdate {
    pub name: String,
    pub location: Option<ProfileLocation>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

// ---------------------------------------------------------------------------------------------
// WireGuard configuration import
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ImportMode {
    /// Parse only; nothing is stored.
    Preview,
    /// Store the secrets and create the profile.
    Commit,
}

/// `POST /v1/profiles/import`. `config` is the `WireGuard` `.conf` text and contains a private
/// key: it is parsed in memory and never stored or echoed.
#[derive(Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ImportRequest {
    pub mode: ImportMode,
    pub name: String,
    pub config: String,
    #[serde(default)]
    pub provider: Option<ProviderKind>,
    #[serde(default)]
    pub location: Option<ProfileLocation>,
}

impl std::fmt::Debug for ImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportRequest")
            .field("mode", &self.mode)
            .field("name", &self.name)
            .field("config", &"<redacted>")
            .field("provider", &self.provider)
            .field("location", &self.location)
            .finish()
    }
}

/// Public part of a parsed configuration.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ImportCandidate {
    pub public_key: WgKey,
    #[ts(type = "Array<string>")]
    pub addresses: Vec<IpNetwork>,
    #[ts(type = "Array<string>")]
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub peer_public_key: WgKey,
    #[ts(type = "string")]
    pub endpoint: SocketAddr,
    #[ts(type = "Array<string>")]
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
    pub has_preshared_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ImportResult {
    pub candidate: Option<ImportCandidate>,
    pub report: ValidationReport,
    /// Present after a successful commit.
    pub profile: Option<RuntimeProfile>,
}

// ---------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub name: String,
    pub provider: ProviderKind,
    /// Where the exit is.
    pub location: Option<ProfileLocation>,
    /// Where the tunnel enters, when not at the exit server's default entry (`ProfileSource`).
    #[serde(default)]
    pub entry: Option<ProfileEntry>,
    pub endpoint: String,
    pub ipv6: bool,
    #[ts(type = "number")]
    pub revision: Revision,
}

/// Everything the workbench shows for one Instance in one object.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InstanceView {
    pub spec: InstanceSpec,
    /// `None` while the manager is unreachable — never guessed.
    pub status: Option<InstanceStatus>,
    pub profile: Option<ProfileSummary>,
    pub gateways: Vec<GatewaySpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
    ClearEmergency,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct LifecycleRequest {
    pub action: LifecycleAction,
}

/// 202 body of lifecycle actions and emergency stop.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Accepted {
    pub operation: Operation,
    /// For stops: the data path is closed.
    pub sealed: Option<bool>,
    /// For stops: the stop latch is on disk (false = pending; retried).
    pub durable: Option<bool>,
}

/// Live rates derived from the last two worker samples (bits per second).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LiveRates {
    pub instance_id: InstanceId,
    pub at: Timestamp,
    #[ts(type = "number")]
    pub generation: u64,
    /// Payload: what the Gateways carried for their clients, plus what the port forwards relayed
    /// to and from the Apps and (strict mode) what the Apps of the sandbox carried (`sandbox`,
    /// the forwards included there).
    pub payload_rx_bps: f64,
    pub payload_tx_bps: f64,
    pub wg_rx_bps: f64,
    pub wg_tx_bps: f64,
    pub active_tcp: u32,
    pub active_udp: u32,
    pub cpu_core_pct: Option<f64>,
    pub rss_bytes: Option<f64>,
    pub gateways: Vec<GatewayRates>,
    /// What the bandwidth caps did over the same interval; null when the worker did not report
    /// it in both samples.
    #[serde(default)]
    pub shaping: Option<ShapingRates>,
    /// Strict mode: the Apps of the connection's sandbox (already part of `payload_*`). Null for
    /// a connection without a sandbox — there is nothing to count, which is not 0.
    #[serde(default)]
    pub sandbox: Option<SandboxRates>,
}

/// The Apps of a strict sandbox over one sample interval.
///
/// Every App of the connection that runs in strict isolation shares the sandbox, so these are
/// their sum: their own flows and the connections forwarded to them (a strict connection's
/// forwards all end in the sandbox).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SandboxRates {
    /// Their payload from the remote hosts (bit/s): the TCP segment and UDP payload of their own
    /// flows as it crosses the sandbox's TUN device (retransmissions included), plus what the
    /// port forwards delivered to them; the worker's other flows are not in it.
    pub rx_bps: f64,
    /// The same towards the remote hosts.
    pub tx_bps: f64,
    /// Their own flows tracked at the later sample (forwarded connections are the forwards').
    pub active_tcp: u32,
    pub active_udp: u32,
    /// This generation so far: flows the remote end had not answered, dropped from a full flow
    /// table to make room, and new flows refused because a table was full of answered ones.
    #[ts(type = "number")]
    pub evicted: u64,
    #[ts(type = "number")]
    pub table_full: u64,
    /// Each App's part of `rx_bps`/`tx_bps`: its own flows (told apart by the ports its
    /// processes hold) and the port forwards that end at it. Payload of a connection the App
    /// supervisor had not seen yet is in the totals only, so the parts may sum to less. An App
    /// with no rate this time (it just started, or its counter went back) is missing.
    #[serde(default)]
    pub apps: Vec<AppRates>,
}

/// One managed App's payload over one sample interval (bit/s).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppRates {
    pub app_id: AppId,
    /// From the remote hosts to the App.
    pub rx_bps: f64,
    /// From the App to the remote hosts.
    pub tx_bps: f64,
}

/// The bandwidth caps of a connection over one sample interval. A share or rate is null where
/// there is no cap or a counter went backwards — never a made-up 0.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ShapingRates {
    /// The caps in force at the later sample (bits per second; null = no cap).
    #[ts(type = "number | null")]
    pub download_bps: Option<u64>,
    #[ts(type = "number | null")]
    pub upload_bps: Option<u64>,
    /// Share of the interval (0–1) during which download payload waited for its cap.
    pub download_limited: Option<f64>,
    pub upload_limited: Option<f64>,
    /// UDP datagrams dropped per second because the cap was reached.
    pub download_dropped_per_sec: Option<f64>,
    pub upload_dropped_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GatewayRates {
    pub gateway_id: GatewayId,
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// The part of `rx_bps`/`tx_bps` relayed for SSH sessions through this Gateway (「SSH
    /// 代理」): TCP connections to port 22, or marked as SSH by the client (`vpnctl ssh-proxy`),
    /// VPN Manager's own SSH downloads excluded. Only the class sums are measured, nothing per
    /// destination.
    #[serde(default)]
    pub ssh_rx_bps: f64,
    #[serde(default)]
    pub ssh_tx_bps: f64,
    /// The part relayed for VPN Manager's own SSH downloads (「SSH 下載」), whatever their port;
    /// never also in `ssh_*`.
    #[serde(default)]
    pub ssh_pull_rx_bps: f64,
    #[serde(default)]
    pub ssh_pull_tx_bps: f64,
    /// SSH sessions open through this Gateway at the later sample.
    #[serde(default)]
    pub ssh_sessions: u32,
    pub active_tcp: u32,
    pub active_udp: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SecretMetadata {
    pub secret_ref: SecretRef,
    pub kind: String,
    pub label: Option<String>,
    pub public_fingerprint: Option<String>,
    pub created_at: Timestamp,
}

/// Server-sent events, one JSON object per `data:` line; `type` matches the SSE event name.
// A wire message, published once and then shared behind an `Arc`: boxing the large variant
// would only add an allocation.
#[expect(
    clippy::large_enum_variant,
    reason = "an event is built, sent and dropped once; it is never stored in bulk, so boxing a variant saves nothing"
)]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum ServerEvent {
    InstanceStatus {
        status: InstanceStatus,
    },
    LiveRates {
        rates: LiveRates,
    },
    AppStatus {
        status: AppStatus,
    },
    ForwardStatus {
        status: ForwardStatus,
    },
    EntityChanged {
        kind: String,
        id: String,
        action: String,
    },
    ManagerConnection {
        connected: bool,
    },
    /// An SSH download job's status (at most one per job and second).
    SshDownloadStatus {
        status: crate::ssh_download::SshDownloadStatus,
    },
    /// The client fell behind or the server restarted: reload snapshots.
    ResyncRequired,
}

/// `POST /v1/ssh-hosts`, `PUT /v1/ssh-hosts/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct SshHostInput {
    pub kind: SshHostKind,
    pub alias: String,
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    #[serde(default)]
    pub identities_only: bool,
    pub gateway_id: Option<GatewayId>,
    pub server_alive_interval: Option<u32>,
}

/// Where the `Include ~/.ssh/vpn-manager.conf` line stands in `~/.ssh/config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshIncludeState {
    /// First directive (only comments before it): our entries take effect.
    Present,
    /// Present, but after other settings or Includes: those may win, so overlays could
    /// connect directly.
    Late,
    /// Not in the file.
    Missing,
    /// `~/.ssh/config` does not exist.
    NoConfig,
    /// Not usable (see `config_problem`): never edited.
    Unsafe,
}

/// State of the generated `~/.ssh/vpn-manager.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SshFileState {
    /// Exactly what VPN Manager last wrote.
    Ok,
    /// Not written yet.
    Absent,
    /// Changed by someone else since VPN Manager wrote it: never overwritten silently.
    Modified,
    /// Symlink, foreign owner or writable by others: never written.
    Unsafe,
}

/// A host block of the user's own `~/.ssh/config` (read only).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshExistingHost {
    /// The `Host` patterns of the block, as written.
    pub patterns: Vec<String>,
    pub host_name: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// The block already sets `ProxyJump` or `ProxyCommand` (an overlay replaces it).
    pub proxied: bool,
    /// Any pattern contains `*`, `?` or `!` (cannot be overlaid).
    pub wildcard: bool,
    /// 1-based line of the `Host` keyword.
    pub line: u32,
}

/// `GET /v1/ssh`: the SSH Manager as seen from the files on disk.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshStatus {
    /// Whether entries can be applied at all; `unavailable_reason` says why not.
    pub available: bool,
    pub unavailable_reason: Option<Text>,
    /// Display paths (e.g. `~/.ssh`).
    pub ssh_dir: String,
    pub managed_path: String,
    /// The exact line `~/.ssh/config` needs first.
    pub include_line: String,
    pub include: SshIncludeState,
    /// `~/.ssh/config` is a symlink (a dotfiles setup): read through it, never edited, so the
    /// Include line is added by hand.
    pub config_linked: bool,
    /// Why `~/.ssh/config` cannot be used, when `include` is `unsafe`.
    pub config_problem: Option<Text>,
    pub file: SshFileState,
    /// What is stored is not what the file says yet (it was modified, a write failed, or the
    /// user's own config changed what an overlay covers).
    pub pending: bool,
    pub existing: Vec<SshExistingHost>,
    /// What VPN Manager writes for the current entries.
    pub preview: String,
    /// How a VPN-routed block is written, with `{port}` for the Gateway port (for previews).
    pub proxy_command: Option<String>,
    pub control_path: Option<String>,
    /// The file's current text when it was modified by someone else (at most 64 KiB).
    pub current_text: Option<String>,
    pub last_error: Option<Text>,
}

/// `POST /v1/ssh/include`, `/v1/ssh/overwrite` and `/v1/ssh/apply`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshActionResult {
    pub status: SshStatus,
    /// The backup made before the change (a file name in the SSH directory).
    pub backup: Option<String>,
}

/// `POST /v1/ssh-hosts/{id}/test`: a SOCKS5 CONNECT through the Gateway and the server's SSH
/// banner (no authentication).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshTestResult {
    pub ok: bool,
    #[ts(type = "number | null")]
    pub latency_ms: Option<u64>,
    pub banner: Option<String>,
    pub error: Option<Text>,
}
