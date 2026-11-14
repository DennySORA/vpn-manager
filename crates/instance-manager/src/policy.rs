//! Security policy on the manager side.
//!
//! It covers compiling a connection's blocklists into its overlay,
//! the addresses a connection itself needs, and refusing a save that would make a blocklist cover
//! one of them (or make the compiled overlay too large).
//!
//! A connection needs its `WireGuard` peer endpoint and its DNS servers. Neither goes through the
//! payload policy (the underlay and the DNS controller's own flows are not payload), so a
//! blocklist naming them could not be honoured for them: instead of silently exempting the user's
//! rule, the save is refused with a conflict that names the list, the connection and the address.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use vpn_domain::blocklist::MAX_PARSED_BYTES;
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::{
    ApiError, AppliedBlocklist, Blocklist, BlocklistId, DnsProfile, DnsProfileId, DnsServer,
    ErrorCode, FieldError, InstanceId, InstanceSpec, ProfileId, RuntimeProfile, SecurityProfile,
    SecurityProfileId, Text, tr,
};
use vpn_store::{Store, StoreError};

/// Something a connection needs to reach that a blocklist must not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedKind {
    Endpoint,
    Dns,
}

impl NeedKind {
    #[must_use]
    pub fn label(self) -> Text {
        match self {
            Self::Endpoint => tr!("WireGuard peer", "WireGuard 對端", "WireGuard ピア"),
            Self::Dns => tr!("DNS server", "DNS 伺服器", "DNS サーバー"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Need {
    pub ip: IpAddr,
    pub kind: NeedKind,
}

/// The address a DNS server is reached at.
#[must_use]
pub const fn dns_address(s: &DnsServer) -> IpAddr {
    match s {
        DnsServer::Udp { address }
        | DnsServer::Tcp { address }
        | DnsServer::Tls { address, .. }
        | DnsServer::Https { address, .. } => address.ip(),
    }
}

/// What a connection with this configuration needs: its peer endpoint and its DNS servers (the
/// DNS profile's, or the profile's own resolvers without one).
#[must_use]
pub fn needs(profile: &RuntimeProfile, dns: Option<&DnsProfile>) -> Vec<Need> {
    let mut out = vec![Need {
        ip: profile.peer.endpoint.ip().to_canonical(),
        kind: NeedKind::Endpoint,
    }];
    let servers: Vec<IpAddr> = dns.map_or_else(
        || profile.interface.dns.clone(),
        |d| d.servers.iter().map(dns_address).collect(),
    );
    for ip in servers {
        let need = Need {
            ip: ip.to_canonical(),
            kind: NeedKind::Dns,
        };
        if !out.contains(&need) {
            out.push(need);
        }
    }
    out
}

/// A security profile's blocklists compiled into one overlay.
#[derive(Debug)]
pub struct Compiled {
    /// Each list and its content (for naming the one that conflicts).
    pub lists: Vec<(AppliedBlocklist, IpRangeSet)>,
    /// Their union: what the worker enforces.
    pub set: IpRangeSet,
    pub digest: String,
    /// Addresses the connection needs that a built-in list covers: left out of its overlay
    /// (the list's name and the need).
    pub exempt: Vec<(String, Need)>,
    /// The lists among `lists` that are the user's own (not built in).
    pub user_lists: HashSet<BlocklistId>,
}

impl Compiled {
    #[must_use]
    pub fn applied(&self) -> Vec<AppliedBlocklist> {
        self.lists.iter().map(|(a, _)| a.clone()).collect()
    }

    /// The first list covering an address the connection needs.
    #[must_use]
    pub fn conflict<'a>(&'a self, needs: &'a [Need]) -> Option<(&'a AppliedBlocklist, &'a Need)> {
        self.lists.iter().find_map(|(list, set)| {
            needs
                .iter()
                .find(|n| set.contains(n.ip))
                .map(|need| (list, need))
        })
    }

    /// The first list of the user's own that covers `ip`.
    #[must_use]
    pub fn user_list_covering(&self, ip: IpAddr) -> Option<&AppliedBlocklist> {
        self.lists
            .iter()
            .find(|(list, set)| self.user_lists.contains(&list.id) && set.contains(ip))
            .map(|(list, _)| list)
    }

    /// Same lists with the same content.
    #[must_use]
    pub fn same_as(&self, lists: &[AppliedBlocklist], digest: &str) -> bool {
        self.digest == digest
            && self.lists.len() == lists.len()
            && self
                .lists
                .iter()
                .zip(lists)
                .all(|((a, _), b)| a.id == b.id && a.content_sha256 == b.content_sha256)
    }
}

#[derive(Debug)]
pub enum CompileError {
    Store(StoreError),
    /// A list the profile names is gone or has no content.
    Missing(BlocklistId),
    /// The union is larger than a worker may hold.
    TooLarge,
}

impl CompileError {
    #[must_use]
    pub fn message(&self) -> Text {
        match self {
            Self::Store(e) => e.to_api().message,
            Self::Missing(id) => tr!(
                "The IP blocklist {id} that the security profile uses does not exist or has no content",
                "安全設定使用的 IP 封鎖清單 {id} 不存在或沒有內容",
                "セキュリティ設定が使う IP ブロックリスト {id} は存在しないか、内容がありません"
            ),
            Self::TooLarge => {
                let mib = MAX_PARSED_BYTES / 1024 / 1024;
                tr!(
                    "The merged IP blocklists exceed the {mib} MiB limit",
                    "合併後的 IP 封鎖清單超過 {mib} MiB 上限",
                    "統合した IP ブロックリストが上限の {mib} MiB を超えています"
                )
            }
        }
    }
}

impl From<StoreError> for CompileError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Say which needed addresses built-in lists cover (left out of the connection's overlay).
pub fn log_exempt(exempt: &[(String, Need)]) {
    for (list, need) in exempt {
        tracing::info!(
            list = %list,
            ip = %need.ip,
            need = %need.kind.label().en,
            "a built-in blocklist covers an address this connection needs: left out of its overlay"
        );
    }
}

/// Compile the current content of the blocklists a connection with `security` enforces.
///
/// That is the profile's selection, or without one the default policy's built-in lists
/// (`blocklist::effective_lists`). Disabled lists and lists still awaiting their first content
/// are left out (they enforce nothing). A built-in list deleted while this ran is skipped; a
/// profile's list that is gone is an error.
///
/// A built-in list never covers what the connection `needs` (its `WireGuard` endpoint, its DNS
/// servers): its content comes from its source, which may list a VPN server's address, so those
/// addresses are left out of this connection's overlay (`Compiled::exempt`) instead of refusing
/// the list or the start. A list of the user's that covers one is still a conflict.
///
/// # Errors
///
/// A Store error, or a list of the profile's selection that is gone.
pub async fn compile(
    store: &Store,
    security: Option<&SecurityProfile>,
    needs: &[Need],
) -> Result<Compiled, CompileError> {
    let all: Vec<Blocklist> = store.list().await?;
    let mut lists = Vec::new();
    let mut exempt = Vec::new();
    let mut user_lists = HashSet::new();
    for id in vpn_domain::blocklist::effective_lists(security, &all) {
        let found = all.iter().find(|l| l.id == id);
        let set = match found {
            Some(_) => store.blocklist_set(id).await?,
            None => None,
        };
        let (Some(list), Some(set)) = (found, set) else {
            if security.is_none() {
                continue;
            }
            return Err(CompileError::Missing(id));
        };
        if list.awaiting_content() {
            continue;
        }
        let covered: Vec<&Need> = if list.builtin.is_some() {
            needs.iter().filter(|n| set.contains(n.ip)).collect()
        } else {
            user_lists.insert(id);
            Vec::new()
        };
        let set = if covered.is_empty() {
            set
        } else {
            let ips: Vec<IpAddr> = covered.iter().map(|n| n.ip).collect();
            exempt.extend(covered.into_iter().map(|n| (list.name.clone(), *n)));
            set.without(&ips)
        };
        lists.push((
            AppliedBlocklist {
                id,
                name: list.name.clone(),
                content_sha256: list.content_sha256.clone(),
            },
            set,
        ));
    }
    let set = IpRangeSet::union(lists.iter().map(|(_, s)| s));
    if set.encoded_len() > MAX_PARSED_BYTES {
        return Err(CompileError::TooLarge);
    }
    let digest = set.digest();
    Ok(Compiled {
        lists,
        set,
        digest,
        exempt,
        user_lists,
    })
}

/// What a running generation pinned: the security profile whose blocklists it follows, and the
/// addresses it was started with.
#[derive(Debug, Clone)]
pub struct RunningPolicy {
    pub instance_name: String,
    pub security_id: Option<SecurityProfileId>,
    pub needs: Vec<Need>,
}

/// A save to check before it is written.
#[derive(Debug)]
pub enum Proposal<'a> {
    Security(&'a SecurityProfile),
    /// A blocklist's new revision (content, name, enabled); `set` is its new content, `None`
    /// when the content stays.
    Blocklist {
        list: &'a Blocklist,
        set: Option<&'a IpRangeSet>,
    },
    Instance(&'a InstanceSpec),
    Profile(&'a RuntimeProfile),
    Dns(&'a DnsProfile),
}

fn conflict_error(path: String, message: impl Into<Text>) -> ApiError {
    let message = message.into();
    ApiError::new(ErrorCode::PolicyConflict, message.clone()).with_fields(vec![FieldError {
        path,
        code: "BLOCKLIST_CONFLICT".into(),
        message,
    }])
}

/// The policy a connection follows: its security profile, or the default policy (`None`).
type PolicyKey = Option<SecurityProfileId>;

/// Everything the check reads, with the proposal applied.
struct World {
    instances: Vec<InstanceSpec>,
    security: HashMap<SecurityProfileId, SecurityProfile>,
    profiles: HashMap<ProfileId, RuntimeProfile>,
    dns: HashMap<DnsProfileId, DnsProfile>,
    lists: HashMap<BlocklistId, Blocklist>,
    sets: HashMap<BlocklistId, IpRangeSet>,
}

impl World {
    async fn load(store: &Store) -> Result<Self, StoreError> {
        Ok(Self {
            instances: store.list::<InstanceSpec>().await?,
            security: store
                .list::<SecurityProfile>()
                .await?
                .into_iter()
                .map(|s| (s.id, s))
                .collect(),
            profiles: store
                .list::<RuntimeProfile>()
                .await?
                .into_iter()
                .map(|p| (p.id, p))
                .collect(),
            dns: store
                .list::<DnsProfile>()
                .await?
                .into_iter()
                .map(|d| (d.id, d))
                .collect(),
            lists: store
                .list::<Blocklist>()
                .await?
                .into_iter()
                .map(|b| (b.id, b))
                .collect(),
            sets: HashMap::new(),
        })
    }

    fn apply(&mut self, proposal: &Proposal<'_>) {
        match proposal {
            Proposal::Security(s) => {
                self.security.insert(s.id, (*s).clone());
            }
            Proposal::Blocklist { list, set } => {
                self.lists.insert(list.id, (*list).clone());
                if let Some(set) = set {
                    self.sets.insert(list.id, (*set).clone());
                }
            }
            Proposal::Instance(i) => {
                self.instances.retain(|x| x.id != i.id);
                self.instances.push((*i).clone());
            }
            Proposal::Profile(p) => {
                self.profiles.insert(p.id, (*p).clone());
            }
            Proposal::Dns(d) => {
                self.dns.insert(d.id, (*d).clone());
            }
        }
    }

    /// The lists a connection following `policy` enforces (`blocklist::effective_lists`), or
    /// `None` when its security profile is gone.
    fn effective(&self, policy: PolicyKey) -> Option<Vec<BlocklistId>> {
        let all: Vec<Blocklist> = self.lists.values().cloned().collect();
        policy.map_or_else(
            || Some(vpn_domain::blocklist::default_lists(&all)),
            |id| {
                self.security
                    .get(&id)
                    .map(|s| vpn_domain::blocklist::effective_lists(Some(s), &all))
            },
        )
    }

    /// What a policy is called in a message.
    fn policy_name(&self, policy: PolicyKey) -> Text {
        policy.and_then(|id| self.security.get(&id)).map_or_else(
            || {
                tr!(
                    "the default security policy",
                    "預設安全政策",
                    "既定のセキュリティポリシー"
                )
            },
            |s| {
                let name = &s.name;
                tr!(
                    "the security profile “{name}”",
                    "安全設定「{name}」",
                    "セキュリティ設定「{name}」"
                )
            },
        )
    }

    async fn set(&mut self, store: &Store, id: BlocklistId) -> Result<&IpRangeSet, ApiError> {
        Ok(match self.sets.entry(id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(
                store
                    .blocklist_set(id)
                    .await
                    .map_err(|e| e.to_api())?
                    .ok_or_else(|| {
                        ApiError::not_found(tr!(
                            "the content of the IP blocklist",
                            "IP 封鎖清單的內容",
                            "IP ブロックリストの内容"
                        ))
                    })?,
            ),
        })
    }

    /// The first of `lists` covering one of `needs`: its id, name and the address. Lists that
    /// are gone or still await their first content cover nothing, and a built-in list never
    /// conflicts (the connection's overlay leaves its needs out, see [`compile`]).
    async fn conflict(
        &mut self,
        store: &Store,
        lists: &[BlocklistId],
        needs: &[Need],
    ) -> Result<Option<(BlocklistId, String, Need)>, ApiError> {
        for id in lists {
            let Some(name) = self
                .lists
                .get(id)
                .filter(|l| !l.awaiting_content() && l.builtin.is_none())
                .map(|l| l.name.clone())
            else {
                continue;
            };
            let set = self.set(store, *id).await?;
            if let Some(need) = needs.iter().find(|n| set.contains(n.ip)) {
                return Ok(Some((*id, name, *need)));
            }
        }
        Ok(None)
    }

    /// The compiled size of `lists` is within what a worker may hold (an upper bound: the sum of
    /// the lists).
    fn size_ok(&self, lists: &[BlocklistId]) -> bool {
        let total: usize = lists
            .iter()
            .filter_map(|id| self.lists.get(id))
            .map(|l| l.stats.parsed_bytes as usize)
            .sum();
        total <= MAX_PARSED_BYTES
    }
}

/// Refuse `proposal` when, saved, it would break a connection's needs or a size limit.
///
/// That is: it would make a blocklist cover an address a connection needs
/// (with its stored configuration, or as a running generation started), or make a policy's
/// compiled blocklists too large. Connections without a security profile follow the default
/// policy, whose lists are the enabled built-in ones. Callers hold the manager's policy lock
/// across check and write.
///
/// # Errors
///
/// `ValidationFailed` when a policy's compiled lists would be too large, the conflict naming
/// the list, the connection and the address when a list would cover a need, or a Store error.
pub async fn check<S: std::hash::BuildHasher + Sync>(
    store: &Store,
    running: &HashMap<InstanceId, RunningPolicy, S>,
    proposal: Proposal<'_>,
) -> Result<(), ApiError> {
    let mut world = World::load(store).await.map_err(|e| e.to_api())?;
    world.apply(&proposal);

    // Policies whose overlay changes with this save: a profile's own, and the default policy
    // when a built-in list changes.
    let changed: HashSet<PolicyKey> = match &proposal {
        Proposal::Security(s) => HashSet::from([Some(s.id)]),
        Proposal::Blocklist { list, .. } => world
            .security
            .values()
            .filter(|s| s.blocklists.contains(&list.id))
            .map(|s| Some(s.id))
            .chain(list.builtin.is_some().then_some(None))
            .collect(),
        _ => HashSet::new(),
    };
    check_sizes(&world, &changed)?;

    // Stored configurations this save affects.
    let affected: Vec<InstanceSpec> = world
        .instances
        .iter()
        .filter(|i| match &proposal {
            Proposal::Security(_) | Proposal::Blocklist { .. } => {
                changed.contains(&i.security_profile_id)
            }
            Proposal::Instance(spec) => i.id == spec.id,
            Proposal::Profile(p) => i.profile_id == p.id,
            Proposal::Dns(d) => i.dns_profile_id == Some(d.id),
        })
        .cloned()
        .collect();
    for instance in &affected {
        let Some(lists) = world.effective(instance.security_profile_id) else {
            continue;
        };
        let Some(profile) = world.profiles.get(&instance.profile_id).cloned() else {
            continue;
        };
        let dns = instance
            .dns_profile_id
            .and_then(|d| world.dns.get(&d))
            .cloned();
        let needs = needs(&profile, dns.as_ref());
        if let Some((id, list, need)) = world.conflict(store, &lists, &needs).await? {
            let path = match &proposal {
                Proposal::Security(s) => format!(
                    "/blocklists/{}",
                    s.blocklists.iter().position(|b| *b == id).unwrap_or(0)
                ),
                Proposal::Blocklist { .. } => "/content".into(),
                Proposal::Instance(_) => "/security_profile_id".into(),
                Proposal::Profile(_) => "/peer/endpoint".into(),
                Proposal::Dns(d) => d
                    .servers
                    .iter()
                    .position(|s| dns_address(s).to_canonical() == need.ip)
                    .map_or_else(|| "/servers".into(), |i| format!("/servers/{i}/address")),
            };
            let remedy = if instance.security_profile_id.is_some() {
                tr!(
                    "remove this address from the list, or let this connection use another security profile",
                    "請從清單移除這個位址，或讓這條連線使用其他安全設定",
                    "リストからこのアドレスを削除するか、この接続で別のセキュリティ設定を使ってください"
                )
            } else {
                tr!(
                    "this connection follows the default security policy: turn this built-in list off, or let this connection use a security profile without it",
                    "這條連線使用預設安全政策；請停用這份內建清單，或讓這條連線使用不含它的安全設定",
                    "この接続は既定のセキュリティポリシーに従っています。この組み込みリストを無効にするか、この接続でこのリストを含まないセキュリティ設定を使ってください"
                )
            };
            let (name, ip) = (&instance.name, need.ip);
            return Err(conflict_error(
                path,
                tr!(
                    "The IP blocklist “{list}” contains {ip} ({what}), which the connection “{name}” needs, so it cannot be applied; {remedy}",
                    "IP 封鎖清單「{list}」包含連線「{name}」需要的 {ip}（{what}），不能套用；{remedy}",
                    "IP ブロックリスト「{list}」には、接続「{name}」が必要とする {ip}（{what}）が含まれているため、適用できません。{remedy}";
                    what = need.kind.label(),
                    remedy = remedy
                ),
            ));
        }
    }

    // Running generations follow their pinned policy's blocklists at once: check what they were
    // started with as well.
    check_running(store, &mut world, running, &changed, &proposal).await
}

/// [`check`]: no policy whose overlay changes compiles to more than a worker may hold.
fn check_sizes(world: &World, changed: &HashSet<PolicyKey>) -> Result<(), ApiError> {
    for policy in changed {
        if let Some(lists) = world.effective(*policy)
            && !world.size_ok(&lists)
        {
            let mib = MAX_PARSED_BYTES / 1024 / 1024;
            let message = tr!(
                "The merged IP blocklists of {policy} exceed the {mib} MiB limit",
                "{policy}的 IP 封鎖清單合併後超過 {mib} MiB 上限",
                "{policy}の IP ブロックリストを統合すると上限の {mib} MiB を超えます";
                policy = world.policy_name(*policy)
            );
            return Err(
                ApiError::new(ErrorCode::ValidationFailed, message.clone()).with_fields(vec![
                    FieldError {
                        path: "/blocklists".into(),
                        code: "BLOCKLISTS_TOO_LARGE".into(),
                        message,
                    },
                ]),
            );
        }
    }
    Ok(())
}

/// [`check`]: no running generation following a changed policy needs an address the saved
/// lists would cover.
async fn check_running<S: std::hash::BuildHasher + Sync>(
    store: &Store,
    world: &mut World,
    running: &HashMap<InstanceId, RunningPolicy, S>,
    changed: &HashSet<PolicyKey>,
    proposal: &Proposal<'_>,
) -> Result<(), ApiError> {
    for run in running.values() {
        if !changed.contains(&run.security_id) {
            continue;
        }
        let Some(lists) = world.effective(run.security_id) else {
            continue;
        };
        if let Some((id, list, need)) = world.conflict(store, &lists, &run.needs).await? {
            let path = match proposal {
                Proposal::Security(s) => format!(
                    "/blocklists/{}",
                    s.blocklists.iter().position(|b| *b == id).unwrap_or(0)
                ),
                _ => "/content".into(),
            };
            let (name, ip) = (&run.instance_name, need.ip);
            return Err(conflict_error(
                path,
                tr!(
                    "The IP blocklist “{list}” contains {ip} ({what}), which the running connection “{name}” needs, so it cannot be applied; remove this address from the list",
                    "IP 封鎖清單「{list}」包含執行中的連線「{name}」需要的 {ip}（{what}），不能套用；請從清單移除這個位址",
                    "IP ブロックリスト「{list}」には、実行中の接続「{name}」が必要とする {ip}（{what}）が含まれているため、適用できません。リストからこのアドレスを削除してください";
                    what = need.kind.label()
                ),
            ));
        }
    }
    Ok(())
}
