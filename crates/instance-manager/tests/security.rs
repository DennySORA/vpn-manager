//! Blocklists, conflicts and bans through the manager's RPC: a blocklist that covers an address a
//! connection needs (its `WireGuard` peer, a DNS server) is refused whichever save would introduce
//! it, with the list, the connection and the address named; nothing is written then. Bans are
//! listed and lifted.

#![cfg(test)]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use vpn_domain::ipset::IpRangeSet;
use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::policy::{self, Need, NeedKind, Proposal, RunningPolicy};
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_ipc::control::{Call, ControlClient, Entity, Reply};
use vpn_platform::paths::Paths;
use vpn_store::Store;
use zeroize::Zeroizing;

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn set(nets: &[&str]) -> IpRangeSet {
    IpRangeSet::from_networks(nets.iter().map(|n| n.parse().unwrap()))
}

/// The stored built-in list of catalogue entry `key`.
async fn builtin(store: &Store, key: &str) -> Blocklist {
    store
        .list::<Blocklist>()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.builtin.as_deref() == Some(key))
        .unwrap()
}

/// `list` as its first (or next) download leaves it: this content, counted.
fn downloaded(list: &Blocklist, content: &IpRangeSet) -> Blocklist {
    Blocklist {
        stats: BlocklistStats {
            entries: u32::try_from(content.len()).expect("fits"),
            parsed_bytes: u32::try_from(content.encoded_len()).expect("fits"),
            ..list.stats.clone()
        },
        content_sha256: content.digest(),
        ..list.clone()
    }
}

fn security(name: &str, blocklists: Vec<BlocklistId>) -> SecurityProfile {
    SecurityProfile {
        id: SecurityProfileId::new(),
        meta: meta(),
        name: name.into(),
        allow_private: Vec::new(),
        blocked_ports: Vec::new(),
        allowed_destinations: Vec::new(),
        allowed_ports: Vec::new(),
        blocklists,
        auto_ban: AutoBanSettings::default(),
    }
}

struct Lab {
    client: ControlClient,
    store: Arc<Store>,
    instance: InstanceSpec,
    office: SecurityProfile,
    _dir: tempfile::TempDir,
}

/// A manager with one stopped Instance: peer 198.51.100.7, the profile's resolver 10.64.0.1,
/// security profile "辦公室" without blocklists.
async fn lab() -> Lab {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([3u8; 32]), 1).unwrap());
    let key = store
        .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
        .await
        .unwrap();
    let profile = store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: "lab".into(),
            provider: ProviderKind::Generic,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: key.secret_ref,
                public_key: WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
                    .unwrap(),
                addresses: vec!["10.99.0.2/32".parse().unwrap()],
                dns: vec!["10.64.0.1".parse().unwrap()],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: WgKey::from_str("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
                    .unwrap(),
                preshared_key: None,
                endpoint: "198.51.100.7:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    let office = store.create(security("辦公室", Vec::new())).await.unwrap();
    let instance = store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "東京出口".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: Some(office.id),
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: TransportRef::default(),
        })
        .await
        .unwrap();
    let manager = Manager::start(
        store.clone(),
        std::env::current_exe().unwrap(),
        paths.clone(),
    )
    .await
    .unwrap();
    let sock = paths.manager_socket();
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        manager,
        store.clone(),
        SystemFacts {
            ssh: None,
            capabilities: vec![],
            performance: None,
        },
    ));
    Lab {
        client: ControlClient::connect(&sock).await.unwrap(),
        store,
        instance,
        office,
        _dir: dir,
    }
}

async fn put_list(
    c: &ControlClient,
    list: Blocklist,
    expected: Option<u64>,
    content: Option<IpRangeSet>,
) -> Result<BlocklistView, ApiError> {
    match c
        .call(Call::PutBlocklist {
            list: Box::new(list),
            expected_revision: expected,
            set: content,
        })
        .await?
    {
        Reply::Blocklist(v) => Ok(*v),
        other => panic!("{other:?}"),
    }
}

/// New content of a built-in list covering what the connection needs is taken: its source
/// decides what it lists (a VPN server's address may well be in it), so the connection's own
/// needs are left out of its overlay and everything else is enforced. The list as saved.
async fn assert_builtin_leaves_needs_out(lab: &Lab) -> Blocklist {
    let drop = builtin(&lab.store, "spamhaus-drop-v4").await;
    let worse = set(&["1.10.16.0/20", "198.51.100.0/24"]);
    let drop = put_list(
        &lab.client,
        downloaded(&drop, &worse),
        Some(drop.meta.revision),
        Some(worse),
    )
    .await
    .unwrap()
    .blocklist;
    let endpoint = [Need {
        ip: "198.51.100.7".parse().unwrap(),
        kind: NeedKind::Endpoint,
    }];
    let compiled = policy::compile(&lab.store, None, &endpoint).await.unwrap();
    assert!(!compiled.set.contains("198.51.100.7".parse().unwrap()));
    for listed in ["198.51.100.6", "198.51.100.8", "1.10.16.1"] {
        assert!(compiled.set.contains(listed.parse().unwrap()), "{listed}");
    }
    assert_eq!(compiled.exempt.len(), 1);
    assert!(compiled.conflict(&endpoint).is_none());
    drop
}

/// A disabled built-in list is out of the default policy; enabled again, it is back, the
/// connection's endpoint it covers left out.
async fn assert_disabled_builtin_is_out(lab: &Lab) {
    let dshield = builtin(&lab.store, "dshield-block").await;
    let peer = set(&["198.51.100.0/24"]);
    let off = put_list(
        &lab.client,
        Blocklist {
            enabled: false,
            ..downloaded(&dshield, &peer)
        },
        Some(dshield.meta.revision),
        Some(peer),
    )
    .await
    .unwrap();
    assert!(!off.default_policy && off.next_refresh_at.is_none());
    let compiled = policy::compile(&lab.store, None, &[]).await.unwrap();
    assert!(compiled.applied().iter().all(|a| a.id != dshield.id));
    let on = put_list(
        &lab.client,
        Blocklist {
            enabled: true,
            ..off.blocklist.clone()
        },
        Some(off.blocklist.meta.revision),
        None,
    )
    .await
    .unwrap();
    assert!(on.default_policy);
    let endpoint = [Need {
        ip: "198.51.100.7".parse().unwrap(),
        kind: NeedKind::Endpoint,
    }];
    let compiled = policy::compile(&lab.store, None, &endpoint).await.unwrap();
    assert!(compiled.applied().iter().any(|a| a.id == dshield.id));
    assert!(!compiled.set.contains("198.51.100.7".parse().unwrap()));
    assert!(compiled.set.contains("198.51.100.200".parse().unwrap()));
}

/// A running generation without a profile: new content of a built-in list never conflicts with
/// what it started with (its needs are left out of its overlay instead).
async fn assert_running_checked(lab: &Lab, instance: InstanceId, drop: &Blocklist) {
    let running = HashMap::from([(
        instance,
        RunningPolicy {
            instance_name: "東京出口".into(),
            security_id: None,
            needs: vec![Need {
                ip: "9.9.9.9".parse().unwrap(),
                kind: NeedKind::Dns,
            }],
        },
    )]);
    let quad9 = set(&["9.9.9.0/24"]);
    let proposal = downloaded(drop, &quad9);
    policy::check(
        &lab.store,
        &running,
        Proposal::Blocklist {
            list: &proposal,
            set: Some(&quad9),
        },
    )
    .await
    .unwrap();
}

/// The lab's connection without its security profile.
async fn leave_profile(lab: &Lab) -> InstanceSpec {
    match lab
        .client
        .call(Call::Update {
            entity: Entity::Instance(InstanceSpec {
                security_profile_id: None,
                ..lab.instance.clone()
            }),
            expected_revision: 1,
        })
        .await
        .unwrap()
    {
        Reply::Entity(e) => match *e {
            Entity::Instance(i) => i,
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_without_a_profile_follows_the_default_policy() {
    let lab = lab().await;
    let c = &lab.client;
    // The connection leaves its security profile: the default policy applies to it.
    let spec = leave_profile(&lab).await;

    // The built-in lists exist but wait for their first download: nothing is enforced yet. The
    // default policy runs auto-ban, on, with the default thresholds.
    let compiled = policy::compile(&lab.store, None, &[]).await.unwrap();
    assert!(compiled.lists.is_empty() && compiled.set.is_empty());
    let resolved = vpn_instance_manager::resolve::resolve(&lab.store, spec.id)
        .await
        .unwrap();
    assert!(resolved.worker.policy.auto_ban.enabled);
    assert_eq!(resolved.worker.policy.auto_ban, AutoBanSettings::default());
    assert_eq!(resolved.worker.policy.allow_private, []);

    // The first download of Spamhaus DROP applies to it.
    let drop = builtin(&lab.store, "spamhaus-drop-v4").await;
    let content = set(&["1.10.16.0/20"]);
    let view = put_list(
        c,
        downloaded(&drop, &content),
        Some(drop.meta.revision),
        Some(content),
    )
    .await
    .unwrap();
    assert!(view.default_policy && !view.awaiting_content);
    assert_eq!(
        view.builtin.as_ref().map(|b| b.key.as_str()),
        Some("spamhaus-drop-v4")
    );
    let compiled = policy::compile(&lab.store, None, &[]).await.unwrap();
    let applied: Vec<BlocklistId> = compiled.applied().iter().map(|a| a.id).collect();
    assert_eq!(applied, vec![drop.id]);
    assert!(compiled.set.contains("1.10.16.1".parse().unwrap()));
    // A custom profile enforces exactly its own selection; the office selected none.
    let office: SecurityProfile = lab
        .store
        .get(lab.office.id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        policy::compile(&lab.store, Some(&office), &[])
            .await
            .unwrap()
            .lists,
        []
    );

    // New content of a built-in list covering what the connection needs is taken, its needs
    // left out of its overlay.
    let drop = assert_builtin_leaves_needs_out(&lab).await;

    // A disabled built-in list is out of the default policy and may hold anything; enabling it
    assert_disabled_builtin_is_out(&lab).await;

    // A running generation without a profile is not held back by a built-in list's content.
    assert_running_checked(&lab, spec.id, &drop).await;

    // Deleted, a built-in list leaves the default policy at once; it is not created again.
    c.call(Call::DeleteBlocklist {
        id: drop.id,
        expected_revision: drop.meta.revision,
    })
    .await
    .unwrap();
    assert!(
        policy::compile(&lab.store, None, &[])
            .await
            .unwrap()
            .lists
            .iter()
            .all(|(a, _)| a.id != drop.id)
    );
    let states = match c.call(Call::BuiltinBlocklists).await.unwrap() {
        Reply::BuiltinBlocklists(v) => v,
        other => panic!("{other:?}"),
    };
    let gone = states
        .iter()
        .find(|s| s.info.key == "spamhaus-drop-v4")
        .unwrap();
    assert!(gone.blocklist_id.is_none() && gone.deleted_at.is_some());
    // Restored on request: a new list, waiting for its first download.
    let back = match c
        .call(Call::RestoreBuiltinBlocklist {
            key: "spamhaus-drop-v4".into(),
        })
        .await
        .unwrap()
    {
        Reply::Blocklist(v) => *v,
        other => panic!("{other:?}"),
    };
    assert!(back.awaiting_content && back.default_policy);
    assert!(back.next_refresh_at.is_some(), "due for its first download");
}

/// An update of `entity` through the RPC (its policy check included).
async fn update(c: &ControlClient, entity: Entity, expected_revision: u64) -> Entity {
    match c
        .call(Call::Update {
            entity,
            expected_revision,
        })
        .await
        .unwrap()
    {
        Reply::Entity(e) => *e,
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_users_list_keeps_its_addresses_out_of_the_dns_fallback() {
    let lab = lab().await;
    let c = &lab.client;
    // With a DNS profile, the WireGuard profile's resolver (10.64.0.1) is the fallback, asked
    // only while every server of the DNS profile fails.
    let dns = lab
        .store
        .create(DnsProfile {
            id: DnsProfileId::new(),
            meta: meta(),
            name: "加密 DNS".into(),
            servers: vec![DnsServer::Tls {
                address: "9.9.9.9:853".parse().unwrap(),
                server_name: "dns.quad9.net".into(),
            }],
            cache: DnsCacheSettings::default(),
            query_timeout_ms: 3000,
            attempts: 2,
            on_failure: DnsOnFailure::default(),
        })
        .await
        .unwrap();
    let with_dns = InstanceSpec {
        dns_profile_id: Some(dns.id),
        ..lab.instance.clone()
    };
    update(c, Entity::Instance(with_dns), 1).await;
    let fallback = || async {
        vpn_instance_manager::resolve::resolve(&lab.store, lab.instance.id)
            .await
            .unwrap()
            .worker
            .dns
            .fallback
    };
    let resolver = DnsServer::Udp {
        address: "10.64.0.1:53".parse().unwrap(),
    };
    assert_eq!(fallback().await, vec![resolver]);

    // A list of the user's covering it is no conflict (the connection does not need it), but
    // the fallback never reaches it: the DNS controller's flows would not pass the list.
    let inner = set(&["10.64.0.0/10"]);
    let blank = Blocklist {
        id: BlocklistId::new(),
        meta: meta(),
        name: "內網".into(),
        source: BlocklistSource::Upload,
        stats: BlocklistStats::default(),
        content_sha256: String::new(),
        content_updated_at: Timestamp::now(),
        invalid_lines: Vec::new(),
        builtin: None,
        enabled: true,
    };
    let list = put_list(c, downloaded(&blank, &inner), None, Some(inner))
        .await
        .unwrap()
        .blocklist;
    let office = SecurityProfile {
        blocklists: vec![list.id],
        ..lab.office.clone()
    };
    update(c, Entity::Security(office), lab.office.meta.revision).await;
    assert_eq!(fallback().await, Vec::new());
}
