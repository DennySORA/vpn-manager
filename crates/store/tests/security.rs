//! Security records: blocklists keep their content apart from their revisions and cannot be
//! deleted while a security profile uses them; URL refresh state; the overlay revision counter;
//! bans with their limit, renewal and expiry.

// Test fixtures: a failed setup step should panic right there.
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::assert_matches;
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::*;
use vpn_store::{Store, StoreError};
use zeroize::Zeroizing;

fn open(dir: &std::path::Path) -> Store {
    Store::open(dir, &Zeroizing::new([7u8; 32]), 1).unwrap()
}

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 0,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn set(nets: &[&str]) -> IpRangeSet {
    IpRangeSet::from_networks(nets.iter().map(|n| n.parse().unwrap()))
}

fn list(name: &str, content: &IpRangeSet) -> Blocklist {
    Blocklist {
        id: BlocklistId::new(),
        meta: meta(),
        name: name.into(),
        source: BlocklistSource::Upload,
        stats: BlocklistStats::default(),
        content_sha256: content.digest(),
        content_updated_at: Timestamp::now(),
        invalid_lines: Vec::new(),
        builtin: None,
        enabled: true,
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

#[tokio::test]
async fn a_blocklist_in_use_cannot_be_deleted_and_the_error_names_the_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path());
    let content = set(&["203.0.113.0/24"]);
    let bl = store
        .create_blocklist(list("drop", &content), content)
        .await
        .unwrap();
    // A profile cannot name a list that does not exist.
    assert_matches!(
        store
            .create(security("ghost", vec![BlocklistId::new()]))
            .await,
        Err(StoreError::InvalidState(_))
    );
    let office = store.create(security("辦公室", vec![bl.id])).await.unwrap();
    let lab = store.create(security("實驗室", vec![bl.id])).await.unwrap();
    let users = store.blocklist_users().await.unwrap();
    let names: Vec<&str> = users[&bl.id].iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, ["辦公室", "實驗室"]);

    match store.delete_blocklist(bl.id, 1).await {
        Err(StoreError::InUse(what)) => {
            assert_eq!(what.zh_tw, "安全設定「辦公室」、「實驗室」");
            assert_eq!(
                StoreError::InUse(what).to_api().message.zh_tw,
                "仍被安全設定「辦公室」、「實驗室」使用，無法刪除"
            );
        }
        other => panic!("{other:?}"),
    }
    // The generic delete path is protected the same way.
    assert_matches!(
        store.delete::<Blocklist>(bl.id.to_string(), 1).await,
        Err(StoreError::InUse(_))
    );

    // Detach from both, then it goes, content and refresh state with it.
    for p in [office, lab] {
        store
            .update(
                SecurityProfile {
                    blocklists: Vec::new(),
                    ..p.clone()
                },
                p.meta.revision,
            )
            .await
            .unwrap();
    }
    store
        .record_blocklist_refresh(bl.id, false, Some("x".into()))
        .await
        .unwrap();
    store.delete_blocklist(bl.id, 1).await.unwrap();
    assert!(store.blocklist_set(bl.id).await.unwrap().is_none());
    assert!(store.blocklist_refresh_states().await.unwrap().is_empty());
}

#[tokio::test]
async fn builtin_lists_are_created_once_and_a_deleted_one_is_remembered() {
    use vpn_domain::builtin_blocklists::BUILTIN_BLOCKLISTS;
    let dir = tempfile::tempdir().unwrap();
    let builtin_of = |lists: &[Blocklist], key: &str| {
        lists
            .iter()
            .find(|l| l.builtin.as_deref() == Some(key))
            .cloned()
    };

    // First start: one list per catalogue entry, waiting for its first download.
    let store = open(dir.path());
    let first: Vec<Blocklist> = store.list().await.unwrap();
    assert_eq!(first.len(), BUILTIN_BLOCKLISTS.len());
    for b in BUILTIN_BLOCKLISTS {
        let l = builtin_of(&first, b.key).unwrap();
        assert_eq!(l.name, b.list_name());
        assert!(l.enabled && l.awaiting_content());
        assert_eq!(
            l.source,
            BlocklistSource::Url {
                url: b.url.into(),
                refresh_hours: Some(b.refresh_hours)
            }
        );
        assert_eq!(
            store.blocklist_set(l.id).await.unwrap(),
            Some(IpRangeSet::new())
        );
    }
    let states = store.builtin_blocklists().await.unwrap();
    assert_eq!(states.len(), BUILTIN_BLOCKLISTS.len());
    assert!(
        states
            .iter()
            .all(|s| s.blocklist_id.is_some() && s.deleted_at.is_none())
    );

    // Starting again creates nothing new.
    drop(store);
    let store = open(dir.path());
    assert_eq!(store.list::<Blocklist>().await.unwrap(), first);

    // A built-in list a security profile uses cannot be deleted, like any list.
    let dshield = builtin_of(&first, "dshield-block").unwrap();
    let office = store
        .create(security("辦公室", vec![dshield.id]))
        .await
        .unwrap();
    assert_matches!(
        store.delete_blocklist(dshield.id, 1).await,
        Err(StoreError::InUse(_))
    );
    store
        .update(
            SecurityProfile {
                blocklists: Vec::new(),
                ..office.clone()
            },
            1,
        )
        .await
        .unwrap();

    // Deleted by the user: remembered, and not created again by later starts.
    store.delete_blocklist(dshield.id, 1).await.unwrap();
    drop(store);
    let store = open(dir.path());
    let lists: Vec<Blocklist> = store.list().await.unwrap();
    assert_eq!(lists.len(), BUILTIN_BLOCKLISTS.len() - 1);
    assert!(builtin_of(&lists, "dshield-block").is_none());
    let gone = store
        .builtin_blocklists()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.info.key == "dshield-block")
        .unwrap();
    assert!(gone.blocklist_id.is_none() && gone.deleted_at.is_some());

    // Only an explicit restore brings it back (a new list, waiting for its first download).
    let restored = store
        .restore_builtin_blocklist("dshield-block".into())
        .await
        .unwrap();
    assert_ne!(restored.id, dshield.id);
    assert!(restored.awaiting_content() && restored.enabled);
    assert_matches!(
        store
            .restore_builtin_blocklist("dshield-block".into())
            .await,
        Err(StoreError::InvalidState(_))
    );
    assert_matches!(
        store.restore_builtin_blocklist("nope".into()).await,
        Err(StoreError::NotFound)
    );
    let back = store.builtin_blocklists().await.unwrap();
    assert!(
        back.iter()
            .all(|s| s.blocklist_id.is_some() && s.deleted_at.is_none())
    );
    drop(store);
    let store = open(dir.path());
    assert_eq!(
        store.list::<Blocklist>().await.unwrap().len(),
        BUILTIN_BLOCKLISTS.len()
    );
}

#[tokio::test]
async fn policy_revisions_only_go_up_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let mut last = 0;
    for _ in 0..2 {
        let store = open(dir.path());
        for _ in 0..3 {
            let r = store.next_policy_revision().await.unwrap();
            assert!(r > last, "{r} after {last}");
            last = r;
        }
    }
    assert_eq!(last, 6);
}
