//! The Provider egress binding: compare-and-set changes that always advance the route fence, a
//! bootstrap latch that never resets, and an egress Instance that cannot be deleted.

// Test code throughout, its helper fns too: they get clippy.toml's test exemptions, so a failed
// setup step panics right there.
#![cfg(test)]

use std::str::FromStr;

use std::assert_matches;
use vpn_domain::*;
use vpn_store::{Store, StoreError};
use zeroize::Zeroizing;

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 0,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

async fn instance(store: &Store) -> InstanceSpec {
    let sm = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(vec![9; 32]),
            None,
        )
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
                private_key: sm.secret_ref,
                public_key: WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
                    .unwrap(),
                addresses: vec!["10.99.0.2/32".parse().unwrap()],
                dns: vec![],
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
    store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "egress".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: TransportRef::default(),
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn changes_are_compare_and_set_and_always_advance_the_route() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &Zeroizing::new([3u8; 32]), 1).unwrap();
    let fresh = store.provider_egress().await.unwrap();
    assert_eq!(
        (
            fresh.revision,
            fresh.route_revision,
            fresh.bootstrap_consumed
        ),
        (1, 1, false)
    );
    assert_eq!(fresh.desired_mode, EgressMode::ViaInstance);
    assert_eq!(fresh.selected_instance_id, None);

    let i = instance(&store).await;
    assert_matches!(
        store
            .put_provider_egress(EgressMode::ViaInstance, Some(InstanceId::new()), 1)
            .await,
        Err(StoreError::InvalidState(_))
    );
    let chosen = store
        .put_provider_egress(EgressMode::ViaInstance, Some(i.id), 1)
        .await
        .unwrap();
    assert_eq!((chosen.revision, chosen.route_revision), (2, 2));
    assert_eq!(chosen.selected_instance_id, Some(i.id));
    // A stale writer loses.
    assert_matches!(
        store
            .put_provider_egress(EgressMode::Disabled, None, 1)
            .await,
        Err(StoreError::RevisionConflict { .. })
    );

    // The egress Instance cannot be deleted while it is the egress.
    assert_matches!(
        store.delete_instance(i.id, 1).await,
        Err(StoreError::InvalidState(_))
    );
    assert_matches!(
        store
            .delete_instance_with_gateways(i.id, 1, Vec::new())
            .await,
        Err(StoreError::InvalidState(_))
    );
    let off = store
        .put_provider_egress(EgressMode::Disabled, None, 2)
        .await
        .unwrap();
    assert_eq!((off.revision, off.route_revision), (3, 3));
    store.delete_instance(i.id, 1).await.unwrap();
}

#[tokio::test]
async fn the_bootstrap_is_used_up_once_and_for_good() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &Zeroizing::new([3u8; 32]), 1).unwrap();
    let used = store.consume_bootstrap().await.unwrap();
    assert!(used.bootstrap_consumed);
    assert_eq!(
        used.route_revision, 2,
        "ends whatever ran on the bootstrap route"
    );
    let again = store.consume_bootstrap().await.unwrap();
    assert_eq!(again.route_revision, 2, "idempotent");
    // A user change keeps the latch; so does reopening the store.
    store
        .put_provider_egress(EgressMode::Disabled, None, 1)
        .await
        .unwrap();
    drop(store);
    let store = Store::open(dir.path(), &Zeroizing::new([3u8; 32]), 1).unwrap();
    assert!(store.provider_egress().await.unwrap().bootstrap_consumed);
}

#[tokio::test]
async fn an_account_with_generated_profiles_cannot_be_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &Zeroizing::new([3u8; 32]), 1).unwrap();
    let credential = store
        .put_secret(
            "provider_credential".into(),
            None,
            Zeroizing::new(b"SYNTHETIC-ACCOUNT".to_vec()),
            None,
        )
        .await
        .unwrap();
    let account = store
        .create(ProviderAccount {
            id: ProviderAccountId::new(),
            meta: meta(),
            provider: ProviderKind::Mullvad,
            label: "main".into(),
            credential_ref: credential.secret_ref,
            expires_at: None,
            observed_at: None,
        })
        .await
        .unwrap();
    let i = instance(&store).await;
    let mut p: RuntimeProfile = store.get(i.profile_id.to_string()).await.unwrap().unwrap();
    p.source = ProfileSource::Provider {
        account_id: account.id,
        device_id: "dev-1".into(),
        server_id: "jp-tyo-wg-001".into(),
        entry: None,
    };
    let p = store.update(p, 1).await.unwrap();
    assert_matches!(
        store
            .delete::<ProviderAccount>(account.id.to_string(), 1)
            .await,
        Err(StoreError::InUse(_))
    );
    store.delete_instance(i.id, 1).await.unwrap();
    store
        .delete::<RuntimeProfile>(p.id.to_string(), p.meta.revision)
        .await
        .unwrap();
    store
        .delete::<ProviderAccount>(account.id.to_string(), 1)
        .await
        .unwrap();
}
