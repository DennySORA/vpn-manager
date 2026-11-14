//! The Mullvad adapter against fixtures shaped like `api.mullvad.net` answers (official app
//! types, the previous implementation's fixtures), served over the in-memory TLS fixture.

#![cfg(test)]

mod support;

use std::time::Duration;

use std::assert_matches;
use support::{Fixture, Reply, Seen, setup};
use vpn_domain::WgKey;
use vpn_providers::mullvad::{AccessToken, AccountNumber, DeviceId, Mullvad, Reconciled};
use vpn_providers::{Family, ProviderError};

const TOKEN: &str = include_str!("fixtures/mullvad/token.json");
const TOKEN_VALUE: &str = "mva_d8c4f1a7e2b94c0d9e6f3a2b1c0d9e8f";
const ACCOUNT: &str = include_str!("fixtures/mullvad/account.json");
const DEVICES: &str = include_str!("fixtures/mullvad/devices.json");
const DEVICE_CREATED: &str = include_str!("fixtures/mullvad/device-created.json");
const RELAYS: &str = include_str!("fixtures/mullvad/relays.json");
const FIRST_DEVICE: &str = "0d9b6c1e-3f2a-4b5c-8d7e-9f0a1b2c3d4e";

const fn key(n: u8) -> WgKey {
    WgKey([n; 32])
}

fn account() -> AccountNumber {
    AccountNumber::parse("1234 5678 1234 5678").unwrap()
}

/// Every endpoint with its recorded shape.
fn api_routes(seen: &Seen) -> Reply {
    let delete_first = format!("/accounts/v1/devices/{FIRST_DEVICE}");
    match (seen.method.as_str(), seen.path.as_str()) {
        ("POST", "/auth/v1/token") => Reply::json(200, TOKEN),
        ("GET", "/accounts/v1/accounts/me") => Reply::json(200, ACCOUNT),
        ("GET", "/accounts/v1/devices") => Reply::json(200, DEVICES),
        ("POST", "/accounts/v1/devices") => Reply::json(201, DEVICE_CREATED),
        ("DELETE", path) if path == delete_first => Reply::empty(204),
        ("GET", "/public/relays/wireguard/v2/") => Reply::json(200, RELAYS),
        _ => Reply::json(404, r#"{"code":"NOT_FOUND","error":"Not found"}"#),
    }
}

fn mullvad(
    handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
) -> (Fixture, Mullvad<Fixture>) {
    let s = setup(handler);
    (s.fixture, Mullvad::new(s.client, Family::V4))
}

/// A token issued by the fixture API, for the authenticated endpoints.
async fn token() -> AccessToken {
    let (_, api) = mullvad(api_routes);
    api.token(&account()).await.unwrap()
}

#[tokio::test]
async fn an_unknown_create_is_reconciled_from_the_list_never_resent() {
    let token = token().await;
    let (fixture, api) = mullvad(|seen| match seen.method.as_str() {
        "POST" => Reply::stall(),
        _ => Reply::json(200, DEVICES),
    });
    let api = api.with_timeout(Duration::from_millis(300));
    let e = api.create_device(&token, &key(5)).await.unwrap_err();
    assert!(e.outcome_unknown(), "{e:?}");

    match api.reconcile_device(&token, &key(5)).await.unwrap() {
        Reconciled::Bound(device) => assert_eq!(device.id.as_str(), FIRST_DEVICE),
        other @ Reconciled::StillUnknown => {
            panic!("expected the device holding the key, got {other:?}")
        }
    }
    assert_eq!(
        api.reconcile_device(&token, &key(7)).await.unwrap(),
        Reconciled::StillUnknown
    );
    let posts = fixture.seen().iter().filter(|s| s.method == "POST").count();
    assert_eq!(posts, 1, "reconciling never creates again");
}

#[test]
fn device_ids_cannot_reshape_the_request_path() {
    let long = "a".repeat(65);
    for bad in [
        "",
        "../accounts",
        "a/b",
        "a?b",
        "a#b",
        "a%2Fb",
        "a b",
        "dévice",
        long.as_str(),
    ] {
        assert!(DeviceId::parse(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        "0d9b6c1e-3f2a-4b5c-8d7e-9f0a1b2c3d4e"
            .parse::<DeviceId>()
            .unwrap()
            .as_str(),
        FIRST_DEVICE
    );
}

#[tokio::test]
async fn secrets_stay_out_of_debug_display_and_errors() {
    let account = account();
    let token = token().await;
    for printed in [
        format!("{account:?}"),
        format!("{account}"),
        format!("{token:?}"),
        format!("{token}"),
    ] {
        assert!(!printed.contains("12345678"), "{printed}");
        assert!(!printed.contains("5678 1234"), "{printed}");
        assert!(!printed.contains(TOKEN_VALUE), "{printed}");
    }
    assert!(format!("{token:?}").contains("2026-10-27T09:30:00Z"));

    // A provider that echoes the credential back cannot make an error carry it.
    let (_, api) = mullvad(|_| {
        Reply::json(
            400,
            r#"{"code":"1234567812345678","error":"account 1234567812345678 is invalid"}"#,
        )
    });
    let e = api.token(&account).await.unwrap_err();
    let (_, api) = mullvad(|_| {
        Reply::json(
            400,
            r#"{"code":"mva_d8c4f1a7e2b94c0d9e6f3a2b1c0d9e8f","error":"bad token mva_d8c4f1a7e2b94c0d9e6f3a2b1c0d9e8f"}"#,
        )
    });
    let e2 = api.devices(&token).await.unwrap_err();
    assert_matches!(
        e2,
        ProviderError::Rejected {
            status: 400,
            code: None
        }
    );
    for printed in [
        format!("{e:?}"),
        e.to_string(),
        format!("{e2:?}"),
        e2.to_string(),
    ] {
        assert!(!printed.contains("12345678"), "{printed}");
        assert!(!printed.contains(TOKEN_VALUE), "{printed}");
    }
}
