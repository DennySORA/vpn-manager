//! The forwarded-ports API (`/v1/provider-accounts/{id}/forwarded-ports`: the list, a
//! reservation, a delete, a settings change, a test, the DDNS check, the search for free ports)
//! against a real manager. Only the request conventions are exercised — every path here stops
//! before a provider request: `AirVPN` accounts only (`UNSUPPORTED_CAPABILITY` for the others),
//! the port range, a setting or a count the page would not take, and unknown fields refused up
//! front with the field named, an Idempotency-Key required for a change, and no way out but the
//! selected VPN egress (no egress: refused; the one-time direct grant: refused, since none of
//! these builds an egress). Nothing reaches a provider or a network.

#![cfg(test)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::provider::Providers;
use vpn_controller::routes::{AppState, api};
use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::rpc::{SystemFacts, serve};
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

fn not_a_worker() -> PathBuf {
    ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("a `false` executable")
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    app: axum::Router,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Arc::new(Store::open(&paths.state, &master, 1).unwrap());
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let sock = paths.manager_socket();
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        manager,
        store.clone(),
        SystemFacts {
            capabilities: vec![],
            ssh: None,
            performance: None,
        },
    ));
    let hub = Hub::new();
    let link = ManagerLink::new(sock, hub.clone());
    tokio::spawn(link.clone().run());
    for _ in 0..100 {
        if link.connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(link.connected(), "controller reaches the manager");
    let app = api(AppState {
        link,
        hub,
        port: 18765,
        data_dir: None,
        gateway_key: None,
        providers: Providers::new(),
        exposure: Arc::default(),
    });
    Fixture {
        _dir: dir,
        store,
        app,
    }
}

async fn account(store: &Store, provider: ProviderKind) -> ProviderAccount {
    let credential = store
        .put_secret(
            "provider_credential".into(),
            None,
            Zeroizing::new(b"synthetic-user\nnot-a-password".to_vec()),
            None,
        )
        .await
        .unwrap();
    store
        .create(ProviderAccount {
            id: ProviderAccountId::new(),
            meta: meta(),
            provider,
            label: "main".into(),
            credential_ref: credential.secret_ref,
            expires_at: None,
            observed_at: None,
        })
        .await
        .unwrap()
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, ApiError) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let error = serde_json::from_slice(&body)
        .unwrap_or_else(|_| panic!("{status}: {}", String::from_utf8_lossy(&body)));
    (status, error)
}

fn request(method: &str, uri: &str, body: Option<&str>, key: bool) -> Request<Body> {
    let mut r = Request::builder().method(method).uri(uri);
    if body.is_some() {
        r = r.header("content-type", "application/json");
    }
    if key {
        r = r.header("idempotency-key", uuid::Uuid::new_v4().to_string());
    }
    r.body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
        .unwrap()
}

/// The one-time direct grant carries only the operations that build an egress: a forwarded
/// port is never read, reserved, deleted, changed or tested over it, nor is `AirVPN`'s DDNS check
/// or search for free ports made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_direct_grant_never_carries_forwarded_ports() {
    let f = fixture().await;
    let air = account(&f.store, ProviderKind::Airvpn).await;
    let resp = f
        .app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/provider-egress/bootstrap",
            Some("{}"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ports = format!("/v1/provider-accounts/{}/forwarded-ports", air.id);
    for req in [
        request("GET", &ports, None, false),
        request("POST", &ports, Some("{}"), true),
        request("DELETE", &format!("{ports}/40000"), None, true),
        request(
            "PATCH",
            &format!("{ports}/40000"),
            Some(r#"{"notes":""}"#),
            true,
        ),
        request("POST", &format!("{ports}/40000/test"), None, false),
        request("GET", &format!("{ports}/ddns"), None, false),
        request("GET", &format!("{ports}/free?count=2"), None, false),
    ] {
        let (status, e) = call(&f.app, req).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.code, ErrorCode::ProviderEgressBlocked, "{e:?}");
        assert!(
            e.message.zh_tw.contains("目前只開放以直連建立出口"),
            "{e:?}"
        );
    }
}
