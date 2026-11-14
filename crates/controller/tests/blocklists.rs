//! IP blocklist, ban and firewall API against a real manager in the same process: preview limits
//! and errors, commit only of what was previewed, conflicts with the addresses a connection
//! needs, delete protection, bans listed and lifted.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::routes::{AppState, api};
use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_platform::paths::Paths;
use vpn_store::Store;
use zeroize::Zeroizing;

struct Env {
    app: axum::Router,
    link: Arc<ManagerLink>,
    _store: Arc<Store>,
    _instance: InstanceSpec,
    office: SecurityProfile,
    _dir: tempfile::TempDir,
}

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

/// The connection's imported profile, its private key in the vault.
async fn lab_profile(store: &Store) -> RuntimeProfile {
    let key = store
        .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
        .await
        .unwrap();
    store
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
                endpoint: "5.6.7.8:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap()
}

/// A manager with one stopped connection (peer 5.6.7.8, resolver 10.64.0.1, security profile
/// 辦公室), served on a socket the controller links to. No Provider egress.
async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([4u8; 32]), 1).unwrap());
    let profile = lab_profile(&store).await;
    let office = store
        .create(SecurityProfile {
            id: SecurityProfileId::new(),
            meta: meta(),
            name: "辦公室".into(),
            allow_private: Vec::new(),
            blocked_ports: Vec::new(),
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            blocklists: Vec::new(),
            auto_ban: AutoBanSettings::default(),
        })
        .await
        .unwrap();
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
            transport: vpn_domain::TransportRef::default(),
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
    let hub = Hub::new();
    let link = ManagerLink::new(sock, hub.clone());
    tokio::spawn(link.clone().run());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !link.connected() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "link never connected"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Env {
        app: api(AppState {
            link: link.clone(),
            hub,
            port: 18765,
            exposure: Arc::default(),
            data_dir: None,
            gateway_key: None,
            providers: vpn_controller::provider::Providers::new(),
        }),
        link,
        _store: store,
        _instance: instance,
        office,
        _dir: dir,
    }
}

struct Sent {
    status: StatusCode,
    etag: Option<String>,
    json: serde_json::Value,
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
    if_match: Option<u64>,
    key: Option<&str>,
) -> Sent {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(ct) = content_type {
        b = b.header(header::CONTENT_TYPE, ct);
    }
    if let Some(r) = if_match {
        b = b.header(header::IF_MATCH, format!("\"{r}\""));
    }
    let key = key.map_or_else(next_key, str::to_owned);
    b = b.header("idempotency-key", key);
    let response = app
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("{status}: {e}: {}", String::from_utf8_lossy(&bytes)))
    };
    Sent { status, etag, json }
}

/// A fresh idempotency key per call (the tests that replay pass their own).
fn next_key() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    format!(
        "00000000-0000-4000-8000-{:012x}",
        N.fetch_add(1, Ordering::Relaxed)
    )
}

async fn get(app: &axum::Router, uri: &str) -> Sent {
    send(app, "GET", uri, None, Vec::new(), None, None).await
}

async fn preview_text(app: &axum::Router, text: &str) -> Sent {
    send(
        app,
        "POST",
        "/v1/blocklists/preview",
        Some("text/plain; charset=utf-8"),
        text.as_bytes().to_vec(),
        None,
        None,
    )
    .await
}

async fn json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
    if_match: Option<u64>,
) -> Sent {
    send(
        app,
        method,
        uri,
        Some("application/json"),
        serde_json::to_vec(&body).unwrap(),
        if_match,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_attach_conflict_and_delete_protection() {
    let e = env().await;
    let text = "1.2.3.0/24\n2a00:dead::/48\n";
    let hash = preview_text(&e.app, text).await.json["import_hash"].clone();

    // Different content than previewed: refused.
    let wrong = json(
        &e.app,
        "POST",
        "/v1/blocklists",
        serde_json::json!({ "name": "DROP", "source": { "kind": "upload" }, "text": "4.3.2.0/24\n", "expected_import_hash": hash }),
        None,
    )
    .await;
    assert_eq!(wrong.status, StatusCode::CONFLICT, "{}", wrong.json);
    assert_eq!(wrong.json["code"], "INVALID_STATE");
    // Nothing usable: refused.
    let empty = json(
        &e.app,
        "POST",
        "/v1/blocklists",
        serde_json::json!({ "name": "空", "source": { "kind": "upload" }, "text": "# none\n", "expected_import_hash": hash }),
        None,
    )
    .await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);

    let created = json(
        &e.app,
        "POST",
        "/v1/blocklists",
        serde_json::json!({ "name": "DROP", "source": { "kind": "upload" }, "text": text, "expected_import_hash": hash }),
        None,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.json);
    assert_eq!(created.etag.as_deref(), Some("\"1\""));
    let id = created.json["blocklist"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created.json["blocklist"]["content_sha256"], hash);
    assert_eq!(created.json["blocklist"]["stats"]["v6_ranges"], 1);
    assert_eq!(
        created.json["blocklist"]["builtin"],
        serde_json::Value::Null
    );
    assert_eq!(created.json["blocklist"]["enabled"], true);
    assert_eq!(created.json["stale"], false);
    assert_eq!(created.json["default_policy"], false);

    // Attach it to the connection's security profile (applies without a restart).
    let attached = json(
        &e.app,
        "PUT",
        &format!("/v1/security-profiles/{}", e.office.id),
        serde_json::json!({ "name": "辦公室", "blocklists": [id], "allowed_ports": [{ "start": 443, "end": 443 }] }),
        Some(1),
    )
    .await;
    assert_eq!(attached.status, StatusCode::OK, "{}", attached.json);
    assert_eq!(attached.json["allowed_ports"][0]["start"], 443);
    // Omitted, auto-ban takes the default: on.
    assert_eq!(attached.json["auto_ban"]["enabled"], true);
    let listed = send(
        &e.app,
        "GET",
        "/v1/blocklists",
        None,
        Vec::new(),
        None,
        None,
    )
    .await;
    let mine = listed
        .json
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["blocklist"]["id"] == id.as_str())
        .unwrap();
    assert_eq!(mine["used_by"][0]["name"], "辦公室");

    changes_are_checked_against_the_connection(&e, &id).await;
}

/// Changes of list `id` (revision 1): the resolver's private range left out, the `WireGuard`
/// peer a conflict, renames and stale revisions, deletion while in use.
async fn changes_are_checked_against_the_connection(e: &Env, id: &str) {
    // New content holding the connection's in-tunnel resolver (10.64.0.1, like Mullvad's): the
    // private range is left out and counted, so the list saves and the resolver keeps working.
    let with_private = "1.2.3.0/24\n10.64.0.0/16\n";
    let preview = preview_text(&e.app, with_private).await;
    assert_eq!(preview.json["stats"]["special_filtered"], 1);
    let saved = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{id}"),
        serde_json::json!({ "name": "DROP", "source": { "kind": "upload" }, "text": with_private, "expected_import_hash": preview.json["import_hash"] }),
        Some(1),
    )
    .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.json);
    assert_eq!(saved.etag.as_deref(), Some("\"2\""));
    assert_eq!(saved.json["blocklist"]["stats"]["special_filtered"], 1);
    let hash = saved.json["blocklist"]["content_sha256"].clone();
    assert_eq!(hash, preview.json["import_hash"]);

    // New content with the connection's (public) WireGuard peer: a conflict naming the address.
    let worse = "1.2.3.0/24\n5.6.7.0/24\n";
    let worse_hash = preview_text(&e.app, worse).await.json["import_hash"].clone();
    let conflict = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{id}"),
        serde_json::json!({ "name": "DROP", "source": { "kind": "upload" }, "text": worse, "expected_import_hash": worse_hash }),
        Some(2),
    )
    .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT, "{}", conflict.json);
    assert_eq!(conflict.json["code"], "POLICY_CONFLICT");
    let message = conflict.json["message"]["zh-TW"].as_str().unwrap();
    assert!(
        message.contains("5.6.7.8（WireGuard 對端）") && message.contains("東京出口"),
        "{message}"
    );

    // Renaming keeps the content and moves the revision.
    let renamed = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{id}"),
        serde_json::json!({ "name": "Spamhaus DROP", "source": { "kind": "upload" } }),
        Some(2),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.json);
    assert_eq!(renamed.etag.as_deref(), Some("\"3\""));
    assert_eq!(renamed.json["blocklist"]["content_sha256"], hash);
    // A stale revision is a conflict, not an overwrite.
    let stale = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{id}"),
        serde_json::json!({ "name": "x", "source": { "kind": "upload" } }),
        Some(2),
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);

    // An upload source has nothing to refresh.
    let refresh = json(
        &e.app,
        "POST",
        &format!("/v1/blocklists/{id}/refresh"),
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(refresh.status, StatusCode::CONFLICT);

    // In use: the error names the profile.
    let del = send(
        &e.app,
        "DELETE",
        &format!("/v1/blocklists/{id}"),
        None,
        Vec::new(),
        Some(3),
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::CONFLICT);
    assert_eq!(
        del.json["message"]["zh-TW"],
        "仍被安全設定「辦公室」使用，無法刪除"
    );

    // Invalid allow rules are refused with their path.
    let bad = json(
        &e.app,
        "PUT",
        &format!("/v1/security-profiles/{}", e.office.id),
        serde_json::json!({ "name": "辦公室", "allowed_ports": [{ "start": 900, "end": 80 }], "allowed_destinations": ["127.0.0.0/8"] }),
        Some(2),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let paths: Vec<&str> = bad.json["field_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["/allowed_destinations/0", "/allowed_ports/0"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builtin_lists_wait_for_the_egress_and_a_deleted_one_stays_deleted() {
    use vpn_domain::builtin_blocklists::BUILTIN_BLOCKLISTS;
    let e = env().await;

    // Built in from the first start, each from its catalogue entry; part of the default policy;
    // nothing downloaded yet, and no Provider egress to download them through.
    let listed = get(&e.app, "/v1/blocklists").await;
    let builtin: Vec<&serde_json::Value> = listed
        .json
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| !v["builtin"].is_null())
        .collect();
    assert_eq!(builtin.len(), BUILTIN_BLOCKLISTS.len());
    for b in BUILTIN_BLOCKLISTS {
        let v = builtin
            .iter()
            .find(|v| v["builtin"]["key"] == b.key)
            .unwrap();
        assert_eq!(v["blocklist"]["source"]["url"], b.url);
        assert_eq!(v["blocklist"]["source"]["refresh_hours"], b.refresh_hours);
        assert_eq!(v["builtin"]["terms_url"], b.terms_url);
        assert_eq!(v["default_policy"], true);
        assert_eq!(v["awaiting_content"], true);
        assert_eq!(v["stale"], false);
        let waiting = v["waiting"]["zh-TW"].as_str().unwrap();
        assert!(waiting.contains("Provider 出口"), "{waiting}");
        assert!(
            v["next_refresh_at"].is_string(),
            "due for the first download"
        );
    }
    let drop_id = builtin
        .iter()
        .find(|v| v["builtin"]["key"] == "spamhaus-drop-v4")
        .unwrap()["blocklist"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // A refresh asked for now waits for the egress too: refused, nothing recorded, the host
    // network never tried.
    let now = json(
        &e.app,
        "POST",
        &format!("/v1/blocklists/{drop_id}/refresh"),
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(now.status, StatusCode::SERVICE_UNAVAILABLE, "{}", now.json);
    assert_eq!(now.json["code"], "PROVIDER_EGRESS_BLOCKED");
    let after = get(&e.app, &format!("/v1/blocklists/{drop_id}")).await;
    assert_eq!(after.json["refresh"], serde_json::Value::Null);
    assert_eq!(after.json["stale"], false);
    // So does the schedule: every list is due, none is tried.
    let pass = vpn_controller::blocklists::refresh_due(&e.link)
        .await
        .unwrap();
    assert_eq!(pass.due, BUILTIN_BLOCKLISTS.len());
    assert_eq!(pass.tried, 0);
    assert!(pass.waiting.is_some());

    // A built-in list keeps its source; its interval can change, and it can be disabled.
    let moved = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{drop_id}"),
        serde_json::json!({ "name": "DROP", "source": { "kind": "url", "url": "https://lists.example.net/drop.txt", "refresh_hours": 24 } }),
        Some(1),
    )
    .await;
    assert_eq!(moved.status, StatusCode::BAD_REQUEST, "{}", moved.json);
    assert_eq!(moved.json["field_errors"][0]["code"], "BLOCKLIST_BUILTIN");
    let off = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{drop_id}"),
        serde_json::json!({ "name": "Spamhaus DROP（IPv4）", "source": { "kind": "url", "url": "https://www.spamhaus.org/drop/drop_v4.json", "refresh_hours": 48 }, "enabled": false }),
        Some(1),
    )
    .await;
    assert_eq!(off.status, StatusCode::OK, "{}", off.json);
    assert_eq!(off.json["blocklist"]["enabled"], false);
    assert_eq!(off.json["blocklist"]["source"]["refresh_hours"], 48);
    assert_eq!(off.json["default_policy"], false);
    assert_eq!(off.json["next_refresh_at"], serde_json::Value::Null);
    assert_eq!(off.json["waiting"], serde_json::Value::Null);
    let refused = json(
        &e.app,
        "POST",
        &format!("/v1/blocklists/{drop_id}/refresh"),
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.json);
    // Enabled again (omitting `enabled` keeps the current state).
    let on = json(
        &e.app,
        "PUT",
        &format!("/v1/blocklists/{drop_id}"),
        serde_json::json!({ "name": "Spamhaus DROP（IPv4）", "source": { "kind": "url", "url": "https://www.spamhaus.org/drop/drop_v4.json", "refresh_hours": 24 }, "enabled": true }),
        Some(2),
    )
    .await;
    assert_eq!(on.status, StatusCode::OK, "{}", on.json);
    assert_eq!(on.json["default_policy"], true);

    a_deleted_builtin_stays_deleted(&e, &drop_id).await;
}

/// The built-in list `drop_id`, deleted: gone from the default policy and remembered, back only
/// by an explicit restore.
async fn a_deleted_builtin_stays_deleted(e: &Env, drop_id: &str) {
    // Deleted by the user: gone from the default policy and remembered.
    let deleted = send(
        &e.app,
        "DELETE",
        &format!("/v1/blocklists/{drop_id}"),
        None,
        Vec::new(),
        Some(3),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.json);
    let states = get(&e.app, "/v1/blocklists/builtin").await;
    assert_eq!(states.status, StatusCode::OK, "{}", states.json);
    let state = states
        .json
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["info"]["key"] == "spamhaus-drop-v4")
        .unwrap()
        .clone();
    assert_eq!(state["blocklist_id"], serde_json::Value::Null);
    assert!(state["deleted_at"].is_string());
    assert!(
        get(&e.app, "/v1/blocklists")
            .await
            .json
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["builtin"]["key"] != "spamhaus-drop-v4")
    );
    // Only an explicit restore brings it back.
    let restored = json(
        &e.app,
        "POST",
        "/v1/blocklists/builtin/spamhaus-drop-v4/restore",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(restored.status, StatusCode::CREATED, "{}", restored.json);
    assert_ne!(restored.json["blocklist"]["id"], drop_id);
    assert_eq!(restored.json["awaiting_content"], true);
    let unknown = json(
        &e.app,
        "POST",
        "/v1/blocklists/builtin/nope/restore",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let again = json(
        &e.app,
        "POST",
        "/v1/blocklists/builtin/spamhaus-drop-v4/restore",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.json);
}
