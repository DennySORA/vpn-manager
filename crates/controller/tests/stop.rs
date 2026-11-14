//! Stop and emergency stop reach the manager even when the Store cannot record the operation
//! (normal write lane full, disk full, writer gone): the stop never waits behind the record.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::routes::{AppState, api};
use vpn_domain::*;
use vpn_ipc::control::{
    CONTROL_MAX_FRAME, CONTROL_PROTOCOL, Call, ClientMsg, Lifecycle, Reply, ServerMsg,
};
use vpn_ipc::frame::split;
use vpn_sync::Mutex;

type Seen = Arc<Mutex<Vec<(InstanceId, Lifecycle)>>>;

/// A stand-in manager. With `store_busy`, every operation record is refused with `STORE_BUSY`;
/// lifecycle calls always succeed and are recorded.
fn manager(path: &Path, store_busy: bool) -> Seen {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let seen = Seen::default();
    let lifecycle = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let lifecycle = lifecycle.clone();
            tokio::spawn(async move {
                let (mut rx, mut tx) = split(stream, CONTROL_MAX_FRAME);
                let Ok(Some((ClientMsg::Hello { .. }, _))) = rx.recv::<ClientMsg>().await else {
                    return;
                };
                let hello = ServerMsg::Hello {
                    protocol: CONTROL_PROTOCOL,
                    build_id: "stand-in".into(),
                    installation_id: InstallationId::new(),
                };
                if tx.send(&hello, &[]).await.is_err() {
                    return;
                }
                // Calls are answered; an event subscription is simply held open.
                while let Ok(Some((msg, _))) = rx.recv::<ClientMsg>().await {
                    let ClientMsg::Call { id, call } = msg else {
                        continue;
                    };
                    let result = match call {
                        Call::BeginOperation { .. } if store_busy => Err(ApiError::new(
                            ErrorCode::StoreBusy,
                            "儲存佇列已滿，請稍後再試",
                        )),
                        Call::BeginOperation {
                            kind, target_id, ..
                        } => {
                            let now = Timestamp::now();
                            Ok(Reply::Begin {
                                operation: Operation {
                                    id: OperationId::new(),
                                    kind,
                                    target_id,
                                    status: OperationStatus::Accepted,
                                    error: None,
                                    result_refs: Vec::new(),
                                    durable: true,
                                    created_at: now,
                                    updated_at: now,
                                },
                                existing: false,
                            })
                        }
                        Call::FinishOperation { .. } => Ok(Reply::Unit),
                        Call::Lifecycle(instance, action) => {
                            lifecycle.lock().push((instance, action));
                            Ok(Reply::Stopped {
                                sealed: true,
                                durable: true,
                            })
                        }
                        _ => Err(ApiError::internal()),
                    };
                    if tx
                        .send(&ServerMsg::Reply { id, result }, &[])
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    seen
}

fn socket_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("vpnm-{tag}-{}-{nanos}.sock", std::process::id()))
}

async fn app(path: &Path) -> axum::Router {
    let hub = Hub::new();
    let link = ManagerLink::new(path.to_path_buf(), hub.clone());
    tokio::spawn(link.clone().run());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !link.connected() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "link never connected"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    api(AppState {
        link,
        hub,
        port: 18765,
        exposure: Arc::default(),
        data_dir: None,
        gateway_key: None,
        providers: vpn_controller::provider::Providers::new(),
    })
}

async fn stop(app: &axum::Router, id: InstanceId, emergency: bool) -> (StatusCode, bool, Accepted) {
    let request = if emergency {
        Request::post(format!("/v1/instances/{id}/emergency-stop")).body(Body::empty())
    } else {
        Request::post(format!("/v1/instances/{id}/actions"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"action":"stop"}"#))
    };
    let mut request = request.unwrap();
    request.headers_mut().insert(
        "idempotency-key",
        uuid::Uuid::new_v4().to_string().parse().unwrap(),
    );
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let location = response.headers().contains_key(header::LOCATION);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let accepted = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{status}: {e}: {}", String::from_utf8_lossy(&body)));
    (status, location, accepted)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stops_reach_the_manager_when_the_store_cannot_record_them() {
    let path = socket_path("busy");
    let seen = manager(&path, true);
    let app = app(&path).await;
    let id = InstanceId::new();

    let (status, location, accepted) = stop(&app, id, true).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        (accepted.sealed, accepted.durable),
        (Some(true), Some(true))
    );
    assert!(
        !accepted.operation.durable && !location,
        "the operation exists only in this answer"
    );
    let (status, _, _) = stop(&app, id, false).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        *seen.lock(),
        [(id, Lifecycle::Emergency), (id, Lifecycle::Stop)]
    );
    let _ = std::fs::remove_file(&path);
}
