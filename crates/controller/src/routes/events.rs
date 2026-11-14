//! `GET /v1/events`: one SSE stream for the workbench. Resumes with `Last-Event-ID` within the
//! same controller boot (each missed event once); otherwise (another boot, a gap the ring no
//! longer holds, or a client that falls behind its bounded queue) it sends `resync_required` so
//! the client reloads snapshots — a client that fell behind is then disconnected. Never blocks
//! the controller: publishing does not wait on any stream.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use tokio::sync::broadcast::error::RecvError;
use vpn_domain::ServerEvent;

use super::AppState;
use crate::hub::{Envelope, Resume};

fn to_sse(env: &Envelope) -> Event {
    let name = match env.event.as_ref() {
        ServerEvent::InstanceStatus { .. } => "instance_status",
        ServerEvent::LiveRates { .. } => "live_rates",
        ServerEvent::AppStatus { .. } => "app_status",
        ServerEvent::ForwardStatus { .. } => "forward_status",
        ServerEvent::EntityChanged { .. } => "entity_changed",
        ServerEvent::ManagerConnection { .. } => "manager_connection",
        ServerEvent::SshDownloadStatus { .. } => "ssh_download_status",
        ServerEvent::ResyncRequired => "resync_required",
    };
    Event::default()
        .id(env.id.clone())
        .event(name)
        .data(serde_json::to_string(env.event.as_ref()).unwrap_or_else(|_| "{}".into()))
}

/// The manager link as it is now, first on every stream: a reconnecting browser may have missed
/// the change. Carries no id, so it does not move `Last-Event-ID`.
fn link_state(connected: bool) -> Event {
    Event::default().event("manager_connection").data(
        serde_json::to_string(&ServerEvent::ManagerConnection { connected })
            .unwrap_or_else(|_| "{}".into()),
    )
}

fn resync() -> Event {
    Event::default()
        .event("resync_required")
        .data(r#"{"type":"resync_required"}"#)
}

pub async fn stream(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let (mut rx, resume) = state.hub.resume(last.as_deref());
    let closing = state.hub.closing();
    let connected = state.link.connected();
    let stream = async_stream::stream! {
        yield Ok(link_state(connected));
        match resume {
            Resume::Replay(events) => {
                for e in events {
                    yield Ok(to_sse(&e));
                }
            }
            Resume::Resync => yield Ok(resync()),
            Resume::Fresh => {}
        }
        loop {
            let next = tokio::select! {
                // Shutdown ends the stream; the browser reconnects to the next controller.
                () = closing.cancelled() => break,
                r = rx.recv() => r,
            };
            match next {
                Ok(env) => yield Ok(to_sse(&env)),
                Err(RecvError::Lagged(_)) => {
                    yield Ok(resync());
                    break;
                }
                Err(RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
