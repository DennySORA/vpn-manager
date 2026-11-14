//! TCP side of a port forward: accept on the tunnel port, admit, connect to the App, (when the
//! forward opted in) tell the App who connected with a PROXY protocol v2 header, relay.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use vpn_tunnel::{InboundListener, InboundStream, TunnelInbound};

use super::{APP_CONNECT_TIMEOUT, AppEndpoint, Shared};

/// Pause after `accept` could not take a connection (flow or memory limit, gate tightening).
const ACCEPT_RETRY: Duration = Duration::from_millis(250);

/// What one lease gives the accept loop.
pub(super) struct Lease {
    pub endpoint: AppEndpoint,
    /// Ends every connection of the lease.
    pub flows: CancellationToken,
    pub tracker: TaskTracker,
    pub limit: Arc<Semaphore>,
    /// Start each connection to the App with a PROXY protocol v2 header.
    pub proxy_protocol: bool,
}

/// Accept until `stop` (the gate tightened, or the lease ended).
pub(super) async fn accept_loop<I: TunnelInbound>(
    mut listener: I::Listener,
    shared: Arc<Shared<I>>,
    lease: Lease,
    stop: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            a = listener.accept() => a,
        };
        match accepted {
            Ok(stream) => admit::<I>(stream, &shared, &lease),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => return,
            Err(_) => {
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(ACCEPT_RETRY) => {}
                }
            }
        }
    }
}

/// Decide on one inbound connection; serve it or reset it.
fn admit<I: TunnelInbound>(
    stream: <I::Listener as InboundListener>::Stream,
    shared: &Arc<Shared<I>>,
    lease: &Lease,
) {
    let source = stream.peer_addr().ip().to_canonical();
    shared.arrived(source, false);
    let c = &shared.counters;
    if !shared.net.payload_open() || lease.flows.is_cancelled() {
        c.refused_closed.fetch_add(1, Ordering::Relaxed);
        stream.abort();
        return;
    }
    if !shared.admit(source) {
        stream.abort();
        return;
    }
    let Ok(permit) = lease.limit.clone().try_acquire_owned() else {
        c.refused_limit.fetch_add(1, Ordering::Relaxed);
        stream.abort();
        return;
    };
    let (shared, endpoint, flows) = (shared.clone(), lease.endpoint, lease.flows.clone());
    let proxy_protocol = lease.proxy_protocol;
    lease.tracker.spawn(async move {
        let _permit = permit;
        serve(stream, &shared, endpoint, flows, proxy_protocol).await;
    });
}

async fn serve<S: InboundStream, I: TunnelInbound>(
    inbound: S,
    shared: &Shared<I>,
    endpoint: AppEndpoint,
    flows: CancellationToken,
    proxy_protocol: bool,
) {
    let c = &shared.counters;
    // Who connected, as the tunnel saw it, and the tunnel address and port reached: the App's
    // own connection comes from loopback.
    let header = if proxy_protocol {
        super::proxy::header(inbound.peer_addr(), inbound.local_addr())
    } else {
        Vec::new()
    };
    let app = tokio::select! {
        () = flows.cancelled() => {
            inbound.abort();
            return;
        }
        app = endpoint.connect(APP_CONNECT_TIMEOUT) => app,
    };
    let Ok(app) = app else {
        c.target_failed.fetch_add(1, Ordering::Relaxed);
        inbound.abort();
        return;
    };
    c.accepted.fetch_add(1, Ordering::Relaxed);
    c.tcp_active.fetch_add(1, Ordering::Relaxed);
    // A revoked lease resets the tunnel side itself (the port's connections); dropping the
    // relay here closes the App side.
    tokio::select! {
        () = flows.cancelled() => {}
        _ = super::relay::relay(
            inbound,
            app,
            &header,
            &shared.counters,
            &shared.relayed,
            shared.tcp_idle,
        ) => {}
    }
    c.tcp_active.fetch_sub(1, Ordering::Relaxed);
}
