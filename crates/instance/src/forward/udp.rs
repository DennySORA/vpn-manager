//! UDP side of a port forward: one flow per remote address (its own loopback socket connected to
//! the App), bounded in number and ended after a minute without a datagram either way.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use vpn_sync::Mutex;
use vpn_tunnel::{TunnelDatagram, TunnelInbound};

use super::{AppEndpoint, Shared, UDP_IDLE_TIMEOUT};
use crate::counters::{ForwardCounters, RelayedCounters};

/// Largest datagram relayed (the tunnel MTU keeps real ones far smaller).
const MAX_DATAGRAM: usize = 64 * 1024;
/// How long a datagram may wait for room in the App's socket before it is dropped.
const APP_SEND_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// What one lease gives the relay.
pub(super) struct Lease {
    pub endpoint: AppEndpoint,
    pub flows: CancellationToken,
    pub tracker: TaskTracker,
    pub table: Arc<Mutex<Flows>>,
    /// Flows at once.
    pub max: usize,
}

/// The relay's flows by remote address.
#[derive(Default)]
pub(super) struct Flows {
    by_source: HashMap<SocketAddr, Arc<Flow>>,
}

impl Flows {
    /// End the flows whose remote address `covered` accepts (a new ban or blocklist entry).
    pub fn end_where(&mut self, covered: impl Fn(SocketAddr) -> bool) {
        self.by_source.retain(|src, flow| {
            let keep = !covered(*src);
            if !keep {
                flow.end.cancel();
            }
            keep
        });
    }
}

struct Flow {
    app: Arc<UdpSocket>,
    /// Milliseconds after `started` of the last datagram either way.
    last: AtomicU64,
    started: Instant,
    end: CancellationToken,
}

impl Flow {
    fn touch(&self) {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(ms, Ordering::Relaxed);
    }

    /// Hand one datagram from the remote side to the App. A socket that stays full for
    /// [`APP_SEND_WAIT`] drops it, like any UDP path would; the relay never waits longer.
    async fn to_app(&self, data: &[u8], c: &ForwardCounters, relayed: &RelayedCounters) {
        match tokio::time::timeout(APP_SEND_WAIT, self.app.send(data)).await {
            Ok(Ok(n)) => {
                c.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                relayed.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                self.touch();
            }
            _ => {
                c.udp_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Receive on the tunnel port until the lease ends.
pub(super) async fn relay<I: TunnelInbound>(
    socket: Arc<I::Datagram>,
    shared: Arc<Shared<I>>,
    lease: Lease,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let c = shared.counters.clone();
    let relayed = shared.relayed.clone();
    loop {
        let received = tokio::select! {
            () = lease.flows.cancelled() => break,
            r = socket.recv_from(&mut buf) => r,
        };
        let Ok((n, src)) = received else {
            // The socket closed (gate sealed, worker ending).
            break;
        };
        let existing = lease.table.lock().by_source.get(&src).cloned();
        if let Some(flow) = existing {
            flow.to_app(&buf[..n], &c, &relayed).await;
            continue;
        }
        // A new flow.
        let source = src.ip().to_canonical();
        shared.arrived(source, true);
        if !shared.net.payload_open() {
            c.refused_closed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if !shared.admit(source) {
            continue;
        }
        if lease.table.lock().by_source.len() >= lease.max {
            c.refused_limit.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let app = if let Ok(app) = lease.endpoint.udp().await {
            Arc::new(app)
        } else {
            c.target_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let flow = Arc::new(Flow {
            app: app.clone(),
            last: AtomicU64::new(0),
            started: Instant::now(),
            end: lease.flows.child_token(),
        });
        lease.table.lock().by_source.insert(src, flow.clone());
        c.accepted.fetch_add(1, Ordering::Relaxed);
        c.udp_active.fetch_add(1, Ordering::Relaxed);
        flow.to_app(&buf[..n], &c, &relayed).await;
        let (socket, table) = (socket.clone(), lease.table.clone());
        let (counters, relayed) = (c.clone(), relayed.clone());
        lease.tracker.spawn(async move {
            back(&*socket, &flow, src, &counters, &relayed).await;
            let mut t = table.lock();
            if t.by_source.get(&src).is_some_and(|f| Arc::ptr_eq(f, &flow)) {
                t.by_source.remove(&src);
            }
            drop(t);
            counters.udp_active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    lease.table.lock().end_where(|_| true);
}

/// The App's answers back to the remote address, until the flow is idle, ends or the App's
/// port is gone.
async fn back<D: TunnelDatagram>(
    socket: &D,
    flow: &Flow,
    remote: SocketAddr,
    c: &ForwardCounters,
    relayed: &RelayedCounters,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let last = std::time::Duration::from_millis(flow.last.load(Ordering::Relaxed));
        let idle_at = tokio::time::Instant::from_std(flow.started + last + UDP_IDLE_TIMEOUT);
        tokio::select! {
            () = flow.end.cancelled() => return,
            () = tokio::time::sleep_until(idle_at) => {
                let last = std::time::Duration::from_millis(flow.last.load(Ordering::Relaxed));
                if flow.started.elapsed() >= last + UDP_IDLE_TIMEOUT {
                    return;
                }
            }
            r = flow.app.recv(&mut buf) => match r {
                Ok(n) => {
                    if socket.send_to(&buf[..n], remote).await.is_ok() {
                        c.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                        relayed.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        flow.touch();
                    } else {
                        c.udp_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Nothing listens on the App's port any more (ICMP port unreachable).
                Err(_) => return,
            },
        }
    }
}
