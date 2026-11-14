//! Each managed App's share of its connection's payload.
//!
//! A strict sandbox's Apps share one TUN device, so the worker counts their own flows per local
//! port of the sandbox ([`SandboxPortWire`]); the App supervisor knows which ports each App's
//! processes hold ([`crate::apps::Apps::strict_ports`]). The port forwards count their payload
//! per forward, and each forward ends at one App. This joins the two into one cumulative count per
//! App and worker generation ([`AppPayloadWire`]), from which the controller derives rates.
//!
//! The worker's port counters are cumulative while a port carries payload; the bytes since the
//! previous sample go to the App that holds the port now. Bytes of a port no App is known to hold
//! yet (a connection opened since the App supervisor's last pass, every 2 s) wait a few seconds
//! for its owner, then stay unattributed: they remain in the sandbox's total only.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use vpn_domain::{AppId, ForwardBindingId};
use vpn_ipc::worker::{AppPayloadWire, SandboxPortWire};

/// How long the bytes of a port without a known owner wait for one.
const PENDING_FOR: Duration = Duration::from_secs(10);

/// A local port of the sandbox: `(udp, port)`.
type PortKey = (bool, u16);

#[derive(Debug, Clone, Copy)]
struct Pending {
    rx: u64,
    tx: u64,
    since: Instant,
}

/// The split of one connection's App payload, for one worker generation at a time.
#[derive(Debug, Default)]
pub struct AppPayload {
    generation: Option<u64>,
    /// The worker's counters of each port at the previous sample.
    ports: HashMap<PortKey, (u64, u64)>,
    /// Bytes of ports no App was known to hold yet.
    pending: HashMap<PortKey, Pending>,
    /// Each forward's counters at the previous sample.
    forwards: HashMap<ForwardBindingId, (u64, u64)>,
    /// Each App's payload this generation, `(rx, tx)`.
    apps: BTreeMap<AppId, (u64, u64)>,
}

/// One forward's counters in a sample: its id, the App it ends at, and its bytes `(in, out)`.
#[derive(Debug, Clone, Copy)]
pub struct ForwardBytes {
    pub id: ForwardBindingId,
    pub app: AppId,
    pub rx: u64,
    pub tx: u64,
}

/// What a counter moved since `before`: a counter that went back started again (its entry went
/// and came back), so all of it is new.
const fn moved(now: u64, before: u64) -> u64 {
    if now >= before { now - before } else { now }
}

impl AppPayload {
    /// Take one sample of `generation`: the worker's per-port counters, which App holds each
    /// port now (`owners`), and the forwards' counters. Returns every App's payload so far.
    pub fn update(
        &mut self,
        generation: u64,
        ports: &[SandboxPortWire],
        owners: &HashMap<PortKey, AppId>,
        forwards: &[ForwardBytes],
        now: Instant,
    ) -> Vec<AppPayloadWire> {
        if self.generation != Some(generation) {
            *self = Self {
                generation: Some(generation),
                ..Self::default()
            };
        }
        let mut seen = HashMap::with_capacity(ports.len());
        for p in ports {
            let key = (p.udp, p.port);
            let (brx, btx) = self.ports.get(&key).copied().unwrap_or((0, 0));
            let (mut rx, mut tx) = (moved(p.rx_bytes, brx), moved(p.tx_bytes, btx));
            seen.insert(key, (p.rx_bytes, p.tx_bytes));
            match owners.get(&key) {
                Some(app) => {
                    if let Some(w) = self.pending.remove(&key) {
                        rx = rx.saturating_add(w.rx);
                        tx = tx.saturating_add(w.tx);
                    }
                    self.add(*app, rx, tx);
                }
                None if rx > 0 || tx > 0 => {
                    let w = self.pending.entry(key).or_insert(Pending {
                        rx: 0,
                        tx: 0,
                        since: now,
                    });
                    w.rx = w.rx.saturating_add(rx);
                    w.tx = w.tx.saturating_add(tx);
                }
                None => {}
            }
        }
        // A port the worker no longer reports was idle long enough: its last bytes came before.
        self.ports = seen;
        // Waiting bytes whose port got an owner since, though it carried nothing new.
        let ready: Vec<(PortKey, AppId)> = self
            .pending
            .keys()
            .filter_map(|k| owners.get(k).map(|app| (*k, *app)))
            .collect();
        for (key, app) in ready {
            if let Some(w) = self.pending.remove(&key) {
                self.add(app, w.rx, w.tx);
            }
        }
        self.pending
            .retain(|_, w| now.saturating_duration_since(w.since) < PENDING_FOR);

        let mut current = HashMap::with_capacity(forwards.len());
        for f in forwards {
            let (brx, btx) = self.forwards.get(&f.id).copied().unwrap_or((0, 0));
            self.add(f.app, moved(f.rx, brx), moved(f.tx, btx));
            current.insert(f.id, (f.rx, f.tx));
        }
        self.forwards = current;

        self.apps
            .iter()
            .map(|(app, (rx, tx))| AppPayloadWire {
                app_id: *app,
                rx_bytes: *rx,
                tx_bytes: *tx,
            })
            .collect()
    }

    fn add(&mut self, app: AppId, rx: u64, tx: u64) {
        let e = self.apps.entry(app).or_insert((0, 0));
        e.0 = e.0.saturating_add(rx);
        e.1 = e.1.saturating_add(tx);
    }
}
