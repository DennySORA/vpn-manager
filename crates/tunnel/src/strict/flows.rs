//! Which local ports belong to the worker's own sockets.
//!
//! In a strict sandbox the worker's flows (DNS upstream, health probes, Gateway dials, the
//! Provider connector) and the managed Apps' flows leave through the same TUN device with the
//! same source address. The packet filter tells them apart by the local port: the kernel
//! connector registers every socket it opens here *before* the socket sends anything, and never
//! sets `SO_REUSEADDR`/`SO_REUSEPORT`, so no App can bind the same address and port while the
//! entry exists (the kernel refuses the second bind).
//!
//! A port forward's tunnel port is registered the same way while it is reserved, with one
//! difference: nothing new comes in to it (a TCP connection request, a datagram) unless a
//! listener of the forward is open on it at that moment; a connection request meanwhile is
//! refused, as by a closed port.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use vpn_sync::Mutex;

use crate::netstack::FlowClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4 {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: L4,
    /// The tunnel address the socket is bound to.
    pub local: IpAddr,
    pub port: u16,
}

/// What a packet from the tunnel to one of the worker's ports meets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnInbound {
    Pass,
    Drop,
    /// A connection request to a port forward's port while nothing listens: refused (reset).
    Closed,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    class: FlowClass,
    /// A port forward's port: how many of its listeners are open (`None` for a client socket).
    listeners: Option<u32>,
}

/// Registry of the worker's own sockets, shared by the kernel connector and the packet filter.
#[derive(Clone, Default)]
pub struct OwnFlows(Arc<Mutex<HashMap<FlowKey, Entry>>>);

impl OwnFlows {
    /// Register `keys` until the returned guard is dropped.
    pub(crate) fn register(&self, keys: Vec<FlowKey>, class: FlowClass) -> FlowGuard {
        self.insert(keys, class, None)
    }

    /// Register a port forward's `keys` (payload) until the returned guard is dropped; nothing
    /// new comes in to them while no listener is open ([`Self::listen`]).
    pub(crate) fn reserve(&self, keys: Vec<FlowKey>) -> FlowGuard {
        self.insert(keys, FlowClass::Payload, Some(0))
    }

    fn insert(&self, keys: Vec<FlowKey>, class: FlowClass, listeners: Option<u32>) -> FlowGuard {
        let mut map = self.0.lock();
        for k in &keys {
            map.insert(*k, Entry { class, listeners });
        }
        drop(map);
        FlowGuard {
            flows: self.clone(),
            keys,
        }
    }

    /// Let new connections and datagrams in to the reserved `keys` until the returned guard is
    /// dropped.
    pub(crate) fn listen(&self, keys: Vec<FlowKey>) -> ListenGuard {
        let mut map = self.0.lock();
        for k in &keys {
            if let Some(Entry {
                listeners: Some(n), ..
            }) = map.get_mut(k)
            {
                *n += 1;
            }
        }
        ListenGuard {
            flows: self.clone(),
            keys,
        }
    }

    pub(crate) fn class_of(&self, key: &FlowKey) -> Option<FlowClass> {
        self.0.lock().get(key).map(|e| e.class)
    }

    /// What a packet from the tunnel to `key` meets: `None` when the port is not the worker's.
    /// A new TCP connection (`opening`) needs an open listener there (a port forward's port
    /// refuses it otherwise, a client socket's drops it), and so does every datagram to a port
    /// forward's UDP port; everything else for the worker's sockets passes.
    pub(crate) fn admits_inbound(&self, key: &FlowKey, opening: bool) -> Option<OwnInbound> {
        let entry = *self.0.lock().get(key)?;
        Some(match (key.proto, entry.listeners) {
            (_, Some(n)) if n > 0 => OwnInbound::Pass,
            (L4::Tcp, Some(_)) if opening => OwnInbound::Closed,
            (L4::Tcp, None) if opening => OwnInbound::Drop,
            (L4::Tcp, _) | (L4::Udp, None) => OwnInbound::Pass,
            (L4::Udp, Some(_)) => OwnInbound::Drop,
        })
    }
}

/// Removes its keys from the registry when dropped (the socket is closed with it).
pub struct FlowGuard {
    flows: OwnFlows,
    keys: Vec<FlowKey>,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        let mut map = self.flows.0.lock();
        for k in &self.keys {
            map.remove(k);
        }
    }
}

/// Closes its listener on a port forward's keys when dropped.
pub struct ListenGuard {
    flows: OwnFlows,
    keys: Vec<FlowKey>,
}

impl Drop for ListenGuard {
    fn drop(&mut self) {
        let mut map = self.flows.0.lock();
        for k in &self.keys {
            if let Some(Entry {
                listeners: Some(n), ..
            }) = map.get_mut(k)
            {
                *n = n.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_live_exactly_as_long_as_their_guard() {
        let flows = OwnFlows::default();
        let key = FlowKey {
            proto: L4::Udp,
            local: "10.99.0.2".parse().unwrap(),
            port: 40000,
        };
        let other_family = FlowKey {
            local: "fd99::2".parse().unwrap(),
            ..key
        };
        let guard = flows.register(vec![key], FlowClass::Control);
        assert_eq!(flows.class_of(&key), Some(FlowClass::Control));
        assert_eq!(
            flows.class_of(&other_family),
            None,
            "the same port number on the other family is not ours"
        );
        drop(guard);
        assert_eq!(flows.class_of(&key), None);
        assert!(flows.0.lock().is_empty());
    }

    #[test]
    fn a_forwarded_port_takes_new_traffic_only_while_it_listens() {
        let flows = OwnFlows::default();
        let local: IpAddr = "10.99.0.2".parse().unwrap();
        let tcp = FlowKey {
            proto: L4::Tcp,
            local,
            port: 51234,
        };
        let udp = FlowKey {
            proto: L4::Udp,
            ..tcp
        };
        let client = FlowKey { port: 40000, ..tcp };
        let _c = flows.register(vec![client], FlowClass::Payload);
        assert_eq!(flows.admits_inbound(&client, false), Some(OwnInbound::Pass));
        assert_eq!(
            flows.admits_inbound(&client, true),
            Some(OwnInbound::Drop),
            "nothing listens on a client socket"
        );
        let held = flows.reserve(vec![tcp, udp]);
        assert_eq!(flows.class_of(&tcp), Some(FlowClass::Payload));
        assert_eq!(flows.admits_inbound(&tcp, true), Some(OwnInbound::Closed));
        assert_eq!(
            flows.admits_inbound(&tcp, false),
            Some(OwnInbound::Pass),
            "established ones go on"
        );
        assert_eq!(flows.admits_inbound(&udp, false), Some(OwnInbound::Drop));
        let first = flows.listen(vec![tcp, udp]);
        let second = flows.listen(vec![udp]);
        assert_eq!(flows.admits_inbound(&tcp, true), Some(OwnInbound::Pass));
        assert_eq!(flows.admits_inbound(&udp, false), Some(OwnInbound::Pass));
        drop(first);
        assert_eq!(flows.admits_inbound(&tcp, true), Some(OwnInbound::Closed));
        assert_eq!(
            flows.admits_inbound(&udp, false),
            Some(OwnInbound::Pass),
            "one still open"
        );
        drop(second);
        assert_eq!(flows.admits_inbound(&udp, false), Some(OwnInbound::Drop));
        drop(held);
        assert_eq!(flows.admits_inbound(&tcp, false), None);
    }
}
