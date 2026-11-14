//! Payload gate: which flow classes the netstack admits right now.
//!
//! Only the Instance Manager's `Activate` (relayed by the Instance Controller) may move the gate to
//! [`GateState::Open`]. Watchdogs may only tighten it. [`GateState::Sealed`] is terminal for the
//! worker's generation.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum GateState {
    /// Nothing admitted (worker configured, tunnel not yet started).
    Closed = 0,
    /// Control flows only: DNS health probes, Provider IP-check probes.
    Probe = 1,
    /// Everything admitted.
    Open = 2,
    /// Nothing admitted, permanently.
    Sealed = 3,
}

impl GateState {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Probe,
            2 => Self::Open,
            3 => Self::Sealed,
            _ => Self::Closed,
        }
    }

    #[must_use]
    pub const fn admits(self, class: FlowClass) -> bool {
        matches!(
            (self, class),
            (Self::Open, _) | (Self::Probe, FlowClass::Control)
        )
    }
}

/// Why a flow exists; decides which gate states admit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowClass {
    /// Health / readiness probes and Provider checks. Never carries App payload.
    Control,
    /// App, Gateway, Port-forward and Provider business traffic.
    Payload,
}

/// Atomic gate holder.
#[derive(Debug)]
pub struct Gate(AtomicU8);

impl Default for Gate {
    fn default() -> Self {
        Self(AtomicU8::new(GateState::Closed as u8))
    }
}

impl Gate {
    pub fn get(&self) -> GateState {
        GateState::from_u8(self.0.load(Ordering::Acquire))
    }

    /// Set a new state. A sealed gate never changes again; returns the state actually in force.
    pub fn set(&self, next: GateState) -> GateState {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if current == GateState::Sealed as u8 {
                return GateState::Sealed;
            }
            match self.0.compare_exchange_weak(
                current,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_matrix_and_terminal_seal() {
        assert!(!GateState::Closed.admits(FlowClass::Control));
        assert!(GateState::Probe.admits(FlowClass::Control));
        assert!(!GateState::Probe.admits(FlowClass::Payload));
        assert!(GateState::Open.admits(FlowClass::Payload));
        assert!(!GateState::Sealed.admits(FlowClass::Control));

        let gate = Gate::default();
        assert_eq!(gate.set(GateState::Open), GateState::Open);
        assert_eq!(gate.set(GateState::Sealed), GateState::Sealed);
        assert_eq!(
            gate.set(GateState::Open),
            GateState::Sealed,
            "sealed never reopens"
        );
        assert_eq!(gate.get(), GateState::Sealed);
    }
}
