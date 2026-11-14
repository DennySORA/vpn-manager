//! Ephemeral port allocation inside one netstack.

use std::collections::HashSet;

const EPHEMERAL_START: u16 = 49152;
const EPHEMERAL_END: u16 = 65535;

/// Next-fit allocator: freed ports are not reused until the range wraps, which keeps a just-closed
/// 4-tuple from being reused immediately.
pub struct PortAllocator {
    used: HashSet<u16>,
    next: u16,
}

impl PortAllocator {
    pub(crate) fn ephemeral() -> Self {
        Self {
            used: HashSet::new(),
            next: EPHEMERAL_START + (rand::random::<u16>() % (EPHEMERAL_END - EPHEMERAL_START)),
        }
    }

    pub(crate) fn alloc(&mut self) -> Option<u16> {
        let span = u32::from(EPHEMERAL_END - EPHEMERAL_START) + 1;
        for _ in 0..span {
            let candidate = self.next;
            self.next = if self.next == EPHEMERAL_END {
                EPHEMERAL_START
            } else {
                self.next + 1
            };
            if self.used.insert(candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Claim a specific port (listeners). Fails if already in use.
    pub(crate) fn claim(&mut self, port: u16) -> bool {
        port != 0 && self.used.insert(port)
    }

    /// Release a port; `0` means "not allocated here" and is ignored.
    pub(crate) fn release(&mut self, port: u16) {
        if port != 0 {
            self.used.remove(&port);
        }
    }
}
