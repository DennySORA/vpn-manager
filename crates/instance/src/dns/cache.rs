//! Per-resolver answer cache: an LRU bounded both by `max_entries` and by bytes, keyed by
//! (lowercase name, record type). Entries live for the answer's TTL; expired entries are dropped
//! when touched or pushed out by newer ones.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use lru::LruCache;
use tokio::time::Instant;
use vpn_sync::Mutex;

use super::wire::Question;

/// Total size of cached answers (wire bytes plus bookkeeping), whatever `max_entries` says.
const BYTE_BUDGET: usize = 8 << 20;
/// Answers larger than this are returned but never cached.
const MAX_ENTRY_BYTES: usize = 16 << 10;
/// Rough per-entry overhead (key, LRU node, `Answer` fields).
const ENTRY_OVERHEAD: usize = 160;

/// One upstream answer, shared by the cache and every coalesced lookup that waited for it.
#[derive(Debug)]
pub(super) struct Answer {
    /// The validated upstream response in wire format.
    pub wire: Box<[u8]>,
    /// `NoError` or `NXDomain` (other codes are upstream failures and never become an `Answer`).
    pub rcode: ResponseCode,
    /// A/AAAA addresses of the question's name, CNAMEs followed (empty for other types).
    pub addrs: Vec<IpAddr>,
    /// Lifetime in seconds: smallest answer TTL clamped to `max_ttl_secs`, or
    /// `negative_ttl_secs` for NXDOMAIN/NODATA.
    pub ttl: u32,
    pub fetched: Instant,
}

impl Answer {
    /// Whole seconds since the answer was fetched, and seconds of lifetime left.
    pub fn age(&self, now: Instant) -> (u32, u32) {
        let elapsed = u32::try_from(now.saturating_duration_since(self.fetched).as_secs())
            .unwrap_or(u32::MAX);
        (elapsed, self.ttl.saturating_sub(elapsed))
    }

    fn expires(&self) -> Instant {
        self.fetched + Duration::from_secs(u64::from(self.ttl))
    }

    fn cost(&self) -> usize {
        self.wire.len() + self.addrs.len() * size_of::<IpAddr>() + ENTRY_OVERHEAD
    }
}

struct Entry {
    answer: Arc<Answer>,
    cost: usize,
}

struct Lru {
    map: LruCache<Question, Entry>,
    bytes: usize,
}

pub(super) struct Cache {
    /// `None` when `max_entries` is 0 (caching disabled).
    lru: Option<Mutex<Lru>>,
}

impl Cache {
    pub fn new(max_entries: u32) -> Self {
        let lru = usize::try_from(max_entries)
            .ok()
            .and_then(NonZeroUsize::new)
            .map(|cap| {
                Mutex::new(Lru {
                    map: LruCache::new(cap),
                    bytes: 0,
                })
            });
        Self { lru }
    }

    pub fn get(&self, key: &Question, now: Instant) -> Option<Arc<Answer>> {
        let mut lru = self.lru.as_ref()?.lock();
        let entry = lru.map.get(key)?;
        if entry.answer.expires() > now {
            return Some(entry.answer.clone());
        }
        if let Some(stale) = lru.map.pop(key) {
            lru.bytes = lru.bytes.saturating_sub(stale.cost);
        }
        None
    }

    /// Forgets every answer (they came from resolvers no longer asked).
    pub fn clear(&self) {
        if let Some(lru) = self.lru.as_ref() {
            let mut lru = lru.lock();
            lru.map.clear();
            lru.bytes = 0;
        }
    }

    pub fn insert(&self, key: Question, answer: Arc<Answer>) {
        let Some(lru) = self.lru.as_ref() else {
            return;
        };
        let cost = answer.cost();
        if answer.ttl == 0 || cost > MAX_ENTRY_BYTES {
            return;
        }
        let mut lru = lru.lock();
        if let Some(old) = lru.map.pop(&key) {
            lru.bytes = lru.bytes.saturating_sub(old.cost);
        }
        while lru.bytes + cost > BYTE_BUDGET {
            match lru.map.pop_lru() {
                Some((_, evicted)) => lru.bytes = lru.bytes.saturating_sub(evicted.cost),
                None => break,
            }
        }
        if let Some((_, evicted)) = lru.map.push(key, Entry { answer, cost }) {
            lru.bytes = lru.bytes.saturating_sub(evicted.cost);
        }
        lru.bytes += cost;
    }
}
