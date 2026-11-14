//! How a file's bytes are read: reads asked for in the order of the file, several in flight on
//! each connection that serves it (a *lane*), and answered so that the transfer takes them in
//! the order of the file again.
//!
//! [`Reads`] stands between the two. The transfer asks ([`Reads::ask`]) for as many reads as
//! the lanes have room for and awaits the answers in the order it asked. A [`Lane`] takes the
//! next read whenever it has room: its [`Pipeline`] decides how many it keeps in flight, within
//! its share of the manager-wide [`ReadBudget`].

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use russh_sftp::client::RawSftpSession;
use russh_sftp::protocol::StatusCode;
use tokio::sync::{Notify, oneshot};
use vpn_sync::Mutex;

use crate::session::{RemoteError, remote_error};

/// What a read brought: the bytes (none where the file ends), or why the server gave none.
pub type Answer = Result<Vec<u8>, RemoteError>;

/// One read of the remote file, on its way to a lane.
pub struct Read {
    offset: u64,
    len: u32,
    answer: oneshot::Sender<Answer>,
}

impl Read {
    /// Give the transfer its answer (nothing happens when it no longer waits for it).
    pub fn answer(self, answer: Answer) {
        let _ = self.answer.send(answer);
    }
}

/// A read the transfer waits for.
pub struct Pending {
    offset: u64,
    len: u32,
    answer: oneshot::Receiver<Answer>,
}

/// What became of a read.
pub struct Reply {
    pub offset: u64,
    pub len: u32,
    /// `None`: the lane that took it left with it.
    pub answer: Option<Answer>,
}

impl Future for Pending {
    type Output = Reply;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Reply> {
        let (offset, len) = (self.offset, self.len);
        Pin::new(&mut self.answer).poll(cx).map(|answer| Reply {
            offset,
            len,
            answer: answer.ok(),
        })
    }
}

/// The reads a transfer waits for, and the room its lanes have for them.
#[derive(Default)]
pub struct Reads {
    wanted: Mutex<VecDeque<Read>>,
    /// A read waits to be taken.
    asked: Notify,
    /// Reads all lanes together keep in flight.
    room: AtomicUsize,
    /// The lanes have more room than before.
    grew: Notify,
}

impl Reads {
    /// Reads the transfer may have asked for and not yet written: what its lanes keep in flight.
    pub fn room(&self) -> usize {
        self.room.load(Ordering::Relaxed)
    }

    /// Returns once the lanes have more room than before.
    pub async fn grown(&self) {
        self.grew.notified().await;
    }

    /// Ask for `len` bytes at `offset`, after the reads already asked for.
    pub fn ask(&self, offset: u64, len: u32) -> Pending {
        let (read, pending) = read(offset, len);
        self.wanted.lock().push_back(read);
        self.asked.notify_one();
        pending
    }

    /// Ask for a read again, ahead of every read not yet taken: its lane left with it.
    pub fn ask_first(&self, offset: u64, len: u32) -> Pending {
        let (read, pending) = read(offset, len);
        self.wanted.lock().push_front(read);
        self.asked.notify_one();
        pending
    }

    /// The reads not yet taken are no longer wanted.
    pub fn forget(&self) {
        self.wanted.lock().clear();
    }

    /// The next read a lane with room does.
    async fn take(&self) -> Read {
        loop {
            let next = self.wanted.lock().pop_front();
            match next {
                // The transfer no longer waits for it.
                Some(read) if read.answer.is_closed() => {}
                Some(read) => return read,
                None => self.asked.notified().await,
            }
        }
    }
}

fn read(offset: u64, len: u32) -> (Read, Pending) {
    let (tx, rx) = oneshot::channel();
    (
        Read {
            offset,
            len,
            answer: tx,
        },
        Pending {
            offset,
            len,
            answer: rx,
        },
    )
}

type Flying = Pin<Box<dyn Future<Output = (Read, Answer, Duration)> + Send>>;

/// One connection serving a file's reads.
pub struct Lane<'a> {
    sftp: Arc<RawSftpSession>,
    handle: &'a str,
    /// The length of a full read, for the lane's share of the budget.
    chunk: u64,
    reads: &'a Reads,
    share: Fetching<'a>,
    pipeline: Pipeline,
    /// The reads it keeps in flight now: its part of `reads.room`.
    room: usize,
    /// It takes no more reads.
    leaving: bool,
    flying: FuturesUnordered<Flying>,
    /// When the server last answered a read, or the lane began to wait for one.
    heard: tokio::time::Instant,
}

/// What a lane did in one [`Lane::turn`].
pub enum Turn {
    /// It took a read, or the server answered one.
    Moved,
    /// The server failed this read, and why.
    Failed(Read, RemoteError),
}

impl<'a> Lane<'a> {
    /// A lane for `handle` (an open file of `sftp`'s connection) with room from the start.
    pub fn new(
        sftp: Arc<RawSftpSession>,
        handle: &'a str,
        chunk: u64,
        reads: &'a Reads,
        budget: &'a ReadBudget,
    ) -> Self {
        let mut lane = Self {
            sftp,
            handle,
            chunk,
            reads,
            share: budget.enter(),
            pipeline: Pipeline::new(Instant::now()),
            room: 0,
            leaving: false,
            flying: FuturesUnordered::new(),
            heard: tokio::time::Instant::now(),
        };
        lane.settle();
        lane
    }

    /// Take its room from the pipeline and the budget, and tell the transfer when it grew.
    fn settle(&mut self) {
        let room = if self.leaving {
            0
        } else {
            self.pipeline.depth.min(self.share.depth(self.chunk))
        };
        if room > self.room {
            self.reads
                .room
                .fetch_add(room - self.room, Ordering::Relaxed);
            self.reads.grew.notify_one();
        } else {
            self.reads
                .room
                .fetch_sub(self.room - room, Ordering::Relaxed);
        }
        self.room = room;
    }

    /// Take no more reads: the transfer asks for no more than the other lanes hold, and this
    /// one only answers what it has in flight (while [`Lane::busy`]).
    pub fn leave(&mut self) {
        self.leaving = true;
        self.settle();
    }

    /// Whether reads are in flight.
    pub fn busy(&self) -> bool {
        !self.flying.is_empty()
    }

    /// Since when the server owes this lane an answer; `None` while nothing is in flight.
    pub fn waits_since(&self) -> Option<tokio::time::Instant> {
        self.busy().then_some(self.heard)
    }

    /// Take the next read when there is room, or hand on the next answer. Without room and
    /// without a read in flight it never returns.
    pub async fn turn(&mut self) -> Turn {
        self.settle();
        let reads = self.reads;
        tokio::select! {
            Some((read, answer, took)) = self.flying.next() => {
                self.heard = tokio::time::Instant::now();
                match answer {
                    Ok(data) => {
                        self.pipeline.answered(took, Instant::now());
                        read.answer(Ok(data));
                        Turn::Moved
                    }
                    Err(why) => Turn::Failed(read, why),
                }
            }
            read = reads.take(), if self.flying.len() < self.room => {
                if self.flying.is_empty() {
                    self.heard = tokio::time::Instant::now();
                }
                self.start(read);
                Turn::Moved
            }
            else => std::future::pending().await,
        }
    }

    fn start(&self, read: Read) {
        let (sftp, handle) = (self.sftp.clone(), self.handle.to_owned());
        self.flying.push(Box::pin(async move {
            let asked = Instant::now();
            let answer = match sftp.read(handle, read.offset, read.len).await {
                Ok(data) => Ok(data.data),
                Err(russh_sftp::client::error::Error::Status(s))
                    if s.status_code == StatusCode::Eof =>
                {
                    Ok(Vec::new())
                }
                Err(e) => Err(remote_error(e)),
            };
            (read, answer, asked.elapsed())
        }));
    }
}

impl Drop for Lane<'_> {
    fn drop(&mut self) {
        self.reads.room.fetch_sub(self.room, Ordering::Relaxed);
    }
}

/// Reads a lane keeps in flight when it starts.
const PIPELINE_START: usize = 16;
/// The most reads a lane keeps in flight: with `READ_CHUNK`, 16 MiB on their way.
const PIPELINE_MAX: usize = 128;
/// The shortest time, and the fewest answers, a depth is measured over before the next decision.
const PIPELINE_EPOCH: Duration = Duration::from_secs(2);
const PIPELINE_EPOCH_READS: u32 = 8;
/// While a read takes less than this many times the shortest one, the depth doubles.
const PIPELINE_GROW_BELOW: f64 = 3.0;
/// Once a read takes this many times the shortest one, the depth is halved.
const PIPELINE_SHRINK_FROM: f64 = 8.0;
/// No read is taken to be answered faster than this (a floor of zero would never be matched).
const PIPELINE_FLOOR: Duration = Duration::from_millis(1);

/// How many reads a lane keeps in flight.
///
/// The server answers a read one round trip after it was asked, so a connection carries at most
/// `depth × read length` per round trip: on a long path a fixed depth caps the rate however much
/// the path carries (measured 2026-11-10 over a 307 ms round trip: 3.2 MB/s for one file with 16
/// reads of 128 KiB in flight, 11.9 MB/s with 64).
///
/// The time a read takes says how much is queued: with a rate `r`, `depth × read length / r`.
/// While that stays within a few round trips the depth doubles; once reads mostly wait — for
/// the path, or for this side's disk — a deeper pipeline would only hold more memory, and the
/// depth is halved. In between it stays.
///
/// "A few round trips", not one: a server whose queue runs dry holds back the last partial
/// packet of an answer until the data before it is acknowledged (sshd leaves Nagle's algorithm
/// on for file transfers), which adds a round trip to every read and halves the rate. With
/// more reads queued than one round trip takes away, the queue does not run dry. The same
/// measurement showed it: reads took 2.1 times the shortest one at a depth of 16, and the rate
/// tripled when the depth doubled.
#[derive(Debug)]
struct Pipeline {
    depth: usize,
    /// The shortest time a read took from asked to answered: one round trip, nothing queued.
    floor: Option<Duration>,
    /// Start of the running measurement, the reads answered since and the time they took.
    since: Instant,
    reads: u32,
    took: Duration,
}

impl Pipeline {
    const fn new(now: Instant) -> Self {
        Self {
            depth: PIPELINE_START,
            floor: None,
            since: now,
            reads: 0,
            took: Duration::ZERO,
        }
    }

    /// A read was answered at `now`, `took` after it was asked: the depth may change with it.
    fn answered(&mut self, took: Duration, now: Instant) {
        let took = took.max(PIPELINE_FLOOR);
        let floor = *self.floor.insert(self.floor.map_or(took, |f| f.min(took)));
        self.reads += 1;
        self.took += took;
        if now.saturating_duration_since(self.since) < PIPELINE_EPOCH
            || self.reads < PIPELINE_EPOCH_READS
        {
            return;
        }
        let usual = self.took / self.reads;
        let before = self.depth;
        if usual <= floor.mul_f64(PIPELINE_GROW_BELOW) {
            self.depth = (self.depth * 2).min(PIPELINE_MAX);
        } else if usual >= floor.mul_f64(PIPELINE_SHRINK_FROM) {
            self.depth = (self.depth / 2).max(PIPELINE_START);
        }
        tracing::debug!(
            reads = self.reads,
            usual_ms = usual.as_millis(),
            floor_ms = floor.as_millis(),
            before,
            depth = self.depth,
            "SSH download: reads in flight on one connection"
        );
        self.since = now;
        self.reads = 0;
        self.took = Duration::ZERO;
    }
}

/// What all files being fetched may have asked for and not yet written, together.
///
/// Every lane keeps an equal share of it in flight and never less than the starting depth: a
/// file that starts next to large ones is not slowed by them, and their pipelines give way as
/// their reads are answered. Without it every connection could hold the deepest pipeline at
/// once (24 × 16 MiB), which a slow local disk turns into that much memory.
pub struct ReadBudget {
    bytes: u64,
    fetching: AtomicU64,
}

/// A lane's place in the [`ReadBudget`], for as long as it serves reads.
struct Fetching<'a>(&'a ReadBudget);

impl ReadBudget {
    pub const fn new(bytes: u64) -> Self {
        Self {
            bytes,
            fetching: AtomicU64::new(0),
        }
    }

    fn enter(&self) -> Fetching<'_> {
        self.fetching.fetch_add(1, Ordering::Relaxed);
        Fetching(self)
    }
}

impl Fetching<'_> {
    /// Reads of `chunk` bytes this lane may keep in flight now.
    fn depth(&self, chunk: u64) -> usize {
        let lanes = self.0.fetching.load(Ordering::Relaxed).max(1);
        usize::try_from(self.0.bytes / lanes / chunk.max(1))
            .unwrap_or(usize::MAX)
            .max(PIPELINE_START)
    }
}

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        self.0.fetching.fetch_sub(1, Ordering::Relaxed);
    }
}
