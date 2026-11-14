//! The workspace's blocking locks: `parking_lot`'s `Mutex` and `RwLock` under a hand-over
//! schedule of our own.
//!
//! `parking_lot` unlocks unfairly: a free lock goes to whoever asks first, so the thread that
//! just unlocked can take it again before a thread that was already waiting has woken up. That is
//! what makes it fast. Until 0.12 the library also bounded the cost, handing a contended lock to
//! a waiter about every half millisecond; 0.13 removed that and kept only the explicit fair
//! unlock. Left alone, a thread that takes a lock in a loop (the netstack pump under load, a
//! writer working through a queue) keeps the others out for as long as it has work.
//!
//! The bound is ours now (`handover.rs`): a thread that has waited a quarter of a millisecond for
//! a lock is starved, and while any thread is, every unlock hands the lock straight to the thread
//! that has been in the queue longest. Every other unlock stays unfair, and a lock nobody is
//! starved for pays one atomic load.
//!
//! Every crate of the workspace takes its locks from here, so the schedule holds for all of
//! them; `deny.toml` keeps this generation of `parking_lot` out of the other crates.

#![forbid(unsafe_code)]

mod handover;
mod mutex;
mod rwlock;

pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
