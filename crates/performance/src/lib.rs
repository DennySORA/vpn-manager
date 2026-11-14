//! Performance Manager logic without I/O (`PERFORMANCE_MANAGER.md`, adapted in
//! docs/architecture.md §9): the metric formulas, fixed-bucket latency histograms, and the
//! passive analysis windows and series behind `GET /v1/performance/summary` and `/series`.
//!
//! The manager owns the processes and the Store and calls into this crate; nothing here opens a
//! socket, a file or a database.

#![forbid(unsafe_code)]

pub mod formula;
pub mod histogram;
pub mod passive;
pub mod series;
