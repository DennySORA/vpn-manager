//! Shared public types of VPN Manager: identifiers, entities, runtime status, operations, errors
//! and validation. This crate is the single source of truth for the HTTP/SSE contract; the
//! frontend's TypeScript types are generated from it with `ts-rs`.

#![forbid(unsafe_code)]

pub mod api;
pub mod blocklist;
pub mod builtin_blocklists;
pub mod common;
pub mod config;
pub mod error;
pub mod ids;
pub mod ipset;
pub mod metrics;
pub mod performance;
pub mod provider;
pub mod ssh_download;
pub mod status;
pub mod system;
pub mod text;
pub mod transport;
pub mod validation;
pub mod wgconf;

pub use api::*;
pub use builtin_blocklists::{BlocklistFamily, BlocklistFormat};
pub use common::*;
pub use config::*;
pub use error::*;
pub use ids::*;
pub use metrics::*;
pub use performance::*;
pub use provider::*;
pub use ssh_download::*;
pub use status::*;
pub use system::*;
pub use text::{Language, Text, TextError, Translations};
pub use transport::*;
pub use validation::{Issue, Severity, ValidationReport};
