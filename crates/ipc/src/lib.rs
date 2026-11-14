//! Typed local IPC between VPN Manager processes. Never an arbitrary method bus: every message
//! is a closed Rust enum, frames are size-bounded, and peers exchange protocol version and build
//! id before anything else.

pub mod control;
pub mod frame;
pub mod identity;
pub mod relay;
pub mod secret;
pub mod ssh_download;
pub mod worker;

pub use frame::{FrameReader, FrameWriter, split, split_with};
pub use secret::SecretBytes;
