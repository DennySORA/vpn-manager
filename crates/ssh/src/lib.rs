//! SSH Manager building blocks.
//!
//! The Store holds the SSH host entries; `~/.ssh/vpn-manager.conf` is generated from them
//! ([`render`]) and written only through [`files`] (atomic, no symlinks, this user's files only).
//! `~/.ssh/config` is read, never interpreted beyond host blocks ([`config`]), and edited only
//! once, when the user asks to add the `Include` line. Hosts that go through a Gateway use
//! `vpnctl ssh-proxy`, a SOCKS5 client ([`socks`]) that fails instead of connecting directly.

pub mod config;
pub mod files;
pub mod render;
pub mod socks;

/// File name of the generated configuration inside the SSH directory.
pub const MANAGED_FILE: &str = "vpn-manager.conf";
