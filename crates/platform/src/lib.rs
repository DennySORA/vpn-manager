//! Platform Manager: the only place VPN Manager performs OS operations — its key files,
//! process spawning, loopback listeners, locks, resource sampling, capability detection and (per
//! platform) sandboxes. Higher layers call these typed functions; nothing here takes shell
//! strings.

pub mod admission;
pub mod apps;
pub mod capabilities;
pub mod clock;
pub mod keystore;
pub mod limits;
pub mod listener;
pub mod lock;
pub mod logfiles;
pub mod netif;
pub mod nobufs;
pub mod paths;
pub mod peer;
pub mod probe;
pub mod process;
pub mod resources;
pub mod sandbox;
pub mod system;
