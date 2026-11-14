//! One VPN Instance worker (`vpnd instance`): Instance Controller, Instance DNS Controller,
//! Gateway Manager, Instance Port Controller, Instance Metrics and the inner Instance Watchdog.
//! Every flow it opens goes through `vpn_tunnel::TunnelConnector`; nothing here dials the host
//! network.

#![forbid(unsafe_code)]
pub mod connector_socket;
pub mod controller;
pub mod counters;
pub mod dns;
pub mod forward;
pub mod gateway;
pub mod inbound;
pub mod plane;
pub mod policy;
pub mod shaping;
pub mod transport;

#[cfg(feature = "testing")]
pub mod testsupport;
