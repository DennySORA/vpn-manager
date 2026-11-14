//! Provider egress for the controller: the Mullvad adapter ([`mullvad`]), the `AirVPN` adapter
//! ([`airvpn`]), the exit IP checkers ([`ipcheck`]) and the HTTP/1.1 client they share
//! ([`https`]).
//!
//! This crate never opens a socket and never resolves a name. Every request goes through a
//! [`Connect`] the caller chooses — the selected Instance's private connector, or the one-time
//! bootstrap socket the manager hands over (docs/architecture.md §7) — pinned to one address
//! [`Family`]. TLS terminates here: certificates are always verified, there is no proxy, no
//! redirect, no HTTP/2, and every response is bounded in size and time. The one exception to
//! TLS is `AirVPN`'s bootstrap, plain HTTP to pinned IPv4 addresses whose payload is RSA/AES
//! encrypted end to end (see [`airvpn`]).
//!
//! Account numbers, access tokens, passwords and `WireGuard` keys live in zeroizing types whose
//! `Debug`/`Display` are redacted; errors never carry provider bodies or secrets.

#![forbid(unsafe_code)]

pub mod airvpn;
pub mod error;
pub mod fetch;
pub mod https;
pub mod ipcheck;
pub mod mullvad;

pub use error::{ProviderError, Unavailable};
pub use https::{
    BoxedStream, Confirmation, Connect, Family, HttpError, HttpsClient, OpenError, Opened, Permit,
    Refusal, Target, Tls,
};

/// Provider-supplied display text (names of countries, cities, devices): trimmed, at most `max`
/// characters, no control characters. `Ok(None)` when empty; `Err` when it is not plain text,
/// which callers report as contract drift.
pub(crate) fn display_text(value: &str, max: usize) -> Result<Option<String>, NotText> {
    let value = value.trim();
    if value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(NotText);
    }
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

/// A provider string that is not plain display text.
#[derive(Debug)]
pub(crate) struct NotText;
