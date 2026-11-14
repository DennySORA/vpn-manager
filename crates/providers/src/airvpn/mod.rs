// SPDX-License-Identifier: GPL-3.0-or-later

//! `AirVPN` adapter: the account's devices and the server catalog.
//!
//! The devices with their `WireGuard` keys (`act=user`) and the server catalog (`act=manifest`)
//! are fetched with the encrypted bootstrap protocol of `AirVPN`'s official client Eddie — the
//! automation path for an account that has only a user name and a password.
//!
//! Sources: Eddie at commit `67e213bf` — `resources/providers/AirVPN.json` (RSA key, bootstrap
//! addresses), `src/Lib.Core/Providers/Service.cs` (exchange, parameters, group defaults, entry
//! addresses), `Engine.cs` (`Auth`), `ConfigBuilder/WireGuard.cs` and `ProfileOptions.cs` (MTU,
//! keepalive), `ConnectionInfo.cs` (load) — and the previous implementation
//! (`web/adapters/airvpn/bootstrap.mjs`, `service.mjs`).
//!
//! - The exchange (`bootstrap`) is plain HTTP `POST /` to a bootstrap address on port 80, by
//!   `AirVPN`'s design: the parameters travel AES-256-CBC encrypted under a fresh key that only
//!   `AirVPN`'s RSA-4096 key unwraps, and the answer comes back under the same key. That key and
//!   the addresses are pinned here ([`RSA_MODULUS`], [`BOOTSTRAP_IPS`]) and never taken from a
//!   manifest, so the manager can allow exactly these four IPv4 addresses. Eddie's IPv6 and
//!   host-name bootstrap URLs are left out: this crate never resolves names, and dials IPv4 here.
//! - Addresses are tried in order, [`ATTEMPT_TIMEOUT`] each: a transport failure, a status
//!   other than 200 or an answer that does not decrypt moves on to the next address. A
//!   decrypted answer is final. Eddie moves on after a refusal too; this does not, since that
//!   would only repeat a password attempt.
//! - AES-CBC answers carry no MAC (`AirVPN`'s design): only the secret key and the strict parsing
//!   below stand between a tampered answer and its use.
//! - [`ProviderError::AuthRejected`]: an `error` attribute on the document element (Eddie
//!   `FetchUrls`); for `act=user` also `message_action="stop"`, a non-empty `message` (Eddie
//!   `Engine.Auth` does not log in then) or no `login`.
//! - IPv6 is kept wherever `AirVPN` provides it (device address and resolver, server entry
//!   addresses); the previous implementation dropped it.
//!
//! The adapter is stateless like the Mullvad one: caching, preflight IP checks and permits are
//! the caller's. Errors and `Debug` never carry the XML, the user name, the password or a key.
//!
//! Forwarded ports have no API at all: [`site`] signs in to `AirVPN`'s website with the same user
//! name and password and uses the Client Area's Ports page (list, reserve, delete). Its session
//! is the caller's to keep, in memory.

mod bootstrap;
mod servers;
pub mod site;
pub mod status;
mod user;
mod xml;

use std::net::Ipv4Addr;
use std::time::Duration;

use aws_lc_rs::rsa::PublicEncryptingKey;

pub use servers::{
    EntryMode, MTU, PERSISTENT_KEEPALIVE, Server, ServerCatalog, ServerWarning, WireGuardParams,
    wireguard_params, wireguard_params_at,
};
pub use user::{Credentials, Device, InvalidCredentials, PresharedKey, PrivateKey, UserInfo};

use crate::error::ProviderError;
use crate::https::Connect;

/// The bootstrap addresses of Eddie's `AirVPN.json`, in its order: the IPv4 ones.
pub const BOOTSTRAP_IPS: [Ipv4Addr; 4] = [
    Ipv4Addr::new(63, 33, 78, 166),
    Ipv4Addr::new(54, 93, 175, 114),
    Ipv4Addr::new(82, 196, 3, 205),
    Ipv4Addr::new(63, 33, 116, 50),
];
/// The bootstrap URLs are `http://` without a port.
pub const BOOTSTRAP_PORT: u16 = 80;
/// `auth_rsa_modulus` of Eddie's `AirVPN.json`: base64, big-endian, 4096 bits.
pub const RSA_MODULUS: &str = "wuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPSMDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSjcoJQgeY66D429m1BDWY3f65c+8HrCQ8qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkNSe4c8gFfHj3ANYwDhTQijb+VaVZqPmxVJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5Jjk2AQ/tyDiybwwZ32fOqYJVGxs13guOlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQK1cWM5AVu4apoNIFG+svS/2kmn0Nx8DRVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlrmW3iWKeFIwZnHt2PMceJMqziV8rRGh9gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn06cotQChpVnALA83hFW5LXJvc85iloWJkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTlSw1SlMEflU4bZiZP8di5e2OJI6vOHjdM2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+Vc=";
/// `auth_rsa_exponent` of Eddie's `AirVPN.json` (65537).
pub const RSA_EXPONENT: &str = "AQAB";
/// Spec: 10 s per attempt (connect, request and answer), as the previous implementation.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest encrypted answer read; the previous implementation's limit. A full manifest is far
/// smaller.
pub const RESPONSE_LIMIT: usize = 8 * 1024 * 1024;

/// `software` parameter: Eddie sends `EddieDesktop_<version>`, the previous implementation
/// `vpn-manager-provider_5`.
const SOFTWARE: &str = "vpn-manager_1";
/// `version` parameter, as the previous implementation sent it.
const VERSION: &str = "500";

/// `AirVPN` bootstrap client over the caller's connector: IPv4, port 80, one pinned address per
/// attempt. Cheap to clone when `C` is.
#[derive(Clone)]
pub struct AirVpn<C> {
    connector: C,
    rsa: PublicEncryptingKey,
    timeout: Duration,
}

impl<C: Connect> AirVpn<C> {
    /// Client for `AirVPN`'s pinned key ([`RSA_MODULUS`], [`RSA_EXPONENT`]).
    pub fn new(connector: C) -> Self {
        Self::build(connector, bootstrap::pinned_key())
    }

    /// Client that seals requests for `key` instead of `AirVPN`'s, so a test can play the
    /// bootstrap server with a throwaway key. Products always use [`AirVpn::new`].
    #[cfg(any(test, feature = "testing"))]
    pub const fn with_rsa_key(connector: C, key: PublicEncryptingKey) -> Self {
        Self::build(connector, key)
    }

    const fn build(connector: C, rsa: PublicEncryptingKey) -> Self {
        Self {
            connector,
            rsa,
            timeout: ATTEMPT_TIMEOUT,
        }
    }

    /// Deadline per attempt, e.g. the remaining operation budget when below
    /// [`ATTEMPT_TIMEOUT`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub const fn connector(&self) -> &C {
        &self.connector
    }

    /// `act=user`: the account, its `WireGuard` peer key and its devices, each with the private
    /// key and preshared key `AirVPN` issued for it.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Unavailable`] when no bootstrap address answers with a decryptable
    /// document, [`ProviderError::AuthRejected`] when `AirVPN` refuses the credentials,
    /// [`ProviderError::Refused`] when the connector will not carry the request, and
    /// [`ProviderError::ContractDrift`] when the decrypted document does not parse.
    pub async fn user(&self, credentials: &Credentials) -> Result<UserInfo, ProviderError> {
        let params = params("user", credentials);
        self.fetch(&params, user::parse_user).await
    }

    /// `act=manifest` with `ts=0` (the whole manifest): the `WireGuard` server catalog. `AirVPN`
    /// asks for the account's credentials here too.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Unavailable`] when no bootstrap address answers with a decryptable
    /// document, [`ProviderError::AuthRejected`] when `AirVPN` refuses the credentials,
    /// [`ProviderError::Refused`] when the connector will not carry the request, and
    /// [`ProviderError::ContractDrift`] when the decrypted document does not parse.
    pub async fn manifest(
        &self,
        credentials: &Credentials,
    ) -> Result<ServerCatalog, ProviderError> {
        let mut params = params("manifest", credentials);
        params.push(("ts", b"0"));
        self.fetch(&params, servers::parse_manifest).await
    }

    async fn fetch<T>(
        &self,
        params: &[(&str, &[u8])],
        parse: fn(&str) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        bootstrap::fetch(&self.connector, &self.rsa, params, self.timeout, parse).await
    }
}

/// Eddie's parameters (`FetchUrls`) with the previous implementation's values and order, and
/// this product's `software`.
fn params<'a>(act: &'a str, credentials: &'a Credentials) -> Vec<(&'a str, &'a [u8])> {
    vec![
        ("act", act.as_bytes()),
        ("login", credentials.username().as_bytes()),
        ("password", credentials.password().as_bytes()),
        ("software", SOFTWARE.as_bytes()),
        ("arch", arch().as_bytes()),
        ("system", system().as_bytes()),
        ("version", VERSION.as_bytes()),
    ]
}

/// `arch` as the previous implementation sent it: Node's `process.arch` name.
fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "powerpc64" => "ppc64",
        "loongarch64" => "loong64",
        other => other,
    }
}

/// `system` as the previous implementation sent it: Node's `process.platform` name.
fn system() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        "solaris" => "sunos",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    /// The manager's direct bootstrap may reach exactly these addresses: nothing here dials
    /// anything it does not allow.
    #[test]
    fn bootstrap_addresses_are_allowlisted() {
        for ip in BOOTSTRAP_IPS {
            assert!(
                vpn_domain::BOOTSTRAP_ALLOWLIST
                    .iter()
                    .any(|(h, p)| *h == ip.to_string() && *p == BOOTSTRAP_PORT),
                "{ip} missing from BOOTSTRAP_ALLOWLIST"
            );
        }
        assert!(
            vpn_domain::BOOTSTRAP_ALLOWLIST
                .iter()
                .any(|(h, p)| *h == status::STATUS_HOST && *p == 443)
        );
    }

    use super::*;
}
