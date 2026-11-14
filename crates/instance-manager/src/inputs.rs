//! What a worker takes from each piece of configuration — never names, locations or dates —
//! fingerprinted when a generation starts and compared after every save, so the status says
//! exactly which saved changes a restart would apply. Secrets are referenced, never read.
//! Gateways are not part of it: they change on a running worker.

use serde::Serialize;
use sha2::{Digest, Sha256};
use vpn_domain::{
    ConfigPart, DnsProfile, InstanceId, InstanceSpec, RuntimeProfile, SecurityProfile,
};
use vpn_store::Store;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInputs {
    instance: String,
    profile: String,
    dns: Option<String>,
    security: Option<String>,
}

#[expect(
    clippy::expect_used,
    reason = "plain configuration values (ids, numbers, strings, keys, addresses; no maps) always serialize to JSON"
)]
fn fingerprint(value: &impl Serialize) -> String {
    // Struct fields serialize in declaration order and these types hold no maps, so equal
    // inputs give equal bytes.
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("configuration serializes"),
    ))
}

impl WorkerInputs {
    /// Mirrors what `resolve` hands the worker.
    pub fn of(
        spec: &InstanceSpec,
        profile: &RuntimeProfile,
        dns: Option<&DnsProfile>,
        security: Option<&SecurityProfile>,
    ) -> Self {
        let (i, p) = (&profile.interface, &profile.peer);
        Self {
            // Bandwidth caps are not part of it: a running worker applies them at once.
            instance: fingerprint(&(
                spec.profile_id,
                spec.dns_profile_id,
                spec.security_profile_id,
                spec.limits.max_tcp_flows,
                spec.limits.max_udp_flows,
                spec.limits.memory_mib,
                spec.strict,
            )),
            profile: fingerprint(&(
                i.private_key,
                &i.public_key,
                &i.addresses,
                i.mtu,
                &i.dns,
                &p.public_key,
                p.preshared_key,
                p.endpoint,
                &p.allowed_ips,
                p.persistent_keepalive,
            )),
            dns: dns.map(|d| {
                fingerprint(&(
                    &d.servers,
                    &d.cache,
                    d.query_timeout_ms,
                    d.attempts,
                    d.on_failure,
                ))
            }),
            // The base rules and the auto-ban settings are fixed for a generation. Blocklists
            // are not part of it: a running worker gets them as an overlay without a restart.
            security: security.map(|s| {
                fingerprint(&(
                    &s.allow_private,
                    &s.blocked_ports,
                    &s.allowed_destinations,
                    &s.allowed_ports,
                    &s.auto_ban,
                ))
            }),
        }
    }

    /// The parts of `now` a generation started with `self` does not run.
    pub fn pending(&self, now: &Self) -> Vec<ConfigPart> {
        [
            (ConfigPart::Instance, self.instance != now.instance),
            (ConfigPart::Profile, self.profile != now.profile),
            (ConfigPart::Dns, self.dns != now.dns),
            (ConfigPart::Security, self.security != now.security),
        ]
        .into_iter()
        .filter_map(|(part, changed)| changed.then_some(part))
        .collect()
    }
}

/// The inputs an Instance would start with now; `None` while something it needs is missing (a
/// start would then fail and say why).
pub async fn current(store: &Store, id: InstanceId) -> Option<WorkerInputs> {
    let spec: InstanceSpec = store.get(id.to_string()).await.ok()??;
    let profile: RuntimeProfile = store.get(spec.profile_id.to_string()).await.ok()??;
    let dns: Option<DnsProfile> = match spec.dns_profile_id {
        Some(d) => Some(store.get(d.to_string()).await.ok()??),
        None => None,
    };
    let security: Option<SecurityProfile> = match spec.security_profile_id {
        Some(s) => Some(store.get(s.to_string()).await.ok()??),
        None => None,
    };
    Some(WorkerInputs::of(
        &spec,
        &profile,
        dns.as_ref(),
        security.as_ref(),
    ))
}
