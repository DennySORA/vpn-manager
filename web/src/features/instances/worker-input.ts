// What a worker takes from each kind of configuration, to tell right after a save whether the
// change needs a restart to apply (and offer one). It mirrors crates/instance-manager/src/inputs.rs,
// which decides the lasting notice: the manager reports `running.pending_changes` itself.

import type {
  AutoBanSettings,
  DnsCacheSettings,
  DnsOnFailure,
  DnsServer,
  InstanceLimits,
  PortRange,
} from "@/api/types";

/** JSON with object keys sorted, so equal values compare equal however they were built. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : v,
  );
}

type RestartLimits = Pick<InstanceLimits, "max_tcp_flows" | "max_udp_flows" | "memory_mib">;

/** What a worker takes from each kind of configuration; names and locations are not part of it. */
export const workerInput = {
  /** Bandwidth caps are not part of it: a running worker applies them at once. */
  instance: (s: {
    profile_id: string;
    dns_profile_id: string | null;
    security_profile_id: string | null;
    limits: (RestartLimits & Partial<InstanceLimits>) | null;
    strict?: boolean;
  }) =>
    canonical([
      s.profile_id,
      s.dns_profile_id,
      s.security_profile_id,
      s.limits && {
        max_tcp_flows: s.limits.max_tcp_flows,
        max_udp_flows: s.limits.max_udp_flows,
        memory_mib: s.limits.memory_mib,
      },
      s.strict ?? false,
    ]),
  /** Keepalive 0 and none are the same (the server stores 0 as none). */
  profile: (mtu: number | null, keepalive: number | null) => canonical([mtu, keepalive === 0 ? null : keepalive]),
  dns: (d: {
    servers: DnsServer[];
    cache: DnsCacheSettings;
    query_timeout_ms: number;
    attempts: number;
    on_failure: DnsOnFailure;
  }) => canonical([d.servers, d.cache, d.query_timeout_ms, d.attempts, d.on_failure]),
  /**
   * The base rules and auto-ban settings are fixed for a running generation; blocklists are not
   * part of it: a running connection gets them as an overlay without a restart.
   */
  security: (p: {
    allow_private: string[];
    blocked_ports: number[];
    allowed_destinations: string[];
    allowed_ports: PortRange[];
    auto_ban: AutoBanSettings;
  }) => canonical([p.allow_private, p.blocked_ports, p.allowed_destinations, p.allowed_ports, p.auto_ban]),
};
