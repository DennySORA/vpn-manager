// Common resolvers, offered by the DNS editor and when a connection needs a DNS profile.

import type { DnsProfile, DnsProfileInput, DnsServer } from "@/api/types";
import { m } from "./messages";

export interface DnsPreset {
  label: string;
  server: DnsServer;
}

export const DNS_PRESETS: DnsPreset[] = [
  { label: m.presets.mullvad, server: { transport: "udp", address: "10.64.0.1:53" } },
  {
    label: "Cloudflare DoH",
    server: { transport: "https", address: "1.1.1.1:443", url: "https://cloudflare-dns.com/dns-query" },
  },
  { label: "Cloudflare DoT", server: { transport: "tls", address: "1.1.1.1:853", server_name: "cloudflare-dns.com" } },
  { label: "Quad9 DoT", server: { transport: "tls", address: "9.9.9.9:853", server_name: "dns.quad9.net" } },
  { label: "Google DoH", server: { transport: "https", address: "8.8.8.8:443", url: "https://dns.google/dns-query" } },
];

/** A NextDNS configuration ID (its 設定 page): six hexadecimal digits, e.g. `abc123`. */
export const NEXTDNS_ID = /^[0-9a-f]{6}$/;

/**
 * A device name for NextDNS's logs: letters, digits and hyphens, neither first nor last. DoT carries it in the server
 * name's first label (`<device>-<id>.dns.nextdns.io`), which holds at most 63 characters, so at most 56 here.
 */
export function isNextDnsDevice(name: string): boolean {
  return name.length <= 56 && /^[A-Za-z0-9-]+$/.test(name) && !name.startsWith("-") && !name.endsWith("-");
}

/** NextDNS's anycast resolvers (IPv4). */
const NEXTDNS_ANYCAST = ["45.90.28.0", "45.90.30.0"] as const;

/**
 * The servers of NextDNS configuration `id` (already checked against NEXTDNS_ID), named `device` in its logs when one
 * is given: DoH to both anycast addresses, then DoT to both, within the four a profile holds.
 */
export function nextDnsServers(id: string, device: string): DnsServer[] {
  const url = `https://dns.nextdns.io/${id}${device ? `/${device}` : ""}`;
  const serverName = `${device ? `${device}-` : ""}${id}.dns.nextdns.io`;
  return [
    ...NEXTDNS_ANYCAST.map((ip): DnsServer => ({ transport: "https", address: `${ip}:443`, url })),
    ...NEXTDNS_ANYCAST.map((ip): DnsServer => ({ transport: "tls", address: `${ip}:853`, server_name: serverName })),
  ];
}

/** `NextDNS（abc123）· office-pc`: the profile name the preset suggests. */
export function nextDnsName(id: string, device: string): string {
  return m.nextDns.profileName(id, device);
}

export const DNS_DEFAULTS: DnsProfileInput = {
  name: "",
  servers: [],
  cache: { max_entries: 4096, max_ttl_secs: 3600, negative_ttl_secs: 60 },
  query_timeout_ms: 3000,
  attempts: 2,
  on_failure: "wireguard_resolvers",
};

/** The address of `1.1.1.1:443` or `[2606:4700::1111]:443`. */
export function serverHost(address: string): string {
  const v6 = /^\[([^\]]+)\]:\d+$/.exec(address);
  if (v6?.[1]) return v6[1];
  const i = address.lastIndexOf(":");
  return i > 0 ? address.slice(0, i) : address;
}

/** A plain-DNS resolver at `ip` (inside the tunnel, e.g. an office or home network's own). */
export function innerPreset(ip: string): DnsPreset {
  return {
    label: m.presets.inner(ip),
    server: { transport: "udp", address: ip.includes(":") ? `[${ip}]:53` : `${ip}:53` },
  };
}

/** A DNS profile asking just this preset's server, named after it. */
export function presetInput(p: DnsPreset): DnsProfileInput {
  return { ...DNS_DEFAULTS, name: p.label, servers: [p.server] };
}

const sameServer = (a: DnsServer, b: DnsServer) =>
  a.transport === b.transport &&
  a.address === b.address &&
  (a.transport !== "tls" || (b.transport === "tls" && a.server_name === b.server_name)) &&
  (a.transport !== "https" || (b.transport === "https" && a.url === b.url));

/** An existing profile that asks exactly this one server (reused instead of a duplicate). */
export function findPresetProfile(profiles: DnsProfile[], p: DnsPreset): DnsProfile | undefined {
  return profiles.find(
    (d) => d.servers.length === 1 && d.servers[0] !== undefined && sameServer(d.servers[0], p.server),
  );
}
