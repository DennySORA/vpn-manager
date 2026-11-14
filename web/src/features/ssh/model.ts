// Client-side mirror of the SSH host rules (crates/domain validation): immediate feedback while
// typing. The server checks again and stays authoritative.

import type { SshExistingHost, SshHost, SshHostInput } from "@/api/types";
import { m } from "./messages";

export interface Draft {
  kind: SshHostInput["kind"];
  alias: string;
  hostName: string;
  user: string;
  port: string;
  identityFile: string;
  identitiesOnly: boolean;
  gatewayId: string;
  interval: string;
}

export type FieldIssues = Partial<Record<keyof Draft, string>>;

const ALIAS = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const USER = /^[A-Za-z0-9._@-]{1,64}$/;
const IDENTITY = /^(~\/|\/)[A-Za-z0-9._/@+~-]{1,254}$/;
const HOST_LABEL = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;

function ipv4(s: string): number[] | null {
  const parts = s.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p))) return null;
  const n = parts.map(Number);
  return n.every((x) => x <= 255) ? n : null;
}

function isIpv6(s: string): boolean {
  return s.includes(":") && /^[0-9a-fA-F:.]+$/.test(s.replace(/^\[|\]$/g, ""));
}

/** Reachable through no tunnel at all (an error when routed through a Gateway). */
export function localOnly(host: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return m.validation.localName;
  if (h.endsWith(".local")) return m.validation.mdnsName;
  const [a, b] = ipv4(h) ?? [];
  if (a !== undefined && (a === 127 || (a === 169 && b === 254) || a === 0 || a >= 224))
    return m.validation.unreachableAddress;
  const v6 = h.replace(/^\[|\]$/g, "");
  if (isIpv6(h) && (v6 === "::1" || v6 === "::" || /^fe[89ab]/i.test(v6) || /^ff/i.test(v6)))
    return m.validation.unreachableAddress;
  return null;
}

/** RFC 1918, CGNAT or ULA: reachable through a tunnel only where the security profile allows it. */
export function privateAddress(host: string): boolean {
  const v4 = ipv4(host);
  if (v4) {
    const [a = 0, b = 0] = v4;
    return (
      a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)
    );
  }
  return isIpv6(host) && /^\[?f[cd]/i.test(host);
}

function validHostName(h: string): boolean {
  if (ipv4(h) || isIpv6(h)) return true;
  const name = h.replace(/\.$/, "");
  const last = name.split(".").pop() ?? "";
  if (/^\d+$/.test(last) || /^0x/i.test(last)) return false;
  return name.length <= 253 && name.split(".").every((l) => HOST_LABEL.test(l));
}

function int(v: string): number | null {
  return /^\d+$/.test(v.trim()) ? Number(v.trim()) : null;
}

export function validate(d: Draft): { errors: FieldIssues; warnings: FieldIssues } {
  const errors: FieldIssues = {};
  const warnings: FieldIssues = {};
  const viaVpn = Boolean(d.gatewayId);
  if (!ALIAS.test(d.alias)) errors.alias = m.validation.alias;
  if (d.kind === "host") {
    const h = d.hostName.trim();
    if (!h) errors.hostName = m.validation.hostRequired;
    else if (!validHostName(h)) errors.hostName = m.validation.hostInvalid;
    else if (viaVpn) {
      const local = localOnly(h);
      if (local) errors.hostName = local;
      else if (privateAddress(h)) warnings.hostName = m.validation.privateAddress;
      else if (!ipv4(h) && !isIpv6(h) && !h.replace(/\.$/, "").includes(".")) warnings.hostName = m.validation.bareName;
    }
    if (d.user && (!USER.test(d.user) || d.user.startsWith("-"))) errors.user = m.validation.user;
    const port = d.port.trim() ? int(d.port) : 22;
    if (port === null || port < 1 || port > 65535) errors.port = "1–65535";
    if (d.identityFile && (!IDENTITY.test(d.identityFile) || d.identityFile.split("/").includes("..")))
      errors.identityFile = m.validation.identityFile;
    if (d.identitiesOnly && !d.identityFile) errors.identitiesOnly = m.validation.identitiesOnly;
    if (!errors.alias && (d.alias.includes(".") || d.alias === h)) warnings.alias = m.validation.aliasResolvable;
  } else if (!viaVpn) {
    errors.gatewayId = m.validation.gatewayRequired;
  }
  const interval = d.interval.trim() ? int(d.interval) : null;
  if (viaVpn && interval === null) errors.interval = m.validation.intervalRequired;
  else if (viaVpn && interval !== null && (interval < 10 || interval > 240))
    errors.interval = m.validation.intervalViaVpn;
  else if (!viaVpn && d.interval.trim() && (interval === null || interval < 10 || interval > 3600))
    errors.interval = m.validation.intervalDirect;
  return { errors, warnings };
}

export function toInput(d: Draft): SshHostInput {
  const host = d.kind === "host";
  return {
    kind: d.kind,
    alias: d.alias.trim(),
    host_name: host ? d.hostName.trim() || null : null,
    user: host ? d.user.trim() || null : null,
    port: host && d.port.trim() ? Number(d.port) : null,
    identity_file: host ? d.identityFile.trim() || null : null,
    identities_only: host && d.identitiesOnly,
    gateway_id: d.gatewayId || null,
    server_alive_interval: d.interval.trim() ? Number(d.interval) : null,
  };
}

export function fromHost(h: SshHost): Draft {
  return {
    kind: h.kind,
    alias: h.alias,
    hostName: h.host_name ?? "",
    user: h.user ?? "",
    port: h.port ? String(h.port) : "",
    identityFile: h.identity_file ?? "",
    identitiesOnly: h.identities_only,
    gatewayId: h.gateway_id ?? "",
    interval: h.server_alive_interval ? String(h.server_alive_interval) : "",
  };
}

/** A name of a `Host` line that matches exactly one host (same rule as the server's renderer). */
const PLAIN_PATTERN = /^[A-Za-z0-9._:[\]-]+$/;

/** Every name an overlay covers: the alias plus the block's other plain names. */
export function overlayNames(alias: string, block: SshExistingHost | null | undefined): string[] {
  const names = [alias];
  for (const p of block?.patterns ?? []) if (PLAIN_PATTERN.test(p) && !names.includes(p)) names.push(p);
  return names;
}

/** How the server writes a VPN-routed block (`{port}` marks the Gateway port). */
export interface RouteTemplate {
  proxy_command: string | null;
  control_path: string | null;
}

/** The block VPN Manager writes for this draft (same format as the server's renderer). */
export function previewBlock(d: Draft, gatewayPort: number | undefined, route: RouteTemplate, names: string[]): string {
  const lines = [`Host ${names.join(" ") || m.preview.alias}`];
  if (d.kind === "host") {
    if (d.hostName.trim()) lines.push(`  HostName ${d.hostName.trim()}`);
    if (d.user.trim()) lines.push(`  User ${d.user.trim()}`);
    if (d.port.trim()) lines.push(`  Port ${d.port.trim()}`);
    if (d.identityFile.trim()) {
      lines.push(`  IdentityFile ${d.identityFile.trim()}`);
      if (d.identitiesOnly) lines.push("  IdentitiesOnly yes");
    }
  }
  if (d.gatewayId) {
    const port = String(gatewayPort ?? m.preview.port);
    lines.push(
      `  ProxyCommand ${(route.proxy_command ?? "vpnctl ssh-proxy --gateway 127.0.0.1:{port} %h %p").replaceAll("{port}", port)}`,
    );
    if (route.control_path) lines.push(`  ControlPath ${route.control_path.replaceAll("{port}", port)}`);
  }
  if (d.interval.trim()) lines.push(`  ServerAliveInterval ${d.interval.trim()}`);
  return lines.join("\n");
}

export function hostLabel(x: SshExistingHost): string {
  return x.patterns.join(" ");
}
