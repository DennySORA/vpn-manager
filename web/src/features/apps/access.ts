// Local access ports of strict Apps: the form rows, the rules (mirroring `check_access_ports` in
// crates/domain/src/validation.rs; the manager also refuses ports another program or Gateway
// holds), the addresses a port is reached at, and how each port's state looks.

import { Ban, CircleOff, Plug, RotateCw } from "lucide-react";
import type { AccessBind, AccessState, AppAccessPort, GatewaySpec } from "@/api/types";
import type { StateLook } from "@/lib/status";
import { m as access } from "./access/messages";
import { m } from "./messages";

export const MAX_ACCESS_PORTS = 8;
export const MAX_ALLOW = 32;
const MIN_PORT = 1024;

/** One access port as typed. */
export interface AccessRow {
  key: string;
  /** The App's port inside its sandbox. */
  appPort: string;
  /** The port on this host. */
  hostPort: string;
  /** `hostPort` is the free-port suggestion, not the user's choice (it follows the App's port). */
  hostAuto: boolean;
  bind: AccessBind;
  /** `lan`: the allowed networks, separated by commas, spaces or new lines. */
  allow: string;
}

export const BIND_LABEL: Record<AccessBind, { title: string; text: string }> = {
  loopback: { title: m.loopbackOnly, text: access.bind.loopbackText },
  lan: { title: access.bind.lan, text: access.bind.lanText },
};

export const ACCESS_STATE: Record<AccessState, StateLook> = {
  serving: { label: access.state.serving, tone: "brand", icon: Plug },
  app_stopped: { label: access.state.app_stopped, tone: "neutral", icon: CircleOff },
  restart_needed: { label: access.state.restart_needed, tone: "warning", icon: RotateCw },
  unavailable: { label: access.state.unavailable, tone: "danger", icon: Ban },
};

export function rowsOf(ports: AppAccessPort[], key: () => string): AccessRow[] {
  return ports.map((p) => ({
    key: key(),
    appPort: String(p.app_port),
    hostPort: String(p.host_port),
    hostAuto: false,
    bind: p.bind,
    allow: p.allow.join(", "),
  }));
}

/** The networks of an allow field, as typed (empty entries dropped). */
export function splitAllow(text: string): string[] {
  return text
    .split(/[\s,，、]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function port(text: string): number | null {
  const t = text.trim();
  if (!/^\d{1,5}$/.test(t)) return null;
  const n = Number(t);
  return n >= MIN_PORT && n <= 65535 ? n : null;
}

/** The request's access ports (sent only once every row passes [`accessProblems`]). */
export function toPorts(rows: AccessRow[]): AppAccessPort[] {
  return rows.map((r) => ({
    app_port: port(r.appPort) ?? 0,
    host_port: port(r.hostPort) ?? 0,
    bind: r.bind,
    allow: r.bind === "lan" ? splitAllow(r.allow) : [],
  }));
}

const V4 =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)$/;

/** `192.168.10.0/24`, `fd00::/64` or a single address; the server judges the rest. */
export function cidrProblem(net: string): string | null {
  const [ip, prefix, extra] = net.split("/");
  if (extra !== undefined || !ip) return access.problem.notNetwork(net);
  const v4 = V4.test(ip);
  const v6 = !v4 && ip.includes(":") && /^[0-9a-fA-F:.]+$/.test(ip);
  if (!v4 && !v6) return access.problem.notNetwork(net);
  if (prefix !== undefined) {
    if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > (v4 ? 32 : 128)) return access.problem.prefix(net);
    if (Number(prefix) === 0) return access.problem.everyAddress;
  }
  if (v4 && ip.startsWith("127.")) return access.problem.loopback;
  return null;
}

/** Problems by JSON pointer (`/access_ports/0/host_port`), as the server would locate them. */
export function accessProblems(rows: AccessRow[], gateways: GatewaySpec[]): Map<string, string> {
  const errors = new Map<string, string>();
  if (rows.length > MAX_ACCESS_PORTS) errors.set("/access_ports", access.problem.tooMany(MAX_ACCESS_PORTS));
  rows.forEach((r, i) => {
    const at = `/access_ports/${i}`;
    const app = port(r.appPort);
    const host = port(r.hostPort);
    const before = rows.slice(0, i);
    if (app === null) errors.set(`${at}/app_port`, access.problem.appPort);
    else if (before.some((o) => port(o.appPort) === app))
      errors.set(`${at}/app_port`, access.problem.appPortRepeated(app));
    if (host === null) errors.set(`${at}/host_port`, access.problem.hostPort);
    else if (before.some((o) => port(o.hostPort) === host))
      errors.set(`${at}/host_port`, access.problem.hostPortRepeated(host));
    else {
      const g = gateways.find((x) => x.port === host);
      if (g) errors.set(`${at}/host_port`, access.problem.hostPortGateway(host, g.name));
    }
    if (r.bind === "lan") {
      const nets = splitAllow(r.allow);
      if (!nets.length) errors.set(`${at}/allow`, access.problem.allowEmpty);
      else if (nets.length > MAX_ALLOW) errors.set(`${at}/allow`, access.problem.tooManyNetworks(MAX_ALLOW));
      else {
        const bad = nets.map(cidrProblem).find((p) => p !== null);
        if (bad) errors.set(`${at}/allow`, bad);
      }
    }
  });
  return errors;
}

/** A URL for a host and a port (IPv6 in brackets). */
export function url(host: string, port: number): string {
  return host.includes(":") ? `http://[${host}]:${port}` : `http://${host}:${port}`;
}

/** Where a port is reached: on this host, and — open to the LAN — at each of this host's addresses. */
export function accessUrls(bind: AccessBind, hostPort: number, hostAddresses: string[]): string[] {
  const local = url("127.0.0.1", hostPort);
  return bind === "lan" ? [local, ...hostAddresses.map((a) => url(a, hostPort))] : [local];
}
