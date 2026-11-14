// AirVPN's forwarded ports (連入埠): labels, the reservation and settings forms' checks, AirVPN's
// test of a port and its DDNS check in words, the forward a reserved port becomes, and which
// connections and forwards belong to it. Pure functions; the server (and AirVPN behind it) decides.

import type {
  ForwardProtocol,
  ForwardView,
  ForwardedPort,
  ForwardedPortSession,
  ForwardedPortUpdate,
  ForwardedPorts,
  InstanceView,
  PortIpLayer,
  PortTestState,
  ProviderAccount,
  RuntimeProfile,
} from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { cityName, countryName } from "@/lib/places";
import type { Tone } from "@/lib/status";
import { m as connectText } from "./connect/messages";
import { m } from "./ports/messages";

export const PORT_PROTOCOL: Record<ForwardProtocol, string> = { tcp: "TCP", udp: "UDP", both: m.protocol.both };

/** AirVPN's DDNS names end in this; a port's `dns_name` is the part before it. */
export const DDNS_SUFFIX = ".airdns.org";

/** A DDNS name as it resolves. */
export function ddnsHost(name: string): string {
  return `${name}${DDNS_SUFFIX}`;
}

/** AirVPN's IP layer of a port; an unknown word is shown as AirVPN wrote it. */
export function ipLayerLabel(layer: string): string {
  switch (layer) {
    case "both":
      return m.ipLayer.both;
    case "ipv4":
      return "IPv4";
    case "ipv6":
      return "IPv6";
    default:
      return layer;
  }
}

/** The device a port is limited to, or every device of the account. */
export function deviceLabel(p: Pick<ForwardedPort, "device_id" | "device_name">): string {
  if (!p.device_id) return m.allDevices;
  return p.device_name ?? m.deviceById(p.device_id.slice(0, 8));
}

export interface PortUsage {
  used: number;
  limit: number;
  full: boolean;
  text: string;
}

export function portUsage(list: Pick<ForwardedPorts, "ports" | "limit">): PortUsage {
  const used = list.ports.length;
  return { used, limit: list.limit, full: used >= list.limit, text: m.usage(used, list.limit) };
}

export type ReserveMode = "random" | "chosen";

export interface PortDraftCheck {
  /** The port to ask for; `null` lets AirVPN pick one. */
  port: number | null;
  error: string | null;
}

/** The reservation form, checked as the server checks it (the range) plus what the list shows. */
export function checkPortDraft(
  mode: ReserveMode,
  text: string,
  list: Pick<ForwardedPorts, "ports" | "min_port" | "limit">,
): PortDraftCheck {
  if (list.ports.length >= list.limit) return { port: null, error: m.reserve.limitReached(list.limit) };
  if (mode === "random") return { port: null, error: null };
  const t = text.trim();
  const range = m.reserve.range(list.min_port);
  if (!/^\d{1,5}$/.test(t)) return { port: null, error: range };
  const n = Number(t);
  if (n < list.min_port || n > 65535) return { port: null, error: range };
  if (list.ports.some((p) => p.port === n)) return { port: null, error: m.reserve.taken(n) };
  return { port: n, error: null };
}

/** The forward a reserved port becomes: AirVPN delivers it on the tunnel address at its local port, and the App listens on the very port the Internet sees. */
export interface ForwardPrefill {
  /** The connection to forward on (one built from the port's account). */
  instance?: string | undefined;
  protocol: ForwardProtocol;
  tunnelPort: number;
  publicPort: number;
  targetPort: number;
}

export function forwardPrefill(p: ForwardedPort, instance?: string): ForwardPrefill {
  return { instance, protocol: p.protocol, tunnelPort: p.local_port, publicPort: p.port, targetPort: p.port };
}

/** Why the App must listen on the forwarded port itself. */
export function sameLocalPort(port: number): string {
  return m.sameLocalPort(port);
}

/** AirVPN remaps the port to another local port: a P2P program then announces a port it does not receive on. */
export function remapWarning(p: Pick<ForwardedPort, "port" | "local_port">): string | null {
  if (p.local_port === p.port) return null;
  return m.remapped(p.port, p.local_port);
}

// -------------------------------------------------------------------------------------------
// Settings (AirVPN's Ports page: one control per setting)
// -------------------------------------------------------------------------------------------

export const IP_LAYER_CHOICES: { value: PortIpLayer; label: string }[] = [
  { value: "both", label: m.ipLayer.both },
  { value: "ipv4", label: m.ipLayer.ipv4Only },
  { value: "ipv6", label: m.ipLayer.ipv6Only },
];

export const PROTOCOL_CHOICES: { value: ForwardProtocol; label: string }[] = [
  { value: "both", label: m.protocol.both },
  { value: "tcp", label: m.protocol.tcpOnly },
  { value: "udp", label: m.protocol.udpOnly },
];

/** The page's limits. */
export const MAX_NOTES = 200;
export const MAX_DDNS_NAME = 60;

/** The settings form of one port. */
export interface PortSettingsDraft {
  notes: string;
  enabled: boolean;
  /** `all` or one of the account's device ids. */
  device: string;
  protocol: ForwardProtocol;
  /** `null`: the port has a layer word of AirVPN's own, kept unless one is picked. */
  ipLayer: PortIpLayer | null;
  localPort: string;
  dnsName: string;
}

export function settingsDraft(p: ForwardedPort): PortSettingsDraft {
  const layer = IP_LAYER_CHOICES.find((c) => c.value === p.ip_layer)?.value ?? null;
  return {
    notes: p.notes ?? "",
    enabled: p.enabled,
    device: p.device_id ?? "all",
    protocol: p.protocol,
    ipLayer: layer,
    localPort: String(p.local_port),
    dnsName: p.dns_name ?? "",
  };
}

/** Each form field's path in the API's change (field errors come back by it). */
export const SETTINGS_PATH: Record<keyof PortSettingsDraft, string> = {
  notes: "/notes",
  enabled: "/enabled",
  device: "/device",
  protocol: "/protocol",
  ipLayer: "/ip_layer",
  localPort: "/local_port",
  dnsName: "/dns_name",
};

/** The settings by name, in the page's order. */
const SETTING_NAME: [keyof ForwardedPortUpdate, string][] = [
  ["notes", m.settings.fields.notes],
  ["enabled", m.settings.fields.enabled],
  ["device", m.settings.fields.device],
  ["protocol", m.settings.fields.protocol],
  ["ip_layer", m.settings.fields.ipVersion],
  ["local_port", "Local port"],
  ["dns_name", m.settings.fields.ddnsName],
];

export interface SettingsCheck {
  /** Only what differs from the port as listed. */
  update: ForwardedPortUpdate;
  /** The names of the settings that change, in the page's order. */
  changed: string[];
  errors: Partial<Record<keyof PortSettingsDraft, string>>;
}

/** A DDNS name as typed: lower case, `.airdns.org` left off when typed. */
function ddnsLabel(text: string): string {
  const t = text.trim().toLowerCase();
  return t.endsWith(DDNS_SUFFIX) ? t.slice(0, -DDNS_SUFFIX.length) : t;
}

/**
 * The change the form asks for — only what differs from the port as listed — checked as AirVPN's
 * page checks it. A value left as AirVPN holds it is no change and is not checked.
 */
export function checkSettings(p: ForwardedPort, d: PortSettingsDraft): SettingsCheck {
  const errors: SettingsCheck["errors"] = {};
  const update: ForwardedPortUpdate = {};
  const notes = d.notes.trim();
  // AirVPN collapses runs of white space.
  if (notes.split(/\s+/).join(" ") !== (p.notes ?? "")) {
    // eslint-disable-next-line no-control-regex -- input validation: a note must not contain control characters
    if (/[\u0000-\u001f\u007f]/.test(notes)) errors.notes = m.settings.errors.notesOneLine;
    else if (Array.from(notes).length > MAX_NOTES) errors.notes = m.settings.errors.notesTooLong(MAX_NOTES);
    else update.notes = notes;
  }
  if (d.enabled !== p.enabled) update.enabled = d.enabled;
  if (d.device !== (p.device_id ?? "all")) update.device = d.device;
  if (d.protocol !== p.protocol) update.protocol = d.protocol;
  if (d.ipLayer !== null && d.ipLayer !== p.ip_layer) update.ip_layer = d.ipLayer;
  const local = d.localPort.trim();
  if (local !== String(p.local_port)) {
    if (!/^\d{1,5}$/.test(local) || Number(local) < 1 || Number(local) > 65535)
      errors.localPort = m.enterRange(1, 65535);
    else if (Number(local) !== p.local_port) update.local_port = Number(local);
  }
  const dns = ddnsLabel(d.dnsName);
  if (dns !== (p.dns_name ?? "")) {
    if (dns && !/^(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$/.test(dns)) errors.dnsName = m.settings.errors.ddnsChars;
    else if (dns.length > MAX_DDNS_NAME) errors.dnsName = m.settings.errors.ddnsTooLong(MAX_DDNS_NAME);
    else update.dns_name = dns;
  }
  const changed = SETTING_NAME.filter(([k]) => update[k] !== undefined).map(([, name]) => name);
  return { update, changed, errors };
}

/** A local port other than the public one: why VPN Manager's forwards and P2P programs need the same. */
export function localPortWarning(port: number, localText: string): string | null {
  const t = localText.trim();
  if (!/^\d{1,5}$/.test(t) || Number(t) === port) return null;
  return m.localPortDiffers(port, t);
}

/** The port as AirVPN read it back, for the settings that changed. */
export function readBack(p: ForwardedPort, update: ForwardedPortUpdate): string {
  const parts: string[] = [];
  const said = m.settings.readBack;
  if (update.notes !== undefined) parts.push(p.notes ? said.notes(p.notes) : said.noNotes);
  if (update.enabled !== undefined) parts.push(p.enabled ? m.enabled : ui.common.disabled);
  if (update.device !== undefined) parts.push(said.device(deviceLabel(p)));
  if (update.protocol !== undefined) parts.push(said.protocol(PORT_PROTOCOL[p.protocol]));
  if (update.ip_layer !== undefined) parts.push(said.ipVersion(ipLayerLabel(p.ip_layer)));
  if (update.local_port !== undefined) parts.push(`Local port ${p.local_port}`);
  if (update.dns_name !== undefined) parts.push(p.dns_name ? `DDNS ${ddnsHost(p.dns_name)}` : said.noDdns);
  return said.list(parts);
}

// -------------------------------------------------------------------------------------------
// AirVPN's test of a port, its DDNS check, its search for free ports
// -------------------------------------------------------------------------------------------

/** What AirVPN's test of one session said, in words. Success only for AirVPN's own "open". */
export function testLook(s: Pick<ForwardedPortSession, "state" | "word">): { label: string; tone: Tone } {
  const state = m.test.state;
  const looks: Record<PortTestState, { label: string; tone: Tone }> = {
    open: { label: state.open, tone: "success" },
    closed: { label: state.closed, tone: "danger" },
    warning: { label: state.warning, tone: "warning" },
    unknown: { label: s.word ? state.unknownSaid(s.word) : state.unknown, tone: "neutral" },
    not_tested: { label: state.not_tested, tone: "neutral" },
  };
  return looks[s.state];
}

/** `ip:port`, an IPv6 address in brackets. */
export function endpoint(ip: string, port: number): string {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** A session's server: its name and where it is (「Alchiba · 阿姆斯特丹，荷蘭」). */
export function serverText(
  s: Pick<ForwardedPortSession, "server_name" | "server_location" | "server_country">,
): string {
  const place = connectText.cityAndCountry(
    s.server_location ? cityName(s.server_location) : null,
    s.server_country ? countryName(s.server_country) : null,
  );
  return [s.server_name, place].filter(Boolean).join(" · ") || m.serverUnknown;
}

/** What AirVPN's DDNS check says about one name, by how many connected sessions use a port with it. */
export function ddnsLook(sessions: number): { text: string; tone: Tone } {
  if (sessions === 0) return { text: m.ddns.unused, tone: "warning" };
  if (sessions === 1) return { text: m.ddns.one, tone: "info" };
  return { text: m.ddns.many(sessions), tone: "warning" };
}

/** How many consecutive free ports one search may ask for (the server's range). */
export const SEARCH_MIN = 2;
export const SEARCH_MAX = 10;

export function checkSearchCount(text: string): { count: number | null; error: string | null } {
  const t = text.trim();
  const n = Number(t);
  if (!/^\d{1,2}$/.test(t) || n < SEARCH_MIN || n > SEARCH_MAX)
    return { count: null, error: m.enterRange(SEARCH_MIN, SEARCH_MAX) };
  return { count: n, error: null };
}

/** Connections built from `account` (their profile came from it). */
export function connectionsOf(
  account: Pick<ProviderAccount, "id">,
  profiles: RuntimeProfile[],
  instances: InstanceView[],
): InstanceView[] {
  const ids = new Set(
    profiles.filter((p) => p.source.kind === "provider" && p.source.account_id === account.id).map((p) => p.id),
  );
  return instances.filter((v) => ids.has(v.spec.profile_id));
}

/** The AirVPN account in VPN Manager a connection was built from; `null` for any other connection. */
export function airvpnAccountOf(
  instance: InstanceView | undefined,
  profiles: RuntimeProfile[],
  accounts: ProviderAccount[],
): ProviderAccount | null {
  if (!instance || instance.profile?.provider !== "airvpn") return null;
  const profile = profiles.find((p) => p.id === instance.spec.profile_id);
  if (profile?.source.kind !== "provider") return null;
  const id = profile.source.account_id;
  return accounts.find((a) => a.id === id && a.provider === "airvpn") ?? null;
}

/** Forwards on `connections` that receive `port` (their public port, or their tunnel port when they name none). */
export function forwardsOnPort(port: number, forwards: ForwardView[], connections: InstanceView[]): ForwardView[] {
  const ids = new Set(connections.map((c) => c.spec.id));
  return forwards.filter(
    (f) => ids.has(f.binding.instance_id) && (f.binding.public_port ?? f.binding.tunnel_port) === port,
  );
}

/** Failures after which the user can still manage ports on AirVPN's website by hand. */
export function websiteFallback(code: string): boolean {
  return [
    "PROVIDER_LOGIN_CHALLENGE",
    "PROVIDER_AUTH_REJECTED",
    "PROVIDER_CONTRACT_DRIFT",
    "PROVIDER_REJECTED",
    "PROVIDER_QUOTA_EXCEEDED",
  ].includes(code);
}

/** Doing it on AirVPN's website instead. */
export const WEBSITE_STEPS = m.websiteSteps;
