// Security view model: the rules the server applies (crates/domain validation, crates/instance
// policy), mirrored so the editor can explain a value before it is saved, and what a running
// connection reports about the blocklist overlay it enforces.

import type {
  AutoBanSettings,
  BlocklistFamily,
  BlocklistFormat,
  BlocklistSource,
  BlocklistStats,
  BlocklistView,
  BuiltinBlocklistState,
  InboundSummary,
  InstanceView,
  PortRange,
  SecurityProfileInput,
} from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale, type ServerText, localized } from "@/i18n";
import { covers, isPrivateRange, parseCidr } from "@/lib/cidr";
import type { Tone } from "@/lib/status";
import { m } from "./messages";

/** The server default (`AutoBanSettings::default`): on, for the default policy and new profiles. */
export const AUTO_BAN_DEFAULT: AutoBanSettings = {
  enabled: true,
  window_secs: 10,
  threshold: 100,
  ban_secs: 900,
  max_bans: 10_000,
};

/** Bounds the server enforces (crates/domain/src/validation.rs). */
export const LIMITS = {
  networks: 256,
  blockedPorts: 256,
  portRanges: 32,
  blocklists: 32,
  rawBytes: 8 * 1024 * 1024,
  entries: 200_000,
} as const;

export const AUTO_BAN_BOUNDS: Record<
  Exclude<keyof AutoBanSettings, "enabled">,
  { min: number; max: number; label: string; unit: string }
> = {
  window_secs: { min: 1, max: 3600, ...m.model.autoBan.window },
  threshold: { min: 1, max: 100_000, ...m.model.autoBan.threshold },
  ban_secs: { min: 1, max: 604_800, ...m.model.autoBan.ban },
  max_bans: { min: 1, max: 100_000, ...m.model.autoBan.maxBans },
};

/**
 * A security profile that allows exactly these private ranges, and otherwise keeps what the default
 * policy enforces: the enabled built-in blocklists (`defaultLists`) and auto-ban.
 */
export function allowRangesInput(ranges: string[], fallbackName: string, builtinLists: string[]): SecurityProfileInput {
  const listed = m.model.allowRangesName(ranges);
  return {
    name: listed.length <= 64 ? listed : fallbackName.slice(0, 64),
    allow_private: ranges,
    blocked_ports: [],
    allowed_destinations: [],
    allowed_ports: [],
    blocklists: builtinLists,
    auto_ban: AUTO_BAN_DEFAULT,
  };
}

/**
 * The lists the default security policy enforces (`default_policy`: the enabled built-in ones), which
 * a new security profile starts with selected. A connection with a profile enforces exactly that
 * profile's selection; one without follows the default policy.
 */
export function defaultLists(views: BlocklistView[]): string[] {
  return views.filter((v) => v.default_policy).map((v) => v.blocklist.id);
}

/** Connections without a security profile: they follow the default policy. */
export function defaultPolicyUsers(views: InstanceView[]): InstanceView[] {
  return views.filter((v) => v.spec.security_profile_id === null);
}

/** Lines or commas of a textarea, trimmed, empties dropped. */
export function tokens(text: string): string[] {
  return text
    .split(/[\n,，、]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

/** CIDRs (a bare address is one host) and the tokens that are not one. */
export function parseCidrList(text: string): { nets: string[]; bad: string[] } {
  const nets: string[] = [];
  const bad: string[] = [];
  for (const t of tokens(text)) {
    const c = parseCidr(t);
    if (!c) bad.push(t);
    else nets.push(t.includes("/") ? t : `${t}/${c.v6 ? 128 : 32}`);
  }
  return { nets, bad };
}

/** Loopback, unspecified, multicast, broadcast, link-local (the server's `is_special`). */
const SPECIAL = [
  "127.0.0.0/8",
  "0.0.0.0/32",
  "224.0.0.0/4",
  "255.255.255.255/32",
  "169.254.0.0/16",
  "::1/128",
  "::/128",
  "ff00::/8",
  "fe80::/10",
].flatMap((c) => {
  const p = parseCidr(c);
  return p ? [p] : [];
});

/** The network's own address is special: no allow rule can open it. A whole family (/0) is fine. */
export function isSpecialNet(text: string): boolean {
  const c = parseCidr(text);
  if (!c || c.prefix === 0) return false;
  const host = { ...c, prefix: c.v6 ? 128 : 32 };
  return SPECIAL.some((s) => covers(s, host));
}

/** Allowed destinations that are private but not allowed as private: still refused. */
export function privateWithoutAllowance(destinations: string[], allowPrivate: string[]): string[] {
  const allow = allowPrivate.flatMap((a) => {
    const c = parseCidr(a);
    return c ? [c] : [];
  });
  return destinations.filter((d) => {
    const c = parseCidr(d);
    return c !== null && c.prefix > 0 && isPrivateRange(d) && !allow.some((a) => covers(a, c));
  });
}

/** "80, 443, 8000-8999" → ranges, plus tokens that are not a port or a range. */
export function parsePortRanges(text: string): { ranges: PortRange[]; bad: string[] } {
  const ranges: PortRange[] = [];
  const bad: string[] = [];
  for (const t of text.split(/[\s,，、]+/).filter(Boolean)) {
    const m = /^(\d{1,5})$/.exec(t) ?? /^(\d{1,5})\s*[-–~]\s*(\d{1,5})$/.exec(t);
    const start = m ? Number(m[1]) : NaN;
    const end = m ? Number(m[2] ?? m[1]) : NaN;
    if (!m || start < 1 || end > 65_535 || end < start) bad.push(t);
    else if (!ranges.some((r) => r.start === start && r.end === end)) ranges.push({ start, end });
  }
  return { ranges, bad };
}

export function formatPortRanges(ranges: PortRange[]): string {
  return ranges.map((r) => (r.start === r.end ? String(r.start) : `${r.start}-${r.end}`)).join(", ");
}

/** Single ports for the blocked list. */
export function parsePorts(text: string): { ports: number[]; bad: string[] } {
  const ports: number[] = [];
  const bad: string[] = [];
  for (const tok of text.split(/[\s,，、]+/).filter(Boolean)) {
    const n = Number(tok);
    if (/^\d+$/.test(tok) && n >= 1 && n <= 65535) {
      if (!ports.includes(n)) ports.push(n);
    } else bad.push(tok);
  }
  return { ports: ports.sort((a, b) => a - b), bad };
}

/** Errors of the auto-ban numbers (null when fine). */
export function autoBanError(field: keyof typeof AUTO_BAN_BOUNDS, text: string): string | null {
  const b = AUTO_BAN_BOUNDS[field];
  if (!/^\d+$/.test(text.trim())) return m.model.autoBan.notWhole(b.label);
  const n = Number(text.trim());
  if (n < b.min || n > b.max)
    return m.model.autoBan.outOfRange(
      b.label,
      b.min.toLocaleString(intlLocale),
      b.max.toLocaleString(intlLocale),
      b.unit,
    );
  return null;
}

const nf = new Intl.NumberFormat(intlLocale);

/** A large decimal count (IPv6 addresses may exceed what a number holds exactly). */
export function formatCount(decimal: string | number): string {
  const text = String(decimal);
  if (!/^\d+$/.test(text)) return "—";
  if (text.length <= 15) return nf.format(Number(text));
  // Three significant digits, rounded (999.5 rounds up into the next power of ten).
  const lead = Math.round(Number(text.slice(0, 4)) / 10);
  const digits = String(lead >= 1000 ? 100 : lead);
  return m.model.about(`${digits[0]}.${digits.slice(1)}`, text.length - 1 + (lead >= 1000 ? 1 : 0));
}

export function entriesLabel(s: BlocklistStats): string {
  return m.model.entries(nf.format(s.entries), s.entries);
}

/** "12,345 筆 · IPv4 1,200 段 · IPv6 3 段". */
export function listSize(s: BlocklistStats): string {
  const parts = [entriesLabel(s)];
  if (s.v4_ranges) parts.push(m.model.ranges("IPv4", nf.format(s.v4_ranges), s.v4_ranges));
  if (s.v6_ranges) parts.push(m.model.ranges("IPv6", nf.format(s.v6_ranges), s.v6_ranges));
  return parts.join(" · ");
}

export function sourceLabel(source: BlocklistSource): string {
  return source.kind === "upload" ? m.model.source.upload : m.model.source.url;
}

const FORMAT_LABEL: Record<BlocklistFormat, string> = {
  plain: m.model.format.plain,
  json_lines: m.model.format.json_lines,
  tab_ranges: m.model.format.tab_ranges,
};

export function formatLabel(f: BlocklistFormat): string {
  return FORMAT_LABEL[f];
}

const FAMILY_LABEL: Record<BlocklistFamily, string> = { ipv4: "IPv4", ipv6: "IPv6", both: m.model.bothFamilies };

/** The address family a built-in list carries. */
export function familyLabel(f: BlocklistFamily): string {
  return FAMILY_LABEL[f];
}

/** Where a list stands, in a word: what the list column and the header show (`null`: all well). */
export function listState(v: BlocklistView): { tone: Tone; label: string } | null {
  if (!v.blocklist.enabled) return { tone: "neutral", label: ui.common.disabled };
  if (v.awaiting_content) {
    if (v.waiting) return { tone: "warning", label: m.model.state.waiting };
    if (v.refresh && !v.refresh.ok) return { tone: "danger", label: m.model.state.firstFailed };
    return { tone: "info", label: m.model.state.awaiting };
  }
  if (v.stale) return { tone: "warning", label: m.model.state.refreshFailed };
  return null;
}

export const REFRESH_CHOICES: (number | null)[] = [null, 6, 12, 24, 48, 168];

export function refreshLabel(hours: number | null | undefined): string {
  if (!hours) return m.model.refresh.manual;
  if (hours === 24) return m.model.refresh.daily;
  if (hours === 168) return m.model.refresh.weekly;
  return m.model.refresh.every(hours);
}

/** What a running connection reports about the blocklist overlay it enforces. */
export type OverlayState =
  | { kind: "not_running" }
  | { kind: "applied"; revision: number; lists: string[] }
  | { kind: "pending"; revision: number; applied: number | null }
  | { kind: "error"; revision: number; message: string };

export function overlayState(v: InstanceView): OverlayState {
  const p = v.status?.running?.policy;
  if (!p) return { kind: "not_running" };
  if (p.error) return { kind: "error", revision: p.revision, message: localized(p.error) };
  if (p.applied_revision === p.revision && p.applied_digest === p.digest) {
    return { kind: "applied", revision: p.revision, lists: p.blocklists.map((b) => b.id) };
  }
  return { kind: "pending", revision: p.revision, applied: p.applied_revision };
}

/** Connections whose security profile is one of `profileIds`. */
export function connectionsUsing(views: InstanceView[], profileIds: string[]): InstanceView[] {
  return views.filter((v) => v.spec.security_profile_id !== null && profileIds.includes(v.spec.security_profile_id));
}

/** Port forwards of these connections, from the inbound summary (`null` while unknown). */
export function forwardsOf(
  summary: InboundSummary | undefined,
  instanceIds: string[],
): { total: number; enabled: number } | null {
  if (!summary) return null;
  let total = 0;
  let enabled = 0;
  for (const c of summary.instances) {
    if (instanceIds.includes(c.instance_id)) {
      total += c.forward_bindings;
      enabled += c.enabled;
    }
  }
  return { total, enabled };
}

/**
 * A list's name for the reader. A built-in list is stored under its catalogue name in Traditional Chinese
 * (crates/domain/src/builtin_blocklists.rs); while it keeps that name it shows the catalogue's name in this page's
 * language. A name the owner gave is shown as it is.
 */
export function listName(v: Pick<BlocklistView, "blocklist" | "builtin">): string {
  const catalogue = v.builtin?.name;
  return catalogue?.["zh-TW"] === v.blocklist.name ? localized(catalogue) : v.blocklist.name;
}

/**
 * The name of a list a connection enforces, for the reader: its overlay names the lists as they are stored, so a
 * built-in list that keeps its catalogue name shows that name in this page's language (as `listName`).
 */
export function appliedListName(
  list: { id: string; name: string },
  catalogue: readonly BuiltinBlocklistState[] | undefined,
): string {
  const entry = catalogue?.find((c) => c.blocklist_id === list.id);
  return entry?.info.name["zh-TW"] === list.name ? localized(entry.info.name) : list.name;
}

/** Lists in their display order: stale first (they need attention), then the built-in ones, then by name. */
export function sortLists(views: BlocklistView[]): BlocklistView[] {
  return [...views].sort(
    (a, b) =>
      Number(b.stale) - Number(a.stale) ||
      Number(b.builtin !== null) - Number(a.builtin !== null) ||
      listName(a).localeCompare(listName(b), intlLocale),
  );
}

/** Whole seconds left until `iso` (0 once past). */
export function secondsLeft(iso: string, now: number): number {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.max(0, Math.ceil((t - now) / 1000)) : 0;
}

/** "14 分 05 秒" / "2 小時 3 分" / "3 天 4 小時". */
export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const d = Math.floor(s / 86_400);
  const h = Math.floor((s % 86_400) / 3600);
  const min = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return m.model.duration.days(d, h);
  if (h > 0) return m.model.duration.hours(h, min);
  if (min > 0) return m.model.duration.minutes(min, String(sec).padStart(2, "0"));
  return m.model.duration.seconds(sec);
}

export type BanSort = "newest" | "expiry" | "source";

export const BAN_SORTS: { value: BanSort; label: string }[] = [
  { value: "newest", label: m.model.banSort.newest },
  { value: "expiry", label: m.model.banSort.expiry },
  { value: "source", label: ui.common.source },
];

const banCollator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

/**
 * A new array in the chosen order: the newest ban first, the one that ends first, or by source address. Ties fall back
 * to the ban's id, so rows never swap places by chance.
 */
export function sortBans<B extends { id: string; source: string; created_at: string; expires_at: string }>(
  list: readonly B[],
  sort: BanSort,
): B[] {
  const tie = (a: B, b: B) => banCollator.compare(a.id, b.id);
  const out = [...list];
  if (sort === "expiry") out.sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at) || tie(a, b));
  else if (sort === "source") out.sort((a, b) => banCollator.compare(a.source, b.source) || tie(a, b));
  else out.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || tie(a, b));
  return out;
}

/** The search box: the source address, the reason or the connection's name, case-insensitive. */
export function matchesBan(
  b: { source: string; reason: ServerText },
  connection: string | undefined,
  q: string,
): boolean {
  const t = q.trim().toLowerCase();
  if (!t) return true;
  return `${b.source} ${localized(b.reason)} ${connection ?? ""}`.toLowerCase().includes(t);
}
