// Display rules for provider accounts, servers, the egress and exit checks. Pure functions: the
// server stays the source of truth; nothing here guesses a fact the API did not state.

import type {
  EgressPhase,
  GateStatus,
  ProfileEntry,
  ProviderAccount,
  ProviderDevice,
  ProviderEgressStatus,
  ProviderEntryInput,
  ProviderGate,
  ProviderGateKind,
  ProviderIpCheck,
  ProviderKind,
  ProviderServer,
  ProviderServerEntry,
  RuntimeProfile,
} from "@/api/types";
import { CalendarClock, CalendarX2, CircleDashed } from "lucide-react";
import { intlLocale } from "@/i18n";
import { cityName, countryName } from "@/lib/places";
import type { StateLook, Tone } from "@/lib/status";
import { m as connectText } from "./connect/messages";
import { m as egressText } from "./egress/messages";
import { m } from "./messages";

export { countryName };

export const PROVIDER_NAME: Record<ProviderKind, string> = {
  generic: m.genericProvider,
  mullvad: "Mullvad",
  airvpn: "AirVPN",
};

/**
 * Profiles that use a device's key: built from it by the provider flow, or imported with the same
 * key (one key serves one running connection at a time, and revoking it breaks them all).
 */
export function profilesOnDevice(
  profiles: RuntimeProfile[],
  account: Pick<ProviderAccount, "id">,
  device: Pick<ProviderDevice, "id" | "public_key">,
): RuntimeProfile[] {
  return profiles.filter(
    (p) =>
      (p.source.kind === "provider" && p.source.account_id === account.id && p.source.device_id === device.id) ||
      p.interface.public_key === device.public_key,
  );
}

const DAY = 86_400_000;

/** Paid-until as a short phrase and how urgent it is. */
export function expiryLook(
  account: Pick<ProviderAccount, "expires_at">,
  now = Date.now(),
): { text: string; tone: Tone } {
  if (!account.expires_at) return { text: m.expiry.unknown, tone: "neutral" };
  const at = Date.parse(account.expires_at);
  const days = Math.floor((at - now) / DAY);
  const date = new Date(at).toLocaleDateString(intlLocale, { year: "numeric", month: "2-digit", day: "2-digit" });
  if (at <= now) return { text: m.expiry.expiredOn(date), tone: "danger" };
  if (days < 1) return { text: m.expiry.today(date), tone: "danger" };
  if (days < 7) return { text: m.expiry.soon(days, date), tone: "warning" };
  return { text: m.expiry.later(days, date), tone: "neutral" };
}

/** The same, short enough for a list row. */
export function expiryShort(
  account: Pick<ProviderAccount, "expires_at">,
  now = Date.now(),
): { text: string; tone: Tone } {
  const full = expiryLook(account, now);
  if (!account.expires_at) return { text: m.expiry.unknown, tone: full.tone };
  const at = Date.parse(account.expires_at);
  if (at <= now) return { text: m.expiry.expired, tone: full.tone };
  const days = Math.floor((at - now) / DAY);
  return { text: days < 1 ? m.expiry.expiresToday : m.expiry.daysLeft(days), tone: full.tone };
}

/** The account's state as a chip: its paid-until date, as the provider last said it (never guessed). */
export function accountLook(account: Pick<ProviderAccount, "expires_at">, now = Date.now()): StateLook {
  const short = expiryShort(account, now);
  const icon = short.tone === "danger" ? CalendarX2 : account.expires_at ? CalendarClock : CircleDashed;
  return { label: short.text, tone: short.tone, icon };
}

export interface CityGroup {
  code: string;
  name: string;
  servers: ProviderServer[];
}

export interface CountryGroup {
  code: string;
  name: string;
  cities: CityGroup[];
  count: number;
}

/** Servers grouped by country and city, both by display name; inactive servers last. */
export function groupServers(servers: ProviderServer[], query: string): CountryGroup[] {
  const q = query.trim().toLowerCase();
  const countries = new Map<string, CountryGroup>();
  for (const s of servers) {
    const country = countryName(s.country_code, s.country);
    const cityLabel = s.city ? cityName(s.city) : "";
    if (
      q &&
      ![s.id, country, s.country, s.city, cityLabel, s.country_code, s.hosting ?? ""].some((v) =>
        v.toLowerCase().includes(q),
      )
    )
      continue;
    const key = s.country_code.toLowerCase();
    let g = countries.get(key);
    if (!g) {
      g = { code: key, name: country, cities: [], count: 0 };
      countries.set(key, g);
    }
    const cityKey = s.city_code || s.city;
    let city = g.cities.find((c) => c.code === cityKey);
    if (!city) {
      city = { code: cityKey, name: cityLabel || connectText.unknownCity, servers: [] };
      g.cities.push(city);
    }
    city.servers.push(s);
    g.count += 1;
  }
  // Countries by their code (shown first on each row): predictable to scan, unlike stroke order.
  const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name, intlLocale);
  return [...countries.values()]
    .sort((a, b) => a.code.localeCompare(b.code))
    .map((g) => ({
      ...g,
      cities: g.cities.sort(byName).map((c) => ({
        ...c,
        servers: c.servers.sort((a, b) => Number(b.active) - Number(a.active) || a.id.localeCompare(b.id)),
      })),
    }));
}

const placeOf = (s: ProviderServer) => (s.city ? cityName(s.city) : countryName(s.country_code, s.country));

/** Default connection name: provider, city and server. */
export function connectionName(provider: ProviderKind, s: ProviderServer): string {
  return `${PROVIDER_NAME[provider]} · ${placeOf(s)} ${s.id}`.slice(0, 64);
}

/**
 * What `name` becomes when its profile moves from server `from` to `to`, when it is a name built
 * from `from` ("Mullvad · 香港 hk-hkg-wg-301", "香港 hk-hkg-wg-301" or the bare server name);
 * `null` for a name the user chose, which stays.
 */
export function followedName(
  name: string,
  provider: ProviderKind,
  from: ProviderServer | undefined,
  to: ProviderServer,
): string | null {
  if (!from) return null;
  if (name === connectionName(provider, from)) return connectionName(provider, to);
  if (name === `${placeOf(from)} ${from.id}`) return `${placeOf(to)} ${to.id}`.slice(0, 64);
  if (name === from.id) return to.id;
  return null;
}

export interface EgressLook {
  tone: Tone;
  title: string;
  busy?: boolean;
}

export const EGRESS_LOOK: Record<EgressPhase, EgressLook> = {
  unconfigured: { tone: "warning", title: egressText.phase.unconfigured },
  bootstrap_direct: { tone: "warning", title: egressText.phase.bootstrap_direct },
  starting_instance: { tone: "info", title: egressText.phase.starting_instance, busy: true },
  switching: { tone: "info", title: egressText.phase.switching, busy: true },
  vpn_ready: { tone: "success", title: egressText.phase.vpn_ready },
  blocked: { tone: "danger", title: egressText.phase.blocked },
  recovery_required: { tone: "danger", title: egressText.phase.recovery_required },
  disabled: { tone: "neutral", title: egressText.phase.disabled },
};

/** The direct grant open now is a manual rebootstrap (not the first setup's). */
export function rebootstrapOpen(s: Pick<ProviderEgressStatus, "bootstrap" | "bootstrap_expires_at">): boolean {
  return Boolean(s.bootstrap_expires_at) && s.bootstrap?.kind === "rebootstrap" && s.bootstrap.stage === "grant_active";
}

/** What an exit check proves. A match needs the provider's own evidence; unknown is never green. */
export function checkLook(c: ProviderIpCheck): { tone: Tone; label: string } {
  if (c.status !== "ok") return { tone: "danger", label: egressText.check.failed };
  const name = PROVIDER_NAME[c.provider];
  switch (c.provider_match) {
    case "match":
      return { tone: "success", label: egressText.check.providerExit(name) };
    case "other":
      return { tone: "warning", label: egressText.check.notProviderExit(name) };
    case "unknown":
      return { tone: "neutral", label: egressText.check.unknownProvider };
  }
}

/** The order a provider's gates are listed in. */
export const GATE_ORDER: ProviderGateKind[] = ["exit_check", "membership", "ipv6", "config_generator", "forward"];

const CHECKER_NAME: Record<ProviderKind, string> = {
  airvpn: "whatismyip",
  mullvad: "am.i.mullvad.net",
  generic: "IPLeak",
};

/** What one gate is, in the words of the provider it belongs to. */
export function gateName(provider: ProviderKind, gate: ProviderGateKind): string {
  switch (gate) {
    case "exit_check":
      return provider === "generic"
        ? egressText.gate.exitObservation(CHECKER_NAME[provider])
        : egressText.gate.exitCheck(CHECKER_NAME[provider]);
    case "membership":
      return egressText.gate.membership;
    case "ipv6":
      return egressText.gate.ipv6;
    case "config_generator":
      return egressText.gate.configGenerator;
    case "forward":
      return egressText.gate.forward;
  }
}

/** Each gate's state on its own: only a pass is green, and nothing unobserved looks done. */
export const GATE_LOOK: Record<GateStatus, { tone: Tone; label: string }> = {
  passed: { tone: "success", label: egressText.gate.status.passed },
  failed: { tone: "danger", label: egressText.gate.status.failed },
  blocked: { tone: "warning", label: egressText.gate.status.blocked },
  not_applicable: { tone: "neutral", label: egressText.gate.status.not_applicable },
  unverified: { tone: "neutral", label: egressText.gate.status.unverified },
};

/** `provider`'s gates, in order. Every gate keeps its own state: none is inferred from another. */
export function gatesOf(gates: ProviderGate[] | undefined, provider: ProviderKind): ProviderGate[] {
  const mine = (gates ?? []).filter((g) => g.provider === provider);
  return GATE_ORDER.flatMap((k) => mine.filter((g) => g.gate === k));
}

/** mm:ss until `iso`, or null once passed. */
export function countdown(iso: string | null | undefined, now = Date.now()): string | null {
  if (!iso) return null;
  const left = Math.max(0, Date.parse(iso) - now);
  if (!left) return null;
  const s = Math.ceil(left / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/**
 * The device a new connection starts from: a usable one that no connection uses (Mullvad: one whose
 * key is on this computer), so two connections do not share a key by default. Otherwise Mullvad
 * registers a new device; AirVPN (keys come from the account) takes its first device.
 */
export function defaultDevice(
  mullvad: boolean,
  devices: ProviderDevice[] | undefined,
  inUse: (d: ProviderDevice) => boolean,
): string {
  const usable = (devices ?? []).filter((d) => d.usable && (!mullvad || d.owned));
  const free = usable.find((d) => !inUse(d));
  if (mullvad) return free?.id ?? "new";
  return (free ?? usable[0])?.id ?? "";
}

// ---------------------------------------------------------------------------------------------------------------
// 入口／出口: where a connection enters the provider's network and where it leaves it.

/**
 * How a provider lets a connection choose its entry: Mullvad enters at another relay (multihop), AirVPN at another of
 * the exit server's own addresses and ports (entry and exit are the same server), the others not at all.
 */
export type Routing = "multihop" | "entries" | "single";

export const ROUTING: Record<ProviderKind, Routing> = { mullvad: "multihop", airvpn: "entries", generic: "single" };

/** The entry chosen in a dialog: the exit server's default, another relay (multihop) or another entry of the exit. */
export type EntryChoice =
  { kind: "same" } | { kind: "relay"; id: string } | { kind: "address"; index: number; port: number };

export const SAME_ENTRY: EntryChoice = { kind: "same" };

/** "位址 3 · UDP 47107": an AirVPN entry — its Entry IP 3 (counted from 1, as AirVPN names them) on that port. */
export function entryAddressLabel(e: Pick<ProviderServerEntry, "index" | "port">): string {
  return connectText.entry.address(e.index + 1, e.port);
}

/** The request's entry for `choice` with exit `exitId`: none for the exit's default (or the exit itself). */
export function entryInput(choice: EntryChoice, exit: ProviderServer | null): ProviderEntryInput | null {
  switch (choice.kind) {
    case "same":
      return null;
    case "relay":
      return choice.id === exit?.id ? null : { kind: "relay", server_id: choice.id };
    case "address": {
      const isDefault = exit?.entries.find((e) => e.index === choice.index && e.port === choice.port)?.default ?? false;
      return isDefault ? null : { kind: "address", index: choice.index, port: choice.port };
    }
  }
}

/** The choice a profile's recorded entry stands for (none: the exit's default). */
export function entryChoiceOf(entry: ProfileEntry | null | undefined): EntryChoice {
  if (!entry) return SAME_ENTRY;
  return entry.kind === "relay"
    ? { kind: "relay", id: entry.server_id }
    : { kind: "address", index: entry.index, port: entry.port };
}

/** Whether two choices are the same entry for exit `exit` (the default named either way is the same). */
export function sameEntry(a: EntryChoice, b: EntryChoice, exit: ProviderServer | null): boolean {
  return JSON.stringify(entryInput(a, exit)) === JSON.stringify(entryInput(b, exit));
}

/** A profile's entry in words: "se-got-wg-001（哥特堡）" or "位址 3 · UDP 47107"; null at the exit's default. */
export function profileEntryText(entry: ProfileEntry | null | undefined): string | null {
  if (!entry) return null;
  if (entry.kind === "address") return entryAddressLabel(entry);
  const city = entry.city ? cityName(entry.city) : null;
  return city ? connectText.entry.relayInCity(entry.server_id, city) : entry.server_id;
}
