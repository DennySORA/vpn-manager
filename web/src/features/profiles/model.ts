// WireGuard profiles: where each one is, what state it is in as a word, and the list's filters and sort orders. Pure;
// the server stays the source of truth (a profile's use is the connections that name it).
import { CalendarClock, CalendarX2, CircleDashed, Network } from "lucide-react";
import type { InstanceView, RuntimeProfile } from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { PROVIDER_NAME } from "@/features/providers/model";
import { intlLocale } from "@/i18n";
import { placeText } from "@/lib/places";
import type { StateLook } from "@/lib/status";
import { m } from "./messages";

/** "東京，日本", or null when the profile names no place. */
export function profilePlace(p: Pick<RuntimeProfile, "location">): string | null {
  return placeText(p.location);
}

/** Connections that name each profile (a profile in use cannot be deleted). */
export function profileUsers(views: readonly InstanceView[]): Map<string, InstanceView[]> {
  const m = new Map<string, InstanceView[]>();
  for (const v of views) m.set(v.spec.profile_id, [...(m.get(v.spec.profile_id) ?? []), v]);
  return m;
}

const DAY = 86_400_000;

/**
 * The profile's state as a word: an expiry the provider stated wins (expired, or within a week), then whether
 * connections use it. Nothing here is observed health: a profile is configuration.
 */
export function profileLook(p: Pick<RuntimeProfile, "expires_at">, users: number, now = Date.now()): StateLook {
  if (p.expires_at) {
    const left = Date.parse(p.expires_at) - now;
    if (left <= 0) return { label: m.look.expired, tone: "danger", icon: CalendarX2 };
    if (left < 7 * DAY)
      return { label: m.look.expiresIn(Math.max(1, Math.floor(left / DAY))), tone: "warning", icon: CalendarClock };
  }
  return users
    ? { label: m.look.usedBy(users), tone: "info", icon: Network }
    : { label: m.look.unused, tone: "neutral", icon: CircleDashed };
}

/** A Mullvad device's key outlives the profiles built on it (the device can be reused or revoked). */
export function keepsDeviceKey(p: Pick<RuntimeProfile, "provider" | "source">): boolean {
  return p.provider === "mullvad" && p.source.kind === "provider";
}

/** Only a provider's profile can move to another server of its account (an imported generic one names no server list). */
export function canChangeServer(p: Pick<RuntimeProfile, "provider" | "source">): boolean {
  return p.source.kind === "provider" || p.provider !== "generic";
}

export type ProfileFilter = "all" | "used" | "unused";

export const PROFILE_FILTERS: { value: ProfileFilter; label: string; title: string }[] = [
  { value: "all", label: ui.common.all, title: m.filter.allTitle },
  { value: "used", label: m.filter.used, title: m.filter.usedTitle },
  { value: "unused", label: m.look.unused, title: m.filter.unusedTitle },
];

export function matchesProfileFilter(users: number, f: ProfileFilter): boolean {
  if (f === "used") return users > 0;
  if (f === "unused") return users === 0;
  return true;
}

/** Name, place, endpoint, provider, server or a connection's name, any words in any order. */
export function matchesProfileQuery(p: RuntimeProfile, q: string, users: readonly InstanceView[] = []): boolean {
  const words = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [
    p.name,
    profilePlace(p) ?? "",
    p.location?.server ?? "",
    p.peer.endpoint,
    PROVIDER_NAME[p.provider],
    ...users.map((v) => v.spec.name),
  ]
    .join(" ")
    .toLowerCase();
  return words.every((w) => hay.includes(w));
}

export type ProfileSort = "created" | "name" | "provider";

export const PROFILE_SORTS: { value: ProfileSort; label: string }[] = [
  { value: "created", label: m.sort.created },
  { value: "name", label: ui.common.name },
  { value: "provider", label: m.provider },
];

const collator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

/** A new array in the chosen order; ties fall back to the creation time and id, so the order never flickers. */
export function sortProfiles(list: readonly RuntimeProfile[], sort: ProfileSort): RuntimeProfile[] {
  const created = (a: RuntimeProfile, b: RuntimeProfile) =>
    Date.parse(a.created_at) - Date.parse(b.created_at) || collator.compare(a.id, b.id);
  const out = [...list];
  if (sort === "name") out.sort((a, b) => collator.compare(a.name, b.name) || created(a, b));
  else if (sort === "provider")
    out.sort(
      (a, b) =>
        collator.compare(PROVIDER_NAME[a.provider], PROVIDER_NAME[b.provider]) ||
        collator.compare(a.name, b.name) ||
        created(a, b),
    );
  else out.sort(created);
  return out;
}
