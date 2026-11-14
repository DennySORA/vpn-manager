import { OctagonX } from "lucide-react";
import type { ConfigPart, InstanceLimits, InstanceView, RuntimeProfile } from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale, localized } from "@/i18n";
import { placeText } from "@/lib/places";
import { PHASE, recoveryReason, type StateLook, UNKNOWN_STATE } from "@/lib/status";
import { m } from "./messages";

export const LATCHED: StateLook = { label: m.latched, tone: "danger", icon: OctagonX };

export function instanceLook(v: InstanceView): StateLook {
  if (!v.status) return UNKNOWN_STATE;
  // The decision it waits for first: the emergency latch it shows may be the stop that is not on disk.
  if (v.status.phase === "recovery_required") return PHASE.recovery_required;
  if (v.status.intent.emergency_latched) return LATCHED;
  return PHASE[v.status.phase];
}

export function isRunning(v: InstanceView): boolean {
  return v.status?.intent.desired === "running";
}

/** The two decisions that end a connection's wait (recovery_required). */
export interface RecoveryWayOut {
  /** Keep it closed: confirm the emergency stop, or the stop. */
  keep: "emergency_stop" | "stop";
  /** Let it run again: clear the emergency first, or start it. */
  resume: "clear_emergency" | "start";
}

/** How the user ends a connection's wait for their decision, or null when it does not wait. */
export function recoveryWayOut(v: InstanceView): RecoveryWayOut | null {
  const s = v.status;
  if (s?.phase !== "recovery_required") return null;
  return s.intent.emergency_latched
    ? { keep: "emergency_stop", resume: "clear_emergency" }
    : { keep: "stop", resume: "start" };
}

/** Something the user should look at (shown on the overview and as a filter). */
export function attentionReason(v: InstanceView): string | null {
  const s = v.status;
  if (!s) return null;
  if (s.phase === "recovery_required") return recoveryReason(s);
  if (s.intent.emergency_latched) return m.attention.latched;
  if (s.phase === "failed")
    return s.recovery.last_fault ? localized(s.recovery.last_fault.message) : m.attention.failed;
  if (s.phase === "degraded") return m.attention.degraded;
  if (s.intent.desired === "running" && s.phase !== "ready" && s.recovery.attempt >= 2 && s.recovery.last_fault)
    return m.attention.retrying(s.recovery.attempt, localized(s.recovery.last_fault.message));
  if (s.intent.persistence !== "durable") return m.attention.intentNotDurable;
  const failed = s.gateways.find((g) => g.state === "failed");
  if (failed) {
    const spec = v.gateways.find((g) => g.id === failed.gateway_id);
    return m.attention.gatewayFailed(spec ? spec.port : null, failed.error ? localized(failed.error) : null);
  }
  if (s.running && s.dns?.interrupted) return m.attention.dnsInterrupted;
  if (s.running && s.dns?.fallback) return m.attention.dnsFallback;
  return null;
}

export type StateFilter = "all" | "running" | "stopped" | "attention";

export function matchesFilter(
  v: InstanceView,
  f: StateFilter,
  attention: (v: InstanceView) => string | null = attentionReason,
): boolean {
  switch (f) {
    case "running":
      return isRunning(v);
    case "stopped":
      return Boolean(v.status) && !isRunning(v);
    case "attention":
      return attention(v) !== null;
    case "all":
      return true;
  }
}

export type InstanceSort = "created" | "name" | "state";

export const INSTANCE_SORTS: { value: InstanceSort; label: string }[] = [
  { value: "created", label: m.sort.created },
  { value: "name", label: ui.common.name },
  { value: "state", label: ui.common.status },
];

const collator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

/** Something to handle first, then connected, then on the way, then stopped; unknown last. */
function stateRank(v: InstanceView, attention: (v: InstanceView) => string | null): number {
  if (!v.status) return 4;
  if (attention(v) !== null) return 0;
  if (!isRunning(v)) return 3;
  return v.status.phase === "ready" ? 1 : 2;
}

/**
 * A new array in the chosen order; ties fall back to the creation order, so rows never swap places by chance. Sorted by
 * state, rows move (and slide) as their state changes.
 */
export function sortInstances(
  list: readonly InstanceView[],
  sort: InstanceSort,
  attention: (v: InstanceView) => string | null = needsAttention,
): InstanceView[] {
  const created = (a: InstanceView, b: InstanceView) =>
    Date.parse(a.spec.created_at) - Date.parse(b.spec.created_at) || collator.compare(a.spec.id, b.spec.id);
  const out = [...list];
  if (sort === "name") out.sort((a, b) => collator.compare(a.spec.name, b.spec.name) || created(a, b));
  else if (sort === "state") out.sort((a, b) => stateRank(a, attention) - stateRank(b, attention) || created(a, b));
  else out.sort(created);
  return out;
}

/** Running connections whose saved configuration applies only after a restart (the list's batch action). */
export function pendingRestart(views: readonly InstanceView[]): InstanceView[] {
  return views.filter((v) => isRunning(v) && !v.status?.intent.emergency_latched && staleConfig(v) !== null);
}

export function matchesQuery(v: InstanceView, q: string): boolean {
  const t = q.trim().toLowerCase();
  if (!t) return true;
  const hay = [
    v.spec.name,
    v.profile?.name,
    v.profile?.endpoint,
    v.profile?.location?.city,
    v.profile?.location?.country,
    locationText(v),
    ...v.gateways.map((g) => String(g.port)),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return hay.includes(t);
}

const PART_LABEL: Record<ConfigPart, string> = m.part;

/**
 * Saved configuration the running generation does not use yet (a restart applies it), as the
 * manager reports it — renaming, a location or an expiry date never counts — or null.
 */
export function staleConfig(v: InstanceView): string | null {
  const parts = v.status?.running?.pending_changes ?? [];
  return parts.length ? m.staleConfig(parts.map((p) => PART_LABEL[p])) : null;
}

/** What to look at on this connection: a problem first, else configuration a restart would apply. */
export function needsAttention(v: InstanceView): string | null {
  return attentionReason(v) ?? staleConfig(v);
}

export type SharedConfig = "profile" | "dns" | "security";

/** The connection is built on this WireGuard, DNS or security profile. */
export function usesConfig(v: InstanceView, kind: SharedConfig, id: string): boolean {
  return (
    (kind === "profile" ? v.spec.profile_id : kind === "dns" ? v.spec.dns_profile_id : v.spec.security_profile_id) ===
    id
  );
}

/**
 * Connections whose worker still runs an older revision of this profile: they apply `revision`
 * only when restarted. Stopped or emergency-latched ones are left alone (a restart would start them).
 */
export function restartTargets(
  views: InstanceView[],
  kind: SharedConfig,
  id: string,
  revision: number,
): InstanceView[] {
  return views.filter((v) => {
    const s = v.status;
    const run = s?.running;
    if (!s || !run || s.intent.desired !== "running" || s.intent.emergency_latched || !usesConfig(v, kind, id))
      return false;
    const started =
      kind === "profile"
        ? run.profile_revision
        : kind === "dns"
          ? run.dns_profile_revision
          : run.security_profile_revision;
    return started === null || started < revision;
  });
}

/**
 * Other connections that hold the same WireGuard key as `profileId` (the same profile, or another
 * profile built on the same key): only one of them can run at a time.
 */
export function keyUsers(
  profileId: string,
  profiles: RuntimeProfile[],
  views: InstanceView[],
  self?: string,
): InstanceView[] {
  const key = profiles.find((p) => p.id === profileId)?.interface.public_key;
  const sameKey = new Set([
    profileId,
    ...profiles.filter((p) => key && p.interface.public_key === key).map((p) => p.id),
  ]);
  return views.filter((v) => v.spec.id !== self && sameKey.has(v.spec.profile_id));
}

/** The profile a new connection starts from: the newest whose key no connection uses, else the newest. */
export function defaultProfile(profiles: RuntimeProfile[], views: InstanceView[]): RuntimeProfile | undefined {
  const newest = [...profiles].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  return newest.find((p) => keyUsers(p.id, profiles, views).length === 0) ?? newest[0];
}

// The worker's netstack (crates/tunnel netstack, crates/instance controller.rs): `memory_mib` is a
// budget for socket buffers, reserved when a connection opens, not a cap on process memory.
const MIB = 1024 * 1024;
/** Receive (512 KiB) + send (256 KiB) buffer a tunnel TCP connection opens with unless its transport says otherwise. */
const TCP_FLOW_BYTES = (512 + 256) * 1024;
/** Kept for DNS and health probes; payload gets at most the rest (each capped at a quarter). */
const CONTROL_FLOWS = 16;
const CONTROL_MEMORY = 8 * MIB;

export interface TcpCapacity {
  /** Proxied TCP connections that can be open at once. */
  limit: number;
  /** The buffer budget, not the TCP limit, is what binds. */
  byMemory: boolean;
  reservedFlows: number;
  reservedMib: number;
}

/**
 * How many proxied TCP connections the limits allow at most (no UDP open), when each reserves `flowBytes` as it opens:
 * the opening buffer sizes of the connection's transport profile.
 */
export function tcpCapacity(
  l: Pick<InstanceLimits, "max_tcp_flows" | "memory_mib">,
  flowBytes = TCP_FLOW_BYTES,
): TcpCapacity {
  const budget = l.memory_mib * MIB;
  const reservedMemory = Math.min(CONTROL_MEMORY, Math.floor(budget / 4));
  const reservedFlows = Math.min(CONTROL_FLOWS, Math.floor(l.max_tcp_flows / 4));
  const byFlows = l.max_tcp_flows - reservedFlows;
  const byMemory = Math.floor((budget - reservedMemory) / Math.max(flowBytes, 1));
  return {
    limit: Math.min(byFlows, byMemory),
    byMemory: byMemory < byFlows,
    reservedFlows,
    reservedMib: reservedMemory / MIB,
  };
}

export function locationText(v: InstanceView): string | null {
  return placeText(v.profile?.location);
}
