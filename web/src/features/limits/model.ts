// Resource limits and bandwidth caps: parsing that mirrors the server's bounds
// (crates/domain/src/validation.rs: check_instance_limits, check_app), what each App limit means
// and whether this host enforces it (from the capabilities), and labels for what is in force.

import type { AppLimits, Capability, EnforcedLimit, LimitKind, ResourceStatus } from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { localized } from "@/i18n";
import { formatBytes } from "@/lib/format";
import { m } from "./messages";

/** Bandwidth caps the server accepts: 0.1 Mbit/s to 100 Gbit/s. */
const CAP_MIN_BPS = 100_000;
const CAP_MAX_BPS = 100_000_000_000;

/** A cap typed in Mbit/s: empty means no cap. */
export function parseCap(text: string): { bps: number | null; error: string | null } {
  const t = text.trim();
  if (!t) return { bps: null, error: null };
  if (!/^(?:\d+|\d+\.\d+)$/.test(t)) return { bps: null, error: m.capNotNumber };
  const bps = Math.round(Number(t) * 1_000_000);
  if (bps < CAP_MIN_BPS || bps > CAP_MAX_BPS) return { bps: null, error: "0.1–100000 Mbit/s" };
  return { bps, error: null };
}

/** A cap as the form shows it (Mbit/s, no trailing zeros); "" for none. */
export function capInput(bps: number | null): string {
  return bps === null ? "" : String(Number((bps / 1_000_000).toFixed(3)));
}

/** A cap for reading: "20 Mbit/s", "不限". */
export function capText(bps: number | null): string {
  return bps === null ? ui.common.unlimited : `${capInput(bps)} Mbit/s`;
}

export const LIMIT_LABEL: Record<LimitKind, string> = m.kind;

export function limitValue(e: Pick<EnforcedLimit, "kind" | "value">): string {
  switch (e.kind) {
    case "memory":
      return formatBytes(e.value);
    case "cpu":
      return `${e.value}%`;
    case "open_files":
    case "processes":
      return String(e.value);
  }
}

/** "cgroup：記憶體 768 MiB、程序 128" per mechanism, then each reason with the names of its limits. */
export function resourceLines(r: ResourceStatus): {
  inForce: string[];
  notInForce: { kinds: string[]; reason: string }[];
} {
  const inForce: string[] = [];
  for (const [mechanism, label] of [
    ["cgroup", "cgroup"],
    ["rlimit", "RLIMIT"],
  ] as const) {
    const set = r.enforced
      .filter((e) => e.mechanism === mechanism)
      .map((e) => m.enforced(LIMIT_LABEL[e.kind], limitValue(e)));
    if (set.length) inForce.push(m.byMechanism(label, set));
  }
  const byReason = new Map<string, string[]>();
  for (const u of r.unenforced) {
    const reason = localized(u.reason);
    byReason.set(reason, [...(byReason.get(reason) ?? []), LIMIT_LABEL[u.kind]]);
  }
  return { inForce, notInForce: [...byReason].map(([reason, kinds]) => ({ kinds, reason })) };
}

export interface LimitField {
  key: keyof AppLimits;
  label: string;
  unit: string;
  /** The capability that says whether this host enforces it. */
  capability: string;
  min: number;
  max: number;
  hint: string;
}

/** The App limits, with the server's bounds. */
export const APP_LIMIT_FIELDS: LimitField[] = [
  {
    key: "memory_mib",
    label: m.field.memory_mib.label,
    unit: "MiB",
    capability: "limit_memory",
    min: 16,
    max: 1_048_576,
    hint: m.field.memory_mib.hint,
  },
  {
    key: "cpu_percent",
    label: m.field.cpu_percent.label,
    unit: "%",
    capability: "limit_cpu",
    min: 1,
    max: 6_400,
    hint: m.field.cpu_percent.hint,
  },
  {
    key: "processes",
    label: m.field.processes.label,
    unit: m.countUnit,
    capability: "limit_processes",
    min: 1,
    max: 65_536,
    hint: m.field.processes.hint,
  },
  {
    key: "open_files",
    label: m.field.open_files.label,
    unit: m.countUnit,
    capability: "limit_open_files",
    min: 16,
    max: 1_048_576,
    hint: m.field.open_files.hint,
  },
];

/** Whether this host enforces a limit, as its capability says (unknown while loading). */
export function limitAvailability(
  capability: string,
  caps: Capability[] | undefined,
): { available: boolean; reason: string | null } {
  if (!caps) return { available: false, reason: m.readingCapabilities };
  const c = caps.find((x) => x.name === capability);
  if (!c) return { available: false, reason: m.notReported };
  return { available: c.state === "supported", reason: c.reason ? localized(c.reason) : null };
}

export type LimitDraft = Record<keyof AppLimits, string>;

export function limitDraft(l: AppLimits | undefined): LimitDraft {
  const s = (v: number | null | undefined) => (v === null || v === undefined ? "" : String(v));
  return {
    memory_mib: s(l?.memory_mib),
    cpu_percent: s(l?.cpu_percent),
    processes: s(l?.processes),
    open_files: s(l?.open_files),
  };
}

/** The limits a draft sets, and the problem of each field (by JSON pointer). */
export function parseLimits(d: LimitDraft): { limits: AppLimits; errors: Map<string, string> } {
  const errors = new Map<string, string>();
  const limits: AppLimits = { memory_mib: null, cpu_percent: null, processes: null, open_files: null };
  for (const f of APP_LIMIT_FIELDS) {
    const t = d[f.key].trim();
    if (!t) continue;
    const n = /^\d+$/.test(t) ? Number(t) : NaN;
    if (!Number.isInteger(n) || n < f.min || n > f.max)
      errors.set(`/limits/${f.key}`, m.field[f.key].range(f.min, f.max));
    else limits[f.key] = n;
  }
  return { limits, errors };
}

/** "記憶體 512 MiB、CPU 50%" for the limits an App sets, or null. */
export function limitsText(l: AppLimits): string | null {
  const set = APP_LIMIT_FIELDS.flatMap((f) => {
    const value = l[f.key];
    return value === null ? [] : [m.field[f.key].set(value)];
  });
  return set.length ? m.setList(set) : null;
}
