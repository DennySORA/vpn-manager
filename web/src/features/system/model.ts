// Words and decisions of the 系統 views, kept pure for tests. The same vocabulary as vpnctl.

import {
  Ban,
  CircleCheck,
  CircleHelp,
  CircleMinus,
  CircleX,
  LoaderCircle,
  ShieldCheck,
  ShieldQuestionMark,
  TriangleAlert,
} from "lucide-react";
import type {
  Capability,
  CapabilityState,
  CheckStatus,
  DiagnosticCheck,
  DiagnosticReport,
  DiskReport,
  DiskSpaceState,
  ReconcileOutcome,
  RecoveryKind,
  RecoveryReport,
  ReserveState,
  ScanGap,
  StoreHealth,
  SystemStatus,
  VaultKeyState,
} from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale, localized } from "@/i18n";
import type { StateLook, Tone } from "@/lib/status";
import { m as diag } from "./diagnostics/messages";
import { m } from "./messages";
import { m as rec } from "./recovery/messages";

export const CHECK: Record<CheckStatus, StateLook> = {
  ok: { label: diag.check.ok, tone: "success", icon: CircleCheck },
  warning: { label: diag.check.warning, tone: "warning", icon: TriangleAlert },
  failed: { label: diag.check.failed, tone: "danger", icon: CircleX },
  // Unknown is never shown as fine.
  unknown: { label: ui.common.unknown, tone: "warning", icon: CircleHelp },
};

export interface CheckSummary {
  ok: number;
  warning: number;
  failed: number;
  unknown: number;
  /** The worst status present (failed > unknown > warning > ok). */
  worst: CheckStatus;
}

export function summarizeChecks(checks: DiagnosticCheck[]): CheckSummary {
  const s: CheckSummary = { ok: 0, warning: 0, failed: 0, unknown: 0, worst: "ok" };
  for (const c of checks) s[c.status] += 1;
  s.worst = s.failed ? "failed" : s.unknown ? "unknown" : s.warning ? "warning" : "ok";
  if (checks.length === 0) s.worst = "unknown";
  return s;
}

/** The report's conclusion in one line: how many checks need attention, or that all are fine. */
export function checksHeadline(s: CheckSummary): string {
  const problems = s.failed + s.unknown + s.warning;
  if (problems + s.ok === 0) return diag.headline.none;
  if (!problems) return diag.headline.allFine(s.ok);
  return diag.headline.attention(problems);
}

/** Problems first, then the rest in the server's order. */
export function orderChecks(checks: DiagnosticCheck[]): DiagnosticCheck[] {
  const rank: Record<CheckStatus, number> = { failed: 0, unknown: 1, warning: 2, ok: 3 };
  return checks
    .map((c, i) => ({ c, i }))
    .sort((a, b) => rank[a.c.status] - rank[b.c.status] || a.i - b.i)
    .map((x) => x.c);
}

export const CAPABILITY: Record<CapabilityState, StateLook> = {
  supported: { label: m.capabilities.state.supported, tone: "success", icon: CircleCheck },
  unsupported: { label: m.capabilities.state.unsupported, tone: "neutral", icon: CircleMinus },
  unverified: { label: m.capabilities.state.unverified, tone: "warning", icon: CircleHelp },
  blocked: { label: m.capabilities.state.blocked, tone: "warning", icon: Ban },
  degraded: { label: m.capabilities.state.degraded, tone: "warning", icon: TriangleAlert },
};

/** The groups of the capability list, in order; each name reads within its group. */
const CAPABILITY_GROUPS: { id: string; title: string; names: [string, string][] }[] = [
  {
    id: "connections",
    title: m.capabilities.group.connections,
    names: [
      ["explicit_proxy", m.capabilities.name.explicit_proxy],
      ["ipv6_tunnel", m.capabilities.name.ipv6_tunnel],
      ["network_rate_limit", m.capabilities.name.network_rate_limit],
      ["strict_netns", m.capabilities.name.strict_netns],
    ],
  },
  {
    id: "apps",
    title: m.capabilities.group.apps,
    names: [
      ["app_proxy_env", m.capabilities.name.app_proxy_env],
      ["app_enforced_proxy", m.capabilities.name.app_enforced_proxy],
      ["app_strict_netns", m.capabilities.name.app_strict_netns],
      ["managed_process_network", m.capabilities.name.managed_process_network],
      ["limit_memory", m.capabilities.name.limit_memory],
      ["limit_cpu", m.capabilities.name.limit_cpu],
      ["limit_processes", m.capabilities.name.limit_processes],
      ["limit_open_files", m.capabilities.name.limit_open_files],
    ],
  },
  {
    id: "forwards",
    title: m.capabilities.group.forwards,
    names: [
      ["forwarded_app_endpoint", m.capabilities.name.forwarded_app_endpoint],
      ["forward_reservation", m.capabilities.name.forward_reservation],
    ],
  },
  { id: "keys", title: m.capabilities.group.keys, names: [["secret_keystore", m.capabilities.name.secret_keystore]] },
];

export interface CapabilityGroup {
  /** Names the group whatever the language (its list's key). */
  id: string;
  title: string;
  items: (Capability & { label: string })[];
}

/** The host's capabilities in fixed groups; names this build does not know go last, under 其他. */
export function groupCapabilities(caps: Capability[]): CapabilityGroup[] {
  const byName = new Map(caps.map((c) => [c.name, c]));
  const known = new Set<string>();
  const groups: CapabilityGroup[] = [];
  for (const g of CAPABILITY_GROUPS) {
    const items: CapabilityGroup["items"] = [];
    for (const [name, label] of g.names) {
      known.add(name);
      const c = byName.get(name);
      if (c) items.push({ ...c, label });
    }
    if (items.length) groups.push({ id: g.id, title: g.title, items });
  }
  const other = caps.filter((c) => !known.has(c.name)).map((c) => ({ ...c, label: c.name }));
  if (other.length) groups.push({ id: "other", title: m.capabilities.group.other, items: other });
  return groups;
}

/** A capability whose reason explains a limit the reader should know about. */
export function capabilityLimited(state: CapabilityState): boolean {
  return state === "blocked" || state === "degraded" || state === "unverified";
}

/** 「11 項可用・1 項降級・2 項這台主機不支援」 */
export function capabilitySummary(caps: Capability[]): string {
  const n = (st: CapabilityState) => caps.filter((c) => c.state === st).length;
  return m.capabilities.summary({
    supported: n("supported"),
    unsupported: n("unsupported"),
    unverified: n("unverified"),
    blocked: n("blocked"),
    degraded: n("degraded"),
  });
}

export interface Verdict {
  tone: Tone;
  title: string;
  detail: string;
  icon: StateLook["icon"];
}

/**
 * The 狀態 view's conclusion from the service path (browser → controller → manager) and the
 * Store, worst first. A Store that cannot write outranks a slow event stream.
 */
export function systemVerdict(
  service: { tone: Tone; label: string; detail: string },
  store: StoreHealth | undefined,
): Verdict {
  if (service.tone === "danger") return { tone: "danger", title: service.label, detail: service.detail, icon: CircleX };
  if (!store) return { tone: "neutral", title: m.verdict.reading, detail: m.verdict.readingDetail, icon: LoaderCircle };
  if (!store.control_ok) {
    return {
      tone: "danger",
      title: m.verdict.controlDown,
      detail: m.verdict.controlDownDetail,
      icon: CircleX,
    };
  }
  if (!store.metrics_ok) {
    return {
      tone: "warning",
      title: m.verdict.metricsDown,
      detail: m.verdict.metricsDownDetail,
      icon: TriangleAlert,
    };
  }
  if (store.keystore !== "supported") {
    return {
      tone: "warning",
      title: m.verdict.keystore(CAPABILITY[store.keystore].label),
      detail: m.verdict.keystoreDetail,
      icon: TriangleAlert,
    };
  }
  if (service.tone !== "success")
    return { tone: service.tone, title: service.label, detail: service.detail, icon: LoaderCircle };
  return {
    tone: "success",
    title: m.verdict.fine,
    detail: m.verdict.fineDetail,
    icon: CircleCheck,
  };
}

/** The web UI listens beyond this host (installed with `--listen-address`, `--allow-client`). */
export function lanOpen(s: Pick<SystemStatus, "controller_listen">): boolean {
  return !s.controller_listen.startsWith("127.") && s.controller_listen !== "::1";
}

/** The addresses the web UI answers at: the one it listens on, or each host address for a wildcard. */
export function controllerUrls(
  s: Pick<SystemStatus, "controller_listen" | "controller_port" | "host_addresses">,
): string[] {
  const url = (a: string) =>
    a.includes(":") ? `http://[${a}]:${s.controller_port}` : `http://${a}:${s.controller_port}`;
  if (s.controller_listen === "0.0.0.0") return s.host_addresses.filter((a) => !a.includes(":")).map(url);
  if (s.controller_listen === "::") return s.host_addresses.map(url);
  return [url(s.controller_listen)];
}

export const SECRET_KIND: Record<string, string> = m.vault.kind;

export const VAULT_KEY: Record<VaultKeyState, StateLook> = {
  matches: { label: diag.vaultKey.matches, tone: "success", icon: ShieldCheck },
  mismatch: { label: diag.vaultKey.mismatch, tone: "danger", icon: CircleX },
  missing: { label: diag.vaultKey.missing, tone: "danger", icon: CircleX },
  unsafe: { label: diag.vaultKey.unsafe, tone: "danger", icon: TriangleAlert },
  unreadable: { label: diag.unreadable, tone: "warning", icon: ShieldQuestionMark },
};

export const DISK_SPACE: Record<DiskSpaceState, StateLook> = {
  normal: { label: diag.disk.state.normal, tone: "success", icon: CircleCheck },
  low: { label: diag.disk.state.low, tone: "warning", icon: TriangleAlert },
  unknown: { label: ui.common.unknown, tone: "warning", icon: CircleHelp },
};

/** Whether something keeps the host's clock synchronized (`SystemStatus.clock_synchronized`). */
export function clockSyncLook(synchronized: boolean | null | undefined): StateLook {
  if (synchronized === true) return { label: diag.clock.look.synced, tone: "success", icon: CircleCheck };
  if (synchronized === false) return { label: diag.clock.look.notSynced, tone: "warning", icon: TriangleAlert };
  return { label: diag.clock.look.unknown, tone: "neutral", icon: CircleHelp };
}

const seconds = new Intl.NumberFormat(intlLocale, { maximumFractionDigits: 1 });

/** How the host's clock stands against this device's (`offsetMs`: server minus browser): "主機慢 30.5 秒". */
export function clockSkewText(offsetMs: number): string {
  const abs = Math.abs(offsetMs);
  if (abs < 1_000) return diag.clock.close;
  return diag.clock.skew(offsetMs < 0, seconds.format(abs / 1_000));
}

export const RESERVE: Record<ReserveState, string> = {
  held: diag.disk.held,
  released: diag.disk.released,
  missing: diag.missing,
};

/** Used share of the data volume and where "low" begins, both 0–1; null when not measured. */
export function diskShare(
  d: Pick<DiskReport, "free_bytes" | "total_bytes" | "low_threshold_bytes">,
): { used: number; low: number | null } | null {
  if (d.free_bytes === null || d.total_bytes === null || d.total_bytes <= 0) return null;
  const clamp = (x: number) => Math.min(1, Math.max(0, x));
  return {
    used: clamp(1 - d.free_bytes / d.total_bytes),
    low: d.low_threshold_bytes === null ? null : clamp(1 - d.low_threshold_bytes / d.total_bytes),
  };
}

/** 「3 天 4 小時」「12 分」 */
export function uptime(secs: number | null): string {
  if (secs === null) return ui.common.unknown;
  const d = Math.floor(secs / 86_400);
  const h = Math.floor(secs / 3600) % 24;
  const min = Math.floor(secs / 60) % 60;
  if (d) return diag.duration.days(d, h);
  if (h) return diag.duration.hours(h, min);
  if (min) return diag.duration.minutes(min);
  return diag.duration.seconds(secs);
}

export const RECOVERY_KIND: Record<RecoveryKind, string> = rec.kind;

export const RECONCILE_OUTCOME: Record<ReconcileOutcome, StateLook> = {
  done: { label: rec.outcome.done, tone: "success", icon: CircleCheck },
  skipped: { label: rec.outcome.skipped, tone: "neutral", icon: CircleHelp },
  failed: { label: rec.outcome.failed, tone: "danger", icon: CircleX },
};

/** `vpn-manager-diagnostics-20261027T115552Z.json` from the report's own time. */
export function diagnosticsFileName(r: DiagnosticReport): string {
  const stamp = r.generated_at.replace(/[-:]/g, "").replace(/\.\d+/, "");
  return `vpn-manager-diagnostics-${stamp}.json`;
}

/** One place an inspection could not look at, in a line. */
export function gapText(g: ScanGap): string {
  return m.gap(localized(g.what), g.path, localized(g.reason));
}

/**
 * The 恢復 view's conclusion, worst first: leftovers a clean can remove, then places the inspection could not look at
 * (nothing found there is not "nothing there"), then leftovers that are only reported; nothing at all is the only fine.
 */
export function recoveryVerdict(
  r: Pick<RecoveryReport, "items" | "gaps">,
): Verdict & { cleanable: number; reportOnly: number } {
  const cleanable = r.items.filter((i) => i.cleanable).length;
  const reportOnly = r.items.length - cleanable;
  const counts = { cleanable, reportOnly };
  if (cleanable) {
    return {
      ...counts,
      tone: "warning",
      icon: TriangleAlert,
      title: rec.verdict.cleanable(cleanable),
      detail: rec.verdict.cleanableDetail,
    };
  }
  if (r.gaps.length) {
    return {
      ...counts,
      tone: "warning",
      icon: ShieldQuestionMark,
      title: rec.verdict.gaps(r.gaps.length),
      detail: rec.verdict.gapsDetail,
    };
  }
  if (reportOnly) {
    return {
      ...counts,
      tone: "info",
      icon: CircleHelp,
      title: rec.verdict.reportOnly(reportOnly),
      detail: rec.verdict.reportOnlyDetail,
    };
  }
  return {
    ...counts,
    tone: "success",
    icon: ShieldCheck,
    title: rec.verdict.none,
    detail: rec.verdict.noneDetail,
  };
}
