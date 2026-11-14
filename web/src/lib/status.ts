// The one vocabulary for runtime states: label, tone and icon. Tones describe observed
// facts; "success" only for observed protection, never for unknown.

import type { LucideIcon } from "lucide-react";
import {
  TriangleAlert,
  CircleDashed,
  CircleOff,
  Hourglass,
  LoaderCircle,
  LockKeyhole,
  OctagonX,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestionMark,
  Square,
} from "lucide-react";
import type { Enforcement, InstanceStatus, Phase } from "@/api/types";
import { localized } from "@/i18n";
import { m } from "./messages";

export type Tone = "success" | "info" | "warning" | "danger" | "neutral" | "brand";

export interface StateLook {
  label: string;
  tone: Tone;
  icon: LucideIcon;
  /** Spinner-like icon that animates. */
  busy?: boolean;
}

export const PHASE: Record<Phase, StateLook> = {
  stopped: { label: m.phase.stopped, tone: "neutral", icon: Square },
  starting: { label: m.phase.starting, tone: "info", icon: LoaderCircle, busy: true },
  connecting: { label: m.phase.connecting, tone: "info", icon: LoaderCircle, busy: true },
  verifying: { label: m.phase.verifying, tone: "info", icon: LoaderCircle, busy: true },
  ready: { label: m.phase.ready, tone: "success", icon: ShieldCheck },
  degraded: { label: m.phase.degraded, tone: "warning", icon: TriangleAlert },
  reconnecting: { label: m.phase.reconnecting, tone: "warning", icon: RefreshCw, busy: true },
  stopping: { label: m.phase.stopping, tone: "info", icon: Hourglass, busy: true },
  failed: { label: m.phase.failed, tone: "danger", icon: OctagonX },
  recovery_required: { label: m.phase.recovery_required, tone: "danger", icon: ShieldAlert },
};

export const ENFORCEMENT: Record<Enforcement, StateLook> = {
  tunnel_only: { label: m.enforcement.tunnel_only, tone: "success", icon: LockKeyhole },
  blocked: { label: m.enforcement.blocked, tone: "neutral", icon: CircleOff },
  unknown: { label: m.enforcement.unknown, tone: "warning", icon: ShieldQuestionMark },
};

export const UNKNOWN_STATE: StateLook = { label: m.unknownState, tone: "warning", icon: CircleDashed };

/** The manager's fault code of a connection held closed because a stop from before its restart is not on disk. */
export const STOP_NOT_CONFIRMED = "STOP_NOT_CONFIRMED";

/** Why a connection waits for the user's decision (recovery_required): the manager's reason, which says the way out. */
export function recoveryReason(s: InstanceStatus): string {
  const f = s.recovery.last_fault;
  return f?.code === STOP_NOT_CONFIRMED ? localized(f.message) : m.recoveryUnproven;
}

/** A one-line human explanation of what the state means for the user's traffic. */
export function trafficExplanation(s: InstanceStatus | null | undefined): string {
  if (!s) return m.traffic.noStatus;
  // Before the latch: an emergency latch it shows may be the very stop that is not on disk.
  if (s.phase === "recovery_required") return recoveryReason(s);
  if (s.intent.emergency_latched) return m.traffic.emergency;
  switch (s.phase) {
    case "ready":
      return m.traffic.ready;
    case "degraded":
      return m.traffic.degraded;
    case "reconnecting":
      return m.traffic.reconnecting;
    case "starting":
    case "connecting":
    case "verifying":
      return m.traffic.establishing;
    case "failed":
      return m.traffic.failed;
    case "stopping":
      return m.traffic.stopping;
    case "stopped":
      return m.traffic.stopped;
  }
}
