// Port forwards: state looks, honest reachability wording, provider guidance and the form model.
// The rules mirror `check_forward` (crates/domain/src/validation.rs) and the manager's checks so
// problems show before a request is sent; the server still decides.

import { CircleSlash, Hourglass, PlugZap, Radar, ShieldAlert, TriangleAlert, Unplug } from "lucide-react";
import type {
  AppView,
  ForwardInput,
  ForwardProtocol,
  ForwardState,
  ForwardStatus,
  ForwardView,
  InstanceView,
} from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale } from "@/i18n";
import { type StateLook, UNKNOWN_STATE } from "@/lib/status";
import { m } from "./messages";

export const PROTOCOL_LABEL: Record<ForwardProtocol, string> = { tcp: "TCP", udp: "UDP", both: m.protocolBoth };

export const FORWARD_STATE: Record<ForwardState, StateLook> = {
  disabled: { label: ui.common.disabled, tone: "neutral", icon: CircleSlash },
  connection_not_ready: { label: m.state.connectionNotReady, tone: "warning", icon: Hourglass },
  target_missing: { label: m.state.targetMissing, tone: "warning", icon: Unplug },
  target_not_owned: { label: m.state.targetNotOwned, tone: "danger", icon: ShieldAlert },
  // Listening is an observed fact of the worker, not proof the Internet reaches it (evidence says that).
  listening: { label: m.state.listening, tone: "brand", icon: PlugZap },
};

export function forwardLook(v: ForwardView): StateLook {
  if (!v.status) return UNKNOWN_STATE;
  if (v.status.reason_code === "PROVIDER_UNSUPPORTED")
    return { label: m.state.unsupported, tone: "neutral", icon: TriangleAlert };
  return FORWARD_STATE[v.status.state];
}

/** Evidence from outside: only an observed arrival counts; never green on configuration alone. */
export function reachLook(s: ForwardStatus | null): StateLook {
  if (!s) return UNKNOWN_STATE;
  return s.reachability.state === "observed"
    ? { label: m.reach.observed, tone: "success", icon: Radar }
    : { label: m.reach.unverified, tone: "neutral", icon: Radar };
}

/** The latest outside arrival of either protocol. */
export function lastObserved(s: ForwardStatus | null): string | null {
  if (!s) return null;
  const all = [s.reachability.tcp_observed_at, s.reachability.udp_observed_at].filter((t): t is string => Boolean(t));
  return all.sort().at(-1) ?? null;
}

export type ForwardFilter = "all" | "listening" | "idle" | "disabled";

export const FORWARD_FILTERS: { value: ForwardFilter; label: string; title: string }[] = [
  { value: "all", label: ui.common.all, title: m.filter.allTitle },
  { value: "listening", label: m.state.listening, title: m.filter.listeningTitle },
  { value: "idle", label: m.filter.idle, title: m.filter.idleTitle },
  { value: "disabled", label: ui.common.disabled, title: m.filter.disabledTitle },
];

/** Each forward is in exactly one of listening / idle / disabled. */
export function matchesForwardFilter(v: ForwardView, f: ForwardFilter): boolean {
  const on = v.binding.enabled;
  switch (f) {
    case "listening":
      return on && v.status?.state === "listening";
    case "idle":
      return on && v.status?.state !== "listening";
    case "disabled":
      return !on;
    case "all":
    default:
      return true;
  }
}

export type ForwardSort = "name" | "port" | "app";

export const FORWARD_SORTS: { value: ForwardSort; label: string }[] = [
  { value: "name", label: ui.common.name },
  { value: "port", label: m.tunnelPort },
  { value: "app", label: m.sort.app },
];

const collator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

/** A new array in the chosen order; ties fall back to the tunnel port, then the ID, so rows never swap by chance. */
export function sortForwards(
  list: readonly ForwardView[],
  sort: ForwardSort,
  appName: (v: ForwardView) => string,
): ForwardView[] {
  const byPort = (a: ForwardView, b: ForwardView) =>
    a.binding.tunnel_port - b.binding.tunnel_port || collator.compare(a.binding.id, b.binding.id);
  const out = [...list];
  if (sort === "port") out.sort(byPort);
  else if (sort === "app") out.sort((a, b) => collator.compare(appName(a), appName(b)) || byPort(a, b));
  else out.sort((a, b) => collator.compare(a.binding.name, b.binding.name) || byPort(a, b));
  return out;
}

/** The port AirVPN tests for a forward: its public port, or its tunnel port when it names none (as 連入埠 match them). */
export function testedPort(v: ForwardView): number {
  return v.binding.public_port ?? v.binding.tunnel_port;
}

export function matchesForward(v: ForwardView, q: string, instanceName?: string, appName?: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const b = v.binding;
  return [
    b.name,
    String(b.tunnel_port),
    String(b.target_port),
    String(b.public_port ?? ""),
    instanceName ?? "",
    appName ?? "",
    PROTOCOL_LABEL[b.protocol],
  ]
    .join(" ")
    .toLowerCase()
    .includes(needle);
}

/** What the provider of a connection lets a forward do, and the steps to get a port there. */
export interface ProviderGuide {
  /** Forwards cannot work on this connection at all; the reason. */
  unsupported: string | null;
  title: string;
  steps: string[];
}

export function providerGuide(owner: InstanceView | undefined): ProviderGuide {
  switch (owner?.profile?.provider) {
    case "mullvad":
      return { unsupported: m.guide.mullvad, title: "Mullvad", steps: [] };
    case "airvpn":
      return { unsupported: null, title: m.guide.airvpnTitle, steps: m.guide.airvpnSteps };
    case "generic":
    case undefined:
    default:
      return { unsupported: null, title: m.guide.genericTitle, steps: m.guide.genericSteps };
  }
}

export interface ForwardDraft {
  instance: string;
  name: string;
  protocol: ForwardProtocol;
  tunnelPort: string;
  publicPort: string;
  app: string;
  targetPort: string;
  enabled: boolean;
  maxConnections: string;
  /** The user's choice; it applies only while the forward carries TCP (see `proxyApplies`). */
  proxyProtocol: boolean;
  /** The user's choice; it applies only where UDP can go straight into a sandbox (see `udpDirectBlocker`). */
  udpDirect: boolean;
}

/** PROXY protocol v2 goes on TCP connections only: a UDP-only forward cannot send it (the server refuses it). */
export function proxyApplies(protocol: ForwardProtocol): boolean {
  return protocol !== "udp";
}

/**
 * Why a forward's UDP cannot go straight into the sandbox (null: it can): it carries no UDP, its connection has no
 * sandbox, or its App does not run in one. The server refuses each (`/udp_direct`); an unknown connection or App is
 * left to it.
 */
export function udpDirectBlocker(
  protocol: ForwardProtocol,
  owner: InstanceView | undefined,
  app: AppView | undefined,
): string | null {
  if (protocol === "tcp") return m.udpBlocked.tcpOnly;
  if (owner && !owner.spec.strict) return m.udpBlocked.notStrictConnection;
  if (app && app.spec.isolation !== "strict_netns") return m.udpBlocked.notStrictApp(app.spec.name);
  return null;
}

function port(v: string): number | null {
  const t = v.trim();
  if (!/^\d{1,5}$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 && n <= 65535 ? n : null;
}

export interface DraftCheck {
  errors: Partial<Record<keyof ForwardDraft, string>>;
  input: ForwardInput | null;
}

/** Validate the form like the server does and build the request. */
export function checkDraft(
  d: ForwardDraft,
  apps: AppView[],
  others: ForwardView[],
  owner: InstanceView | undefined,
): DraftCheck {
  const errors: DraftCheck["errors"] = {};
  if (!d.instance) errors.instance = m.errors.chooseConnection;
  const guide = providerGuide(owner);
  if (guide.unsupported) errors.instance = guide.unsupported;
  const tunnelPort = port(d.tunnelPort);
  if (tunnelPort === null) errors.tunnelPort = m.errors.port;
  const publicPort = d.publicPort.trim() ? port(d.publicPort) : null;
  if (d.publicPort.trim() && publicPort === null) errors.publicPort = m.errors.publicPort;
  const targetPort = port(d.targetPort);
  if (targetPort === null || targetPort < 1024) errors.targetPort = m.errors.appPort;
  const max = /^\d+$/.test(d.maxConnections.trim()) ? Number(d.maxConnections.trim()) : Number.NaN;
  if (!(max >= 1 && max <= 16384)) errors.maxConnections = m.errors.maxConnections;
  const app = apps.find((a) => a.spec.id === d.app);
  if (!app) errors.app = m.errors.chooseApp;
  else if (app.spec.instance_id !== d.instance) errors.app = m.errors.appConnection;
  else if (d.protocol !== "tcp" && app.spec.isolation === "enforced_proxy") errors.protocol = m.errors.enforcedUdp;
  if (tunnelPort !== null) {
    const clash = others.find(
      (o) =>
        o.binding.instance_id === d.instance &&
        o.binding.tunnel_port === tunnelPort &&
        (o.binding.protocol === "both" || d.protocol === "both" || o.binding.protocol === d.protocol),
    );
    if (clash) errors.tunnelPort = m.errors.portTaken(clash.binding.name);
  }
  // Kept in the draft wherever it cannot apply (it comes back with UDP, a strict connection and App), never sent there.
  const udpDirect = d.udpDirect && udpDirectBlocker(d.protocol, owner, app) === null;
  if (udpDirect && tunnelPort !== null && targetPort !== null && targetPort !== tunnelPort)
    errors.udpDirect = m.errors.udpDirectPort(tunnelPort);
  const name = d.name.trim() || m.defaultName(tunnelPort);
  if (name.length > 64) errors.name = ui.common.nameTooLong;
  const valid = Object.keys(errors).length === 0 && tunnelPort !== null && targetPort !== null;
  return {
    errors,
    input: valid
      ? {
          instance_id: d.instance,
          name,
          protocol: d.protocol,
          tunnel_port: tunnelPort,
          public_port: publicPort,
          target_app_id: d.app,
          target_port: targetPort,
          enabled: d.enabled,
          max_connections: max,
          // Kept in the draft while UDP is chosen (it comes back with TCP), never sent for UDP.
          proxy_protocol: d.proxyProtocol && proxyApplies(d.protocol),
          udp_direct: udpDirect,
        }
      : null,
  };
}
