// Local proxy ports (Gateways): their runtime states as words, and the list's filters and sort orders. Pure.
import { CircleCheck, CircleX, PowerOff, Square } from "lucide-react";
import type { GatewayRuntime, GatewaySpec, InstanceView } from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale } from "@/i18n";
import { type StateLook, UNKNOWN_STATE } from "@/lib/status";
import { m } from "./messages";

export const GATEWAY_STATE: Record<GatewayRuntime["state"], StateLook> = {
  serving: { label: m.state.serving, tone: "success", icon: CircleCheck },
  blocked: { label: m.state.blocked, tone: "neutral", icon: Square },
  inactive: { label: m.state.inactive, tone: "neutral", icon: Square },
  failed: { label: m.state.failed, tone: "danger", icon: CircleX },
};

/** What the manager last reported for this port (through its connection's status), if anything. */
export function gatewayRuntime(g: GatewaySpec, owner: InstanceView | undefined): GatewayRuntime | undefined {
  return owner?.status?.gateways.find((r) => r.gateway_id === g.id);
}

/** A port switched off is not bound: that is known from its settings, even when nothing reports it. */
export const DISABLED_GATEWAY: StateLook = { label: ui.common.disabled, tone: "neutral", icon: PowerOff };

/** The port's state as a word: the manager's report, else 已停用 when switched off, else unknown (never assumed). */
export function gatewayLook(g: GatewaySpec, runtime: GatewayRuntime | undefined): StateLook {
  if (runtime) return GATEWAY_STATE[runtime.state];
  return g.enabled ? UNKNOWN_STATE : DISABLED_GATEWAY;
}

export type GatewayFilter = "all" | "serving" | "idle" | "disabled";

export const GATEWAY_FILTERS: { value: GatewayFilter; label: string; title: string }[] = [
  { value: "all", label: ui.common.all, title: m.filter.allHint },
  { value: "serving", label: m.state.serving, title: m.filter.servingHint },
  { value: "idle", label: m.filter.idle, title: m.filter.idleHint },
  { value: "disabled", label: ui.common.disabled, title: m.filter.disabledHint },
];

/** Each port is in exactly one of serving / idle / disabled. */
export function matchesGatewayFilter(g: GatewaySpec, runtime: GatewayRuntime | undefined, f: GatewayFilter): boolean {
  switch (f) {
    case "serving":
      return g.enabled && runtime?.state === "serving";
    case "idle":
      return g.enabled && runtime?.state !== "serving";
    case "disabled":
      return !g.enabled;
    case "all":
    default:
      return true;
  }
}

export type GatewaySort = "port" | "name" | "instance";

export const GATEWAY_SORTS: { value: GatewaySort; label: string }[] = [
  { value: "port", label: m.port },
  { value: "name", label: ui.common.name },
  { value: "instance", label: m.owner },
];

const collator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

/** A new array in the chosen order; ties fall back to the port, so the order never flickers. */
export function sortGateways(
  list: readonly GatewaySpec[],
  sort: GatewaySort,
  ownerName: (g: GatewaySpec) => string,
): GatewaySpec[] {
  const byPort = (a: GatewaySpec, b: GatewaySpec) => a.port - b.port;
  const out = [...list];
  if (sort === "name") out.sort((a, b) => collator.compare(a.name, b.name) || byPort(a, b));
  else if (sort === "instance") out.sort((a, b) => collator.compare(ownerName(a), ownerName(b)) || byPort(a, b));
  else out.sort(byPort);
  return out;
}
