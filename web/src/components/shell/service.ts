import { ApiFailure } from "@/api/client";
import { useConnection } from "@/api/events";
import { useSystemStatus } from "@/api/queries";
import type { Tone } from "@/lib/status";
import { m } from "./messages";

export interface ServiceState {
  tone: Tone;
  label: string;
  detail: string;
  pulse?: boolean | undefined;
  /** Which service does not answer, when one does not. */
  down?: "controller" | "manager" | undefined;
}

/** Whether the controller reaches the manager (event stream first, then the status poll); null until known. */
export function useManagerConnected(): boolean | null {
  const sys = useSystemStatus();
  const conn = useConnection();
  return conn.manager ?? sys.data?.manager_connected ?? null;
}

/**
 * Health of the path browser → controller → manager, from observed facts only: the status poll,
 * the event stream and the manager link the controller reports.
 */
export function useServiceState(): ServiceState {
  const sys = useSystemStatus();
  const conn = useConnection();
  const unreachable = sys.isError && sys.error instanceof ApiFailure && sys.error.kind === "network";
  const manager = useManagerConnected();

  if (unreachable) {
    return {
      tone: "danger",
      label: m.service.controllerDown,
      detail: m.service.controllerDownDetail,
      down: "controller",
    };
  }
  if (manager === false) {
    return {
      tone: "danger",
      label: m.service.managerDown,
      detail: m.service.managerDownDetail,
      down: "manager",
    };
  }
  if (conn.stream !== "open") {
    if (!conn.opened)
      return { tone: "neutral", label: m.service.connecting, detail: m.service.openingStream, pulse: true };
    return {
      tone: "warning",
      label: m.service.streamReconnecting,
      detail: m.service.streamReconnectingDetail,
      pulse: true,
    };
  }
  if (sys.data && manager) {
    return { tone: "success", label: m.service.healthy, detail: m.service.healthyDetail };
  }
  return { tone: "neutral", label: m.service.connecting, detail: m.service.readingStatus, pulse: true };
}

/** Why changes cannot be sent right now (controller or manager unreachable), or null. */
export function useMutationBlocked(): string | null {
  const s = useServiceState();
  return s.tone === "danger" ? m.service.blocked(s.label) : null;
}
