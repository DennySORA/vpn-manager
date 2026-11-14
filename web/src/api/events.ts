// One SSE stream (`/v1/events`) patches the query caches. EventSource resumes with
// Last-Event-ID by itself; when the server says `resync_required` (we fell behind or it
// restarted) every snapshot is reloaded instead of guessing.

import { type QueryClient, useQueryClient } from "@tanstack/react-query";
import { useEffect, useSyncExternalStore } from "react";
import { usePageVisible } from "@/lib/use-media";
import type { SshDownloadStatus } from "./generated/SshDownloadStatus";
import { keys } from "./keys";
import { patchSshDownloadStatus } from "./ssh-downloads";
import type { AppStatus, AppView, ForwardStatus, ForwardView, InstanceStatus, InstanceView, LiveRates } from "./types";

const LIVE_POINTS = 600;

/** `opened`: the stream has been open at least once (a first connect is not a reconnect). */
interface Connection {
  stream: "connecting" | "open" | "closed";
  manager: boolean | null;
  opened: boolean;
}

let connection: Connection = { stream: "connecting", manager: null, opened: false };
const listeners = new Set<() => void>();

function setConnection(next: Partial<Connection>) {
  connection = { ...connection, ...next };
  for (const l of listeners) l();
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}
const snapshot = () => connection;

/** The latest connection state outside React (merging refetched data). */
export function connectionSnapshot(): Connection {
  return connection;
}

/** Live connection state of the event stream and the controller→manager link. */
export function useConnection(): Connection {
  return useSyncExternalStore(subscribe, snapshot);
}

function patchStatus(qc: QueryClient, status: InstanceStatus) {
  // Newer facts only: a late event never replaces a status observed after it.
  qc.setQueryData<InstanceView[]>(keys.instances, (views) =>
    views?.map((v) =>
      v.spec.id === status.instance_id &&
      (!v.status || Date.parse(v.status.observed_at) <= Date.parse(status.observed_at))
        ? { ...v, status }
        : v,
    ),
  );
}

/** The newer of two observations of one App (an event may land while a request is in flight). */
export function newerAppStatus(a: AppStatus | null, b: AppStatus | null): AppStatus | null {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(a.observed_at) > Date.parse(b.observed_at) ? a : b;
}

/** Put a fresher status of one App into the list cache (from an action's answer or an event). */
export function patchAppStatus(qc: QueryClient, status: AppStatus) {
  qc.setQueryData<AppView[]>(keys.apps, (views) =>
    views?.map((v) => (v.spec.id === status.app_id ? { ...v, status: newerAppStatus(v.status, status) } : v)),
  );
}

/** The newer of two observations of one forward. */
export function newerForwardStatus(a: ForwardStatus | null, b: ForwardStatus | null): ForwardStatus | null {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(a.observed_at) > Date.parse(b.observed_at) ? a : b;
}

/** Put a fresher status of one forward into the list cache. */
export function patchForwardStatus(qc: QueryClient, status: ForwardStatus) {
  qc.setQueryData<ForwardView[]>(keys.forwards, (views) =>
    views?.map((v) =>
      v.binding.id === status.binding_id ? { ...v, status: newerForwardStatus(v.status, status) } : v,
    ),
  );
}

function appendRates(qc: QueryClient, rates: LiveRates) {
  qc.setQueryData<LiveRates[]>(keys.live(rates.instance_id), (prev) => {
    const next = prev ? [...prev, rates] : [rates];
    return next.length > LIVE_POINTS ? next.slice(next.length - LIVE_POINTS) : next;
  });
}

/**
 * The stream runs only while the tab is visible: every open tab would otherwise hold one of the
 * browser's six HTTP/1.1 connections to this origin, and enough tabs would leave none for an
 * emergency stop. A tab that becomes visible again reconnects and reloads.
 */
export function useEventStream() {
  const qc = useQueryClient();
  const visible = usePageVisible();
  useEffect(() => {
    if (!visible) {
      setConnection({ stream: "closed", manager: null });
      return;
    }
    const es = new EventSource("/v1/events");
    // Coming back (from a hidden tab or a dropped stream): what was missed is reloaded.
    const resumed = connection.opened;
    setConnection({ stream: "connecting" });
    es.onopen = () => {
      setConnection({ stream: "open", opened: true });
      if (resumed) void qc.invalidateQueries();
    };
    // Unknown until the next stream says (the server sends the link state first).
    es.onerror = () => {
      setConnection({ stream: es.readyState === EventSource.CLOSED ? "closed" : "connecting", manager: null });
    };

    // The event's JSON, or null when it does not parse; the event name says its shape.
    const parse = (e: { data: unknown }): unknown => {
      try {
        return typeof e.data === "string" ? JSON.parse(e.data) : null;
      } catch {
        return null;
      }
    };
    es.addEventListener("instance_status", (e) => {
      const ev = parse(e) as { status: InstanceStatus } | null;
      if (ev) patchStatus(qc, ev.status);
    });
    es.addEventListener("live_rates", (e) => {
      const ev = parse(e) as { rates: LiveRates } | null;
      if (ev) appendRates(qc, ev.rates);
    });
    es.addEventListener("app_status", (e) => {
      const ev = parse(e) as { status: AppStatus } | null;
      if (!ev) return;
      patchAppStatus(qc, ev.status);
      // A start or stop changes the tree and the output: refresh an open inspector at once.
      void qc.invalidateQueries({ queryKey: keys.appProcesses(ev.status.app_id) });
    });
    es.addEventListener("forward_status", (e) => {
      const ev = parse(e) as { status: ForwardStatus } | null;
      if (ev) patchForwardStatus(qc, ev.status);
    });
    es.addEventListener("ssh_download_status", (e) => {
      const ev = parse(e) as { status: SshDownloadStatus } | null;
      if (ev) patchSshDownloadStatus(qc, ev.status);
    });
    es.addEventListener("manager_connection", (e) => {
      const ev = parse(e) as { connected: boolean } | null;
      if (ev) {
        setConnection({ manager: ev.connected });
        if (ev.connected) void qc.invalidateQueries();
      }
    });
    es.addEventListener("entity_changed", () => {
      void qc.invalidateQueries();
    });
    es.addEventListener("resync_required", () => {
      void qc.invalidateQueries();
    });
    return () => {
      es.close();
      setConnection({ stream: "closed" });
    };
  }, [qc, visible]);
}
