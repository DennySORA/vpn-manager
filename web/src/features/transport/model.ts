// Transport profiles as the UI handles them: the ones that are part of the program and the saved ones in one shape
// (`Choice`), so the list, the connection's select and the detail all name, find and describe a profile the same way.
// The bounds mirror `crates/domain/src/transport.rs` (the server checks them again).
import type {
  BuiltinTransport,
  CongestionControl,
  FlowSettings,
  HealthSettings,
  TransportProfile,
  TransportRef,
  TransportSettings,
  TransportStatus,
} from "@/api/types";
import { localized } from "@/i18n";
import { m } from "./messages";

/** Key of the built-in profile every connection uses until another is chosen. */
export const AUTO_KEY = "auto";

/** A profile a connection can use, wherever it lives. */
export interface Choice {
  /** What names it in a list, a select and the URL: a built-in's key, a saved profile's id. */
  value: string;
  ref: TransportRef;
  name: string;
  builtin: boolean;
  /** What a built-in profile is for, in one sentence. */
  summary: string | null;
  health: HealthSettings;
  settings: TransportSettings;
  /** The saved profile behind it (its revision is what a save or a delete names). */
  saved: TransportProfile | null;
}

export function refValue(r: TransportRef): string {
  return r.kind === "builtin" ? r.key : r.id;
}

/** Every profile: the built-in ones first, as the program lists them, then the saved ones. */
export function choices(builtin: readonly BuiltinTransport[], saved: readonly TransportProfile[]): Choice[] {
  return [
    ...builtin.map((b): Choice => ({
      value: b.key,
      ref: { kind: "builtin", key: b.key },
      name: localized(b.name),
      builtin: true,
      summary: localized(b.summary),
      health: b.health,
      settings: b.settings,
      saved: null,
    })),
    ...saved.map((p): Choice => ({
      value: p.id,
      ref: { kind: "profile", id: p.id },
      name: p.name,
      builtin: false,
      summary: null,
      health: p.health,
      settings: p.settings,
      saved: p,
    })),
  ];
}

export function findChoice(all: readonly Choice[], ref: TransportRef): Choice | undefined {
  const value = refValue(ref);
  return all.find((c) => c.value === value && c.builtin === (ref.kind === "builtin"));
}

/** The name a reference reads as; a profile that is gone says so. */
export function refName(all: readonly Choice[], ref: TransportRef): string {
  return findChoice(all, ref)?.name ?? m.model.gone;
}

/** The fixed values of every range of a profile: one for a fixed profile, none for a range whose profile is gone. */
export function flows(c: Choice, all: readonly Choice[]): FlowSettings[] {
  if (c.settings.mode === "fixed") return [c.settings.flow];
  return c.settings.bands.flatMap((b) => {
    const used = findChoice(all, b.profile);
    return used?.settings.mode === "fixed" ? [used.settings.flow] : [];
  });
}

const KIB = 1024;

/** Buffer memory a new TCP connection reserves, bytes: the largest of the profile's ranges (as the server counts). */
export function tcpStartBytes(c: Choice | undefined, all: readonly Choice[]): number {
  const each = (c ? flows(c, all) : []).map(
    (f) => (Math.min(f.tcp_recv_start_kib, f.tcp_recv_kib) + Math.min(f.tcp_send_start_kib, f.tcp_send_kib)) * KIB,
  );
  return each.length ? Math.max(...each) : (512 + 256) * KIB;
}

/** Buffer memory a UDP flow reserves, bytes (both directions): the largest of the profile's ranges. */
export function udpBytes(c: Choice | undefined, all: readonly Choice[]): number {
  const each = (c ? flows(c, all) : []).map((f) => f.udp_buffer_kib * 2 * KIB);
  return each.length ? Math.max(...each) : 128 * KIB;
}

/** A size given in KiB, in the unit it reads best in: "256 KiB", "1 MiB", "1.5 MiB". */
export function sizeText(kib: number): string {
  if (kib < 1024) return `${kib} KiB`;
  const mib = kib / 1024;
  return `${Number.isInteger(mib) ? mib : mib.toFixed(mib < 10 ? 2 : 1).replace(/\.?0+$/, "")} MiB`;
}

/** Bytes as MiB with as many decimals as they need: "0.75 MiB", "3 MiB". */
export function mibText(bytes: number): string {
  const mib = bytes / (1024 * 1024);
  return `${Number(mib.toFixed(3))} MiB`;
}

/** A buffer's opening and upper size: one number when they are the same. */
export function bufferText(startKib: number, upperKib: number): string {
  return startKib >= upperKib ? sizeText(upperKib) : m.model.bufferRange(sizeText(startKib), sizeText(upperKib));
}

/**
 * The most one connection can carry through a buffer of `kib` at a round trip of `rttMs`, in MB/s: a sender fills the
 * window the buffer offers once per round trip.
 */
export function ceilingMbps(kib: number, rttMs: number): string {
  const mb = (kib * KIB) / (rttMs / 1000) / 1_000_000;
  return mb >= 10 ? mb.toFixed(0) : mb.toFixed(1);
}

export const CONGESTION_LABEL: Record<CongestionControl, string> = { cubic: "Cubic", reno: "Reno", bbr: "BBR" };

/** A congestion control as the worker names the one in use (the kernel's name in strict mode). */
function congestionName(inUse: string): string {
  return inUse in CONGESTION_LABEL ? CONGESTION_LABEL[inUse as CongestionControl] : inUse;
}

/**
 * The congestion control a running connection's own TCP connections use, next to the one its
 * profile asks for: nothing while both are the default, the reason when they differ.
 */
export function congestionNow(t: TransportStatus): string | null {
  const asked = CONGESTION_LABEL[t.flow.congestion];
  const now = t.congestion;
  if (now === null) {
    return t.flow.congestion === "cubic" ? null : m.model.congestionUnconfirmed(asked);
  }
  const inUse = congestionName(now.in_use);
  if (now.fallback === null) {
    return now.in_use === "cubic" ? null : m.model.congestionInEffect(inUse);
  }
  return now.fallback === "userspace_stack"
    ? m.model.congestionUserspace(asked, inUse)
    : m.model.congestionKernel(asked, inUse);
}

/** What a profile holds, in one line (a list row's second line). */
export function brief(c: Choice, all: readonly Choice[]): string {
  if (c.settings.mode === "fixed") {
    const f = c.settings.flow;
    return m.model.fixed(sizeText(f.tcp_send_kib), sizeText(f.tcp_recv_kib));
  }
  // The ranges, shortest round trip first.
  return m.model.automatic(c.settings.bands.map((b) => refName(all, b.profile)));
}

/**
 * What the profile of a range holds, in one line under the range: a fixed profile's buffers alone (a range always uses
 * a fixed one, so the line does not say so again).
 */
export function rangeBrief(c: Choice, all: readonly Choice[]): string {
  if (c.settings.mode !== "fixed") return brief(c, all);
  const f = c.settings.flow;
  return m.model.buffers(sizeText(f.tcp_send_kib), sizeText(f.tcp_recv_kib));
}

/** The values every connection had before transport profiles existed: what a new profile starts from. */
export const BALANCED_FLOW: FlowSettings = {
  tcp_recv_kib: 512,
  tcp_recv_start_kib: 512,
  tcp_send_kib: 256,
  tcp_send_start_kib: 256,
  congestion: "cubic",
  nagle: false,
  ack_delay_ms: 10,
  connect_timeout_secs: 15,
  keepalive_secs: 60,
  dead_peer_secs: 300,
  udp_buffer_kib: 64,
};

export const DEFAULT_HEALTH: HealthSettings = {
  probe_interval_secs: 30,
  probe_failures: 2,
  handshake_timeout_secs: 15,
};

/** Inclusive bounds of each number (the server's). */
export const BOUNDS = {
  tcpKib: [16, 16_384],
  udpKib: [16, 4_096],
  ackDelayMs: [0, 500],
  connectSecs: [3, 120],
  keepaliveSecs: [10, 3_600],
  deadPeerSecs: [30, 7_200],
  probeIntervalSecs: [5, 600],
  probeFailures: [1, 10],
  handshakeSecs: [3, 120],
  bands: [1, 6],
  rttMs: [0, 10_000],
} as const satisfies Record<string, readonly [number, number]>;
