// Formatting for machine values. Units are explicit; unknown stays unknown (never 0).

import { intlLocale } from "@/i18n";
import { m } from "./messages";
import { serverNow } from "./server-clock";

const rtf = new Intl.RelativeTimeFormat(intlLocale, { numeric: "auto" });
const nf1 = new Intl.NumberFormat(intlLocale, { maximumFractionDigits: 1 });
const nf0 = new Intl.NumberFormat(intlLocale, { maximumFractionDigits: 0 });

/** Bits per second, SI units (as network speeds are quoted). */
export function formatBps(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return "—";
  if (bps < 1_000) return `${nf0.format(bps)} bps`;
  if (bps < 1_000_000) return `${nf1.format(bps / 1_000)} Kbps`;
  if (bps < 1_000_000_000) return `${nf1.format(bps / 1_000_000)} Mbps`;
  return `${nf1.format(bps / 1_000_000_000)} Gbps`;
}

/** Byte counts, binary units (as file sizes are quoted). Accepts u64 decimal strings. */
export function formatBytes(value: number | string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const n = typeof value === "string" ? Number(value) : value;
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? nf0.format(v) : nf1.format(v)} ${units[i]}`;
}

/** "12 秒前" / "3 分鐘後": a server timestamp against the server's time unless `now` says otherwise. */
export function relativeTime(iso: string | null | undefined, now: number = serverNow()): string {
  if (!iso) return m.notObserved;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return m.notObserved;
  const diff = (t - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 5) return m.justNow;
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86_400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(Math.round(diff / 86_400), "day");
}

export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(intlLocale, { hour12: false });
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

export function formatPercent(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return `${nf1.format(v)}%`;
}

/** The parts as one list in this language: 「A、B與C」, "A, B, and C". */
export function joinList(parts: readonly string[]): string {
  return m.joinList(parts);
}
