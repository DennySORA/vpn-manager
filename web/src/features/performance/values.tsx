// How 效能統計 writes a value: the number in mono, or — with its reason (a dotted underline that is focusable, the reason
// in a tooltip and in sr-only text, so keyboard and screen-reader users read it too). Unknown is never 0.

import type { ReactNode } from "react";
import type { LatencySummary } from "@/api/generated/LatencySummary";
import { Tip } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { m } from "./messages";
import { formatUs, latencyTriple, reasonText } from "./model";

/** A value with its reason when unknown. */
export function Val({ v, className }: { v: { text: string; reason: string | null }; className?: string }) {
  if (v.reason) {
    return (
      <Tip content={m.value.reasonWithCode(reasonText(v.reason), v.reason)}>
        <span
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a tooltip trigger: keyboard users focus it to read the tooltip
          tabIndex={0}
          className={cn(
            "machine cursor-help text-fg-tertiary underline decoration-dotted underline-offset-4",
            className,
          )}
        >
          —<span className="sr-only">{m.value.srReason(reasonText(v.reason))}</span>
        </span>
      </Tip>
    );
  }
  return <span className={cn("machine text-fg", className)}>{v.text}</span>;
}

/** Two values stacked, each with a short label, so neither splits across lines. */
export function Pair({ a, b }: { a: [string, ReactNode]; b: [string, ReactNode] }) {
  return (
    <span className="inline-grid grid-cols-[auto_auto] items-baseline justify-end gap-x-1.5 whitespace-nowrap">
      <span className="text-caption text-fg-tertiary">{a[0]}</span>
      <span className="text-right">{a[1]}</span>
      <span className="text-caption text-fg-tertiary">{b[0]}</span>
      <span className="text-right">{b[1]}</span>
    </span>
  );
}

/** p50／p95／p99 (bucket upper bounds) with the bounds and counts in the tooltip; no samples is said, not 0. */
export function Latency({ l }: { l: LatencySummary | undefined }) {
  if (!l) return <span className="text-fg-tertiary">—</span>;
  if (l.count === "0") {
    return (
      <Tip content={m.value.reasonWithCode(m.reason.NO_LATENCY_SAMPLES, "NO_LATENCY_SAMPLES")}>
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a tooltip trigger: keyboard users focus it to read the tooltip */}
        <span tabIndex={0} className="cursor-help text-fg-tertiary underline decoration-dotted underline-offset-4">
          {m.latency.noSamples}
        </span>
      </Tip>
    );
  }
  const q = (upper: string | null, lower: string | null) =>
    upper === null
      ? `> ${formatUs(lower)}`
      : lower === null
        ? `≤ ${formatUs(upper)}`
        : `${formatUs(lower)}–${formatUs(upper)}`;
  return (
    <Tip
      content={m.latency.buckets(
        q(l.p50_us, l.p50_lower_us),
        q(l.p95_us, l.p95_lower_us),
        q(l.p99_us, l.p99_lower_us),
        l.count,
        l.timeout_count,
      )}
    >
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a tooltip trigger: keyboard users focus it to read the tooltip */}
      <span tabIndex={0} className="machine cursor-help whitespace-nowrap text-fg [overflow-wrap:normal]">
        {latencyTriple(l.p50_us, l.p95_us, l.p99_us)}
      </span>
    </Tip>
  );
}
