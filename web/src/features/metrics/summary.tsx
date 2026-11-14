// The range in a few numbers, each with its scope and coverage, and what made data unknown. The summary is the view's
// one raised region; its figures update in place on every refresh (totals over a sliding range are live readings: they
// never fade). The gap legend's swatches match the chart bands.

import type { CSSProperties, ReactNode } from "react";
import type { MetricsSeries } from "@/api/types";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { cn } from "@/lib/cn";
import { formatBps, formatBytes } from "@/lib/format";
import {
  availability,
  coverage,
  dnsFailureRate,
  formatDuration,
  formatRatio,
  type GapClass,
  GAP_REASON,
  type Known,
  latencyText,
  notFoundSummary,
  pointSpan,
  resolutionText,
  summarizeGaps,
} from "./model";
import { m } from "./messages";

function Tile({ label, value, detail, hint }: { label: string; value: Known; detail?: ReactNode; hint?: string }) {
  return (
    <div className="min-w-0 px-4 py-3.5" title={hint}>
      <p className="text-caption text-fg-tertiary">{label}</p>
      <p className={cn("mt-1 truncate text-metric", value.value === null ? "text-fg-tertiary" : "machine text-fg")}>
        {value.value ?? ui.common.unknown}
      </p>
      <p className="mt-0.5 text-caption text-fg-tertiary [overflow-wrap:anywhere]">
        {value.value === null ? value.reason : detail}
      </p>
    </div>
  );
}

const known = (value: string | null, reason = m.noDataInRange): Known => ({
  value,
  reason: value === null ? reason : null,
});

/** The highest point of the chart, named with what one point averages over. */
const peak = (bps: number | null, each: string) =>
  bps === null ? m.summary.peakUnknown : m.summary.peak(formatBps(bps), each);

/**
 * The parts of a total apart from ordinary proxy traffic, on a line of their own: the App sandboxes' (where the scope
 * has one: null is nothing to count, not 0), and SSH 下載's and SSH 代理's when they carried anything. A part's name and
 * size never break apart.
 */
function Parts({
  sandbox,
  pull,
  ssh,
}: {
  sandbox: number | null | undefined;
  pull: number | null;
  ssh: number | null;
}) {
  // Keyed by the part, never by its text.
  const parts: { key: "sandbox" | "pull" | "ssh"; text: string }[] = [];
  if (sandbox !== null && sandbox !== undefined)
    parts.push({ key: "sandbox", text: m.summary.partSize(m.parts.appSandbox, formatBytes(sandbox)) });
  if (pull) parts.push({ key: "pull", text: m.summary.partSize(m.parts.sshDownloads, formatBytes(pull)) });
  if (ssh) parts.push({ key: "ssh", text: m.summary.partSize(m.parts.sshProxy, formatBytes(ssh)) });
  if (!parts.length) return null;
  return (
    <span className="block">
      {m.ofWhich}{" "}
      {parts.map((p, i) => (
        <span key={p.key}>
          {i ? m.listSeparator : ""}
          <span className="whitespace-nowrap">{p.text}</span>
        </span>
      ))}
    </span>
  );
}

export function Summary({
  s,
  scopeLabel,
  rangeLabel,
  style,
}: {
  s: MetricsSeries;
  scopeLabel: string;
  rangeLabel: string;
  style?: CSSProperties;
}) {
  const t = s.totals;
  const instanceLevel = !s.scope.startsWith("gateway:");
  const each = pointSpan(s.resolution_secs);
  const dns = dnsFailureRate(t);
  const avail = availability(t);
  const cov = coverage(t);
  const reporting = s.scope === "all" ? s.instances.length : null;
  return (
    <section aria-label={m.summary.label} style={style} className={cn("panel-raised", STAGGER_IN)}>
      <p className="border-b border-line-subtle px-4 py-2.5 text-caption text-fg-secondary">
        {m.summary.header(
          <span className="font-medium text-fg">{scopeLabel}</span>,
          rangeLabel,
          resolutionText(s.resolution_secs),
          <span className="machine">{formatDuration(t.covered_ms)}</span>,
          formatRatio(cov),
          reporting,
        )}
      </p>
      <div className="grid grid-cols-2 divide-line-subtle md:grid-cols-3 lg:grid-cols-5 lg:divide-x">
        <Tile
          label={ui.common.download}
          value={known(t.payload_rx_bytes === null ? null : formatBytes(t.payload_rx_bytes))}
          detail={
            <>
              {peak(t.peak_payload_rx_bps, each)}
              <Parts sandbox={t.sandbox_rx_bytes} pull={t.ssh_pull_rx_bytes} ssh={t.ssh_rx_bytes} />
            </>
          }
          hint={m.summary.downloadHint}
        />
        <Tile
          label={ui.common.upload}
          value={known(t.payload_tx_bytes === null ? null : formatBytes(t.payload_tx_bytes))}
          detail={
            <>
              {peak(t.peak_payload_tx_bps, each)}
              <Parts sandbox={t.sandbox_tx_bytes} pull={t.ssh_pull_tx_bytes} ssh={t.ssh_tx_bytes} />
            </>
          }
        />
        <Tile
          label={m.summary.connectLatency}
          value={latencyText(t.connect_p95_us, t.connect_count)}
          detail={m.summary.connects(
            t.connect_count ?? "—",
            t.connect_timeouts ?? "—",
            t.connect_failures ?? "—",
            notFoundSummary(s),
          )}
          hint={m.summary.latencyHint}
        />
        {instanceLevel ? (
          <Tile
            label={m.summary.dnsFailureRate}
            value={dns}
            detail={m.summary.dns(
              t.dns_queries ?? "—",
              t.dns_cache_hits ?? "—",
              latencyText(t.dns_p95_us, t.dns_upstream_count, "—").value ?? "—",
            )}
          />
        ) : (
          <Tile label={m.summary.dnsFailureRate} value={{ value: null, reason: m.summary.gatewayDns }} />
        )}
        {s.scope === "all" ? (
          <Tile
            label={m.summary.wireguardReceived}
            value={known(t.wg_rx_bytes === null ? null : formatBytes(t.wg_rx_bytes))}
            detail={m.summary.wireguardSent(t.wg_tx_bytes === null ? "—" : formatBytes(t.wg_tx_bytes))}
          />
        ) : (
          <Tile
            label={m.availability}
            value={known(
              avail === null ? null : formatRatio(avail),
              t.covered_ms > 0 ? m.summary.gateUnknown : m.noDataInRange,
            )}
            detail={m.summary.availabilityDetail(
              formatDuration(t.covered_ms),
              formatDuration(t.serving_ms ?? 0),
              cov < 1 ? formatDuration(t.range_ms - t.covered_ms) : null,
            )}
            hint={m.summary.availabilityHint}
          />
        )}
      </div>
    </section>
  );
}

/** The legend swatch of a gap class: the same washes as the chart bands, a little stronger to read at 12 px. */
const SWATCH: Record<GapClass, string> = {
  absent: "size-3 bg-white/12",
  unavailable: "size-3 bg-white/12",
  incomplete: "size-3 bg-warning/45",
  restart: "h-3 w-0.5 bg-info",
};

/** Why parts of the charts are empty, by reason (only reasons in this range). */
export function GapLegend({ s, style }: { s: MetricsSeries; style?: CSSProperties }) {
  // A restart is listed once, from its marker (its window without a rate is the same event).
  const gaps = summarizeGaps(s.gaps, s.from_ms, s.to_ms).filter((g) => g.reason !== "new_generation");
  if (s.restarts.length) gaps.push({ reason: "new_generation", spans: s.restarts.length, ms: 0 });
  if (!gaps.length) return null;
  return (
    <section
      aria-label={m.summary.gapLegend}
      style={style}
      className={cn("flex flex-wrap items-start gap-x-5 gap-y-2 px-1", STAGGER_IN)}
    >
      {gaps.map((g) => {
        const look = GAP_REASON[g.reason];
        return (
          <p
            key={g.reason}
            className="flex min-w-0 max-w-[420px] items-start gap-2 text-caption text-fg-secondary animate-fade-in"
          >
            <span
              aria-hidden
              className={cn(
                "mt-1 shrink-0 rounded-[2px] forced-colors:border forced-colors:border-[CanvasText]",
                SWATCH[look.cls],
              )}
            />
            <span className="min-w-0">
              <span className="font-medium text-fg">{look.label}</span>{" "}
              <span className="machine text-fg-tertiary">
                {look.cls === "restart" ? m.times(g.spans) : m.summary.spans(g.spans, formatDuration(g.ms))}
              </span>
              <span className="block text-fg-tertiary">{look.detail}</span>
            </span>
          </p>
        );
      })}
      {s.gaps_truncated ? <p className="text-caption text-warning">{m.summary.truncated}</p> : null}
    </section>
  );
}
