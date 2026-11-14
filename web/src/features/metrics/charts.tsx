// The charts of 數據統計: which columns each one plots, in which unit and scale, and the card
// around it (legend, gap bands, tooltip details, table view).

import { type CSSProperties, type ReactNode, useMemo } from "react";
import type { MetricsSeries } from "@/api/types";
import { ChartFrame, ChartTable } from "@/components/charts/chart-frame";
import {
  type Band,
  type ChartSeries,
  type Frame,
  type Hover,
  type Scale,
  SeriesChart,
} from "@/components/charts/series-chart";
import { m as ui } from "@/components/ui/messages";
import { intlLocale } from "@/i18n";
import { formatBps, formatBytes, formatPercent } from "@/lib/format";
import { m } from "./charts/messages";
import { m as metrics } from "./messages";
import {
  formatGauge,
  formatMicros,
  formatRate,
  formatRatio,
  GAP_REASON,
  gapBands,
  gapsAt,
  latencyText,
  notFoundText,
  restartMarkers,
  timeTicks,
  windowLabel,
} from "./model";

const RX = "var(--color-series-rx)";
const TX = "var(--color-series-tx)";
const FAIL = "var(--color-danger)";

// Module-level scales and formatters: stable identities keep the plot layer memoized.
const BPS: Scale = { kind: "linear", minTop: 1_000_000 };
const FLOWS: Scale = { kind: "linear", minTop: 4 };
const PER_SEC: Scale = { kind: "linear", minTop: 1 };
const RATIO: Scale = { kind: "fixed", max: 1 };
const LOG: Scale = { kind: "log" };
const CPU: Scale = { kind: "linear", minTop: 5 };
const MEMORY: Scale = { kind: "linear", minTop: 64 * 1_048_576, binary: true };

const fmtBps = (v: number) => formatBps(v);
const fmtGauge = (v: number) => formatGauge(v);
const fmtRate = (v: number) => formatRate(v);
const fmtRatio = (v: number) => formatRatio(v);
const fmtPct = (v: number) => formatPercent(v);
const fmtBytes = (v: number) => formatBytes(v);
const fmtLatency = (v: number) => `≤ ${formatMicros(v)}`;
const axisRate = (v: number) => (v >= 10 ? String(Math.round(v)) : String(Number(v.toFixed(2))));
const axisRatio = (v: number) => `${Math.round(v * 100)}%`;

export type ChartId = "traffic" | "wireguard" | "flows" | "latency" | "dns" | "cache" | "cpu" | "memory";

interface ChartDef {
  id: ChartId;
  title: string;
  subtitle: string;
  /** What the chart shows for one 代理埠, when it differs. */
  gatewaySubtitle?: string;
  /** Only an Instance (or every Instance) has it; a Gateway does not. */
  instanceOnly: boolean;
  /** Resource readings: also shaded where the worker did not report them. */
  resource?: boolean;
  scale: Scale;
  format: (v: number) => string;
  formatAxis: (v: number) => string;
  series: (s: MetricsSeries, instanceLevel: boolean) => ChartSeries[];
  unknownText?: (s: MetricsSeries, i: number, series: ChartSeries) => string | null;
  details?: (s: MetricsSeries, i: number, instanceLevel: boolean) => ReactNode;
}

const num = (v: number | null | undefined) => (v === null || v === undefined ? "—" : v.toLocaleString(intlLocale));

/** A part of a connection's traffic apart from its ordinary proxy traffic. */
type PartKey = "sandbox" | "pull" | "ssh";

export const CHARTS: ChartDef[] = [
  {
    id: "traffic",
    title: m.traffic.title,
    subtitle: m.traffic.subtitle,
    gatewaySubtitle: m.traffic.gatewaySubtitle,
    instanceOnly: false,
    scale: BPS,
    format: fmtBps,
    formatAxis: fmtBps,
    series: (s) => [
      { key: "rx", label: ui.common.download, color: RX, values: s.payload_rx_bps },
      { key: "tx", label: ui.common.upload, color: TX, values: s.payload_tx_bps },
    ],
    // The point's parts apart from ordinary proxy traffic: the App sandboxes' where a connection of the scope has one,
    // SSH 下載's and SSH 代理's where they carried anything.
    details: (s, i) => {
      const parts: [PartKey, string, number | null, number | null][] = [
        ["sandbox", metrics.parts.appSandbox, s.sandbox_rx_bps[i] ?? null, s.sandbox_tx_bps[i] ?? null],
        ["pull", metrics.parts.sshDownloads, s.ssh_pull_rx_bps[i] ?? null, s.ssh_pull_tx_bps[i] ?? null],
        ["ssh", metrics.parts.sshProxy, s.ssh_rx_bps[i] ?? null, s.ssh_tx_bps[i] ?? null],
      ];
      const shown = parts.filter(([part, , rx, tx]) =>
        part === "sandbox" ? rx !== null || tx !== null : (rx ?? 0) > 0 || (tx ?? 0) > 0,
      );
      if (!shown.length) return null;
      // Each arrow stays with its value when the line wraps.
      return (
        <>
          {shown.map(([part, label, rx, tx]) => (
            <p key={part}>
              {m.traffic.part(label)} <span className="whitespace-nowrap">↓ {formatBps(rx)}</span>{" "}
              <span className="whitespace-nowrap">↑ {formatBps(tx)}</span>
            </p>
          ))}
        </>
      );
    },
  },
  {
    id: "wireguard",
    title: "WireGuard",
    subtitle: m.wireguard.subtitle,
    instanceOnly: true,
    scale: BPS,
    format: fmtBps,
    formatAxis: fmtBps,
    series: (s) => [
      { key: "rx", label: m.wireguard.received, color: RX, values: s.wg_rx_bps },
      { key: "tx", label: m.wireguard.sent, color: TX, values: s.wg_tx_bps },
    ],
  },
  {
    id: "flows",
    title: m.flows.title,
    subtitle: m.flows.subtitle,
    gatewaySubtitle: m.flows.gatewaySubtitle,
    instanceOnly: false,
    scale: FLOWS,
    format: fmtGauge,
    formatAxis: fmtGauge,
    series: (s) => [
      { key: "tcp", label: "TCP", color: RX, values: s.active_tcp },
      { key: "udp", label: "UDP", color: TX, values: s.active_udp },
    ],
  },
  {
    id: "latency",
    title: m.latency.title,
    subtitle: m.latency.subtitle,
    gatewaySubtitle: m.latency.gatewaySubtitle,
    instanceOnly: false,
    scale: LOG,
    format: fmtLatency,
    formatAxis: formatMicros,
    series: (s, instanceLevel) => {
      const out: ChartSeries[] = [
        { key: "p50", label: m.latency.connect("p50"), color: "var(--color-series-p50)", values: s.connect_p50_us },
        { key: "p95", label: m.latency.connect("p95"), color: "var(--color-series-p95)", values: s.connect_p95_us },
        { key: "p99", label: m.latency.connect("p99"), color: "var(--color-series-p99)", values: s.connect_p99_us },
      ];
      if (instanceLevel) out.push({ key: "dns", label: "DNS p95", color: TX, values: s.dns_p95_us });
      return out;
    },
    unknownText: (s, i, series) => {
      const dns = series.key === "dns";
      return latencyText(
        null,
        (dns ? s.dns_upstream_count[i] : s.connect_count[i]) ?? null,
        dns ? m.latency.noUpstream : undefined,
      ).reason;
    },
    details: (s, i, instanceLevel) => (
      <>
        <p>
          {m.latency.connects(
            num(s.connect_count[i]),
            num(s.connect_timeouts[i]),
            num(s.connect_failures[i]),
            notFoundText(s.connect_not_found[i], num),
            num(s.connect_rejected[i]),
          )}
        </p>
        {instanceLevel ? <p>{m.latency.dnsUpstream(num(s.dns_upstream_count[i]), num(s.dns_timeouts[i]))}</p> : null}
      </>
    ),
  },
  {
    id: "dns",
    title: m.dns.title,
    subtitle: m.dns.subtitle,
    instanceOnly: true,
    scale: PER_SEC,
    format: fmtRate,
    formatAxis: axisRate,
    series: (s) => [
      { key: "q", label: m.dns.queries, color: RX, values: s.dns_queries_per_sec },
      { key: "f", label: m.dns.failures, color: FAIL, values: s.dns_failures_per_sec },
    ],
  },
  {
    id: "cache",
    title: m.cache.title,
    subtitle: m.cache.subtitle,
    instanceOnly: true,
    scale: RATIO,
    format: fmtRatio,
    formatAxis: axisRatio,
    series: (s) => [{ key: "hit", label: m.cache.hitRate, color: RX, values: s.dns_cache_hit_ratio }],
    unknownText: (s, i) => (s.dns_queries_per_sec[i] === 0 ? m.cache.noQueries : null),
  },
  {
    id: "cpu",
    title: m.cpu.title,
    subtitle: m.cpu.subtitle,
    instanceOnly: true,
    resource: true,
    scale: CPU,
    format: fmtPct,
    formatAxis: fmtPct,
    series: (s) => [{ key: "cpu", label: "CPU", color: RX, values: s.cpu_core_pct }],
  },
  {
    id: "memory",
    title: m.memory.title,
    subtitle: m.memory.subtitle,
    instanceOnly: true,
    resource: true,
    scale: MEMORY,
    format: fmtBytes,
    formatAxis: fmtBytes,
    series: (s) => [{ key: "rss", label: "RSS", color: RX, values: s.rss_bytes }],
  },
];

/** What every chart of one answer shares: windows, ticks, gap bands and restart markers. */
export interface ChartContext {
  frame: Frame;
  ticks: { t: number; label: string }[];
  bands: Band[];
  resourceBands: Band[];
  markers: number[];
}

export function chartContext(s: MetricsSeries): ChartContext {
  const step = s.resolution_secs * 1_000;
  return {
    frame: { timestamps: s.timestamps, stepMs: step, from: s.from_ms, to: s.to_ms },
    ticks: timeTicks(s.from_ms, s.to_ms),
    bands: gapBands(s.gaps, false),
    resourceBands: gapBands(s.gaps, true),
    markers: restartMarkers(s.restarts, step, s.to_ms),
  };
}

export function ChartCard({
  def,
  s,
  ctx,
  instanceLevel,
  hover,
  onHover,
  emptyText,
  style,
  className,
}: {
  def: ChartDef;
  s: MetricsSeries;
  ctx: ChartContext;
  instanceLevel: boolean;
  hover: Hover | null;
  onHover: (h: Hover | null) => void;
  emptyText: string;
  /** The entrance stagger (the page's grid passes its index). */
  style?: CSSProperties;
  className?: string;
}) {
  const series = useMemo(() => def.series(s, instanceLevel), [def, s, instanceLevel]);
  const subtitle = (instanceLevel ? undefined : def.gatewaySubtitle) ?? def.subtitle;
  const gapNote = (i: number) => {
    const t = s.timestamps[i];
    if (t === undefined) return null;
    const mid = t + (Math.min(t + s.resolution_secs * 1_000, s.to_ms) - t) / 2;
    const reasons = gapsAt(s.gaps, mid).filter((r) => def.resource === true || r !== "unavailable");
    return reasons.length ? <p>{m.gapNote(reasons.map((r) => GAP_REASON[r].label))}</p> : null;
  };
  const rowLabel = (i: number) => windowLabel(s.timestamps[i] ?? s.from_ms, s.resolution_secs, s.to_ms);
  return (
    <ChartFrame
      id={def.id}
      title={def.title}
      subtitle={subtitle}
      legend={series}
      style={style}
      className={className}
      // Room for a title, two subtitle lines and the legend: plots of one row line up.
      headerClassName="min-h-[82px] content-start"
      table={() => (
        <ChartTable
          caption={def.title}
          timestamps={s.timestamps}
          series={series}
          format={def.format}
          rowLabel={rowLabel}
          unknownText={(i, x) => def.unknownText?.(s, i, x) ?? "—"}
        />
      )}
    >
      <SeriesChart
        id={def.id}
        label={m.chartLabel(def.title, subtitle)}
        frame={ctx.frame}
        series={series}
        scale={def.scale}
        format={def.format}
        formatAxis={def.formatAxis}
        bands={def.resource ? ctx.resourceBands : ctx.bands}
        markers={ctx.markers}
        ticks={ctx.ticks}
        hover={hover}
        onHover={onHover}
        windowLabel={rowLabel}
        unknownText={def.unknownText ? (i, x) => def.unknownText?.(s, i, x) ?? ui.common.unknown : undefined}
        details={(i) => {
          const d = def.details?.(s, i, instanceLevel);
          const g = gapNote(i);
          return d || g ? (
            <>
              {d}
              {g}
            </>
          ) : null;
        }}
        emptyText={emptyText}
      />
    </ChartFrame>
  );
}
