// 總覽's 流量 chart, under the traffic path: every connection's payload (bit/s) over 15 分鐘 to 24 小時 — the stored series
// of 數據統計 extended to the host's now by the live samples (features/overview/traffic) — as two small multiples, ↓ 下載
// and ↑ 上傳, each with the whole payload and, dashed in their own colours, its SSH 下載 and SSH 代理 parts (so SSH never
// hides inside ordinary proxy traffic, in either direction). The same marks, scale, gap bands, restart markers, cursor
// readout (one cursor shared by both plots) and table as 數據統計's 流量 (SeriesChart, ChartTable): a window without
// data is left blank and the readout says why. The App sandboxes' part is said per window in the readout; each part's
// share of the range beside the legend.
//
// Motion (docs/frontend-design.md §8.1): the panel rises in with the page; the plots never animate (they redraw in place
// as the window slides with the clock, nothing replays); the range control's block slides on the snappy spring; a range
// still loading keeps the previous answer dimmed; the table reveals when asked for.
import { ChartLine, Table2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useLiveRatesMap, useMetricsSeries } from "@/api/queries";
import { ChartLegend, ChartTable } from "@/components/charts/chart-frame";
import { type ChartSeries, type Hover, type Scale, SeriesChart } from "@/components/charts/series-chart";
import { DockHeader, DockPanel } from "@/components/ui/dock";
import { SectionLink } from "@/components/ui/inspector";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { Segmented } from "@/components/ui/segmented";
import { ErrorCallout, Skeleton } from "@/components/ui/states";
import { ToolButton } from "@/components/ui/tool-strip";
import { SSH_PROXY_COLOR, SSH_PULL_COLOR } from "@/features/gateways/ssh-traffic";
import { GAP_REASON, gapsAt, windowLabel } from "@/features/metrics/model";
import { cn } from "@/lib/cn";
import { formatBps, formatPercent } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { useMedia } from "@/lib/use-media";
import { usePersistentChoice } from "@/lib/use-persistent";
import { m } from "./messages";
import {
  OVERVIEW_DEFAULT_RANGE,
  OVERVIEW_RANGE_VALUES,
  OVERVIEW_RANGES,
  partShare,
  type TrafficView,
  trafficView,
} from "./traffic";

const RX = "var(--color-series-rx)";
const TX = "var(--color-series-tx)";
/** The SSH parts are dashed: drawn over the whole payload, both stay visible where they coincide. */
const PART_DASH = "5 4";
// Module-level: stable identities keep the plot layer memoized.
const BPS: Scale = { kind: "linear", minTop: 1_000_000 };
const fmtBps = (v: number) => formatBps(v);
const LEGEND = [
  { key: "rx", label: ui.common.download, color: RX },
  { key: "tx", label: ui.common.upload, color: TX },
  { key: "pull", label: m.pull.label, color: SSH_PULL_COLOR, dash: PART_DASH },
  { key: "ssh", label: m.proxy.label, color: SSH_PROXY_COLOR, dash: PART_DASH },
];

type Direction = "rx" | "tx";

/** One plot's lines: the whole payload of a direction and its two SSH parts. */
function plotSeries(v: TrafficView, d: Direction): ChartSeries[] {
  const rx = d === "rx";
  return [
    { key: d, label: rx ? ui.common.download : ui.common.upload, color: rx ? RX : TX, values: v[d] },
    { key: "pull", label: m.pull.label, color: SSH_PULL_COLOR, dash: PART_DASH, values: rx ? v.pullRx : v.pullTx },
    { key: "ssh", label: m.proxy.label, color: SSH_PROXY_COLOR, dash: PART_DASH, values: rx ? v.sshRx : v.sshTx },
  ];
}

/** The table's columns: both plots' lines, the parts named with their direction. */
function tableSeries(v: TrafficView): ChartSeries[] {
  return (["rx", "tx"] as const).flatMap((d) =>
    plotSeries(v, d).map((s, i) =>
      i === 0 ? s : { ...s, key: `${s.key}-${d}`, label: `${s.label} ${d === "rx" ? "↓" : "↑"}` },
    ),
  );
}

/** 「 · SSH 下載占 12%」 for each part that carried something in the range. */
function sharesText(v: TrafficView): string {
  const parts: [string, number | null][] = [
    [m.pull.label, partShare(v, "pull")],
    [m.proxy.label, partShare(v, "ssh")],
    [m.sandbox.label, partShare(v, "sandbox")],
  ];
  return parts
    .filter((p): p is [string, number] => p[1] !== null && p[1] > 0)
    .map(([label, share]) => ` · ${m.chart.share(label, formatPercent(share * 100))}`)
    .join("");
}

export function TrafficChart({ ids, index = 0 }: { ids: string[]; index?: number }) {
  const [range, setRange] = usePersistentChoice("overview.trafficRange", OVERVIEW_RANGE_VALUES, OVERVIEW_DEFAULT_RANGE);
  const series = useMetricsSeries(range, "all");
  const live = useLiveRatesMap(ids);
  const now = useServerNow();
  const [hover, setHover] = useState<Hover | null>(null);
  const [asTable, setAsTable] = useState(false);
  // Taller where the screen has the room (the panel fills the space under the traffic path, 需要處理 stays in view).
  const tall = useMedia("(min-height: 1040px)");
  const height = tall ? 156 : 118;
  const s = series.data;
  const view = useMemo(() => (s ? trafficView(s, live, now) : null), [s, live, now]);
  const plots = useMemo(
    () => (view ? { rx: plotSeries(view, "rx"), tx: plotSeries(view, "tx"), table: tableSeries(view) } : null),
    [view],
  );
  const shares = view ? sharesText(view) : "";
  const rangeLong = OVERVIEW_RANGES.find((r) => r.value === range)?.long ?? range;

  const rowLabel = (i: number) =>
    view && s ? windowLabel(view.frame.timestamps[i] ?? view.frame.from, s.resolution_secs, view.frame.to) : "";
  const reasons = (i: number) => {
    const t = view?.frame.timestamps[i];
    if (!view || !s || t === undefined) return [];
    const mid = t + (Math.min(t + view.frame.stepMs, view.frame.to) - t) / 2;
    return gapsAt(s.gaps, mid).filter((r) => r !== "unavailable");
  };
  const unknownText = (i: number) => {
    const r = reasons(i);
    if (r.length) return GAP_REASON[r[0] ?? "missing"].label;
    const t = view?.frame.timestamps[i];
    return view && t !== undefined && t >= view.liveFrom ? m.chart.noLiveSample : ui.common.noData;
  };
  // The readout's extra lines for window `i` of a plot: the App sandboxes' part, gap reasons, a window not stored yet.
  const details = (d: Direction) => (i: number) => {
    if (!view) return null;
    const t = view.frame.timestamps[i];
    const sandbox = (d === "rx" ? view.sandboxRx : view.sandboxTx)[i] ?? null;
    const r = reasons(i);
    const pending = t !== undefined && t >= view.liveFrom;
    if (sandbox === null && !r.length && !pending) return null;
    return (
      <>
        {sandbox !== null ? <p>{m.chart.sandboxPart(formatBps(sandbox))}</p> : null}
        {r.length ? <p>{m.chart.gaps(r.map((x) => GAP_REASON[x].label))}</p> : null}
        {pending ? <p className="text-fg-tertiary">{m.chart.livePending}</p> : null}
      </>
    );
  };

  return (
    <DockPanel aria-labelledby="traffic-title" style={staggerStyle(index)} className={STAGGER_IN}>
      <DockHeader
        icon={<ChartLine aria-hidden />}
        title={m.chart.title}
        titleId="traffic-title"
        className="h-auto min-h-9 flex-wrap py-1"
        actions={
          <div className="flex flex-wrap items-center justify-end gap-1.5">
            <Segmented
              label={m.chart.range}
              size="sm"
              value={range}
              onChange={(v) => {
                setHover(null);
                setRange(v);
              }}
              options={OVERVIEW_RANGES.map((r) => ({ value: r.value, label: r.label, title: r.long }))}
            />
            <ToolButton
              label={m.chart.tableLabel}
              text={m.chart.table}
              icon={<Table2 aria-hidden />}
              pressed={asTable}
              onClick={() => {
                setAsTable((v) => !v);
              }}
            />
          </div>
        }
      />
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-4 pt-2.5">
        <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
          <ChartLegend series={LEGEND} />
          <span className="text-caption text-fg-tertiary">
            {m.chart.scope(rangeLong)}
            {shares}
          </span>
        </div>
        <SectionLink to={`/metrics?range=${range}`} icon={ChartLine}>
          {m.chart.viewInMetrics}
        </SectionLink>
      </div>
      <div className="px-4 pt-2 pb-3">
        {series.isError && s ? (
          <ErrorCallout
            error={series.error}
            title={m.chart.stale}
            onRetry={() => void series.refetch()}
            retrying={series.isFetching}
            className="mb-2"
          />
        ) : null}
        {view && plots ? (
          <div
            className={cn(
              "grid grid-cols-1 gap-1 transition-opacity duration-(--duration-fast)",
              series.isPlaceholderData && "opacity-50",
            )}
          >
            {(["rx", "tx"] as const).map((d) => (
              <div key={d}>
                <p className="mb-1.5 flex items-center gap-1.5 text-caption text-fg-secondary">
                  <span aria-hidden className={d === "rx" ? "text-series-rx" : "text-series-tx"}>
                    {d === "rx" ? "↓" : "↑"}
                  </span>
                  {d === "rx" ? ui.common.download : ui.common.upload}
                </p>
                <SeriesChart
                  id={`overview-traffic-${d}`}
                  label={m.chart.plotLabel(d === "rx" ? ui.common.download : ui.common.upload, rangeLong)}
                  frame={view.frame}
                  series={plots[d]}
                  scale={BPS}
                  format={fmtBps}
                  formatAxis={fmtBps}
                  bands={view.bands}
                  markers={view.markers}
                  ticks={view.ticks}
                  hover={hover}
                  onHover={setHover}
                  windowLabel={rowLabel}
                  unknownText={unknownText}
                  details={details(d)}
                  emptyText={m.chart.empty(rangeLong)}
                  height={height}
                />
              </div>
            ))}
          </div>
        ) : series.isError ? (
          <ErrorCallout
            error={series.error}
            title={m.chart.loadFailed}
            onRetry={() => void series.refetch()}
            retrying={series.isFetching}
          />
        ) : (
          <div
            role="status"
            aria-label={m.chart.loading}
            className="space-y-2 py-2"
            style={{ height: 2 * height + 44 }}
          >
            <Skeleton className="h-full w-full" />
          </div>
        )}
        {asTable && view && plots ? (
          <div className="mt-2 animate-reveal">
            <ChartTable
              caption={m.chart.title}
              timestamps={view.frame.timestamps}
              series={plots.table}
              format={fmtBps}
              rowLabel={rowLabel}
              unknownText={(i) => unknownText(i)}
              maxRows={360}
            />
          </div>
        ) : null}
      </div>
    </DockPanel>
  );
}
