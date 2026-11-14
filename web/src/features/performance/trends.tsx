// The trends of 效能統計 on the shared series chart (components/charts/series-chart): one unit per chart, gaps shaded and
// explained, one time cursor shared by the charts of a panel (←／→ with the keyboard), a table view per chart. The range
// is the page's (the tool strip above everything); the CPU／記憶體 switch belongs to the role panel only. A refresh
// redraws in place; a range change keeps the previous answer dimmed until the next one lands.

import { Activity, ChartLine, Network, X } from "lucide-react";
import { type CSSProperties, useMemo, useState } from "react";
import { usePerformanceSeries } from "@/api/performance";
import type { InstancePerformance } from "@/api/generated/InstancePerformance";
import type { MetricsRange } from "@/api/generated/MetricsRange";
import type { PerformanceSeriesSet } from "@/api/generated/PerformanceSeriesSet";
import type { ProcessRole } from "@/api/generated/ProcessRole";
import { ChartFrame, ChartTable } from "@/components/charts/chart-frame";
import { type ChartSeries, type Hover, type Scale, SeriesChart } from "@/components/charts/series-chart";
import { StatusPill } from "@/components/ui/badge";
import { IconButton } from "@/components/ui/button";
import { SectionLink } from "@/components/ui/inspector";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { Panel } from "@/components/ui/panel";
import { Segmented } from "@/components/ui/segmented";
import { ErrorState, Skeleton } from "@/components/ui/states";
import { TILE_TONE } from "@/components/ui/tones";
import { gapBands, timeTicks, windowLabel } from "@/features/metrics/model";
import { cn } from "@/lib/cn";
import { formatBps, formatBytes } from "@/lib/format";
import { PHASE } from "@/lib/status";
import { m } from "./messages";
import { pct, perfFrame, ROLE_LABEL, seriesOf } from "./model";

const RX = "var(--color-series-rx)";
const TX = "var(--color-series-tx)";

// Module-level scales and formatters: stable identities keep the plot layer memoized.
const CPU: Scale = { kind: "linear", minTop: 5 };
const RSS: Scale = { kind: "linear", minTop: 64 * 1_048_576, binary: true };
const BPS: Scale = { kind: "linear", minTop: 1_000_000 };
const fmtBytes = (v: number) => formatBytes(v);
const fmtBps = (v: number) => formatBps(v);

const ROLES: ProcessRole[] = ["manager", "controller", "worker"];

/** One chart of a series set: the shared chart in a compact frame, its table one toggle away. */
function TrendChart({
  id,
  title,
  set,
  series,
  scale,
  format,
  resource,
  hover,
  onHover,
  aside,
  height = 136,
  style,
}: {
  id: string;
  title: string;
  set: PerformanceSeriesSet;
  series: ChartSeries[];
  scale: Scale;
  format: (v: number) => string;
  /** Resource readings: also shaded where the host did not report them. */
  resource: boolean;
  hover: Hover | null;
  onHover: (h: Hover | null) => void;
  aside?: string | undefined;
  height?: number;
  style?: CSSProperties;
}) {
  const frame = useMemo(() => perfFrame(set), [set]);
  const ticks = useMemo(() => timeTicks(set.from_ms, set.to_ms, 4), [set.from_ms, set.to_ms]);
  const bands = useMemo(() => gapBands(set.gaps, resource), [set.gaps, resource]);
  const rowLabel = (i: number) => windowLabel(set.timestamps[i] ?? set.from_ms, set.resolution_secs, set.to_ms);
  return (
    <ChartFrame
      id={id}
      title={title}
      aside={aside}
      legend={series}
      compact
      style={style}
      className={STAGGER_IN}
      table={() => (
        <ChartTable
          caption={title}
          timestamps={set.timestamps}
          series={series}
          format={format}
          rowLabel={rowLabel}
          maxRows={400}
        />
      )}
    >
      <SeriesChart
        id={id}
        label={m.trends.chartLabel(title)}
        frame={frame}
        series={series}
        scale={scale}
        format={format}
        formatAxis={format}
        bands={bands}
        markers={[]}
        ticks={ticks}
        hover={hover}
        onHover={onHover}
        windowLabel={rowLabel}
        emptyText={m.trends.empty}
        height={height}
      />
    </ChartFrame>
  );
}

function ChartsLoading({ count }: { count: number }) {
  return (
    <div role="status" aria-label={m.trends.loading} className="grid gap-x-6 gap-y-5 md:grid-cols-2 2xl:grid-cols-4">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="space-y-2">
          <Skeleton className="w-32" />
          <Skeleton className="h-32 w-full" />
        </div>
      ))}
    </div>
  );
}

/** CPU or memory of the product and of each role, as small multiples sharing one cursor. */
export function RoleTrends({ range, style }: { range: MetricsRange; style?: CSSProperties }) {
  const [metric, setMetric] = useState<"cpu" | "rss">("cpu");
  const [hover, setHover] = useState<Hover | null>(null);
  const q = usePerformanceSeries("system", range);
  const set = q.data;
  const metricKey = metric === "cpu" ? "cpu_core_pct" : "rss_bytes";
  const charts = useMemo(() => {
    const list: { key: string; title: string; role: ProcessRole | null }[] = [
      { key: "product", title: m.trends.productTotal, role: null },
      ...ROLES.map((r) => ({ key: r, title: ROLE_LABEL[r], role: r })),
    ];
    return list.map((c, i) => ({
      ...c,
      series: [
        { key: c.key, label: c.title, color: i === 0 ? RX : TX, values: seriesOf(set, metricKey, c.role) },
      ] satisfies ChartSeries[],
      coverage: set?.series.find((x) => x.metric === metricKey && x.role === c.role)?.coverage_ratio,
    }));
  }, [set, metricKey]);
  const shared = set?.notes.includes("RSS_SUM_COUNTS_SHARED_PAGES") && metric === "rss";
  return (
    <Panel
      icon={Activity}
      title={m.trends.roles}
      description={set ? m.trends.resolution(set.resolution_secs, shared === true) : m.trends.stored}
      action={
        <Segmented
          size="sm"
          label={m.trends.metric}
          value={metric}
          onChange={setMetric}
          options={[
            { value: "cpu", label: m.cpuCore },
            { value: "rss", label: m.trends.memory },
          ]}
        />
      }
      className={STAGGER_IN}
      style={style}
    >
      {q.isError && !set ? (
        <ErrorState compact error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} />
      ) : !set ? (
        <ChartsLoading count={4} />
      ) : (
        <div
          aria-busy={q.isPlaceholderData || undefined}
          className={cn(
            "grid gap-x-6 gap-y-5 transition-opacity duration-(--duration-base) ease-standard md:grid-cols-2 2xl:grid-cols-4",
            q.isPlaceholderData && "opacity-55 delay-(--duration-fast)",
          )}
        >
          {charts.map((c, index) => (
            <TrendChart
              key={c.key}
              id={`role-${c.key}`}
              title={c.title}
              aside={c.coverage !== undefined ? m.trends.coverage((c.coverage * 100).toFixed(0)) : undefined}
              set={set}
              series={c.series}
              scale={metric === "cpu" ? CPU : RSS}
              format={metric === "cpu" ? pct : fmtBytes}
              resource
              hover={hover}
              onHover={setHover}
              style={staggerStyle(index)}
            />
          ))}
        </div>
      )}
    </Panel>
  );
}

/**
 * The selected connection's trends: its payload rates and its worker's CPU over the page's range. A different connection
 * slides in from the right (the caller's content swap); the header links to its history and to the connection.
 */
export function InstanceTrend({
  i,
  range,
  onClose,
}: {
  i: InstancePerformance;
  range: MetricsRange;
  onClose: () => void;
}) {
  const [hover, setHover] = useState<Hover | null>(null);
  const q = usePerformanceSeries(`instance:${i.instance_id}`, range);
  const set = q.data;
  const payload = useMemo<ChartSeries[]>(
    () => [
      { key: "down", label: ui.common.download, color: RX, values: seriesOf(set, "payload_download_bps", null) },
      { key: "up", label: ui.common.upload, color: TX, values: seriesOf(set, "payload_upload_bps", null) },
    ],
    [set],
  );
  const cpu = useMemo<ChartSeries[]>(
    () => [{ key: "cpu", label: "worker CPU", color: RX, values: seriesOf(set, "cpu_core_pct", null) }],
    [set],
  );
  const titleId = `trend-${i.instance_id}`;
  return (
    <section aria-labelledby={titleId} className="panel overflow-hidden">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line-subtle px-4 py-3">
        <span
          aria-hidden
          className={cn("grid size-8 shrink-0 place-items-center rounded-lg border [&_svg]:size-4", TILE_TONE.info)}
        >
          <Network />
        </span>
        {/* Its basis makes the links wrap under the title on a narrow screen instead of squeezing it. */}
        <div className="grid min-w-0 flex-1 basis-64 gap-0.5">
          <h2
            id={titleId}
            className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-data font-semibold text-fg"
          >
            <span className="[overflow-wrap:anywhere]">{m.trends.of(i.name)}</span>
            <StatusPill look={PHASE[i.phase]} />
            {i.generation !== null ? (
              <span className="machine text-micro font-normal text-fg-tertiary">{m.generation(i.generation)}</span>
            ) : null}
          </h2>
          <p className="text-caption text-fg-tertiary">{m.trends.payloadNote}</p>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-0.5">
          <SectionLink to={`/metrics?scope=instance:${i.instance_id}`} icon={ChartLine}>
            {m.trends.history}
          </SectionLink>
          <SectionLink to={`/instances/${i.instance_id}`} icon={Network}>
            {m.trends.toConnection}
          </SectionLink>
          <IconButton label={m.trends.close(i.name)} icon={X} onClick={onClose} className="size-7" />
        </div>
      </header>
      <div className="px-4 py-4">
        {q.isError && !set ? (
          <ErrorState compact error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} />
        ) : !set ? (
          <ChartsLoading count={2} />
        ) : (
          <div
            aria-busy={q.isPlaceholderData || undefined}
            className={cn(
              "grid gap-x-6 gap-y-5 transition-opacity duration-(--duration-base) ease-standard lg:grid-cols-2",
              q.isPlaceholderData && "opacity-55 delay-(--duration-fast)",
            )}
          >
            <TrendChart
              id={`${titleId}-payload`}
              title={m.trends.payloadRate}
              set={set}
              series={payload}
              scale={BPS}
              format={fmtBps}
              resource={false}
              hover={hover}
              onHover={setHover}
              height={152}
              style={staggerStyle(0)}
            />
            <TrendChart
              id={`${titleId}-cpu`}
              title={m.trends.workerCpu}
              set={set}
              series={cpu}
              scale={CPU}
              format={pct}
              resource
              hover={hover}
              onHover={setHover}
              height={152}
              style={staggerStyle(1)}
            />
          </div>
        )}
      </div>
    </section>
  );
}
