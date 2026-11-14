// 數據統計 (/metrics): the persisted history of every connection (or one connection, or one 代理埠) over a range, with
// the gaps explained and the retention of the data. The page recipe of docs/frontend-design.md §8.1 for a report: the
// page header with its (?) help; one tool strip above everything it scopes — the range (segmented), the object (a menu)
// and, on the right, the resolution and how fresh the data is; then the views as tabs (`?view=`): 流量 (traffic,
// WireGuard, connections), 延遲與 DNS (latency, DNS queries, cache hits) and 資源 (CPU, memory) each start with the
// summary (the view's one raised region) and the gap legend, then their charts (one shared time cursor); 各連線 is the
// per-object breakdown (a row's chart button narrows the page and shows 流量); 保存 is the retention of the data.
// Range, object, sort and view live in the URL. While recording is not as usual (the oldest data overwritten on a full
// disk, writes failing) a notice says so under the tool strip. Motion: the sections rise in once when the page opens;
// a refresh updates in place (nothing replays); switching range or object keeps the previous answer dimmed until the
// new one lands; when the object changes which charts exist, the remaining cards slide to their new places.

import {
  ArrowDownUp,
  ChartLine,
  Cpu,
  Database,
  EthernetPort,
  Layers,
  LoaderCircle,
  Network,
  Plus,
  Rows3,
  SearchX,
  Timer,
} from "lucide-react";
import { motion } from "motion/react";
import { type CSSProperties, type ReactNode, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { ApiFailure, describeFailure } from "@/api/client";
import { useApps, useGateways, useInstances, useMetricsSeries, useMetricsStatus, useSystemStatus } from "@/api/queries";
import type { GatewaySpec, InstanceView, MetricsSeries } from "@/api/types";
import type { Hover } from "@/components/charts/series-chart";
import { useCrumb } from "@/components/shell/nav";
import { Page, PageHeader } from "@/components/shell/page";
import { Button } from "@/components/ui/button";
import { FIT_WIDTH, STAGGER_IN } from "@/components/ui/look";
import { Menu, MenuLabel, MenuRadioGroup, MenuRadioItem, MenuSeparator } from "@/components/ui/menu";
import { staggerStyle } from "@/components/ui/motion";
import { layoutTransition } from "@/components/ui/motion-tokens";
import { Segmented } from "@/components/ui/segmented";
import { EmptyState, ErrorCallout, ErrorState, Skeleton } from "@/components/ui/states";
import { type TabItem, TabPanel, Tabs } from "@/components/ui/tabs";
import { ToolButton, ToolStrip } from "@/components/ui/tool-strip";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime } from "@/lib/format";
import { useQueryParam, useSetQueryParams, useTabParam } from "@/lib/url";
import { useNow } from "@/lib/use-media";
import { Breakdown } from "./breakdown";
import { CHARTS, ChartCard, type ChartId, chartContext } from "./charts";
import { m } from "./messages";
import {
  DEFAULT_RANGE,
  parseRange,
  parseScope,
  RANGES,
  resolutionText,
  type Scope,
  scopeLabel,
  scopeOptions,
  scopeParam,
  type SortKey,
} from "./model";
import { RecordingNotice } from "./recording";
import { RetentionPanel } from "./retention";
import { GapLegend, Summary } from "./summary";

const SORTS: SortKey[] = ["rx", "tx", "peak", "p95", "avail"];

export type MetricsView = "traffic" | "latency" | "resources" | "breakdown" | "retention";

export const METRICS_VIEWS: TabItem<MetricsView>[] = [
  { value: "traffic", label: m.views.traffic, icon: ArrowDownUp },
  { value: "latency", label: m.views.latency, icon: Timer },
  { value: "resources", label: m.views.resources, icon: Cpu },
  { value: "breakdown", label: m.views.breakdown, icon: Rows3 },
  { value: "retention", label: m.views.retention, icon: Database },
];

type ChartView = "traffic" | "latency" | "resources";

/** The charts of each chart view: what is read together (one shared cursor) sits together. */
export const CHART_GROUPS: Record<ChartView, ChartId[]> = {
  traffic: ["traffic", "wireguard", "flows"],
  latency: ["latency", "dns", "cache"],
  resources: ["cpu", "memory"],
};

const SCOPE_ICON = { all: Layers, instance: Network, gateway: EthernetPort } as const;

const clock = new Intl.DateTimeFormat(intlLocale, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/**
 * The object the page shows (對象), as a tool-strip menu: 全部連線, every connection, every proxy port (menuitemradio,
 * the current one checked; typing jumps to a name). A scope that no longer exists stays listed, marked 找不到.
 */
export function ScopeMenu({
  scope,
  views,
  gateways,
  onChange,
}: {
  scope: Scope;
  views: InstanceView[];
  gateways: GatewaySpec[];
  onChange: (s: Scope) => void;
}) {
  const options = scopeOptions(scope, views, gateways);
  const value = scopeParam(scope);
  const current = options.find((o) => o.value === value)?.label ?? scopeLabel(scope, views, gateways);
  const Icon = SCOPE_ICON[scope.kind];
  const group = (g: "instance" | "gateway") => options.filter((o) => o.group === g);
  return (
    <Menu
      align="start"
      label={m.scope.label}
      trigger={
        <ToolButton
          label={m.scope.current(current)}
          aria-label={m.scope.current(current)}
          icon={<Icon aria-hidden />}
          className="max-w-full min-w-0"
          text={<span className="block max-w-[min(18rem,52vw)] truncate">{current}</span>}
        />
      }
    >
      <MenuRadioGroup
        value={value}
        onValueChange={(v) => {
          onChange(parseScope(v));
        }}
        label={m.scope.label}
      >
        {options
          .filter((o) => o.group === "all" || o.group === "missing")
          .map((o) => (
            <MenuRadioItem key={o.value} value={o.value}>
              {o.label}
            </MenuRadioItem>
          ))}
        {group("instance").length ? (
          <>
            <MenuSeparator />
            <MenuLabel>{m.scope.connections}</MenuLabel>
            {group("instance").map((o) => (
              <MenuRadioItem key={o.value} value={o.value}>
                {o.label}
              </MenuRadioItem>
            ))}
          </>
        ) : null}
        {group("gateway").length ? (
          <>
            <MenuSeparator />
            <MenuLabel>{m.scope.gateways}</MenuLabel>
            {group("gateway").map((o) => (
              <MenuRadioItem key={o.value} value={o.value}>
                {o.label}
              </MenuRadioItem>
            ))}
          </>
        ) : null}
      </MenuRadioGroup>
    </Menu>
  );
}

/** Placeholders shaped like the summary and the first charts (role=status). */
function LoadingLayout() {
  return (
    <div role="status" aria-label={m.loading} className="grid grid-cols-1 gap-4">
      <div
        style={staggerStyle(2)}
        className={cn("panel-raised grid grid-cols-2 gap-4 px-4 py-4 md:grid-cols-3 lg:grid-cols-5", STAGGER_IN)}
      >
        {Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="w-16" />
            <Skeleton className="h-6 w-28" />
            <Skeleton className="w-36" />
          </div>
        ))}
      </div>
      <div className="grid items-start gap-4 md:grid-cols-2">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} style={staggerStyle(3 + i)} className={cn("panel h-[260px] space-y-3 px-4 py-4", STAGGER_IN)}>
            <Skeleton className="w-24" />
            <Skeleton className="w-56" />
            <Skeleton className="mt-6 h-32 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * One chart view: the summary and the gap legend, then its charts (one shared cursor). For one 代理埠, the charts that
 * only a connection has are replaced by one card that says why and offers the owning connection.
 */
function ChartsView({
  group,
  s,
  scope,
  views,
  gateways,
  onScope,
  emptyText,
}: {
  group: ChartView;
  s: MetricsSeries;
  scope: Scope;
  views: InstanceView[];
  gateways: GatewaySpec[];
  onScope: (s: Scope) => void;
  emptyText: string;
}) {
  const [hover, setHover] = useState<Hover | null>(null);
  const ctx = useMemo(() => chartContext(s), [s]);
  const instanceLevel = scope.kind !== "gateway";
  const owner = scope.kind === "gateway" ? gateways.find((g) => g.id === scope.id)?.instance_id : undefined;
  const ownerName = owner ? views.find((v) => v.spec.id === owner)?.spec.name : undefined;
  const range = RANGES.find((r) => r.value === s.range);
  const ids = CHART_GROUPS[group];
  const inGroup = CHARTS.filter((c) => ids.includes(c.id));
  const charts = inGroup.filter((c) => instanceLevel || !c.instanceOnly);
  const dropped = charts.length < inGroup.length;
  // Cards that exist only for a connection come and go with the object: the ones that stay glide from their old cell to
  // the new one (Motion layout, snappy), measured only when the set of cards changes.
  const layoutVersion = `${charts.map((c) => c.id).join()}|${String(instanceLevel)}`;
  const at = (i: number): CSSProperties => staggerStyle(i);
  return (
    <div className="grid grid-cols-1 gap-4">
      <Summary
        s={s}
        scopeLabel={scopeLabel(scope, views, gateways)}
        rangeLabel={range?.long ?? s.range}
        style={at(2)}
      />
      <GapLegend s={s} style={at(3)} />
      <div className="relative grid items-start gap-4 md:grid-cols-2">
        {charts.map((def, i) => (
          <motion.div
            key={def.id}
            layout="position"
            layoutDependency={layoutVersion}
            transition={layoutTransition()}
            className="min-w-0"
          >
            <ChartCard
              def={def}
              s={s}
              ctx={ctx}
              instanceLevel={instanceLevel}
              hover={hover}
              onHover={setHover}
              emptyText={emptyText}
              style={at(4 + i)}
              className={STAGGER_IN}
            />
          </motion.div>
        ))}
        {dropped ? (
          <section
            key="other"
            aria-label={m.otherCharts.label}
            style={at(4 + charts.length)}
            className={cn("panel flex flex-col justify-center gap-3 px-4 py-5", STAGGER_IN)}
          >
            <p className="text-data text-fg-secondary">{m.otherCharts.detail}</p>
            {owner ? (
              <div>
                <Button
                  size="sm"
                  icon={ChartLine}
                  onClick={() => {
                    onScope({ kind: "instance", id: owner });
                  }}
                >
                  {m.otherCharts.viewOwner(ownerName ?? owner.slice(0, 8))}
                </Button>
              </div>
            ) : null}
          </section>
        ) : null}
      </div>
    </div>
  );
}

/**
 * The right end of the tool strip: the resolution and how fresh the shown answer is (a spinner while one is on its way).
 * It reads the one-second clock itself, so the charts never re-render for it.
 */
function Freshness({ s, fetching, updatedAt }: { s: MetricsSeries | undefined; fetching: boolean; updatedAt: number }) {
  // `updatedAt` is when this browser received the answer: its own clock, not the server's.
  const now = useNow();
  return (
    <p className="ml-auto flex min-h-7 items-center gap-2 text-caption whitespace-nowrap text-fg-tertiary">
      {fetching ? <LoaderCircle aria-hidden className="size-3.5 animate-spin" /> : null}
      {s ? (
        <span title={absoluteTime(new Date(updatedAt).toISOString())}>
          {m.freshness.updated(resolutionText(s.resolution_secs), relativeTime(new Date(updatedAt).toISOString(), now))}
        </span>
      ) : fetching ? (
        <span>{m.freshness.reading}</span>
      ) : null}
    </p>
  );
}

export function MetricsPage() {
  const navigate = useNavigate();
  const [rangeQ, setRangeQ] = useQueryParam("range");
  const [scopeQ, setScopeQ] = useQueryParam("scope");
  const [sortQ, setSortQ] = useQueryParam("sort");
  const [view, setView] = useTabParam<MetricsView>(
    "view",
    METRICS_VIEWS.map((v) => v.value),
  );
  const setParams = useSetQueryParams();
  const range = parseRange(rangeQ);
  const scope = parseScope(scopeQ);
  const sort = SORTS.find((k) => k === sortQ) ?? "rx";
  const series = useMetricsSeries(range, scopeParam(scope));
  const status = useMetricsStatus();
  const sys = useSystemStatus();
  const instances = useInstances();
  const gatewaysQ = useGateways();
  const appsQ = useApps();
  const views = instances.data ?? [];
  const gateways = gatewaysQ.data ?? [];
  const apps = appsQ.data ?? [];
  useCrumb(scope.kind === "all" ? null : scopeLabel(scope, views, gateways));

  const setScope = (s: Scope) => {
    setScopeQ(s.kind === "all" ? null : scopeParam(s), { push: true });
  };
  // A breakdown row's chart button: one navigation narrows the page and shows its charts (流量).
  const showCharts = (s: Scope) => {
    setParams({ scope: s.kind === "all" ? null : scopeParam(s), view: null }, { push: true });
  };
  const s = series.data;
  const notFound = series.error instanceof ApiFailure && series.error.status === 404;
  const noConnections = instances.data?.length === 0;
  const emptyText = noConnections ? m.empty.noConnections : m.empty.noData;

  /** A view of the answer: loading, failed, nothing yet, or the view itself (the previous answer dimmed while the next loads). */
  const answer = (render: (s: MetricsSeries, shownScope: Scope) => ReactNode): ReactNode => {
    if (!s)
      return series.isError ? (
        <div style={staggerStyle(2)} className={cn("panel", STAGGER_IN)}>
          {notFound ? (
            <EmptyState
              icon={SearchX}
              title={m.notFound.title}
              actions={
                <Button
                  size="sm"
                  icon={Layers}
                  onClick={() => {
                    setScope({ kind: "all" });
                  }}
                >
                  {m.notFound.showAll}
                </Button>
              }
            >
              {m.notFound.detail(describeFailure(series.error))}
            </EmptyState>
          ) : (
            <ErrorState
              error={series.error}
              onRetry={() => void series.refetch()}
              retrying={series.isFetching}
              title={m.loadFailed}
            />
          )}
        </div>
      ) : (
        <LoadingLayout />
      );
    if (noConnections && s.instances.length === 0)
      return (
        <div style={staggerStyle(2)} className={cn("panel", STAGGER_IN)}>
          <EmptyState
            brand
            icon={Network}
            title={m.start.title}
            actions={
              <Button variant="primary" size="sm" icon={Plus} onClick={() => void navigate("/instances?new=1")}>
                {m.start.add}
              </Button>
            }
          >
            {m.start.detail}
          </EmptyState>
        </div>
      );
    // The previous answer stays while the next range or object loads: dimmed (after a short delay, so a quick answer
    // never flickers), and busy for assistive technology at once.
    return (
      <div
        aria-busy={series.isPlaceholderData || undefined}
        className={cn(
          "transition-opacity duration-(--duration-base) ease-standard",
          series.isPlaceholderData && "opacity-55 delay-(--duration-fast)",
        )}
      >
        {render(s, parseScope(s.scope))}
      </div>
    );
  };
  const charts = (group: ChartView) =>
    answer((a, shown) => (
      <ChartsView
        group={group}
        s={a}
        scope={shown}
        views={views}
        gateways={gateways}
        onScope={setScope}
        emptyText={emptyText}
      />
    ));
  const PANEL = "px-4 pt-4 pb-6 md:px-6 md:pb-8";

  return (
    <Page>
      <PageHeader title={m.title} description={m.description} help={m.help} helpText={m.helpText} />
      <ToolStrip label={m.toolStrip} style={staggerStyle(1)} className={cn("px-4 py-1.5 md:px-6", STAGGER_IN)}>
        <Segmented
          label={m.timeRange}
          value={range}
          onChange={(v) => {
            setRangeQ(v === DEFAULT_RANGE ? null : v);
          }}
          options={RANGES.map((r) => ({ value: r.value, label: r.label, title: r.long }))}
          className={FIT_WIDTH}
        />
        <ScopeMenu scope={scope} views={views} gateways={gateways} onChange={setScope} />
        <Freshness s={s} fetching={series.isFetching} updatedAt={series.dataUpdatedAt} />
      </ToolStrip>
      <RecordingNotice recording={sys.data?.store.metrics_recording} />
      {s && series.isError ? (
        <div className="shrink-0 border-b border-line-subtle px-4 py-2 md:px-6">
          <ErrorCallout
            error={series.error}
            title={m.stale.title(clock.format(series.dataUpdatedAt))}
            onRetry={() => void series.refetch()}
            retrying={series.isFetching}
          >
            <p>{m.stale.detail}</p>
          </ErrorCallout>
        </div>
      ) : null}
      <Tabs label={m.title} value={view} onChange={setView} items={METRICS_VIEWS} className={cn(STAGGER_IN, "[--i:1]")}>
        <TabPanel value="traffic" className={PANEL}>
          {charts("traffic")}
        </TabPanel>
        <TabPanel value="latency" className={PANEL}>
          {charts("latency")}
        </TabPanel>
        <TabPanel value="resources" className={PANEL}>
          {charts("resources")}
        </TabPanel>
        <TabPanel value="breakdown" className={PANEL}>
          {answer((a, shown) => (
            <Breakdown
              s={a}
              views={views}
              gateways={gateways}
              apps={apps}
              scope={shown}
              sort={sort}
              onSort={(k) => {
                setSortQ(k === "rx" ? null : k);
              }}
              onScope={showCharts}
              style={staggerStyle(2)}
            />
          ))}
        </TabPanel>
        <TabPanel value="retention" className={PANEL}>
          <RetentionPanel
            status={status.data}
            error={status.error}
            onRetry={() => void status.refetch()}
            retrying={status.isFetching}
            style={staggerStyle(2)}
          />
        </TabPanel>
      </Tabs>
    </Page>
  );
}
