// /performance 「效能統計」: the passive analysis of the running product (即時觀測). It only reads the samples the product
// already keeps and generates no traffic. The report recipe of docs/frontend-design.md §8.1: the page header with its
// (?) help; one tool strip above everything it scopes (the trends' range, and on the right how fresh the analysis is);
// the stale note under it; then the views as tabs (`?view=`), each led by the product summary (the view's one raised
// region): 程序 (the processes and the trends by role), 連線 (the connections and proxy ports; selecting one shows its
// trends below, in the URL) and 線索 (the bottleneck readings and the reference scale; the tab counts the readings).
// Motion: the sections rise in once when the page opens; the 5-second refresh updates in place; another connection's
// trends slide in.

import { Cpu, Lightbulb, LoaderCircle, Network, SearchX } from "lucide-react";
import type { ReactNode } from "react";
import { useConnection } from "@/api/events";
import { usePerformanceSummary } from "@/api/performance";
import { Page, PageHeader, PaneSwap } from "@/components/shell/page";
import { Button } from "@/components/ui/button";
import { FIT_WIDTH, STAGGER_IN } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { Segmented } from "@/components/ui/segmented";
import { Callout, EmptyState, ErrorCallout, ErrorState, Skeleton } from "@/components/ui/states";
import { TabCount, type TabItem, TabPanel, Tabs } from "@/components/ui/tabs";
import { ToolStrip } from "@/components/ui/tool-strip";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { Connections } from "./connections";
import { Hints, Reference } from "./insights";
import { m } from "./messages";
import { DEFAULT_PERF_RANGE, PERF_RANGES, parsePerfRange, summaryState } from "./model";
import { Processes } from "./processes";
import { CompletenessNotes, SummaryBand } from "./summary";
import { InstanceTrend, RoleTrends } from "./trends";

export type PerformanceView = "processes" | "connections" | "hints";

const PERFORMANCE_VIEWS: TabItem<PerformanceView>[] = [
  { value: "processes", label: m.views.processes, icon: Cpu },
  { value: "connections", label: m.views.connections, icon: Network },
  { value: "hints", label: m.views.hints, icon: Lightbulb },
];

const clock = new Intl.DateTimeFormat(intlLocale, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function LoadingLayout() {
  return (
    <div role="status" aria-label={m.loading} className="grid grid-cols-1 gap-4">
      <div
        style={staggerStyle(2)}
        className={cn("panel-raised grid grid-cols-2 gap-4 px-5 py-4 lg:grid-cols-4", STAGGER_IN)}
      >
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="w-24" />
            <Skeleton className="h-7 w-28" />
            <Skeleton className="w-36" />
          </div>
        ))}
      </div>
      {Array.from({ length: 2 }, (_, i) => (
        <div key={i} style={staggerStyle(3 + i)} className={cn("panel space-y-3 px-4 py-4", STAGGER_IN)}>
          <Skeleton className="w-32" />
          <Skeleton className="w-72" />
          <Skeleton className="h-24 w-full" />
        </div>
      ))}
    </div>
  );
}

/**
 * Under the tool strip: the numbers are not current — a refresh failed (with a retry), or the manager is away or the
 * last analysis is old. It reads the one-second clock itself, so the charts never re-render for it.
 */
function StaleNote({ q }: { q: ReturnType<typeof usePerformanceSummary> }) {
  const now = useServerNow();
  const conn = useConnection();
  const s = q.data;
  if (!s) return null;
  const st = summaryState(s, now);
  const at = clock.format(Date.parse(s.observed_at));
  let note: ReactNode = null;
  if (q.isError) {
    note = (
      <ErrorCallout
        error={q.error}
        title={m.stale.refreshFailed(at)}
        onRetry={() => void q.refetch()}
        retrying={q.isFetching}
      >
        <p>{m.stale.frozen}</p>
      </ErrorCallout>
    );
  } else if (conn.manager === false || st.kind === "stale") {
    note = (
      <div role="status" className="animate-fade-in">
        <Callout tone="warning" title={m.stale.outdated(at)}>
          {m.stale.detail(conn.manager === false, st.kind === "stale" ? st.ageSeconds : null)}
        </Callout>
      </div>
    );
  }
  return note ? <div className="shrink-0 border-b border-line-subtle px-4 py-2 md:px-6">{note}</div> : null;
}

/**
 * The shown view: the URL's, or — for a link that selects a connection (`?instance=`) without saying which view — 連線,
 * the only view where the selection shows. Choosing 程序 with a connection selected says so in the URL.
 */
function useView(selected: string | null): [PerformanceView, (v: PerformanceView) => void] {
  const [viewQ, setViewQ] = useQueryParam("view");
  const view = PERFORMANCE_VIEWS.find((v) => v.value === viewQ)?.value ?? (selected ? "connections" : "processes");
  return [
    view,
    (v) => {
      setViewQ(v === "processes" && !selected ? null : v, { push: true });
    },
  ];
}

export function PerformancePage() {
  const q = usePerformanceSummary();
  const [rangeQ, setRangeQ] = useQueryParam("range");
  const [instanceQ] = useQueryParam("instance");
  const [view, setView] = useView(instanceQ);
  const setParams = useSetQueryParams();
  // Selecting (or clearing) a connection happens in 連線 and keeps it shown there, also when the URL named no view.
  const setInstanceQ = (id: string | null) => {
    setParams({ instance: id, view: "connections" });
  };
  const range = parsePerfRange(rangeQ);
  const s = q.data;
  const selected = instanceQ && s ? (s.instances.find((i) => i.instance_id === instanceQ) ?? null) : null;

  /** A view of the analysis, led by the product summary (loading and failure are the same for every view). */
  const analysis = (render: (s: NonNullable<typeof q.data>) => ReactNode): ReactNode => {
    if (!s)
      return q.isError ? (
        <div style={staggerStyle(2)} className={cn("panel", STAGGER_IN)}>
          <ErrorState title={m.loadFailed} error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} />
        </div>
      ) : (
        <LoadingLayout />
      );
    return (
      <div className="grid grid-cols-1 gap-4">
        <CompletenessNotes s={s} style={staggerStyle(2)} />
        <SummaryBand s={s} style={staggerStyle(3)} />
        {render(s)}
      </div>
    );
  };
  const PANEL = "px-4 pt-4 pb-6 md:px-6 md:pb-8";
  const hints = s?.hints.length ?? 0;
  const hintTone = s?.hints.some((h) => h.severity === "warning") ? "warning" : "neutral";

  return (
    <Page>
      <PageHeader title={m.title} description={m.description} help={m.help} helpText={m.helpText} />
      <ToolStrip label={m.toolStrip.label} style={staggerStyle(1)} className={cn("px-4 py-1.5 md:px-6", STAGGER_IN)}>
        <Segmented
          label={m.toolStrip.range}
          value={range}
          onChange={(v) => {
            setRangeQ(v === DEFAULT_PERF_RANGE ? null : v);
          }}
          options={PERF_RANGES.map((r) => ({ value: r.value, label: r.label, title: r.long }))}
          className={FIT_WIDTH}
        />
        <p className="ml-auto flex min-h-7 items-center gap-2 text-caption whitespace-nowrap text-fg-tertiary">
          {q.isFetching ? <LoaderCircle aria-hidden className="size-3.5 animate-spin" /> : null}
          {s ? (
            <span>
              {m.toolStrip.latest(<span className="machine">{clock.format(Date.parse(s.observed_at))}</span>)}
            </span>
          ) : q.isFetching ? (
            <span>{m.toolStrip.reading}</span>
          ) : null}
        </p>
      </ToolStrip>
      <StaleNote q={q} />
      <Tabs
        label={m.title}
        value={view}
        onChange={setView}
        // The readings come and go with each analysis: the tab says how many there are now.
        items={PERFORMANCE_VIEWS.map((v) =>
          v.value === "hints" && hints
            ? { ...v, badge: <TabCount value={hints} tone={hintTone} label={m.views.hintsUnit(hints)} /> }
            : v,
        )}
        className={cn(STAGGER_IN, "[--i:1]")}
      >
        <TabPanel value="processes" className={PANEL}>
          {analysis((a) => (
            <>
              <Processes s={a} style={staggerStyle(4)} />
              <RoleTrends range={range} style={staggerStyle(5)} />
            </>
          ))}
        </TabPanel>
        <TabPanel value="connections" className={PANEL}>
          {analysis((a) => (
            <>
              <Connections
                s={a}
                selected={instanceQ}
                onSelect={(id) => {
                  setInstanceQ(id);
                }}
                style={staggerStyle(4)}
              />
              {instanceQ ? (
                // Another connection's trends slide in from the right (keyed by the connection); live updates of the
                // same one never replay it.
                <div className={cn("relative", STAGGER_IN)}>
                  <PaneSwap className="min-w-0">
                    {selected ? (
                      <InstanceTrend
                        key={selected.instance_id}
                        i={selected}
                        range={range}
                        onClose={() => {
                          setInstanceQ(null);
                        }}
                      />
                    ) : (
                      <div key="missing" className="panel">
                        <EmptyState
                          compact
                          icon={SearchX}
                          title={m.missing.title}
                          actions={
                            <Button
                              size="sm"
                              onClick={() => {
                                setInstanceQ(null);
                              }}
                            >
                              {m.missing.clear}
                            </Button>
                          }
                        >
                          {m.missing.body}
                        </EmptyState>
                      </div>
                    )}
                  </PaneSwap>
                </div>
              ) : null}
            </>
          ))}
        </TabPanel>
        <TabPanel value="hints" className={PANEL}>
          {analysis((a) => (
            <div className="grid items-start gap-4 xl:grid-cols-2">
              <Hints s={a} style={staggerStyle(4)} />
              <Reference s={a} style={staggerStyle(5)} />
            </div>
          ))}
        </TabPanel>
      </Tabs>
    </Page>
  );
}
