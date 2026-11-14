// 總覽 (/): the summary of protection (signature 1), the traffic topology (effect
// region A) with the traffic chart under it, and what needs handling. The sections rise in one after another when the page opens; counters fade when
// they change; items needing attention come and go with presence and the list slides (Motion layout). The brand scene drifts
// behind the header as the page's ambient background (a brand moment; the data panels in front stay solid).
import { CircleAlert, FilePlus2, Network, Plus, ShieldCheck } from "lucide-react";
import { type ReactNode, useMemo } from "react";
import { Link, useNavigate } from "react-router";
import { useApps, useInstances, useLiveRatesMap, useSystemStatus } from "@/api/queries";
import type { InstanceView, SystemStatus } from "@/api/types";
import { BrandBackdrop } from "@/components/scene/brand-backdrop";
import { m as shell } from "@/components/shell/messages";
import { Page, PageHeader } from "@/components/shell/page";
import { useManagerConnected } from "@/components/shell/service";
import { Button } from "@/components/ui/button";
import { ChangeValue } from "@/components/ui/change-value";
import { DockBody, DockHeader, DockPanel } from "@/components/ui/dock";
import { LIST_ROW, LIST_ROW_IDLE, STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { PresenceList } from "@/components/ui/presence-list";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { TEXT_TONE } from "@/components/ui/tones";
import { needsAttention } from "@/features/instances/model";
import { recordingAttention } from "@/features/metrics/model";
import { clockSkewText } from "@/features/system/model";
import { cn } from "@/lib/cn";
import { formatBps } from "@/lib/format";
import { CLOCK_SKEW_NOTICE_MS, useServerNow, useServerOffset } from "@/lib/server-clock";
import { m } from "./messages";
import { liveSandboxNote, liveTotal } from "./model";
import { Topology } from "./topology";
import { TrafficChart } from "./traffic-chart";

/**
 * One figure of the summary. `changes`: the value is a count that changes now and then (it fades when it does); live
 * rates that change every second do not fade. `note`: a second line under the detail.
 */
function Metric({
  label,
  value,
  detail,
  note,
  tone,
  changes,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  note?: string | null;
  tone?: "success" | "warning" | "danger" | undefined;
  changes?: unknown;
}) {
  return (
    <div className="min-w-0 px-5 py-4">
      <p className="text-caption text-fg-tertiary">{label}</p>
      <p
        className={cn(
          "machine mt-1 truncate text-metric transition-colors duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)",
          tone ? TEXT_TONE[tone] : "text-fg",
        )}
      >
        {changes !== undefined ? <ChangeValue value={changes}>{value}</ChangeValue> : value}
      </p>
      {detail ? <p className="mt-0.5 truncate text-caption text-fg-tertiary">{detail}</p> : null}
      {note ? (
        // A line cut short by a narrow column is still readable on hover.
        <p title={note} className="truncate text-caption text-fg-tertiary tabular-nums">
          {note}
        </p>
      ) : null}
    </div>
  );
}

interface AttentionItem {
  key: string;
  title: string;
  text: string;
  to: string;
}

/**
 * What needs handling besides the connections: a control database that cannot be written, metrics not as usual, a host
 * clock nothing keeps synchronized (`offset`: server minus browser, said when it is off by a few seconds).
 */
function systemItems(sys: SystemStatus | undefined, offset: number | null = null): AttentionItem[] {
  const items: AttentionItem[] = [];
  if (sys && !sys.store.control_ok) {
    items.push({ key: "store", title: m.system.storeTitle, text: m.system.storeText, to: "/system" });
  }
  const recording = recordingAttention(sys?.store.metrics_recording);
  if (recording) items.push({ key: "recording", title: shell.nav.metrics.label, text: recording, to: "/metrics" });
  if (sys?.clock_synchronized === false) {
    const skew = offset !== null && Math.abs(offset) >= CLOCK_SKEW_NOTICE_MS ? clockSkewText(offset) : null;
    items.push({
      key: "clock",
      title: m.system.clockTitle,
      text: m.system.clockText(skew),
      to: "/system?view=runtime",
    });
  }
  return items;
}

function Attention({
  views,
  reason,
  index,
}: {
  views: InstanceView[];
  reason: (v: InstanceView) => string | null;
  index: number;
}) {
  const sys = useSystemStatus();
  const offset = useServerOffset();
  const items: AttentionItem[] = [];
  for (const v of views) {
    const r = reason(v);
    if (r) items.push({ key: v.spec.id, title: v.spec.name, text: r, to: `/instances/${v.spec.id}` });
  }
  items.push(...systemItems(sys.data, offset));
  return (
    <DockPanel
      aria-labelledby="attention-title"
      style={staggerStyle(index)}
      className={cn("xl:sticky xl:top-0", STAGGER_IN)}
    >
      <DockHeader
        icon={<CircleAlert aria-hidden />}
        title={m.attention.title}
        titleId="attention-title"
        count={items.length}
      />
      <DockBody className="p-1.5">
        {items.length ? (
          <PresenceList
            items={items}
            keyOf={(i) => i.key}
            className="grid grid-cols-1 gap-0.5"
            label={m.attention.items}
          >
            {(i) => (
              <Link
                to={i.to}
                className={cn(LIST_ROW, LIST_ROW_IDLE, "flex gap-2.5 rounded-lg px-3 py-2.5 no-underline")}
              >
                <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-warning" />
                <span className="min-w-0">
                  <span className="block truncate text-data font-medium text-fg">{i.title}</span>
                  <span className="block text-caption text-fg-secondary [overflow-wrap:anywhere]">{i.text}</span>
                </span>
              </Link>
            )}
          </PresenceList>
        ) : (
          <p className="flex items-center gap-2.5 px-2.5 py-3 text-data text-fg-secondary animate-fade-in">
            <ShieldCheck aria-hidden className="size-4 shrink-0 text-success" />
            {m.attention.none}
          </p>
        )}
      </DockBody>
    </DockPanel>
  );
}

/** The two live figures (download, upload): every running connection's payload, its proxy ports' and, in strict
 * isolation, its sandbox's Apps'. Re-renders every second on its own. */
function LiveTotals({ ids }: { ids: string[] }) {
  const live = useLiveRatesMap(ids);
  const now = useServerNow();
  const total = liveTotal(live, now);
  return (
    <>
      <Metric
        label={ui.common.download}
        value={total.fresh ? formatBps(total.rx) : "—"}
        detail={m.summary.allConnections}
        note={liveSandboxNote(total, "rx")}
      />
      <Metric
        label={ui.common.upload}
        value={total.fresh ? formatBps(total.tx) : "—"}
        detail={m.summary.allConnections}
        note={liveSandboxNote(total, "tx")}
      />
    </>
  );
}

export function OverviewPage() {
  const navigate = useNavigate();
  const instances = useInstances();
  const apps = useApps();
  const views = instances.data ?? [];
  // A problem first, else configuration that applies only after a restart.
  const reason = (v: InstanceView) => needsAttention(v);
  // The live rates arrive every second: only LiveTotals and the topology lanes read them, so the rest of the page
  // re-renders when its own data changes, not on every tick.
  const runningKey = views
    .filter((v) => v.status?.intent.desired === "running")
    .map((v) => v.spec.id)
    .join(",");
  const running = useMemo(() => (runningKey ? runningKey.split(",") : []), [runningKey]);
  const ready = views.filter((v) => v.status?.phase === "ready" && !v.status.intent.emergency_latched).length;
  // The same items as the 需要處理 list: the connections' and the system's own.
  const sys = useSystemStatus();
  const attention = views.filter((v) => reason(v) !== null).length + systemItems(sys.data).length;
  const serving = views.reduce((n, v) => n + (v.status?.gateways.filter((g) => g.state === "serving").length ?? 0), 0);
  // With no connection yet nothing carries a status: whether the manager answers says it then.
  const manager = useManagerConnected();
  const known = views.length ? views.some((v) => v.status) : manager === true;
  const protectedDetail = known
    ? !views.length
      ? m.summary.noConnection
      : ready
        ? m.summary.tunnelOnly
        : m.summary.noReady
    : manager === null && !views.length
      ? m.summary.reading
      : m.summary.managerDown;

  return (
    <Page>
      {/* The ambient brand scene behind the whole page, fading out towards the bottom; the solid panels cover it. */}
      <div className="relative isolate flex min-h-0 flex-1 flex-col">
        <BrandBackdrop variant="ambient" className="-z-10" />
        <PageHeader
          title={shell.nav.overview.label}
          description={m.page.description}
          help={m.page.help}
          helpText={m.page.helpText}
          actions={
            <>
              <Button icon={FilePlus2} onClick={() => void navigate("/profiles?import=1")}>
                {m.page.importProfile}
              </Button>
              <Button variant="primary" icon={Plus} onClick={() => void navigate("/instances?new=1")}>
                {m.page.addConnection}
              </Button>
            </>
          }
        />
        <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-6 md:px-6 md:pb-8">
          {instances.isError && !instances.data ? (
            <div style={staggerStyle(1)} className={cn("panel", STAGGER_IN)}>
              <ErrorState
                error={instances.error}
                onRetry={() => void instances.refetch()}
                retrying={instances.isFetching}
              />
            </div>
          ) : (
            <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
              <div className="min-w-0 space-y-4">
                <section
                  aria-label={m.summary.label}
                  style={staggerStyle(1)}
                  className={cn(
                    "panel-raised grid grid-cols-2 divide-line-subtle lg:grid-cols-4 lg:divide-x",
                    STAGGER_IN,
                  )}
                >
                  {instances.isPending ? (
                    <div role="status" aria-label={m.summary.loading} className="contents">
                      {Array.from({ length: 4 }, (_, i) => (
                        <div key={i} className="space-y-2 px-5 py-4">
                          <Skeleton className="w-16" />
                          <Skeleton className="h-7 w-24" />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <>
                      <Metric
                        label={m.summary.protected}
                        value={known ? `${ready}/${views.length}` : "—"}
                        changes={known ? `${ready}/${views.length}` : null}
                        detail={protectedDetail}
                        tone={ready ? "success" : undefined}
                      />
                      <LiveTotals ids={running} />
                      <Metric
                        label={m.attention.title}
                        value={known ? attention : "—"}
                        changes={known ? attention : null}
                        detail={<ChangeValue value={serving}>{m.summary.serving(serving)}</ChangeValue>}
                        tone={attention ? "warning" : undefined}
                      />
                    </>
                  )}
                </section>
                {views.length ? (
                  <>
                    <Topology index={3} views={views} apps={apps.data ?? []} liveIds={running} />
                    <TrafficChart index={4} ids={running} />
                  </>
                ) : instances.isSuccess ? (
                  <section aria-label={m.path.title} style={staggerStyle(3)} className={cn("panel", STAGGER_IN)}>
                    <EmptyState icon={Network} title={m.path.emptyTitle} compact>
                      {m.path.emptyBody}
                    </EmptyState>
                  </section>
                ) : null}
              </div>
              <Attention index={5} views={views} reason={reason} />
            </div>
          )}
        </div>
      </div>
    </Page>
  );
}
