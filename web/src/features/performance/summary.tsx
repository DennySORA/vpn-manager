// The top of 效能統計: the product's figures in one raised band (the view's one primary summary) and the in-place notes
// about how complete the analysis is. Live readings update in place every 5 seconds and never fade; the process count
// fades briefly when it changes (a count, not a reading).

import type { LucideIcon } from "lucide-react";
import { Cpu, Gauge, MemoryStick, Radar } from "lucide-react";
import { type CSSProperties, type ReactNode, useMemo } from "react";
import type { InstancePerformance } from "@/api/generated/InstancePerformance";
import type { PerformanceOverview } from "@/api/generated/PerformanceOverview";
import { ChangeValue } from "@/components/ui/change-value";
import { STAGGER_IN } from "@/components/ui/look";
import { Callout } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import { relativeTime } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { m } from "./messages";
import { bytesObs, obs, pct, summaryState } from "./model";
import { Val } from "./values";

function Figure({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: LucideIcon;
  label: string;
  value: ReactNode;
  detail?: ReactNode;
}) {
  return (
    <div className="min-w-0 px-5 py-4">
      <p className="flex items-center gap-1.5 text-caption text-fg-tertiary">
        <Icon aria-hidden className="size-3.5 shrink-0" />
        {label}
      </p>
      <div className="mt-1 truncate text-metric text-fg">{value}</div>
      {detail ? <p className="mt-0.5 text-caption text-fg-tertiary [overflow-wrap:anywhere]">{detail}</p> : null}
    </div>
  );
}

/** Data／probe／control flows over every connection; unknown when any connection does not know its own. */
export function flowTotals(instances: readonly InstancePerformance[]) {
  const sum = (f: (i: InstancePerformance) => number | null) =>
    instances.reduce<number | null>((n, i) => {
      const v = f(i);
      return n === null || v === null ? null : n + v;
    }, 0);
  return {
    data: sum((i) => i.summary.active_data_flows),
    probe: sum((i) => i.summary.active_probe_flows),
    control: sum((i) => i.summary.active_control_flows),
  };
}

export function SummaryBand({ s, style }: { s: PerformanceOverview; style?: CSSProperties }) {
  const product = s.system.product;
  const flows = useMemo(() => flowTotals(s.instances), [s.instances]);
  return (
    <section
      aria-label={m.summary.label}
      style={style}
      className={cn("panel-raised grid grid-cols-2 divide-line-subtle lg:grid-cols-4 lg:divide-x", STAGGER_IN)}
    >
      <Figure
        icon={Cpu}
        label={m.summary.cpu}
        value={<Val v={obs(product.cpu_core_pct, pct)} />}
        detail={m.summary.cpuHost(
          <Val v={obs(product.cpu_host_pct, pct)} />,
          <span className="machine">{s.system.logical_cpu_count}</span>,
          s.system.logical_cpu_count,
        )}
      />
      <Figure
        icon={MemoryStick}
        label={m.summary.rss}
        value={<Val v={bytesObs(product.rss_bytes)} />}
        detail={m.summary.sharedPages}
      />
      <Figure
        icon={Gauge}
        label={m.summary.processes}
        value={<ChangeValue value={product.processes} className="machine" />}
        detail={m.summary.processRoles}
      />
      <Figure
        icon={Radar}
        label={m.summary.flows}
        value={
          <span className="machine">
            {flows.data ?? "—"} / {flows.probe ?? "—"} / {flows.control ?? "—"}
          </span>
        }
        detail={m.summary.flowsApart}
      />
    </section>
  );
}

/** How complete the analysis is (the stale case is the page's, under the tool strip). It reads the clock itself. */
export function CompletenessNotes({ s, style }: { s: PerformanceOverview; style?: CSSProperties }) {
  const now = useServerNow();
  const st = summaryState(s, now);
  if (st.kind === "collecting") {
    return (
      <div style={style} className={STAGGER_IN}>
        <Callout tone="info" title={m.summary.collecting}>
          {m.summary.collectingDetail(
            relativeTime(s.collecting_since, now),
            s.latency_window_secs / 60,
            st.secondsLeft,
          )}
        </Callout>
      </div>
    );
  }
  if (st.kind === "partial") {
    return (
      <div style={style} className={STAGGER_IN}>
        <Callout tone="info" title={m.summary.partial}>
          {m.summary.partialDetail(st.omittedGateways, st.lowCoverage)}
        </Callout>
      </div>
    );
  }
  return null;
}
