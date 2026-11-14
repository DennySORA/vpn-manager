// 瓶頸線索 and 參考規模 of 效能統計: readings of the current numbers (always labelled 推論, never a measured cause), which
// come and go with each analysis (presence: they rise in, leave with a fade and the rest slide up), and the spec's
// 5／10／500 reference work set beside what runs now — a scale, never a live value or a limit.

import { Lightbulb, Ruler } from "lucide-react";
import { type CSSProperties, useMemo } from "react";
import type { PerformanceOverview } from "@/api/generated/PerformanceOverview";
import { Tag } from "@/components/ui/badge";
import { ChangeValue } from "@/components/ui/change-value";
import { CARD, STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Panel } from "@/components/ui/panel";
import { PresenceList } from "@/components/ui/presence-list";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { m } from "./messages";

/** A hint's identity across analyses: its kind and scope (a repeat of the same pair is numbered). */
export function hintKeys(
  hints: PerformanceOverview["hints"],
): { key: string; h: PerformanceOverview["hints"][number] }[] {
  const seen = new Map<string, number>();
  return hints.map((h) => {
    const base = `${h.kind}:${h.scope.kind}:${h.scope.entity_id ?? ""}`;
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    return { key: n > 1 ? `${base}#${n}` : base, h };
  });
}

export function Hints({ s, style }: { s: PerformanceOverview; style?: CSSProperties }) {
  const items = useMemo(() => hintKeys(s.hints), [s.hints]);
  return (
    <Panel
      icon={Lightbulb}
      title={m.hints.title}
      count={s.hints.length}
      description={m.hints.description}
      style={style}
      className={STAGGER_IN}
    >
      {items.length ? (
        <PresenceList items={items} keyOf={(x) => x.key} className="grid grid-cols-1 gap-2" label={m.hints.title}>
          {({ h }) => (
            <div className="flex items-start gap-2.5">
              <Tag tone={h.severity === "warning" ? "warning" : "info"} icon={Lightbulb}>
                {m.hints.inferred}
              </Tag>
              <p className="min-w-0 text-data text-fg-secondary">{localized(h.message)}</p>
            </div>
          )}
        </PresenceList>
      ) : (
        <p className="text-data text-fg-tertiary animate-fade-in">{m.hints.none}</p>
      )}
    </Panel>
  );
}

export function Reference({ s, style }: { s: PerformanceOverview; style?: CSSProperties }) {
  const r = s.reference;
  return (
    <Panel
      icon={Ruler}
      title={m.reference.title}
      description={m.reference.description}
      style={style}
      className={STAGGER_IN}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-dashed border-line-strong px-4 py-3">
          <p className="text-caption text-fg-tertiary">{m.reference.scale}</p>
          <p className="mt-1 text-data text-fg">{m.reference.workload(r.instances, r.gateways, r.data_flows)}</p>
          <p className="text-caption text-fg-tertiary">
            {m.reference.perUnit(r.gateways_per_instance, r.flows_per_gateway)}
          </p>
        </div>
        <div className={cn(CARD, "px-4 py-3")}>
          <p className="text-caption text-fg-tertiary">{m.reference.now}</p>
          <p className="mt-1 text-data text-fg">
            {m.reference.current(
              <ChangeValue value={r.ready_instances} className="machine" />,
              <ChangeValue value={r.serving_gateways} className="machine" />,
              <span className="machine">{r.active_data_flows ?? ui.common.unknown}</span>,
            )}
          </p>
          <p className="text-caption text-fg-tertiary">
            {m.reference.eligible(
              r.gateways_per_instance,
              <ChangeValue value={r.eligible_instances} className="machine" />,
            )}
          </p>
        </div>
      </div>
    </Panel>
  );
}
