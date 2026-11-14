// What the metrics database keeps, for how long, the space it takes and what went missing in the last day. The settings
// themselves live on 系統 (a link, not an action of this page). Facts are property rows with their source underneath;
// the gap list comes and goes with presence (docs/frontend-design.md §8.1).

import { Archive, CircleDashed, Database, Settings2, Workflow } from "lucide-react";
import type { CSSProperties } from "react";
import type { MetricsStatus } from "@/api/types";
import { UsageMeter } from "@/components/charts/meter";
import { PropertyGrid, PropertyRow, PropertySection, SectionLink } from "@/components/ui/inspector";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, ErrorState, Skeleton } from "@/components/ui/states";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, formatBytes, relativeTime } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { m as metrics } from "./messages";
import { formatDuration, formatRatio, GAP_REASON } from "./model";
import { m } from "./retention/messages";

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** "3 天前（10/24 12:00:00）". */
function since(ms: number | null, now: number): string {
  if (ms === null) return ui.common.noData;
  return metrics.when(relativeTime(iso(ms), now), absoluteTime(iso(ms)));
}

/** Space used of the quota: a meter, its tone from the share (≥ 85 % a warning, over the quota a problem). */
function Quota({ used, quota }: { used: number; quota: number }) {
  const share = quota > 0 ? used / quota : 0;
  return (
    <div className="grid grid-cols-1 gap-1.5">
      <UsageMeter
        label={m.quota.label}
        value={used}
        max={quota}
        valueText={m.quota.usedOf(formatBytes(used), formatBytes(quota))}
        tone={share >= 1 ? "danger" : share >= 0.85 ? "warning" : "normal"}
      />
      <p className="flex justify-between gap-3 text-caption text-fg-secondary">
        <span className="machine">{m.quota.usedShare(formatBytes(used), formatRatio(Math.min(share, 9.99)))}</span>
        <span className="text-fg-tertiary">
          {m.quota.limit} <span className="machine">{formatBytes(quota)}</span>
        </span>
      </p>
    </div>
  );
}

function Kept({ status, now }: { status: MetricsStatus; now: number }) {
  const pruned = status.pruned_before;
  return (
    <PropertySection title={m.kept.title} icon={<Archive aria-hidden />}>
      <div className="grid grid-cols-1 gap-3">
        {status.over_quota ? (
          <Callout tone="warning" title={m.kept.overQuota}>
            {m.kept.overQuotaDetail}
          </Callout>
        ) : null}
        <Quota used={status.used_bytes} quota={status.quota_bytes} />
        <PropertyGrid>
          <PropertyRow label={m.kept.raw} hint={m.kept.rawHint(status.sample_interval_ms / 1_000)}>
            {m.kept.hours(status.retention.raw_hours)}
          </PropertyRow>
          <PropertyRow label={m.kept.minute} hint={m.kept.minuteHint}>
            {m.kept.days(status.retention.minute_days)}
          </PropertyRow>
          <PropertyRow label={m.kept.hour} hint={m.kept.hourHint}>
            {m.kept.days(status.retention.hour_days)}
          </PropertyRow>
          <PropertyRow label={m.kept.oldest}>
            <span>{m.kept.oldestRaw(since(status.oldest.raw_ms, now))}</span>
            <span>{m.kept.oldestMinute(since(status.oldest.minute_ms, now))}</span>
            <span>{m.kept.oldestHour(since(status.oldest.hour_ms, now))}</span>
          </PropertyRow>
          {pruned.raw_ms !== null || pruned.minute_ms !== null || pruned.hour_ms !== null ? (
            <PropertyRow label={m.kept.pruned} hint={m.kept.prunedHint(GAP_REASON.quota.label)}>
              {pruned.raw_ms !== null ? <span>{m.kept.prunedRaw(absoluteTime(iso(pruned.raw_ms)))}</span> : null}
              {pruned.minute_ms !== null ? (
                <span>{m.kept.prunedMinute(absoluteTime(iso(pruned.minute_ms)))}</span>
              ) : null}
              {pruned.hour_ms !== null ? <span>{m.kept.prunedHour(absoluteTime(iso(pruned.hour_ms)))}</span> : null}
            </PropertyRow>
          ) : null}
        </PropertyGrid>
      </div>
    </PropertySection>
  );
}

function Missing({ status, now }: { status: MetricsStatus; now: number }) {
  return (
    <PropertySection title={m.missing.title} icon={<CircleDashed aria-hidden />} count={status.gaps_24h.length}>
      {status.gaps_24h.length ? (
        <PresenceList
          items={status.gaps_24h}
          keyOf={(g) => g.reason}
          className="divide-y divide-line-subtle"
          label={m.missing.title}
        >
          {(g) => (
            <div className="flex items-start justify-between gap-4 py-2">
              <span className="min-w-0">
                <span className="block text-data text-fg">{GAP_REASON[g.reason].label}</span>
                <span className="block text-caption text-fg-tertiary">{GAP_REASON[g.reason].detail}</span>
              </span>
              <span className="machine shrink-0 text-right text-caption text-fg-secondary">
                {metrics.times(g.events)}
                {g.duration_ms !== null ? (
                  <span className="block text-fg-tertiary">{formatDuration(g.duration_ms)}</span>
                ) : null}
                {g.last_ms !== null ? (
                  <span className="block font-sans text-fg-tertiary">
                    {m.missing.last(relativeTime(iso(g.last_ms), now))}
                  </span>
                ) : null}
              </span>
            </div>
          )}
        </PresenceList>
      ) : (
        <p className="text-data text-fg-secondary animate-fade-in">{m.missing.none}</p>
      )}
    </PropertySection>
  );
}

function Tasks({ status, now }: { status: MetricsStatus; now: number }) {
  const rollup = status.last_rollup;
  const retention = status.last_retention;
  return (
    <PropertySection title={m.tasks.title} icon={<Workflow aria-hidden />}>
      <PropertyGrid>
        <PropertyRow
          label={m.tasks.rollup}
          hint={
            status.rollup_until_ms !== null ? m.tasks.rolledUpTo(absoluteTime(iso(status.rollup_until_ms))) : undefined
          }
        >
          {rollup ? (
            rollup.ok ? (
              m.tasks.doneAt(relativeTime(rollup.at, now))
            ) : (
              <span className="text-warning">
                {m.tasks.failedAt(relativeTime(rollup.at, now), rollup.error ? localized(rollup.error) : null)}
              </span>
            )
          ) : (
            m.tasks.notRun
          )}
        </PropertyRow>
        <PropertyRow
          label={m.tasks.cleanup}
          hint={retention?.run.ok ? m.tasks.cleanupHint(retention.expired_rows, retention.quota_rows) : undefined}
        >
          {retention ? (
            retention.run.ok ? (
              m.tasks.doneAt(relativeTime(retention.run.at, now))
            ) : (
              <span className="text-warning">
                {m.tasks.failedAt(
                  relativeTime(retention.run.at, now),
                  retention.run.error ? localized(retention.run.error) : null,
                )}
              </span>
            )
          ) : (
            m.tasks.notRun
          )}
        </PropertyRow>
        <PropertyRow label={m.tasks.collector} hint={m.tasks.collectorHint(relativeTime(status.collector.since, now))}>
          <span className="machine">
            {m.tasks.written(status.collector.written, status.collector.queued, status.collector.capacity)}
          </span>
          {status.collector.dropped > 0 ? (
            <span className="text-warning">{m.tasks.dropped(status.collector.dropped)}</span>
          ) : null}
          {status.collector.write_failures > 0 ? (
            <span className="text-warning">{m.tasks.writeFailures(status.collector.write_failures)}</span>
          ) : null}
        </PropertyRow>
      </PropertyGrid>
    </PropertySection>
  );
}

export function RetentionPanel({
  status,
  error,
  onRetry,
  retrying,
  style,
}: {
  status: MetricsStatus | undefined;
  error: unknown;
  onRetry: () => void;
  retrying?: boolean;
  style?: CSSProperties;
}) {
  // Relative times tick here, not in the page (the charts never re-render for the clock).
  const now = useServerNow();
  return (
    <section aria-labelledby="retention-title" style={style} className={cn("panel overflow-hidden", STAGGER_IN)}>
      <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line-subtle px-4 py-2.5">
        <div className="min-w-0">
          <h2 id="retention-title" className="flex items-center gap-2 text-data font-semibold text-fg">
            <Database aria-hidden className="size-4 text-fg-tertiary" />
            {m.title}
          </h2>
          <p className="text-caption text-fg-tertiary">
            {status ? m.observedAt(relativeTime(status.observed_at, now)) : m.about}
          </p>
        </div>
        <SectionLink to="/system" icon={Settings2}>
          {m.settings}
        </SectionLink>
      </header>
      {status ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 lg:divide-x lg:divide-line-subtle">
          <div className="min-w-0">
            <Kept status={status} now={now} />
          </div>
          <div className="min-w-0 max-lg:border-t max-lg:border-line-subtle">
            <Missing status={status} now={now} />
            <Tasks status={status} now={now} />
          </div>
        </div>
      ) : error ? (
        <ErrorState compact error={error} onRetry={onRetry} retrying={retrying} title={m.loadFailed} />
      ) : (
        <div className="space-y-3 px-4 py-4" role="status" aria-label={m.loading}>
          <Skeleton className="w-full" />
          <Skeleton className="w-64" />
          <Skeleton className="w-48" />
        </div>
      )}
    </section>
  );
}
