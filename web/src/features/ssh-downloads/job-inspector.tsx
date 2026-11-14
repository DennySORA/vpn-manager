// The inspector of one SSH download job (docs/frontend-design.md §8.1): the EntityHeader carries its state and its
// frequent actions (暫停／繼續／重試, 編輯, the ⋯ menu — the same menu as its list row); the fixed footer is the view's
// primary task, a listing now. In between, the views are tabs (`?tab=`): 進度 (the conclusion — why it waits or stopped,
// and the fail-closed rule — then the files in flight with their progress and the queue), 紀錄 (the records, paged),
// 日誌 and 設定 (connection, folders, settings). Why it waits or stopped leads every tab.
import {
  ArrowDownToLine,
  ArrowDownUp,
  FileClock,
  FolderDown,
  FolderTree,
  History,
  KeyRound,
  ListOrdered,
  Network,
  ScrollText,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";
import { Link } from "react-router";
import type { GatewaySpec } from "@/api/generated/GatewaySpec";
import type { InstanceView } from "@/api/generated/InstanceView";
import type { SshDownloadActive } from "@/api/generated/SshDownloadActive";
import type { SshDownloadLogEntry } from "@/api/generated/SshDownloadLogEntry";
import type { SshDownloadTransfer } from "@/api/generated/SshDownloadTransfer";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import { sshDownloadKeys, useSshDownloadLog, useSshDownloadTransfers } from "@/api/ssh-downloads";
import { queryClient } from "@/api/query-client";
import { ActionButton } from "@/components/ui/action-button";
import type { EntityAction } from "@/components/ui/action-model";
import { StatusPill, Tag } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChangeValue } from "@/components/ui/change-value";
import { FooterActions, HeaderActions } from "@/components/ui/entity-actions";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  InspectorTab,
  InspectorTabs,
  PropertyGrid,
  PropertyRow,
  PropertySection,
} from "@/components/ui/inspector";
import { TEXT_LINK } from "@/components/ui/look";
import { PresenceList } from "@/components/ui/presence-list";
import { ProgressTrack } from "@/components/ui/progress";
import { Callout, ErrorCallout, Skeleton } from "@/components/ui/states";
import { ToolButton } from "@/components/ui/tool-strip";
import { instanceLook } from "@/features/instances/model";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, formatBytes, relativeTime } from "@/lib/format";
import { useTabParam } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { useJobActions } from "./action-host";
import type { JobActionId } from "./actions";
import { m } from "./inspector/messages";
import { m as shared } from "./messages";
import {
  dueIn,
  FILTER_LABEL,
  formatDuration,
  formatEta,
  formatRate,
  jobLook,
  progressText,
  recordsText,
  runningFor,
  STEP_LABEL,
  targetText,
  TRANSFER_LOOK,
} from "./model";

/** The same action as the header's or the menu's, offered next to what it fixes (one name, icon and run). */
function InlineAction({ action }: { action: EntityAction | undefined }) {
  if (!action) return null;
  return (
    <ActionButton
      size="sm"
      icon={action.icon}
      pending={action.pending}
      pendingLabel={action.pendingLabel}
      disabledReason={action.pending ? null : action.disabledReason}
      onClick={action.run}
    >
      {action.label}
    </ActionButton>
  );
}

function ActiveFile({ a }: { a: SshDownloadActive }) {
  const done = Number(a.bytes_done);
  const total = a.bytes_total === null ? null : Number(a.bytes_total);
  const resumed = Number(a.resumed_from);
  return (
    <div className="grid grid-cols-1 gap-1.5 rounded-lg border border-line-subtle bg-sunken/50 px-3 py-2.5">
      <div className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-data font-medium text-fg" title={a.name}>
          {a.name}
        </span>
        <Tag tone={a.step === "failing" ? "warning" : "info"}>{STEP_LABEL[a.step]}</Tag>
      </div>
      <ProgressTrack
        value={a.step === "downloading" && total !== null ? done : null}
        max={total ?? 1}
        tone={a.step === "failing" ? "failed" : "running"}
        label={shared.progressOf(a.name)}
        valueText={progressText(a)}
        size="sm"
      />
      <p className="machine flex flex-wrap gap-x-3 text-caption text-fg-secondary">
        <span>{progressText(a)}</span>
        <span>{formatRate(a.rate_bps)}</span>
        <span>{m.active.remaining(formatEta(a.eta_secs))}</span>
        {a.connections > 1 ? <span>{m.active.connections(a.connections)}</span> : null}
      </p>
      {resumed > 0 || a.attempt > 1 ? (
        <p className="text-caption text-fg-tertiary">
          {resumed > 0 ? m.active.resumedFrom(formatBytes(resumed)) : null}
          {resumed > 0 && a.attempt > 1 ? " · " : null}
          {a.attempt > 1 ? m.active.attempt(a.attempt) : null}
        </p>
      ) : null}
    </div>
  );
}

/** How long this run has lasted: the one-second clock lives here, not in the inspector. */
function RunningFor({ since }: { since: string }) {
  const now = useServerNow();
  return <>{runningFor(since, now)}</>;
}

function TransferRow({ t, now }: { t: SshDownloadTransfer; now: number }) {
  const look = TRANSFER_LOOK[t.state];
  return (
    <div className="grid grid-cols-1 gap-1 border-b border-line-subtle py-2 last:border-b-0">
      <div className="flex min-w-0 items-center gap-2">
        {t.name_recorded ? (
          <span className="min-w-0 flex-1 truncate text-data text-fg" title={t.name}>
            {t.name}
          </span>
        ) : (
          <span className="min-w-0 flex-1 truncate text-data text-fg-secondary" title={m.transfer.namesOff}>
            <span className="machine">{t.name}</span>
            <span className="text-caption text-fg-tertiary">{m.transfer.nameOff}</span>
          </span>
        )}
        <StatusPill look={{ label: look.label, tone: look.tone, icon: look.icon }} />
      </div>
      <p className="machine flex flex-wrap gap-x-3 text-caption text-fg-tertiary">
        <span>{t.size !== null ? formatBytes(t.size) : m.transfer.sizeUnknown}</span>
        {t.duration_ms !== null ? <span>{formatDuration(t.duration_ms)}</span> : null}
        <span title={absoluteTime(t.finished_at ?? t.created_at)}>
          {relativeTime(t.finished_at ?? t.created_at, now)}
        </span>
        {t.attempts > 0 && t.state !== "completed" ? <span>{m.transfer.noProgress(t.attempts)}</span> : null}
      </p>
      {t.error ? (
        <p
          className={cn("text-caption [overflow-wrap:anywhere]", t.state === "failed" ? "text-danger" : "text-warning")}
        >
          {localized(t.error)}
        </p>
      ) : null}
      {t.state === "completed" && t.local_path ? (
        <p className="machine truncate text-micro text-fg-tertiary" title={t.local_path}>
          → {t.local_path}
        </p>
      ) : null}
      {t.state === "failed" ? (
        <p className="machine truncate text-micro text-fg-tertiary" title={t.remote_path}>
          {m.transfer.remote(t.remote_path)}
        </p>
      ) : null}
    </div>
  );
}

/**
 * The records and the log follow the job, whichever tab shows: another finished file reloads the records, the
 * unfinished files and the log; a new state (often a new log line) reloads the log (statuses arrive at most once a
 * second). A tab that is not shown is only marked stale and loads when it is opened.
 */
function useFollowJob(v: SshDownloadView) {
  const finished = (v.status?.completed ?? 0) + (v.status?.failed ?? 0);
  const seenFinished = useRef(finished);
  useEffect(() => {
    if (finished !== seenFinished.current) {
      seenFinished.current = finished;
      void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.transfers(v.job.id, "history") });
      void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.transfers(v.job.id, "active") });
      void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.log(v.job.id) });
    }
  }, [finished, v.job.id]);
  const stamp = `${v.status?.state}:${v.status?.reason_code}:${v.status?.last_scan_at}`;
  const seenStamp = useRef(stamp);
  useEffect(() => {
    if (stamp !== seenStamp.current) {
      seenStamp.current = stamp;
      void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.log(v.job.id) });
    }
  }, [stamp, v.job.id]);
}

/** The same clear as the menu's, beside what it clears (one name, icon and confirmation). */
function ClearButton({ action }: { action: EntityAction | undefined }) {
  if (!action) return null;
  return (
    <ToolButton
      label={action.label}
      text={action.label}
      icon={<action.icon aria-hidden />}
      pending={action.pending}
      disabledReason={action.pending ? null : action.disabledReason}
      onClick={action.run}
    />
  );
}

/** The finished files, newest first, a page at a time. */
function HistorySection({ v, now, clear }: { v: SshDownloadView; now: number; clear: EntityAction | undefined }) {
  const history = useSshDownloadTransfers(v.job.id, "history");
  const items = history.data?.pages.flatMap((p) => p.items) ?? [];
  const kept = recordsText(v.job);
  return (
    <PropertySection
      title={m.history.title}
      icon={<History aria-hidden />}
      count={history.data ? items.length : null}
      actions={<ClearButton action={clear} />}
    >
      {history.isPending ? (
        <div role="status" aria-label={m.history.reading} className="grid grid-cols-1 gap-1.5">
          <Skeleton className="w-full" />
          <Skeleton className="w-2/3" />
        </div>
      ) : history.isError && !history.data ? (
        <ErrorCallout
          error={history.error}
          title={m.history.failed}
          onRetry={() => void history.refetch()}
          retrying={history.isFetching}
        />
      ) : items.length ? (
        <div className="grid grid-cols-1">
          <PresenceList items={items} keyOf={(t) => t.id} className="grid grid-cols-1" label={m.history.of(v.job.name)}>
            {(t) => <TransferRow t={t} now={now} />}
          </PresenceList>
          {history.hasNextPage ? (
            <Button
              size="sm"
              variant="quiet"
              className="mt-1 justify-self-start"
              pending={history.isFetchingNextPage}
              pendingLabel={m.history.loading}
              onClick={() => void history.fetchNextPage()}
            >
              {m.history.older}
            </Button>
          ) : (
            <p className="mt-1 text-caption text-fg-tertiary">{m.history.kept(kept.kept, kept.names)}</p>
          )}
        </div>
      ) : (
        <p className="text-caption text-fg-tertiary">{m.history.none}</p>
      )}
    </PropertySection>
  );
}

function LogLine({ e, now }: { e: SshDownloadLogEntry; now: number }) {
  const tone = e.level === "error" ? "text-danger" : e.level === "warning" ? "text-warning" : "text-fg-secondary";
  return (
    <li className="grid grid-cols-1 gap-0.5 border-b border-line-subtle py-1.5 last:border-b-0">
      <span className="flex min-w-0 items-center gap-2 text-micro text-fg-tertiary">
        <span title={absoluteTime(e.at)}>{relativeTime(e.at, now)}</span>
        <span className="machine">{e.code}</span>
        {e.file ? (
          <span className="min-w-0 truncate" title={e.file}>
            {e.file}
          </span>
        ) : null}
      </span>
      <span className={cn("text-caption [overflow-wrap:anywhere]", tone)}>{localized(e.message)}</span>
    </li>
  );
}

function LogSection({ v, now, clear }: { v: SshDownloadView; now: number; clear: EntityAction | undefined }) {
  const log = useSshDownloadLog(v.job.id);
  const items = log.data?.items ?? [];
  return (
    <PropertySection
      title={m.log.title}
      icon={<ScrollText aria-hidden />}
      count={log.data ? items.length : null}
      actions={<ClearButton action={clear} />}
    >
      {log.isPending ? (
        <Skeleton className="w-full" />
      ) : log.isError && !log.data ? (
        <ErrorCallout
          error={log.error}
          title={m.log.failed}
          onRetry={() => void log.refetch()}
          retrying={log.isFetching}
        />
      ) : items.length ? (
        <ul aria-label={m.log.of(v.job.name)} className="grid grid-cols-1">
          {items.map((e) => (
            <LogLine key={e.seq} e={e} now={now} />
          ))}
        </ul>
      ) : (
        <p className="text-caption text-fg-tertiary">{m.log.none}</p>
      )}
    </PropertySection>
  );
}

export type JobTab = "progress" | "history" | "log" | "settings";

export const JOB_TABS: JobTab[] = ["progress", "history", "log", "settings"];

const JOB_TAB_LABEL: Record<JobTab, string> = {
  progress: m.tabs.progress,
  history: m.tabs.history,
  log: m.tabs.log,
  settings: m.tabs.settings,
};

export function JobInspector({
  v,
  gateway,
  owner,
}: {
  v: SshDownloadView;
  gateway: GatewaySpec | undefined;
  owner: InstanceView | undefined;
}) {
  const now = useServerNow();
  const [tab, setTab] = useTabParam<JobTab>("tab", JOB_TABS);
  useFollowJob(v);
  const actions = useJobActions(v, Boolean(gateway));
  const action = (id: JobActionId) => actions.find((a) => a.id === id);
  const s = v.status;
  // A planned moment that has come says so ("即將"), never "剛剛".
  const scanIn = dueIn(s?.next_scan_at, now);
  const retryIn = dueIn(s?.next_retry_at, now);
  const look = jobLook(v);
  const unfinished = useSshDownloadTransfers(s && s.unfinished > 0 ? v.job.id : undefined, "active");
  const waitingFiles = (unfinished.data?.pages.flatMap((p) => p.items) ?? []).filter(
    (t) => !s?.active.some((a) => a.transfer_id === t.id),
  );
  const ownerLook = owner ? instanceLook(owner) : null;

  // The conclusion: why the job waits or stopped leads every tab; the fail-closed rule leads 進度.
  const problem: ReactNode =
    s?.state === "error" && s.reason_code === "HOST_KEY_CHANGED" ? (
      <Callout
        key="problem"
        tone="danger"
        icon={KeyRound}
        title={m.problem.hostKeyChanged}
        actions={<InlineAction action={action("trust_host_key")} />}
      >
        <p>{m.problem.hostKeyStopped}</p>
        <p className="machine mt-1 text-micro text-fg-tertiary [overflow-wrap:anywhere]">
          {m.problem.recordedKey(s.host_key?.fingerprint ?? "—")}
          <br />
          {m.problem.offeredKey(s.offered_host_key?.fingerprint ?? "—")}
        </p>
      </Callout>
    ) : s?.state === "error" ? (
      <Callout
        key="problem"
        tone="danger"
        title={shared.state.error}
        actions={<InlineAction action={action("retry")} />}
      >
        <p className="[overflow-wrap:anywhere]">{s.reason ? localized(s.reason) : null}</p>
        {s.next_retry_at ? <p className="mt-1 text-caption text-fg-tertiary">{m.problem.recheck(retryIn)}</p> : null}
      </Callout>
    ) : s?.state === "waiting_vpn" ? (
      <Callout key="problem" tone="warning" title={shared.state.waiting_vpn}>
        <p className="[overflow-wrap:anywhere]">{s.reason ? localized(s.reason) : null}</p>
        <p className="mt-1 text-caption text-fg-tertiary">{m.problem.waiting(Boolean(s.next_retry_at), retryIn)}</p>
      </Callout>
    ) : s?.state === "retrying" ? (
      <Callout key="problem" tone="warning" title={shared.state.retrying}>
        <p className="[overflow-wrap:anywhere]">{s.reason ? localized(s.reason) : null}</p>
        {s.next_retry_at ? <p className="mt-1 text-caption text-fg-tertiary">{m.problem.nextTry(retryIn)}</p> : null}
      </Callout>
    ) : s?.state === "paused" ? (
      <Callout
        key="problem"
        tone="info"
        title={shared.state.paused}
        actions={<InlineAction action={action("resume")} />}
      >
        {s.unfinished ? m.problem.pausedUnfinished(s.unfinished) : m.problem.pausedIdle}
      </Callout>
    ) : !s ? (
      <Callout key="problem" tone="warning" title={m.problem.unknown}>
        {m.problem.unknownBody}
      </Callout>
    ) : null;
  const lead = (progress: boolean): ReactNode[] | null => {
    const items = [
      problem,
      progress && s ? (
        <Callout key="vpn" tone="info" icon={ShieldCheck} title={shared.onlyVpn}>
          {m.problem.onlyVia(gateway ? gateway.name : null, owner ? owner.spec.name : null, v.job.host)}
        </Callout>
      ) : null,
    ].filter(Boolean);
    return items.length ? items : null;
  };

  return (
    <InspectorFrame
      tabbed
      header={
        <EntityHeader
          icon={FolderDown}
          tone="info"
          title={v.job.name}
          status={<StatusPill look={look} title={s?.reason ? localized(s.reason) : undefined} />}
          description={
            <span className="grid grid-cols-1 gap-1">
              <span className="machine truncate" title={targetText(v.job)}>
                {targetText(v.job)}
              </span>
              <span className="machine truncate text-fg-tertiary" title={`${v.job.source_dir} → ${v.job.local_dir}`}>
                {v.job.source_dir} → {v.job.local_dir}
              </span>
            </span>
          }
          id={v.job.id}
          idLabel={m.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={m.actionsOf(v.job.name)} />}
        />
      }
      footer={
        <InspectorFooter
          note={
            s?.last_scan_at ? (
              <span>{m.lastScan(relativeTime(s.last_scan_at, now), Boolean(s.next_scan_at), scanIn)}</span>
            ) : (
              m.neverScanned
            )
          }
        >
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      <InspectorTabs
        label={m.viewsOf(v.job.name)}
        value={tab}
        onChange={setTab}
        items={JOB_TABS.map((t) => ({ value: t, label: JOB_TAB_LABEL[t] }))}
      >
        <InspectorTab value="progress" lead={lead(true)}>
          <PropertySection
            title={m.active.title}
            icon={<ArrowDownToLine aria-hidden />}
            count={s ? s.active.length : null}
          >
            {s?.active.length ? (
              <PresenceList
                items={s.active}
                keyOf={(a) => a.transfer_id}
                className="grid grid-cols-1 gap-2"
                label={m.active.of(v.job.name)}
              >
                {(a) => <ActiveFile a={a} />}
              </PresenceList>
            ) : (
              <p className="text-caption text-fg-tertiary">
                {s?.state === "scanning" ? m.active.scanning : m.active.none}
              </p>
            )}
          </PropertySection>

          <PropertySection title={m.traffic.title} icon={<ArrowDownUp aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={shared.rate} mono hint={m.traffic.rateHint}>
                {s?.running_since ? `↓ ${formatRate(s.wire_rx_bps)} · ↑ ${formatRate(s.wire_tx_bps)}` : "—"}
              </PropertyRow>
              <PropertyRow label={m.traffic.total} mono hint={m.traffic.sinceStart}>
                {s ? `↓ ${formatBytes(s.wire_rx_bytes)} · ↑ ${formatBytes(s.wire_tx_bytes)}` : "—"}
              </PropertyRow>
              <PropertyRow
                label={m.traffic.runTime}
                mono
                hint={s?.running_since ? m.traffic.startedAt(absoluteTime(s.running_since)) : m.traffic.notTimed}
              >
                {s?.running_since ? <RunningFor since={s.running_since} /> : "—"}
              </PropertyRow>
              <PropertyRow label={m.traffic.path} hint={m.traffic.pathHint}>
                {gateway ? (
                  <span>
                    {m.traffic.via(
                      <Link to={`/gateways/${gateway.id}`} className={TEXT_LINK}>
                        {gateway.name}
                      </Link>,
                      owner ? owner.spec.name : null,
                    )}
                  </span>
                ) : (
                  <span className="text-warning">{shared.action.gatewayMissing}</span>
                )}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>

          <PropertySection title={m.queue.title} icon={<ListOrdered aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={m.queue.waiting} mono hint={s?.queue_truncated ? m.queue.truncated : undefined}>
                <ChangeValue value={s?.queued ?? null}>{s ? shared.list.files(s.queued) : "—"}</ChangeValue>
              </PropertyRow>
              <PropertyRow label={m.queue.unfinished} mono hint={s?.unfinished ? m.queue.unfinishedHint : undefined}>
                {s ? shared.list.files(s.unfinished) : "—"}
              </PropertyRow>
              <PropertyRow label={m.queue.connections} mono hint={m.queue.connectionsHint}>
                {s ? m.queue.connectionsOf(s.connections, s.connections_max) : "—"}
              </PropertyRow>
              <PropertyRow
                label={m.queue.lastScan}
                hint={s?.last_scan_at ? m.queue.skipped(s.last_scan_skipped) : undefined}
              >
                {s?.last_scan_at ? m.queue.at(relativeTime(s.last_scan_at, now), absoluteTime(s.last_scan_at)) : "—"}
              </PropertyRow>
              <PropertyRow label={m.queue.sinceStart} mono hint={m.traffic.sinceStart}>
                {s ? m.queue.tally(s.completed, s.failed, formatBytes(s.bytes)) : "—"}
              </PropertyRow>
            </PropertyGrid>
            {waitingFiles.length ? (
              <div className="mt-2 grid grid-cols-1">
                <p className="text-caption font-medium text-fg-secondary">{m.queue.retrying}</p>
                {waitingFiles.map((t) => (
                  <TransferRow key={t.id} t={t} now={now} />
                ))}
              </div>
            ) : null}
          </PropertySection>
        </InspectorTab>

        <InspectorTab value="history" lead={lead(false)}>
          <HistorySection v={v} now={now} clear={action("clear_history")} />
        </InspectorTab>

        <InspectorTab value="log" lead={lead(false)}>
          <LogSection v={v} now={now} clear={action("clear_log")} />
        </InspectorTab>

        <InspectorTab value="settings" lead={lead(false)}>
          <PropertySection title={m.settings.connection} icon={<Network aria-hidden />}>
            <PropertyGrid>
              <PropertyRow
                label={shared.field.gateway}
                hint={ownerLook && owner ? m.settings.gatewayOwner(owner.spec.name, ownerLook.label) : undefined}
              >
                {gateway ? (
                  <Link to={`/gateways/${gateway.id}`} className={TEXT_LINK}>
                    {m.settings.gatewayAddress(gateway.name, gateway.port)}
                  </Link>
                ) : (
                  <span className="text-warning">{shared.action.gatewayMissing}</span>
                )}
              </PropertyRow>
              <PropertyRow label={shared.field.server} mono>
                {targetText(v.job)}
              </PropertyRow>
              <PropertyRow label={shared.field.login} hint={m.settings.loginHint}>
                {[
                  v.job.identity_file ? m.settings.privateKey(v.job.identity_file) : null,
                  v.job.key_passphrase ? m.settings.passphraseStored : null,
                  v.job.password ? m.settings.passwordStored : null,
                ]
                  .filter(Boolean)
                  .join(" · ") || "—"}
              </PropertyRow>
              <PropertyRow
                label={m.settings.hostKey}
                mono
                hint={
                  s?.host_key
                    ? m.settings.hostKeySeen(s.host_key.algorithm, absoluteTime(s.host_key.seen_at))
                    : m.settings.hostKeyFirst
                }
              >
                {s?.host_key?.fingerprint ?? m.settings.neverConnected}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>

          <PropertySection title={m.settings.folders} icon={<FolderTree aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={m.settings.source} mono hint={m.settings.sourceHint}>
                {v.job.source_dir}
              </PropertyRow>
              <PropertyRow label={m.settings.work} mono hint={m.settings.workHint}>
                {v.job.work_dir}
              </PropertyRow>
              <PropertyRow label={m.settings.failed} mono>
                {v.job.failed_dir}
              </PropertyRow>
              <PropertyRow label={m.settings.local} mono hint={m.settings.localHint}>
                {v.job.local_dir}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>

          <PropertySection title={m.settings.title} icon={<Settings2 aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={m.settings.concurrent} mono>
                {v.job.connections}
              </PropertyRow>
              <PropertyRow label={shared.field.attempts} hint={m.settings.attemptsHint}>
                {m.settings.attempts(v.job.retries)}
              </PropertyRow>
              <PropertyRow label={shared.field.backoff} hint={shared.field.backoffHint}>
                {m.settings.backoff(v.job.retry_backoff_secs)}
              </PropertyRow>
              <PropertyRow label={shared.field.scanInterval}>
                {m.settings.scanInterval(v.job.scan_interval_secs)}
              </PropertyRow>
              <PropertyRow label={shared.field.nameFilter} hint={FILTER_LABEL[v.job.name_filter].text}>
                {FILTER_LABEL[v.job.name_filter].title}
              </PropertyRow>
              <PropertyRow label={m.settings.dotFiles}>
                {v.job.skip_hidden ? m.settings.skipped : m.settings.downloaded}
              </PropertyRow>
              <PropertyRow label={m.settings.created}>{absoluteTime(v.job.created_at)}</PropertyRow>
            </PropertyGrid>
          </PropertySection>

          <PropertySection title={shared.field.records} icon={<FileClock aria-hidden />}>
            <PropertyGrid>
              <PropertyRow
                label={m.settings.fileNames}
                hint={v.job.record_names ? m.settings.fileNamesOn : m.settings.fileNamesOff}
              >
                {recordsText(v.job).names}
              </PropertyRow>
              <PropertyRow label={m.settings.kept} hint={m.settings.keptHint}>
                {recordsText(v.job).kept}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>
        </InspectorTab>
      </InspectorTabs>
    </InspectorFrame>
  );
}
