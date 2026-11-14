// 恢復: what VPN Manager owns and what a crash left behind. The conclusion comes first (the view's one raised summary,
// with the inspection's actions: 重新檢查 and 清理 N 個項目), then the leftovers — each with its own 清理, or the reason
// it is only reported — and what the manager holds. Every clean, of one item or of all, is confirmed first with exactly
// the items it touches; it touches only what the manager can prove is its own and stale, and never starts anything.
// Cleaned items leave the list with a fade and the rest slide up (docs/frontend-design.md §8.1).

import { Boxes, BrushCleaning, CircleHelp, ClipboardList, TriangleAlert } from "lucide-react";
import { type CSSProperties, useMemo, useState } from "react";
import { Link } from "react-router";
import { useApps, useInstances } from "@/api/queries";
import { useReconcile, useRecovery } from "@/api/system";
import type { ReconcileResult, RecoveryItem } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { StatusPill, Tag } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { ConfirmDialog } from "@/components/ui/dialog";
import { HeaderActions, RowActions } from "@/components/ui/entity-actions";
import { m as ui } from "@/components/ui/messages";
import { PropertyGrid, PropertyRow } from "@/components/ui/inspector";
import { STAGGER_IN, TEXT_LINK } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { Panel } from "@/components/ui/panel";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorCallout, ErrorState, Skeleton } from "@/components/ui/states";
import { reportFailure, toast } from "@/components/ui/toast";
import { AppResourceList } from "@/features/apps/resources";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime, shortId } from "@/lib/format";
import { useIntentKey } from "@/lib/intent";
import { PHASE } from "@/lib/status";
import { useServerNow } from "@/lib/server-clock";
import {
  cleanableItems,
  type RecoveryActionContext,
  type RecoveryActionId,
  type RecoveryItemActionId,
  recoveryActions,
  recoveryItemActions,
  recoveryPending,
} from "./actions";
import { m as system } from "./messages";
import { gapText, RECONCILE_OUTCOME, RECOVERY_KIND, recoveryVerdict } from "./model";
import { m } from "./recovery/messages";
import { SummaryBand, SummaryCount } from "./summary";

const clock = new Intl.DateTimeFormat(intlLocale, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/** What a leftover belongs to, by name, linked when it still exists. */
function Owner({ item, owners }: { item: RecoveryItem; owners: Map<string, { name: string; to: string }> }) {
  if (!item.instance_id) return null;
  const app = item.kind === "app_leftover";
  const owner = owners.get(item.instance_id);
  return (
    <span className="text-caption text-fg-tertiary">
      {m.item.owner(
        app,
        owner ? (
          <Link to={owner.to} className={TEXT_LINK}>
            {owner.name}
          </Link>
        ) : (
          <span className="machine">{shortId(item.instance_id)}</span>
        ),
      )}
    </span>
  );
}

/** A leftover's name for its controls: the title, and the file it is when two could share a title. */
export function itemName(item: Pick<RecoveryItem, "title" | "path">): string {
  const file = item.path?.split("/").filter(Boolean).pop();
  const title = localized(item.title);
  return file ? m.item.name(title, file) : title;
}

function ItemRow({
  item,
  actions,
  owners,
}: {
  item: RecoveryItem;
  actions: EntityAction[];
  owners: Map<string, { name: string; to: string }>;
}) {
  return (
    <div className="flex items-start gap-3 py-3">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-data font-medium text-fg">{localized(item.title)}</span>
          <Tag tone={item.cleanable ? "warning" : "neutral"}>{item.cleanable ? m.cleanable : m.reportOnly}</Tag>
          <span className="text-caption text-fg-tertiary">{RECOVERY_KIND[item.kind]}</span>
          <Owner item={item} owners={owners} />
        </div>
        <p className="mt-1 text-data text-fg-secondary [overflow-wrap:anywhere]">{localized(item.detail)}</p>
        {item.path ? (
          <p className="mt-1 flex min-w-0 items-start gap-1 text-caption text-fg-tertiary">
            <span className="machine min-w-0">{item.path}</span>
            <CopyButton value={item.path} label={m.item.path} />
          </p>
        ) : null}
        {item.action ? (
          <p className="mt-1 text-caption text-fg-tertiary">{m.item.onClean(localized(item.action))}</p>
        ) : null}
      </div>
      <RowActions actions={actions} name={itemName(item)} className="-mt-0.5 shrink-0" />
    </div>
  );
}

function Result({
  result,
  names,
  onDismiss,
  style,
}: {
  result: ReconcileResult;
  /** The items as they were named when the clean was sent (two can share a title; the name adds the file). */
  names: ReadonlyMap<string, string>;
  onDismiss: () => void;
  style?: CSSProperties;
}) {
  return (
    <Panel
      icon={ClipboardList}
      title={m.result.title}
      description={m.result.meta(
        absoluteTime(result.observed_at),
        result.operation_id ? shortId(result.operation_id) : "—",
      )}
      action={
        <Button size="sm" variant="quiet" onClick={onDismiss}>
          {ui.common.close}
        </Button>
      }
      style={style}
      className={STAGGER_IN}
    >
      {result.actions.length ? (
        <PresenceList items={result.actions} keyOf={(a) => a.item_id} className="space-y-2" label={m.result.title}>
          {(a) => (
            <div className="flex items-start gap-3">
              <StatusPill look={RECONCILE_OUTCOME[a.outcome]} className="mt-px shrink-0" />
              <span className="min-w-0 text-data text-fg [overflow-wrap:anywhere]">
                {names.get(a.item_id) ?? localized(a.title)}
                <span className="text-fg-tertiary">{m.item.then(localized(a.detail))}</span>
              </span>
            </div>
          )}
        </PresenceList>
      ) : (
        <p className="text-data text-fg-tertiary">{m.result.repeated}</p>
      )}
    </Panel>
  );
}

/** "12 秒前檢查": the clock ticks here only, never re-rendering the lists. */
function CheckedAgo({ at }: { at: string }) {
  const now = useServerNow();
  return <span title={absoluteTime(at)}>{m.verdict.checked(relativeTime(at, now))}</span>;
}

/** A confirmation the view opened: the items it will clean (fixed when it opened), and whether that is every one. */
interface Confirming {
  items: RecoveryItem[];
  all: boolean;
  open: boolean;
}

export function RecoveryView() {
  const q = useRecovery();
  const instances = useInstances();
  const apps = useApps();
  const reconcile = useReconcile();
  const intent = useIntentKey("recovery.reconcile");
  const blocked = useMutationBlocked();
  const [confirming, setConfirming] = useState<Confirming | null>(null);
  const [running, setRunning] = useState<{ items: ReadonlySet<string>; all: boolean } | null>(null);
  const [result, setResult] = useState<{ data: ReconcileResult; names: ReadonlyMap<string, string> } | null>(null);
  /** Focus goes to the page title after a clean that removed the row it was opened from. */
  const [cleanedRow, setCleanedRow] = useState(false);
  const owners = useMemo(() => {
    const map = new Map<string, { name: string; to: string }>();
    for (const v of instances.data ?? []) map.set(v.spec.id, { name: v.spec.name, to: `/instances/${v.spec.id}` });
    for (const a of apps.data ?? []) map.set(a.spec.id, { name: a.spec.name, to: `/apps/${a.spec.id}` });
    return map;
  }, [instances.data, apps.data]);
  const name = (id: string) => owners.get(id)?.name ?? shortId(id);
  const r = q.data;
  const cleanable = cleanableItems(r);
  const ctx: RecoveryActionContext = { blocked, cleaning: reconcile.isPending ? running : null };

  const clean = (items: RecoveryItem[], all: boolean) => {
    const input = { items: items.map((i) => i.id) };
    // The result names items as they are now (cleaned ones leave the report).
    const names = new Map([...(r?.items ?? []), ...items].map((i) => [i.id, itemName(i)]));
    setRunning({ items: new Set(input.items), all });
    reconcile.mutate(
      { key: intent.next(input), input },
      {
        onSuccess: (res) => {
          intent.settle();
          setRunning(null);
          setCleanedRow(!all);
          setConfirming((c) => (c ? { ...c, open: false } : c));
          setResult({ data: res.data, names });
          const done = res.data.actions.filter((a) => a.outcome === "done").length;
          const failed = res.data.actions.filter((a) => a.outcome === "failed").length;
          if (failed) toast.error(m.toast.partial, m.toast.partialDetail(done, failed));
          else toast.success(m.toast.cleaned(done));
        },
        onError: (e) => {
          intent.settle(e);
          setRunning(null);
          setCleanedRow(false);
          setConfirming((c) => (c ? { ...c, open: false } : c));
          reportFailure(m.toast.intent, e);
        },
      },
    );
  };
  const ask = (items: RecoveryItem[], all: boolean) => {
    setCleanedRow(false);
    setConfirming({ items, all, open: true });
  };

  const viewActions: EntityAction<RecoveryActionId>[] = recoveryActions(r, ctx).map((spec) => ({
    ...spec,
    pending: recoveryPending(spec.id, ctx, q.isFetching),
    run: () => {
      if (spec.id === "recheck") void q.refetch();
      else ask(cleanable, true);
    },
  }));
  const itemActions = (item: RecoveryItem): EntityAction<RecoveryItemActionId>[] =>
    recoveryItemActions(item, ctx).map((spec) => ({
      ...spec,
      pending: Boolean(ctx.cleaning?.items.has(item.id)),
      run: () => {
        ask([item], false);
      },
    }));

  if (!r) {
    return (
      <div className="px-4 pt-5 pb-8 md:px-6">
        {q.isError ? (
          <div className={cn("panel", STAGGER_IN)}>
            <ErrorState
              error={q.error}
              onRetry={() => void q.refetch()}
              retrying={q.isFetching}
              title={m.view.failed}
            />
          </div>
        ) : (
          <div
            className={cn("panel-raised space-y-3 px-5 py-5", STAGGER_IN)}
            role="status"
            aria-label={m.view.checking}
          >
            <Skeleton className="w-64" />
            <Skeleton className="w-48" />
          </div>
        )}
      </div>
    );
  }

  const v = recoveryVerdict(r);
  const ordered = [...cleanable, ...r.items.filter((i) => !i.cleanable)];
  const confirmAll = confirming?.all ?? false;
  return (
    <div className="space-y-4 px-4 pt-5 pb-8 md:px-6">
      <SummaryBand
        label={m.verdict.label}
        tone={v.tone}
        icon={v.icon}
        title={v.title}
        detail={
          <>
            <CheckedAgo at={r.observed_at} /> · {m.verdict.scope}
          </>
        }
        aside={<HeaderActions actions={viewActions} menuLabel={m.actions.menu} />}
        style={staggerStyle(0)}
      >
        <dl className="grid grid-cols-3 md:divide-x md:divide-line-subtle">
          <SummaryCount label={m.cleanable} icon={BrushCleaning} count={v.cleanable} tone="warning" />
          <SummaryCount label={m.reportOnly} icon={CircleHelp} count={v.reportOnly} tone="info" />
          <SummaryCount label={system.owned.notChecked} icon={TriangleAlert} count={r.gaps.length} tone="warning" />
        </dl>
      </SummaryBand>

      {q.isError ? (
        <ErrorCallout
          error={q.error}
          title={m.view.stale(clock.format(Date.parse(r.observed_at)))}
          onRetry={() => void q.refetch()}
          retrying={q.isFetching}
        />
      ) : null}

      {result ? (
        <Result
          result={result.data}
          names={result.names}
          onDismiss={() => {
            setResult(null);
          }}
          style={staggerStyle(1)}
        />
      ) : null}

      {r.gaps.length ? (
        <div style={staggerStyle(1)} className={STAGGER_IN}>
          <Callout tone="warning" title={m.view.gaps(r.gaps.length)}>
            <ul className="mt-1 space-y-0.5">
              {r.gaps.map((g) => (
                <li key={`${g.what.en}-${g.path ?? ""}`} className="[overflow-wrap:anywhere]">
                  {gapText(g)}
                </li>
              ))}
            </ul>
          </Callout>
        </div>
      ) : null}

      <Panel
        icon={BrushCleaning}
        title={m.items.title}
        count={r.items.length}
        description={m.items.description}
        style={staggerStyle(2)}
        className={STAGGER_IN}
      >
        {r.items.length ? (
          <PresenceList
            items={ordered}
            keyOf={(i) => i.id}
            className="-my-3 divide-y divide-line-subtle"
            label={m.items.title}
          >
            {(i) => <ItemRow item={i} actions={itemActions(i)} owners={owners} />}
          </PresenceList>
        ) : r.gaps.length ? (
          <p className="text-data text-fg-secondary">{m.items.noneFound}</p>
        ) : (
          <EmptyState compact icon={BrushCleaning} title={m.verdict.none}>
            {m.items.emptyBody}
          </EmptyState>
        )}
      </Panel>

      <Panel
        icon={Boxes}
        title={system.owned.title}
        description={m.owned.description}
        style={staggerStyle(3)}
        className={STAGGER_IN}
      >
        <PropertyGrid>
          <PropertyRow label={system.owned.workers}>
            {r.resources.workers.length ? (
              r.resources.workers.map((w) => (
                <span key={w.pid} className="machine">
                  {m.owned.worker(w.pid, <span className="font-sans">{name(w.instance_id)}</span>, w.generation)}
                  {w.process_started_at ? (
                    <span className="ml-1.5 font-sans text-fg-tertiary">
                      {system.startedAt(absoluteTime(w.process_started_at))}
                    </span>
                  ) : null}
                  {w.phase ? <span className="ml-1.5 font-sans text-fg-tertiary">{PHASE[w.phase].label}</span> : null}
                </span>
              ))
            ) : (
              <span className="text-fg-tertiary">{system.owned.noWorkers}</span>
            )}
          </PropertyRow>
          <PropertyRow label={system.owned.managedApps}>
            <AppResourceList apps={r.resources.apps} name={name} />
          </PropertyRow>
          <PropertyRow
            label={system.owned.gateways}
            hint={
              r.resources.unanswered.length ? (
                <span className="text-warning">{system.owned.unanswered(r.resources.unanswered.map(name))}</span>
              ) : undefined
            }
          >
            {r.resources.listeners.length ? (
              r.resources.listeners.map((l) => (
                <span key={l.gateway_id} className="machine">
                  127.0.0.1:{l.port}
                  <span className="ml-1.5 font-sans text-fg-tertiary">
                    {m.owned.listener(name(l.instance_id), l.state === "serving")}
                  </span>
                </span>
              ))
            ) : (
              <span className="text-fg-tertiary">{system.owned.noGateways}</span>
            )}
          </PropertyRow>
          <PropertyRow label={system.owned.keyLocks} mono>
            {m.owned.keyLocks(r.resources.key_locks.length, r.resources.key_locks.filter((l) => l.used_by).length)}
          </PropertyRow>
          <PropertyRow label={system.owned.connectors} mono>
            {m.owned.connectors(
              r.resources.connector_sockets.length,
              r.resources.connector_sockets.filter((s) => s.live).length,
            )}
          </PropertyRow>
          {r.resources.sandboxes.length ? (
            <PropertyRow label={system.owned.sandboxes}>
              {r.resources.sandboxes.map((s) => (
                <span key={s.file} className="machine">
                  holder pid {s.holder_pid} · <span className="font-sans">{name(s.instance_id)}</span>
                  <span className="ml-1.5 font-sans text-fg-tertiary">epoch {s.epoch}</span>
                </span>
              ))}
            </PropertyRow>
          ) : null}
        </PropertyGrid>
      </Panel>

      <ConfirmDialog
        open={Boolean(confirming?.open)}
        onOpenChange={(o) => {
          setConfirming((c) => (c ? { ...c, open: o } : c));
        }}
        title={
          confirmAll
            ? m.confirm.all(confirming?.items.length ?? 0)
            : m.confirm.one(localized(confirming?.items[0]?.title ?? ""))
        }
        confirmLabel={confirmAll ? m.actions.cleanCount(confirming?.items.length ?? 0) : m.actions.clean}
        pending={reconcile.isPending}
        onConfirm={() => {
          if (confirming && !reconcile.isPending) clean(confirming.items, confirming.all);
        }}
        // The row that opened a one-item clean is gone: focus goes to the page title, not to the page.
        onCloseAutoFocus={(e) => {
          if (!cleanedRow) return;
          e.preventDefault();
          document.getElementById("page-title")?.focus({ preventScroll: true });
        }}
      >
        <p>{m.confirm.scope}</p>
        <ul className="max-h-60 space-y-1.5 overflow-y-auto rounded-md border border-line bg-sunken px-3 py-2 text-data">
          {(confirming?.items ?? []).map((i) => (
            <li key={i.id} className="grid grid-cols-1">
              <span>
                <span className="text-fg">{localized(i.title)}</span>
                <span className="text-fg-tertiary">
                  {m.item.then(i.action ? localized(i.action) : m.actions.clean)}
                </span>
              </span>
              {/* The exact thing it touches. */}
              {i.path ? <span className="machine text-caption text-fg-tertiary">{i.path}</span> : null}
            </li>
          ))}
        </ul>
        <p className="text-fg-tertiary">{m.confirm.effect}</p>
      </ConfirmDialog>
    </div>
  );
}
