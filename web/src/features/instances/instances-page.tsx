// 連線 (/instances): the template list page (docs/frontend-design.md §8.1). Page header with its one primary action;
// a tool strip (search, state filter, sort, count, then the list's batch action); a table whose rows come and go with
// presence and slide on filter, sort, add and remove (Motion layout), with one sliding selection marker; each row has one quick
// action and the same ⋯ menu as the inspector, all from one action model (actions.ts).
import { Network, Plus, RotateCw } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useInstances, useLiveRates } from "@/api/queries";
import type { InstanceView } from "@/api/types";
import { latest, Sparkline } from "@/components/charts/rate-chart";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput, SplitView } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { StatusPill } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/dialog";
import { RowActions } from "@/components/ui/entity-actions";
import { COUNT_PILL, FIT_WIDTH } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { SortMenu } from "@/components/ui/sort-menu";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { ToolButton, ToolSeparator, ToolStrip } from "@/components/ui/tool-strip";
import { GATEWAY_STATE } from "@/features/gateways/model";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { formatBps } from "@/lib/format";
import { ENFORCEMENT } from "@/lib/status";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { InstanceActionHost, useInstanceActions } from "./action-host";
import { restartPending } from "./actions";
import { InstanceDialog } from "./instance-dialog";
import { InstanceInspector } from "./instance-inspector";
import { m } from "./messages";
import {
  INSTANCE_SORTS,
  type InstanceSort,
  instanceLook,
  isRunning,
  locationText,
  matchesFilter,
  matchesQuery,
  needsAttention,
  pendingRestart,
  sortInstances,
  type StateFilter,
} from "./model";

function RateCell({ id, running }: { id: string; running: boolean }) {
  const live = useLiveRates(running ? id : undefined);
  const now = useServerNow();
  const cur = latest(live.data, now);
  if (!running) return <span className="text-caption text-fg-disabled">—</span>;
  return (
    <div className="flex items-center justify-end gap-2">
      <Sparkline samples={live.data} width={64} className="hidden xl:block" />
      <div className="machine w-[84px] text-right text-caption leading-4">
        <div className="text-fg">↓ {formatBps(cur?.payload_rx_bps)}</div>
        <div className="text-fg-tertiary">↑ {formatBps(cur?.payload_tx_bps)}</div>
      </div>
    </div>
  );
}

function InstanceRow({
  v,
  attention,
  selected,
  index,
  exiting,
  onSelect,
}: {
  v: InstanceView;
  /** What to look at (a problem, or configuration a restart would apply). */
  attention: string | null;
  selected: boolean;
  index: number;
  exiting: boolean;
  onSelect: () => void;
}) {
  const actions = useInstanceActions(v);
  const look = instanceLook(v);
  const enforcement = v.status ? ENFORCEMENT[v.status.enforcement] : null;
  const where = locationText(v);
  const endpoint = v.status?.tunnel?.endpoint ?? v.profile?.endpoint;
  const EnfIcon = enforcement?.icon;
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting} running={Boolean(look.busy)}>
      <Td className="max-w-0">
        <Link
          to={`/instances/${v.spec.id}`}
          data-row-link={v.spec.id}
          aria-current={selected ? "true" : undefined}
          title={v.spec.name}
          className="block text-body font-medium text-fg [overflow-wrap:anywhere] lg:truncate"
        >
          {v.spec.name}
        </Link>
        <div
          className="truncate text-caption text-fg-tertiary"
          title={attention ?? ([where, endpoint].filter(Boolean).join(" · ") || undefined)}
        >
          {attention ? (
            <span className="text-warning">{attention}</span>
          ) : (
            <>
              {where ? `${where} · ` : null}
              <span className="font-mono">{endpoint ?? "—"}</span>
            </>
          )}
        </div>
      </Td>
      <Td className="w-[136px]">
        <StatusPill look={look} className="h-5.5" />
        <div className="mt-0.5 flex items-center gap-1 text-micro text-fg-tertiary">
          {EnfIcon ? <EnfIcon aria-hidden className="size-3" strokeWidth={2} /> : null}
          {enforcement ? enforcement.label : m.list.trafficUnknown}
        </div>
      </Td>
      <Td className="w-[152px] max-sm:hidden">
        <div className="flex flex-wrap gap-1">
          {v.gateways.length ? (
            v.gateways.map((g) => {
              const rt = v.status?.gateways.find((r) => r.gateway_id === g.id);
              const failed = rt?.state === "failed";
              return (
                <span
                  key={g.id}
                  title={rt ? m.list.gatewayState(g.name, GATEWAY_STATE[rt.state].label) : g.name}
                  className={cn(
                    "machine rounded-sm border px-1.5 text-caption leading-5",
                    failed ? "border-danger/40 text-danger" : "border-line text-fg-secondary",
                  )}
                >
                  :{g.port}
                </span>
              );
            })
          ) : (
            <span className="text-caption text-fg-tertiary">{ui.common.none}</span>
          )}
        </div>
      </Td>
      <Td align="right" className="hidden w-[112px] md:table-cell xl:w-[180px]">
        <RateCell id={v.spec.id} running={isRunning(v)} />
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={v.spec.name} />
      </Td>
    </Tr>
  );
}

const FILTERS: { value: StateFilter; label: string; title: string }[] = [
  { value: "all", label: ui.common.all, title: m.filter.allTitle },
  { value: "running", label: ui.common.running, title: m.filter.runningTitle },
  { value: "stopped", label: ui.common.stopped, title: m.filter.stoppedTitle },
  { value: "attention", label: m.filter.attention, title: m.filter.attentionTitle },
];

/** The list's batch action: restart the running connections whose saved configuration waits for a restart. */
function RestartPending({ all }: { all: InstanceView[] }) {
  const blocked = useMutationBlocked();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const targets = pendingRestart(all);
  const n = targets.length;
  const reason = blocked ?? (n ? null : m.restartPending.none);
  return (
    <>
      <ToolButton
        label={m.restartPending.label}
        aria-label={n ? m.restartPending.labelCount(n) : m.restartPending.label}
        icon={<RotateCw aria-hidden />}
        text={
          <span className="inline-flex items-center gap-1.5">
            <span className="max-xl:sr-only">{m.restartPending.text}</span>
            <span className={COUNT_PILL}>{n}</span>
          </span>
        }
        disabledReason={reason}
        pending={pending}
        onClick={() => {
          setOpen(true);
        }}
      />
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        tone="primary"
        title={m.restartPending.confirmTitle(n)}
        confirmLabel={m.restartPending.confirm(n)}
        pending={pending}
        onConfirm={() => {
          setPending(true);
          // Who to restart is decided again now, from the latest facts.
          void restartPending(pendingRestart(all)).finally(() => {
            setPending(false);
            setOpen(false);
          });
        }}
      >
        <p>{m.restartPending.changed(targets.map((v) => v.spec.name))}</p>
        <p>{m.restartPending.effect}</p>
      </ConfirmDialog>
    </>
  );
}

export function InstancesPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const instances = useInstances();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useQueryParam("q");
  const [state, setState] = useQueryParam("state");
  const [sortParam, setSort] = useQueryParam("sort");
  const setQueryParams = useSetQueryParams();
  const [newOpen, setNewOpen] = useQueryParam("new");
  // The inspector's tab: selecting another object keeps it (where that object has the tab).
  const [tabParam] = useQueryParam("tab");
  const filter = (FILTERS.some((f) => f.value === state) ? state : "all") as StateFilter;
  const sort = (INSTANCE_SORTS.some((s) => s.value === sortParam) ? sortParam : "created") as InstanceSort;

  const all = useMemo(() => instances.data ?? [], [instances.data]);
  const rows = useMemo(
    () =>
      sortInstances(
        all.filter((v) => matchesFilter(v, filter, needsAttention) && matchesQuery(v, q ?? "")),
        sort,
        needsAttention,
      ),
    [all, filter, q, sort],
  );
  // `?new=1&profile=<id>`: a new connection from that WireGuard profile (offered after an import).
  const closeNew = () => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("new");
        next.delete("profile");
        return next;
      },
      { replace: true },
    );
  };
  const selected = all.find((v) => v.spec.id === id);
  useCrumb(selected?.spec.name);

  const search = (() => {
    const s = new URLSearchParams();
    if (q) s.set("q", q);
    if (state) s.set("state", state);
    if (sortParam) s.set("sort", sortParam);
    if (tabParam) s.set("tab", tabParam);
    const t = s.toString();
    return t ? `?${t}` : "";
  })();
  const select = (next: string) => {
    void navigate(`/instances/${next}${search}`);
  };
  const onKeyDown = useRowNavigation(
    rows.map((v) => v.spec.id),
    id,
    select,
  );

  let list: ReactNode;
  if (instances.isPending) list = <LoadingRows rows={4} label={m.list.loading} />;
  else if (instances.isError && !instances.data)
    list = (
      <ErrorState error={instances.error} onRetry={() => void instances.refetch()} retrying={instances.isFetching} />
    );
  else if (all.length === 0)
    list = (
      <EmptyState
        brand
        icon={Network}
        title={m.list.emptyTitle}
        actions={
          <Button
            variant="primary"
            icon={Plus}
            onClick={() => {
              setNewOpen("1", { push: true });
            }}
          >
            {m.list.add}
          </Button>
        }
      >
        {m.list.emptyBody}
      </EmptyState>
    );
  else
    list = (
      <>
        <ToolStrip label={m.list.toolbar} className="px-3 py-1.5">
          <SearchInput
            value={q ?? ""}
            onChange={(v) => {
              setQ(v || null);
            }}
            label={m.list.search}
            placeholder={m.list.searchPlaceholder}
          />
          <Segmented
            label={ui.common.filterByState}
            value={filter}
            onChange={(v) => {
              setState(v === "all" ? null : v);
            }}
            options={FILTERS.map((f) => ({
              ...f,
              count: all.filter((v) => matchesFilter(v, f.value, needsAttention)).length,
            }))}
            className={FIT_WIDTH}
          />
          <SortMenu
            value={sort}
            options={INSTANCE_SORTS}
            onChange={(v) => {
              setSort(v === "created" ? null : v);
            }}
          />
          {/* The count and the list's batch action stay together on the right, also when the strip wraps. */}
          <div className="ml-auto flex items-center gap-2">
            <Count shown={rows.length} total={all.length} unit={m.list.unit(all.length)} />
            <ToolSeparator />
            <RestartPending all={all} />
          </div>
        </ToolStrip>
        {instances.isError ? (
          // Stale: the last list stays, marked, with a retry (the lifecycle controls say why they wait).
          <div className="shrink-0 border-b border-line-subtle px-3 py-2">
            <ErrorCallout
              error={instances.error}
              title={m.list.stale(new Date(instances.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void instances.refetch()}
              retrying={instances.isFetching}
            />
          </div>
        ) : null}
        {rows.length ? (
          <TableFrame
            label={shell.nav.instances.label}
            onKeyDown={onKeyDown}
            selectionMarker
            tableClassName="max-sm:min-w-0"
          >
            <thead>
              <tr>
                <Th>{ui.common.name}</Th>
                <Th>{ui.common.status}</Th>
                <Th className="max-sm:hidden">{shell.nav.gateways.label}</Th>
                <Th align="right" className="hidden md:table-cell">
                  {m.list.liveRate}
                </Th>
                <Th align="right">
                  <span className="sr-only">{ui.common.actions}</span>
                </Th>
              </tr>
            </thead>
            <TBody items={rows} keyOf={(v) => v.spec.id}>
              {(v, row) => (
                <InstanceRow
                  v={v}
                  attention={needsAttention(v)}
                  index={row.index}
                  exiting={row.exiting}
                  selected={v.spec.id === id}
                  onSelect={() => {
                    select(v.spec.id);
                  }}
                />
              )}
            </TBody>
          </TableFrame>
        ) : (
          <EmptyState
            compact
            icon={Network}
            title={m.list.noMatch}
            actions={
              <Button
                size="sm"
                onClick={() => {
                  setQueryParams({ q: null, state: null });
                }}
              >
                {ui.common.clearFilters}
              </Button>
            }
          />
        )}
      </>
    );

  return (
    <Page>
      <InstanceActionHost views={all}>
        <PageHeader
          title={shell.nav.instances.label}
          description={m.page.description}
          help={m.page.help}
          helpText={m.page.helpText}
          actions={
            <Button
              variant="primary"
              icon={Plus}
              onClick={() => {
                setNewOpen("1", { push: true });
              }}
            >
              {m.list.add}
            </Button>
          }
        />
        <SplitView
          list={list}
          inspector={selected ? <InstanceInspector key={selected.spec.id} view={selected} /> : null}
          inspectorTitle={selected ? m.page.detailsOf(selected.spec.name) : m.page.details}
          onCloseInspector={() => void navigate(`/instances${search}`)}
          placeholder={
            id && instances.isSuccess ? (
              <EmptyState compact icon={Network} title={m.page.notFound}>
                {ui.common.mayHaveBeenDeleted}
              </EmptyState>
            ) : (
              <EmptyState compact icon={Network} title={m.page.select}>
                {m.page.selectHint}
              </EmptyState>
            )
          }
        />
        <InstanceDialog
          open={newOpen === "1"}
          onOpenChange={(o) => {
            if (o) setNewOpen("1");
            else closeNew();
          }}
          profileId={params.get("profile") ?? undefined}
        />
      </InstanceActionHost>
    </Page>
  );
}
