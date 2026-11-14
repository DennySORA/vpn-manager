// 受管 App (/apps): the list page recipe of docs/frontend-design.md §8.1 — page header with its one primary action; a
// tool strip (search, state filter, sort, count, then the list's batch action); rows that come and go with presence and
// slide on filter, sort, add and remove (Motion layout), one sliding selection marker; each row has its quick action
// (停止／啟動) and the same ⋯ menu as the inspector, all from one action model (actions.ts).
import { AppWindow, Plus, RotateCw } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useApps, useGateways, useInstances } from "@/api/queries";
import type { AppView, GatewaySpec, InstanceView } from "@/api/types";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput, SplitView } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChangeValue } from "@/components/ui/change-value";
import { ConfirmDialog } from "@/components/ui/dialog";
import { RowActions } from "@/components/ui/entity-actions";
import { COUNT_PILL, FIT_WIDTH } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { SortMenu } from "@/components/ui/sort-menu";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { ToolButton, ToolSeparator, ToolStrip } from "@/components/ui/tool-strip";
import { instanceLook } from "@/features/instances/model";
import { intlLocale, localized } from "@/i18n";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { AppActionHost, useAppActions } from "./action-host";
import { restartApps, wasDeletedHere } from "./actions";
import { AppDialog } from "./app-dialog";
import { AppInspector } from "./app-inspector";
import { m } from "./messages";
import {
  APP_FILTERS,
  APP_SORTS,
  type AppFilter,
  appLook,
  appNeedsAttention,
  type AppSort,
  basename,
  exposedListeners,
  ISOLATION,
  matchesApp,
  matchesAppFilter,
  pendingRestartApps,
  sortApps,
} from "./model";

function AppRow({
  v,
  owner,
  gateway,
  selected,
  index,
  exiting,
  onSelect,
}: {
  v: AppView;
  owner: InstanceView | undefined;
  gateway: GatewaySpec | undefined;
  selected: boolean;
  index: number;
  exiting: boolean;
  onSelect: () => void;
}) {
  const actions = useAppActions(v);
  const look = appLook(v);
  const mode = ISOLATION[v.spec.isolation];
  const attention = appNeedsAttention(v);
  const s = v.status;
  const exposed = exposedListeners(v);
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting} running={Boolean(look.busy)}>
      <Td className="max-w-0">
        <Link
          to={`/apps/${v.spec.id}`}
          data-row-link={v.spec.id}
          aria-current={selected ? "true" : undefined}
          title={v.spec.name}
          className="block text-body font-medium text-fg [overflow-wrap:anywhere] lg:truncate"
        >
          {v.spec.name}
        </Link>
        <div
          className="flex min-w-0 items-center gap-1.5 text-caption text-fg-tertiary"
          title={attention ?? v.spec.executable}
        >
          {attention ? (
            <span className="truncate text-warning">{attention}</span>
          ) : (
            <>
              <Tag
                tone={v.spec.isolation === "proxy_env" ? "warning" : "neutral"}
                icon={mode.icon}
                className="shrink-0"
              >
                {mode.short}
              </Tag>
              {/* On a phone-wide screen the mode is what fits; the executable is in the inspector. */}
              <span className="truncate font-mono max-sm:hidden">{basename(v.spec.executable)}</span>
            </>
          )}
        </div>
      </Td>
      <Td className="w-[148px]">
        <StatusPill look={look} title={s?.last_error ? localized(s.last_error.message) : undefined} className="h-5.5" />
      </Td>
      <Td className="w-[168px] max-w-[168px] max-sm:hidden">
        {owner ? (
          <span className="flex min-w-0 flex-col">
            <span title={owner.spec.name} className="truncate text-data text-fg">
              {owner.spec.name}
            </span>
            <span className="truncate text-micro text-fg-tertiary">
              {instanceLook(owner).label}
              {v.spec.isolation === "strict_netns"
                ? ` · ${ISOLATION.strict_netns.short}`
                : gateway
                  ? ` · :${gateway.port}`
                  : ""}
            </span>
          </span>
        ) : (
          <span className="text-caption text-fg-tertiary">—</span>
        )}
      </Td>
      <Td className="w-[96px] max-md:hidden">
        <ChangeValue value={s?.process_count ?? null} className="machine text-caption text-fg-secondary">
          {s?.process_count ?? "—"}
        </ChangeValue>
        <span className="sr-only">{m.page.processesSuffix(s?.process_count ?? null)}</span>
        {exposed ? <span className="block text-micro text-danger">{m.page.exposed(exposed)}</span> : null}
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={v.spec.name} />
      </Td>
    </Tr>
  );
}

/** The list's batch action: restart the running Apps whose saved settings wait for a restart. */
function RestartPending({ all }: { all: AppView[] }) {
  const blocked = useMutationBlocked();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const targets = pendingRestartApps(all);
  const n = targets.length;
  const reason = blocked ?? (n ? null : m.page.restartPending.none);
  return (
    <>
      <ToolButton
        label={m.page.restartPending.label}
        aria-label={n ? m.page.restartPending.labelCount(n) : m.page.restartPending.label}
        icon={<RotateCw aria-hidden />}
        text={
          <span className="inline-flex items-center gap-1.5">
            <span className="max-xl:sr-only">{m.page.restartPending.short}</span>
            <ChangeValue value={n} className={COUNT_PILL} />
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
        title={m.page.restartPending.title(n)}
        confirmLabel={m.page.restartPending.confirm(n)}
        pending={pending}
        onConfirm={() => {
          setPending(true);
          // Who to restart is decided again now, from the latest facts.
          void restartApps(pendingRestartApps(all)).finally(() => {
            setPending(false);
            setOpen(false);
          });
        }}
      >
        <p>{m.page.restartPending.changed(targets.map((v) => v.spec.name))}</p>
        <p>{m.page.restartPending.effect}</p>
      </ConfirmDialog>
    </>
  );
}

export function AppsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const apps = useApps();
  const instances = useInstances();
  const gateways = useGateways();
  const [q, setQ] = useQueryParam("q");
  const [state, setState] = useQueryParam("state");
  const [sortParam, setSort] = useQueryParam("sort");
  const [newOpen, setNewOpen] = useQueryParam("new");
  // The inspector's tab: selecting another object keeps it (where that object has the tab).
  const [tabParam] = useQueryParam("tab");
  // Several names change in one URL update (two setters in one event would only keep the last; lib/url.ts).
  const setQueryParams = useSetQueryParams();
  const clearFilters = () => {
    setQueryParams({ q: null, state: null });
  };
  const filter = (APP_FILTERS.some((f) => f.value === state) ? state : "all") as AppFilter;
  const sort = (APP_SORTS.some((s) => s.value === sortParam) ? sortParam : "name") as AppSort;
  const owners = useMemo(() => new Map((instances.data ?? []).map((v) => [v.spec.id, v])), [instances.data]);
  const gatewayOf = useMemo(() => new Map((gateways.data ?? []).map((g) => [g.id, g])), [gateways.data]);
  const createReason = instances.isPending
    ? m.page.readingConnections
    : !instances.data?.length
      ? m.page.needsConnection
      : null;

  const all = useMemo(() => apps.data ?? [], [apps.data]);
  const rows = useMemo(
    () =>
      sortApps(
        all.filter(
          (v) => matchesAppFilter(v, filter) && matchesApp(v, q ?? "", owners.get(v.spec.instance_id)?.spec.name),
        ),
        sort,
        (v) => owners.get(v.spec.instance_id)?.spec.name ?? "",
      ),
    [all, filter, q, sort, owners],
  );
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
    void navigate(`/apps/${next}${search}`);
  };
  const onKeyDown = useRowNavigation(
    rows.map((v) => v.spec.id),
    id,
    select,
  );
  const createButton = (
    <ActionButton
      variant="primary"
      icon={Plus}
      disabledReason={createReason}
      onClick={() => {
        setNewOpen("1", { push: true });
      }}
    >
      {m.page.add}
    </ActionButton>
  );

  let list: ReactNode;
  if (apps.isPending) list = <LoadingRows label={m.page.loading} />;
  else if (apps.isError && !apps.data)
    list = <ErrorState error={apps.error} onRetry={() => void apps.refetch()} retrying={apps.isFetching} />;
  else if (!all.length)
    list = (
      <EmptyState brand icon={AppWindow} title={m.page.empty} actions={createButton}>
        {instances.isSuccess && !instances.data.length ? m.page.emptyNeedsConnection : m.page.emptyHint}
      </EmptyState>
    );
  else
    list = (
      <>
        <ToolStrip label={m.page.listLabel} className="px-3 py-1.5">
          <SearchInput
            value={q ?? ""}
            onChange={(v) => {
              setQ(v || null);
            }}
            label={m.page.search}
            placeholder={m.page.searchHint}
          />
          <Segmented
            label={ui.common.filterByState}
            value={filter}
            onChange={(v) => {
              setState(v === "all" ? null : v);
            }}
            options={APP_FILTERS.map((f) => ({ ...f, count: all.filter((v) => matchesAppFilter(v, f.value)).length }))}
            className={FIT_WIDTH}
          />
          <SortMenu
            value={sort}
            options={APP_SORTS}
            onChange={(v) => {
              setSort(v === "name" ? null : v);
            }}
          />
          {/* The count and the list's batch action stay together on the right, also when the strip wraps. */}
          <div className="ml-auto flex items-center gap-2">
            <Count shown={rows.length} total={all.length} unit={m.page.unit(all.length)} />
            <ToolSeparator />
            <RestartPending all={all} />
          </div>
        </ToolStrip>
        {apps.isError ? (
          // Stale: the last list stays, marked, with a retry (the lifecycle controls say why they wait).
          <div className="shrink-0 border-b border-line-subtle px-3 py-2">
            <ErrorCallout
              error={apps.error}
              title={m.page.stale(new Date(apps.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void apps.refetch()}
              retrying={apps.isFetching}
            />
          </div>
        ) : null}
        {rows.length ? (
          <TableFrame
            label={shell.nav.apps.label}
            onKeyDown={onKeyDown}
            selectionMarker
            tableClassName="max-sm:min-w-0"
          >
            <thead>
              <tr>
                <Th>{m.app}</Th>
                <Th>{ui.common.status}</Th>
                <Th className="max-sm:hidden">{m.connection}</Th>
                <Th className="max-md:hidden">{m.processes}</Th>
                <Th align="right">
                  <span className="sr-only">{ui.common.actions}</span>
                </Th>
              </tr>
            </thead>
            <TBody items={rows} keyOf={(v) => v.spec.id}>
              {(v, row) => (
                <AppRow
                  v={v}
                  owner={owners.get(v.spec.instance_id)}
                  gateway={v.spec.gateway_id ? gatewayOf.get(v.spec.gateway_id) : undefined}
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
            icon={AppWindow}
            title={m.page.noMatch}
            actions={
              <Button size="sm" onClick={clearFilters}>
                {ui.common.clearFilters}
              </Button>
            }
          />
        )}
      </>
    );

  return (
    <Page>
      <AppActionHost views={all}>
        <PageHeader
          title={shell.nav.apps.label}
          description={m.page.description}
          help={m.page.help(m.page.helpSummary)}
          helpText={m.page.helpSummary}
          actions={createButton}
        />
        <SplitView
          list={list}
          inspector={
            selected ? (
              <AppInspector
                key={selected.spec.id}
                app={selected}
                owner={owners.get(selected.spec.instance_id)}
                gateway={selected.spec.gateway_id ? gatewayOf.get(selected.spec.gateway_id) : undefined}
              />
            ) : null
          }
          inspectorTitle={selected ? m.page.detailsOf(selected.spec.name) : m.page.details}
          onCloseInspector={() => void navigate(`/apps${search}`)}
          placeholder={
            id && apps.isSuccess && !wasDeletedHere(id) ? (
              <EmptyState compact icon={AppWindow} title={m.page.notFound}>
                {ui.common.mayHaveBeenDeleted}
              </EmptyState>
            ) : (
              <EmptyState compact icon={AppWindow} title={m.page.select}>
                {m.page.selectHint}
              </EmptyState>
            )
          }
        />
        <AppDialog
          open={newOpen === "1"}
          onOpenChange={(o) => {
            setNewOpen(o ? "1" : null);
          }}
          // One navigation closes the dialog (no `new`) and selects the new App.
          onSaved={(v) => {
            void navigate(`/apps/${v.spec.id}${search}`, { replace: true });
          }}
        />
      </AppActionHost>
    </Page>
  );
}
