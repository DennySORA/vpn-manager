// 轉發 (/forwards): the list page recipe of docs/frontend-design.md §8.1 — page header with its one primary action; a
// tool strip (search, state filter, sort, count); rows that come and go with presence and slide on filter, sort, add and
// remove, one sliding selection marker; each row has its quick action (停用／啟用) and the same ⋯ menu as the inspector,
// all from one action model (actions.ts). `?new=1` opens the new-forward dialog, `&app=` preselects the App.
import { Plus, Waypoints } from "lucide-react";
import { type ReactNode, useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useApps, useForwards, useInstances } from "@/api/queries";
import type { AppView, ForwardView, InstanceView } from "@/api/types";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput, SplitView } from "@/components/shell/page";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RowActions } from "@/components/ui/entity-actions";
import { FIT_WIDTH, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { RelativeTime } from "@/components/ui/relative-time";
import { Segmented } from "@/components/ui/segmented";
import { SortMenu } from "@/components/ui/sort-menu";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { ToolStrip } from "@/components/ui/tool-strip";
import { instanceLook } from "@/features/instances/model";
import { intlLocale, localized } from "@/i18n";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { ForwardActionHost, useForwardActions } from "./action-host";
import { wasDeletedHere } from "./actions";
import { ForwardDialog } from "./forward-dialog";
import { ForwardInspector } from "./forward-inspector";
import { m } from "./messages";
import {
  FORWARD_FILTERS,
  FORWARD_SORTS,
  type ForwardFilter,
  forwardLook,
  type ForwardSort,
  lastObserved,
  matchesForward,
  matchesForwardFilter,
  PROTOCOL_LABEL,
  reachLook,
  sortForwards,
} from "./model";

function ForwardRow({
  v,
  owner,
  app,
  selected,
  index,
  exiting,
  onSelect,
}: {
  v: ForwardView;
  owner: InstanceView | undefined;
  app: AppView | undefined;
  selected: boolean;
  index: number;
  exiting: boolean;
  onSelect: () => void;
}) {
  const actions = useForwardActions(v);
  const b = v.binding;
  const seen = lastObserved(v.status);
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting}>
      <Td className="max-w-0">
        <Link
          to={`/forwards/${b.id}`}
          data-row-link={b.id}
          aria-current={selected ? "true" : undefined}
          title={b.name}
          className="block text-body font-medium text-fg [overflow-wrap:anywhere] lg:truncate"
        >
          {b.name}
        </Link>
        <div className="flex min-w-0 items-center gap-1.5 text-caption text-fg-tertiary">
          <Tag tone="neutral" className="shrink-0">
            {PROTOCOL_LABEL[b.protocol]}
          </Tag>
          {/* On a phone-wide screen the port is what fits; the rest is in the inspector (and 已停用 in the state column). */}
          <span className="machine truncate">
            <span className="max-sm:hidden">tunnel </span>:{b.tunnel_port}
            {b.public_port && b.public_port !== b.tunnel_port ? (
              <span className="max-sm:hidden"> · {m.page.publicAt(b.public_port)}</span>
            ) : null}
          </span>
          {!b.enabled ? <span className="shrink-0 text-warning max-sm:hidden">· {ui.common.disabled}</span> : null}
        </div>
      </Td>
      <Td className="w-[160px] max-w-[160px] max-sm:hidden">
        <span className="flex min-w-0 flex-col">
          <span title={app?.spec.name} className="truncate text-data text-fg">
            {app?.spec.name ?? "—"}
          </span>
          <span className="machine text-micro text-fg-tertiary">127.0.0.1:{b.target_port}</span>
        </span>
      </Td>
      <Td className="hidden w-[150px] max-w-[150px] xl:table-cell">
        {owner ? (
          <span className="flex min-w-0 flex-col">
            <span title={owner.spec.name} className="truncate text-data text-fg">
              {owner.spec.name}
            </span>
            <span className="text-micro text-fg-tertiary">{instanceLook(owner).label}</span>
          </span>
        ) : (
          <span className="text-caption text-fg-tertiary">—</span>
        )}
      </Td>
      <Td className="w-[136px]">
        <StatusPill
          look={forwardLook(v)}
          title={v.status?.reason ? localized(v.status.reason) : undefined}
          className="h-5.5"
        />
      </Td>
      <Td className="w-[148px] max-md:hidden">
        <span className="flex flex-col items-start gap-0.5">
          <StatusPill look={reachLook(v.status)} />
          {seen ? (
            <span className="text-micro text-fg-tertiary">
              <RelativeTime at={seen} />
            </span>
          ) : null}
        </span>
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={b.name} />
      </Td>
    </Tr>
  );
}

export function ForwardsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const forwards = useForwards();
  const instances = useInstances();
  const apps = useApps();
  const [q, setQ] = useQueryParam("q");
  const [state, setState] = useQueryParam("state");
  const [sortParam, setSort] = useQueryParam("sort");
  const [newOpen, setNewOpen] = useQueryParam("new");
  const [forApp] = useQueryParam("app");
  // Several names change in one URL update (two setters in one event would only keep the last; lib/url.ts).
  const setQueryParams = useSetQueryParams();
  const removeParams = (...names: string[]) => {
    setQueryParams(Object.fromEntries(names.map((name) => [name, null])));
  };
  const filter = (FORWARD_FILTERS.some((f) => f.value === state) ? state : "all") as ForwardFilter;
  const sort = (FORWARD_SORTS.some((s) => s.value === sortParam) ? sortParam : "name") as ForwardSort;
  const owners = useMemo(() => new Map((instances.data ?? []).map((v) => [v.spec.id, v])), [instances.data]);
  const appOf = useMemo(() => new Map((apps.data ?? []).map((a) => [a.spec.id, a])), [apps.data]);
  const createReason = apps.isPending ? m.page.readingApps : !apps.data?.length ? m.page.addAppFirst : null;

  const all = useMemo(() => forwards.data ?? [], [forwards.data]);
  const rows = useMemo(
    () =>
      sortForwards(
        all.filter(
          (v) =>
            matchesForwardFilter(v, filter) &&
            matchesForward(
              v,
              q ?? "",
              owners.get(v.binding.instance_id)?.spec.name,
              appOf.get(v.binding.target_app_id)?.spec.name,
            ),
        ),
        sort,
        (v) => appOf.get(v.binding.target_app_id)?.spec.name ?? "",
      ),
    [all, filter, q, sort, owners, appOf],
  );
  const selected = all.find((v) => v.binding.id === id);
  useCrumb(selected?.binding.name);
  const search = (() => {
    const s = new URLSearchParams();
    if (q) s.set("q", q);
    if (state) s.set("state", state);
    if (sortParam) s.set("sort", sortParam);
    const t = s.toString();
    return t ? `?${t}` : "";
  })();
  const select = (next: string) => {
    void navigate(`/forwards/${next}${search}`);
  };
  const onKeyDown = useRowNavigation(
    rows.map((v) => v.binding.id),
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
      {m.add}
    </ActionButton>
  );

  let list: ReactNode;
  if (forwards.isPending) list = <LoadingRows label={m.page.loading} />;
  else if (forwards.isError && !forwards.data)
    list = <ErrorState error={forwards.error} onRetry={() => void forwards.refetch()} retrying={forwards.isFetching} />;
  else if (!all.length)
    list = (
      <EmptyState brand icon={Waypoints} title={m.page.empty} actions={createButton}>
        {apps.isSuccess && !apps.data.length
          ? m.page.emptyNoApps((text) => (
              <Link to="/apps?new=1" className={TEXT_LINK}>
                {text}
              </Link>
            ))
          : m.page.emptyBody}
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
            placeholder={m.page.searchPlaceholder}
          />
          <Segmented
            label={ui.common.filterByState}
            value={filter}
            onChange={(v) => {
              setState(v === "all" ? null : v);
            }}
            options={FORWARD_FILTERS.map((f) => ({
              ...f,
              count: all.filter((v) => matchesForwardFilter(v, f.value)).length,
            }))}
            className={FIT_WIDTH}
          />
          <SortMenu
            value={sort}
            options={FORWARD_SORTS}
            onChange={(v) => {
              setSort(v === "name" ? null : v);
            }}
          />
          <Count shown={rows.length} total={all.length} unit={m.unit(all.length)} />
        </ToolStrip>
        {forwards.isError ? (
          <div className="shrink-0 border-b border-line-subtle px-3 py-2">
            <ErrorCallout
              error={forwards.error}
              title={m.page.stale(new Date(forwards.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void forwards.refetch()}
              retrying={forwards.isFetching}
            />
          </div>
        ) : null}
        {rows.length ? (
          <TableFrame label={m.title} onKeyDown={onKeyDown} selectionMarker tableClassName="max-sm:min-w-0">
            <thead>
              <tr>
                <Th>{m.column.forward}</Th>
                <Th className="max-sm:hidden">{m.column.target}</Th>
                <Th className="hidden xl:table-cell">{m.column.connection}</Th>
                <Th>{ui.common.status}</Th>
                <Th className="max-md:hidden">{m.column.reach}</Th>
                <Th align="right">
                  <span className="sr-only">{ui.common.actions}</span>
                </Th>
              </tr>
            </thead>
            <TBody items={rows} keyOf={(v) => v.binding.id}>
              {(v, row) => (
                <ForwardRow
                  v={v}
                  owner={owners.get(v.binding.instance_id)}
                  app={appOf.get(v.binding.target_app_id)}
                  index={row.index}
                  exiting={row.exiting}
                  selected={v.binding.id === id}
                  onSelect={() => {
                    select(v.binding.id);
                  }}
                />
              )}
            </TBody>
          </TableFrame>
        ) : (
          <EmptyState
            compact
            icon={Waypoints}
            title={m.page.noMatch}
            actions={
              <Button
                size="sm"
                onClick={() => {
                  removeParams("q", "state");
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
      <ForwardActionHost forwards={all}>
        <PageHeader
          title={m.title}
          description={m.description}
          help={m.help}
          helpText={m.helpText}
          actions={createButton}
        />
        <SplitView
          list={list}
          inspector={
            selected ? (
              <ForwardInspector
                key={selected.binding.id}
                forward={selected}
                owner={owners.get(selected.binding.instance_id)}
                app={appOf.get(selected.binding.target_app_id)}
              />
            ) : null
          }
          inspectorTitle={selected ? m.page.detailsOf(selected.binding.name) : m.page.details}
          onCloseInspector={() => void navigate(`/forwards${search}`)}
          placeholder={
            id && forwards.isSuccess && !wasDeletedHere(id) ? (
              <EmptyState compact icon={Waypoints} title={m.page.notFound}>
                {ui.common.mayHaveBeenDeleted}
              </EmptyState>
            ) : (
              <EmptyState compact icon={Waypoints} title={m.page.choose}>
                {m.page.chooseHint}
              </EmptyState>
            )
          }
        />
        <ForwardDialog
          open={newOpen === "1"}
          // Closing drops the preselected App with the dialog (`?new=1&app=`), in one URL update.
          onOpenChange={(o) => {
            if (o) setNewOpen("1");
            else removeParams("new", "app");
          }}
          appId={forApp ?? undefined}
          onSaved={(v) => {
            void navigate(`/forwards/${v.binding.id}${search}`, { replace: true });
          }}
        />
      </ForwardActionHost>
    </Page>
  );
}
