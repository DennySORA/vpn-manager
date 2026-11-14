// 代理埠 (/gateways): the list page recipe of docs/frontend-design.md §8.1 — page header with its one primary action;
// a tool strip (search, state filter, sort, count); rows that come and go with presence and slide on filter, sort, add
// and remove, one sliding selection marker; each row has its quick action (停用／啟用) and the same ⋯ menu as the
// inspector, all from one action model (actions.ts).
import { EthernetPort, Plus } from "lucide-react";
import { type ReactNode, useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useGateways, useInstances, useLiveRates } from "@/api/queries";
import type { GatewaySpec, InstanceView } from "@/api/types";
import { latest } from "@/components/charts/rate-chart";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput, SplitView } from "@/components/shell/page";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RowActions } from "@/components/ui/entity-actions";
import { FIT_WIDTH } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { SortMenu } from "@/components/ui/sort-menu";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { ToolStrip } from "@/components/ui/tool-strip";
import { instanceLook } from "@/features/instances/model";
import { intlLocale } from "@/i18n";
import { formatBps } from "@/lib/format";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { GatewayActionHost, useGatewayActions } from "./action-host";
import { proxyAddress } from "./actions";
import { GatewayDialog, KIND_LABEL } from "./gateway-dialog";
import { GatewayInspector } from "./gateway-inspector";
import { m } from "./messages";
import {
  GATEWAY_FILTERS,
  GATEWAY_SORTS,
  type GatewayFilter,
  type GatewaySort,
  gatewayLook,
  gatewayRuntime,
  matchesGatewayFilter,
  sortGateways,
} from "./model";

function RowRate({ owner, id }: { owner: InstanceView | undefined; id: string }) {
  const live = useLiveRates(owner?.status?.intent.desired === "running" ? owner.spec.id : undefined);
  const now = useServerNow();
  const r = latest(live.data, now)?.gateways.find((x) => x.gateway_id === id);
  if (!r) return <span className="text-caption text-fg-disabled">—</span>;
  return (
    <div className="machine text-caption leading-4">
      <div className="text-fg">↓ {formatBps(r.rx_bps)}</div>
      <div className="text-fg-tertiary">↑ {formatBps(r.tx_bps)}</div>
    </div>
  );
}

function GatewayRow({
  g,
  owner,
  selected,
  index,
  exiting,
  onSelect,
}: {
  g: GatewaySpec;
  owner: InstanceView | undefined;
  selected: boolean;
  index: number;
  exiting: boolean;
  onSelect: () => void;
}) {
  const actions = useGatewayActions(g, owner);
  const rt = gatewayRuntime(g, owner);
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting}>
      <Td className="w-[184px] max-w-[184px] max-sm:w-auto max-sm:max-w-0">
        <Link
          to={`/gateways/${g.id}`}
          data-row-link={g.id}
          aria-current={selected ? "true" : undefined}
          className="machine block truncate text-body font-medium whitespace-nowrap text-fg"
        >
          {proxyAddress(g)}
        </Link>
        <div
          title={`${KIND_LABEL[g.kind]} · ${g.name}`}
          className="flex min-w-0 items-center gap-1.5 truncate text-caption text-fg-tertiary"
        >
          <span className="font-medium text-fg-secondary">{KIND_LABEL[g.kind]}</span>·{" "}
          <span className="truncate">{g.name}</span>
          {!g.enabled ? <span className="shrink-0 text-warning">· {ui.common.disabled}</span> : null}
        </div>
      </Td>
      <Td className="max-w-0 max-sm:hidden">
        {owner ? (
          <span className="flex min-w-0 flex-col">
            <span title={owner.spec.name} className="text-data text-fg [overflow-wrap:anywhere] lg:truncate">
              {owner.spec.name}
            </span>
            <span className="text-micro text-fg-tertiary">{instanceLook(owner).label}</span>
          </span>
        ) : (
          "—"
        )}
      </Td>
      <Td className="w-[112px]">
        <StatusPill look={gatewayLook(g, rt)} />
      </Td>
      <Td className="w-[88px] max-md:hidden">
        <span className="machine text-caption text-fg-secondary">
          {rt ? `${rt.active_tcp} / ${rt.active_udp}` : "—"}
        </span>
        <span className="sr-only">{m.page.tcpUdp}</span>
      </Td>
      <Td align="right" className="hidden w-[112px] lg:table-cell">
        <RowRate owner={owner} id={g.id} />
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={g.name} />
      </Td>
    </Tr>
  );
}

export function GatewaysPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const gateways = useGateways();
  const instances = useInstances();
  const [q, setQ] = useQueryParam("q");
  const [state, setState] = useQueryParam("state");
  const [sortParam, setSort] = useQueryParam("sort");
  const setQueryParams = useSetQueryParams();
  const [newOpen, setNewOpen] = useQueryParam("new");
  const filter = (GATEWAY_FILTERS.some((f) => f.value === state) ? state : "all") as GatewayFilter;
  const sort = (GATEWAY_SORTS.some((s) => s.value === sortParam) ? sortParam : "port") as GatewaySort;
  const owners = useMemo(() => new Map((instances.data ?? []).map((v) => [v.spec.id, v])), [instances.data]);
  const noInstances = !instances.data?.length;
  const createReason = instances.isPending ? m.page.loadingInstances : noInstances ? m.page.needInstance : null;

  const all = useMemo(() => gateways.data ?? [], [gateways.data]);
  const rows = useMemo(() => {
    const t = (q ?? "").trim().toLowerCase();
    const shown = all.filter(
      (g) =>
        matchesGatewayFilter(g, gatewayRuntime(g, owners.get(g.instance_id)), filter) &&
        (!t ||
          `${g.name} ${g.port} ${KIND_LABEL[g.kind]} ${owners.get(g.instance_id)?.spec.name ?? ""}`
            .toLowerCase()
            .includes(t)),
    );
    return sortGateways(shown, sort, (g) => owners.get(g.instance_id)?.spec.name ?? "");
  }, [all, q, filter, sort, owners]);
  const selected = all.find((g) => g.id === id);
  useCrumb(selected?.name);
  const search = (() => {
    const s = new URLSearchParams();
    if (q) s.set("q", q);
    if (state) s.set("state", state);
    if (sortParam) s.set("sort", sortParam);
    const t = s.toString();
    return t ? `?${t}` : "";
  })();
  const select = (next: string) => {
    void navigate(`/gateways/${next}${search}`);
  };
  const onKeyDown = useRowNavigation(
    rows.map((g) => g.id),
    id,
    select,
  );

  let list: ReactNode;
  if (gateways.isPending) list = <LoadingRows label={m.page.loading} />;
  else if (gateways.isError && !gateways.data)
    list = <ErrorState error={gateways.error} onRetry={() => void gateways.refetch()} retrying={gateways.isFetching} />;
  else if (!all.length)
    list = (
      <EmptyState
        brand
        icon={EthernetPort}
        title={m.page.emptyTitle}
        actions={
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
        }
      >
        {noInstances ? m.page.needInstanceBody : m.page.emptyBody}
      </EmptyState>
    );
  else
    list = (
      <>
        <ToolStrip label={m.page.list} className="px-3 py-1.5">
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
            options={GATEWAY_FILTERS.map((f) => ({
              ...f,
              count: all.filter((g) => matchesGatewayFilter(g, gatewayRuntime(g, owners.get(g.instance_id)), f.value))
                .length,
            }))}
            className={FIT_WIDTH}
          />
          <SortMenu
            value={sort}
            options={GATEWAY_SORTS}
            onChange={(v) => {
              setSort(v === "port" ? null : v);
            }}
          />
          <Count shown={rows.length} total={all.length} unit={m.unit(all.length)} />
        </ToolStrip>
        {gateways.isError ? (
          <div className="shrink-0 border-b border-line-subtle px-3 py-2">
            <ErrorCallout
              error={gateways.error}
              title={m.page.staleTitle(
                new Date(gateways.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }),
              )}
              onRetry={() => void gateways.refetch()}
              retrying={gateways.isFetching}
            />
          </div>
        ) : null}
        {rows.length ? (
          <TableFrame label={m.title} onKeyDown={onKeyDown} selectionMarker tableClassName="max-sm:min-w-0">
            <thead>
              <tr>
                <Th>{m.page.address}</Th>
                <Th className="max-sm:hidden">{m.owner}</Th>
                <Th>{ui.common.status}</Th>
                <Th className="max-md:hidden">{m.connectionCount}</Th>
                <Th align="right" className="hidden lg:table-cell">
                  {m.rate}
                </Th>
                <Th align="right">
                  <span className="sr-only">{ui.common.actions}</span>
                </Th>
              </tr>
            </thead>
            <TBody items={rows} keyOf={(g) => g.id}>
              {(g, row) => (
                <GatewayRow
                  g={g}
                  owner={owners.get(g.instance_id)}
                  index={row.index}
                  exiting={row.exiting}
                  selected={g.id === id}
                  onSelect={() => {
                    select(g.id);
                  }}
                />
              )}
            </TBody>
          </TableFrame>
        ) : (
          <EmptyState
            compact
            icon={EthernetPort}
            title={m.page.noMatch}
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
      <GatewayActionHost gateways={all}>
        <PageHeader
          title={m.title}
          description={m.page.description}
          help={m.page.help}
          helpText={m.page.helpText}
          actions={
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
          }
        />
        <SplitView
          list={list}
          inspector={
            selected ? (
              <GatewayInspector key={selected.id} g={selected} owner={owners.get(selected.instance_id)} />
            ) : null
          }
          inspectorTitle={selected ? m.page.detailsOf(selected.name) : m.page.details}
          onCloseInspector={() => void navigate(`/gateways${search}`)}
          placeholder={
            <EmptyState compact icon={EthernetPort} title={id && gateways.isSuccess ? m.page.notFound : m.page.select}>
              {id && gateways.isSuccess ? ui.common.mayHaveBeenDeleted : m.page.selectBody}
            </EmptyState>
          }
        />
        <GatewayDialog
          open={newOpen === "1"}
          onOpenChange={(o) => {
            setNewOpen(o ? "1" : null);
          }}
        />
      </GatewayActionHost>
    </Page>
  );
}
