// 自動封鎖紀錄 (/security/bans?instance=&q=&sort=): the list page recipe of docs/frontend-design.md §8.1 without an
// inspector (a ban has nothing more to show than its row). What auto-ban can see at all comes first (which connections
// run it and whether anything is forwarded in); then a tool strip (search, the connection filter, sort, count) and a
// table whose rows come and go with presence and slide on filter, sort, a new ban and a lifted or expired one (Motion layout).
// Each row has its quick action (解除封鎖, confirmed with its exact scope) and a ⋯ menu, from one action model.
import { ShieldBan } from "lucide-react";
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useBans, useInboundSummary, useInstances, useSecurityProfiles } from "@/api/queries";
import type { Ban, InstanceView } from "@/api/types";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/dialog";
import { RowActions } from "@/components/ui/entity-actions";
import { Select } from "@/components/ui/field";
import { STAGGER_IN, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { SortMenu } from "@/components/ui/sort-menu";
import { Callout, EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr } from "@/components/ui/table";
import { ToolStrip } from "@/components/ui/tool-strip";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime } from "@/lib/format";
import { useQueryParam } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { type BanActionId, banActions, copySource, sendUnban, useUnbanSending } from "./ban-actions";
import { m } from "./bans/messages";
import {
  BAN_SORTS,
  type BanSort,
  connectionsUsing,
  defaultPolicyUsers,
  formatDuration,
  forwardsOf,
  matchesBan,
  secondsLeft,
  sortBans,
} from "./model";

/**
 * What auto-ban can see at all: which connections run it — those without a security profile (the
 * default policy turns it on) and those whose profile enables it — and whether anything is
 * forwarded in.
 */
function Coverage({ instances }: { instances: InstanceView[] }) {
  const security = useSecurityProfiles();
  const inbound = useInboundSummary();
  const enabled = (security.data ?? []).filter((p) => p.auto_ban.enabled);
  const covered = [
    ...defaultPolicyUsers(instances),
    ...connectionsUsing(
      instances,
      enabled.map((p) => p.id),
    ),
  ];
  const forwards = forwardsOf(
    inbound.data,
    covered.map((v) => v.spec.id),
  );
  if (!security.data) return null;
  if (!covered.length) {
    return (
      <Callout tone="info" title={m.coverage.none}>
        {instances.length ? m.coverage.allOff : m.coverage.noConnections}
      </Callout>
    );
  }
  if (inbound.isError && !inbound.data) {
    return (
      <Callout tone="warning" title={m.coverage.forwardsUnknown}>
        {m.coverage.forwardsOnly}
      </Callout>
    );
  }
  if (forwards?.total === 0) {
    return (
      <Callout tone="warning" title={m.coverage.noForwards(covered.length)}>
        {m.coverage.noForwardsBody(
          <Link to="/forwards" className={TEXT_LINK}>
            {shell.nav.forwards.label}
          </Link>,
        )}
      </Callout>
    );
  }
  return forwards ? (
    <p className="text-data text-fg-tertiary">
      {m.coverage.covered(
        covered.length,
        forwards.total,
        <Link to="/forwards" className={TEXT_LINK}>
          {m.coverage.forwardsLink(forwards.total)}
        </Link>,
        forwards.enabled,
      )}
    </p>
  ) : null;
}

interface Host {
  confirmUnban: (b: Ban) => void;
}

const HostContext = createContext<Host | null>(null);

/** The actions of ban `b`, bound: what each one does and whether the lift is on its way. */
function useBanActions(b: Ban, names: ReadonlyMap<string, string>, now: number): EntityAction<BanActionId>[] {
  const host = useContext(HostContext);
  const navigate = useNavigate();
  const blocked = useMutationBlocked();
  const sending = useUnbanSending(b.id);
  const run = (id: BanActionId) => {
    switch (id) {
      case "unban":
        host?.confirmUnban(b);
        return;
      case "copy_source":
        void copySource(b);
        return;
      case "open_instance":
        void navigate(`/instances/${b.instance_id}`);
        return;
    }
  };
  return banActions(b, { blocked, now, instanceKnown: names.has(b.instance_id), sending }).map((spec) => ({
    ...spec,
    pending: spec.id === "unban" && sending === "unban",
    run: () => {
      run(spec.id);
    },
  }));
}

/**
 * Hosts the lift confirmation for the page: the row and a link (`?ban=<id>&do=unban`) open this one
 * dialog. It keeps showing the ban it was opened for while the row leaves.
 */
function BanActionHost({
  bans,
  names,
  children,
}: {
  bans: readonly Ban[];
  names: ReadonlyMap<string, string>;
  children: ReactNode;
}) {
  const [state, setState] = useState<{ ban: Ban; open: boolean } | null>(null);
  const host = useMemo<Host>(
    () => ({
      confirmUnban: (ban) => {
        setState({ ban, open: true });
      },
    }),
    [],
  );
  const ban = state?.ban;
  const sending = useUnbanSending(ban?.id ?? "");
  const [params, setParams] = useSearchParams();
  const request = params.get("do");
  const target = params.get("ban");
  useEffect(() => {
    if (request !== "unban" || !target) return;
    const found = bans.find((b) => b.id === target);
    if (!found) return;
    // Both parameters in one update (two updates in a row would each start from the same URL).
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("do");
        next.delete("ban");
        return next;
      },
      { replace: true },
    );
    host.confirmUnban(found);
  }, [request, target, bans, host, setParams]);
  return (
    <HostContext.Provider value={host}>
      {children}
      <ConfirmDialog
        open={Boolean(state?.open)}
        onOpenChange={(open) => {
          setState((s) => (s ? { ...s, open } : s));
        }}
        title={ban ? m.unbanConfirm.title(ban.source) : m.unbanConfirm.titleNone}
        confirmLabel={m.actions.unban}
        tone="primary"
        pending={sending === "unban"}
        onConfirm={() =>
          ban &&
          void sendUnban(ban, () => {
            setState((s) => (s ? { ...s, open: false } : s));
          })
        }
      >
        <p>{m.unbanConfirm.scope(ban ? (names.get(ban.instance_id) ?? m.deletedConnection) : "")}</p>
        <p>{m.unbanConfirm.rest}</p>
      </ConfirmDialog>
    </HostContext.Provider>
  );
}

function BanRow({
  b,
  names,
  index,
  exiting,
}: {
  b: Ban;
  names: ReadonlyMap<string, string>;
  index: number;
  exiting: boolean;
}) {
  // The countdown and the lift action's availability tick here, per row, not across the whole page.
  const now = useServerNow();
  const actions = useBanActions(b, names, now);
  const left = secondsLeft(b.expires_at, now);
  const name = names.get(b.instance_id);
  const lifting = actions.some((a) => a.pending);
  return (
    <Tr index={index} exiting={exiting} running={lifting}>
      <Td className="max-w-0">
        <span className="machine block text-body font-medium text-fg">{b.source}</span>
        <span className="block text-caption text-fg-tertiary sm:hidden">{localized(b.reason)}</span>
      </Td>
      <Td className="max-w-0 max-md:hidden">
        {name ? (
          <Link to={`/instances/${b.instance_id}`} className={cn(TEXT_LINK, "text-data [overflow-wrap:anywhere]")}>
            {name}
          </Link>
        ) : (
          <span className="text-fg-tertiary">{m.deletedConnection}</span>
        )}
      </Td>
      <Td className="max-sm:hidden">
        <span className="block text-fg-secondary [overflow-wrap:anywhere]">{localized(b.reason)}</span>
        <span className="block text-caption text-fg-tertiary">
          {m.row.meta(
            <span title={absoluteTime(b.created_at)}>{m.row.bannedAt(relativeTime(b.created_at, now))}</span>,
            <span className="machine">#{b.policy_revision}</span>,
          )}
        </span>
      </Td>
      <Td className="w-[112px] whitespace-nowrap">
        {/* A countdown: linear, never faded. */}
        <span
          title={m.row.until(absoluteTime(b.expires_at))}
          className={cn("machine", left > 0 ? "text-fg" : "text-fg-tertiary")}
        >
          {lifting ? m.row.lifting : left > 0 ? formatDuration(left) : m.row.expired}
        </span>
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={b.source} />
      </Td>
    </Tr>
  );
}

export function BansPage() {
  useCrumb(null);
  const [instance, setInstance] = useQueryParam("instance");
  const [q, setQ] = useQueryParam("q");
  const [sortParam, setSort] = useQueryParam("sort");
  const sort = (BAN_SORTS.some((s) => s.value === sortParam) ? sortParam : "newest") as BanSort;
  const bans = useBans(instance);
  const instances = useInstances();
  const views = useMemo(() => instances.data ?? [], [instances.data]);
  const names = useMemo(() => new Map(views.map((v) => [v.spec.id, v.spec.name])), [views]);
  const all = useMemo(() => bans.data ?? [], [bans.data]);
  const rows = useMemo(
    () =>
      sortBans(
        all.filter((b) => matchesBan(b, names.get(b.instance_id), q ?? "")),
        sort,
      ),
    [all, names, q, sort],
  );

  let table: ReactNode;
  if (bans.isPending) table = <LoadingRows rows={4} label={m.loading} />;
  else if (bans.isError && !bans.data)
    table = <ErrorState error={bans.error} onRetry={() => void bans.refetch()} retrying={bans.isFetching} />;
  else if (!all.length)
    table = (
      <EmptyState icon={ShieldBan} title={instance ? m.empty.connection : m.empty.all}>
        {m.empty.body}
      </EmptyState>
    );
  else if (!rows.length)
    table = (
      <EmptyState
        compact
        icon={ShieldBan}
        title={m.empty.noMatch}
        actions={
          <Button
            size="sm"
            onClick={() => {
              setQ(null);
            }}
          >
            {shell.clearSearch}
          </Button>
        }
      />
    );
  else
    table = (
      <TableFrame label={m.table.label} tableClassName="max-sm:min-w-0">
        <thead>
          <tr>
            <Th>{ui.common.source}</Th>
            <Th className="max-md:hidden">{m.table.connection}</Th>
            <Th className="max-sm:hidden">{m.table.reason}</Th>
            <Th>{m.table.left}</Th>
            <Th align="right">
              <span className="sr-only">{ui.common.actions}</span>
            </Th>
          </tr>
        </thead>
        <TBody items={rows} keyOf={(b) => b.id}>
          {(b, row) => <BanRow b={b} names={names} index={row.index} exiting={row.exiting} />}
        </TBody>
      </TableFrame>
    );

  return (
    <Page>
      <BanActionHost bans={all} names={names}>
        <PageHeader title={shell.nav.bans.label} description={m.description} help={m.help} helpText={m.helpText} />
        <div className="flex min-h-0 flex-1 flex-col gap-3 px-4 pb-4 md:px-6 md:pb-6">
          <div style={staggerStyle(1)} className={cn("shrink-0", STAGGER_IN)}>
            <Coverage instances={views} />
          </div>
          <section
            aria-label={m.log}
            style={staggerStyle(2)}
            className={cn("panel flex min-h-0 flex-1 flex-col overflow-hidden", STAGGER_IN)}
          >
            <ToolStrip label={m.log} className="px-3 py-1.5">
              <SearchInput
                value={q ?? ""}
                onChange={(v) => {
                  setQ(v || null);
                }}
                label={m.search.label}
                placeholder={m.search.placeholder}
              />
              <Select
                name="instance"
                aria-label={m.filter.label}
                value={instance ?? ""}
                onChange={(e) => {
                  setInstance(e.target.value || null);
                }}
                compact
                className="w-48"
              >
                <option value="">{m.filter.all}</option>
                {views.map((v) => (
                  <option key={v.spec.id} value={v.spec.id}>
                    {v.spec.name}
                  </option>
                ))}
                {instance && !names.has(instance) ? <option value={instance}>{m.filter.deleted}</option> : null}
              </Select>
              <SortMenu
                value={sort}
                options={BAN_SORTS}
                onChange={(v) => {
                  setSort(v === "newest" ? null : v);
                }}
              />
              <div className="ml-auto flex items-center gap-2">
                {bans.data ? <Count shown={rows.length} total={all.length} unit={m.unit(all.length)} /> : null}
              </div>
            </ToolStrip>
            {bans.isError && bans.data ? (
              // Stale: the last list stays, marked, with a retry.
              <div className="shrink-0 border-b border-line-subtle px-3 py-2">
                <ErrorCallout
                  error={bans.error}
                  title={m.stale(new Date(bans.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
                  onRetry={() => void bans.refetch()}
                  retrying={bans.isFetching}
                />
              </div>
            ) : null}
            {table}
          </section>
        </div>
      </BanActionHost>
    </Page>
  );
}
