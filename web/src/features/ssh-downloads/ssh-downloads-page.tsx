// SSH 下載 (/ssh-downloads): the list page recipe of docs/frontend-design.md §8.1 — page header with its one primary
// action (新增下載工作); a tool strip (search, state filter, sort, count); rows that come and go with presence, one
// sliding selection marker; each row has its quick action (暫停／繼續／重試) and the same ⋯ menu as the inspector, all
// from one action model (actions.ts). Statuses arrive live (SSE, at most once per job and second).
import { FolderDown, Plus } from "lucide-react";
import { type ReactNode, useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router";
import type { GatewaySpec } from "@/api/generated/GatewaySpec";
import type { SshDownloadStatus } from "@/api/generated/SshDownloadStatus";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import { useGateways, useInstances } from "@/api/queries";
import { useSshDownloads } from "@/api/ssh-downloads";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { Count, Page, PageHeader, SearchInput, SplitView } from "@/components/shell/page";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RowActions } from "@/components/ui/entity-actions";
import { FIT_WIDTH } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { ProgressTrack } from "@/components/ui/progress";
import { Segmented } from "@/components/ui/segmented";
import { SortMenu } from "@/components/ui/sort-menu";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { ToolStrip } from "@/components/ui/tool-strip";
import { intlLocale, localized } from "@/i18n";
import { formatBytes } from "@/lib/format";
import { useQueryParam, useSetQueryParams } from "@/lib/url";
import { JobActionHost, useJobActions } from "./action-host";
import { JobDialog } from "./job-dialog";
import { JobInspector } from "./job-inspector";
import { m } from "./messages";
import {
  formatRate,
  JOB_FILTERS,
  JOB_SORTS,
  type JobFilter,
  type JobSort,
  jobLook,
  matchesJobFilter,
  socksCapable,
  sortJobs,
  targetText,
} from "./model";

/** What the row says about the work: the files in flight (one progress line), else the queue. */
function Work({ v }: { v: SshDownloadView }) {
  const s = v.status;
  if (!s) return <span className="text-caption text-fg-disabled">—</span>;
  if (s.active.length) {
    const done = s.active.reduce((n, a) => n + Number(a.bytes_done), 0);
    const known = s.active.every((a) => a.bytes_total !== null);
    const total = known ? s.active.reduce((n, a) => n + Number(a.bytes_total), 0) : null;
    return (
      <div className="grid min-w-0 grid-cols-1 gap-1">
        <span className="truncate text-caption text-fg-secondary">
          {s.active.length === 1 ? s.active[0]?.name : m.list.files(s.active.length)}
          {s.queued ? m.list.alsoQueued(s.queued) : ""}
        </span>
        <ProgressTrack
          value={total === null ? null : done}
          max={total ?? 1}
          tone="running"
          size="sm"
          label={m.progressOf(v.job.name)}
          valueText={total === null ? formatBytes(done) : m.list.bytesOf(formatBytes(done), formatBytes(total))}
        />
      </div>
    );
  }
  return (
    <span className="text-caption text-fg-tertiary">
      {s.queued
        ? m.list.queued(s.queued)
        : s.unfinished
          ? m.list.unfinished(s.unfinished)
          : s.last_scan_at
            ? m.list.noNewFiles
            : m.list.notScanned}
    </span>
  );
}

/**
 * A running job's SSH traffic (↓ from the server, ↑ to it), as its connections cross the Gateway: what that
 * connection counts for it.
 */
function WireRate({ s }: { s: SshDownloadStatus | null }) {
  if (!s?.running_since) return <span className="text-caption text-fg-disabled">—</span>;
  return (
    <div
      className="machine text-right text-caption leading-4"
      title={m.list.wire(formatRate(s.wire_rx_bps), formatRate(s.wire_tx_bps))}
    >
      <div className="text-fg">↓ {formatRate(s.wire_rx_bps)}</div>
      <div className="text-fg-tertiary">↑ {formatRate(s.wire_tx_bps)}</div>
    </div>
  );
}

function JobRow({
  v,
  gateway,
  selected,
  index,
  exiting,
  onSelect,
}: {
  v: SshDownloadView;
  gateway: GatewaySpec | undefined;
  selected: boolean;
  index: number;
  exiting: boolean;
  onSelect: () => void;
}) {
  const actions = useJobActions(v, Boolean(gateway));
  const s = v.status;
  const busy = s?.state === "downloading" || s?.state === "scanning" || s?.state === "connecting";
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting} running={busy}>
      <Td className="max-w-0">
        <Link
          to={`/ssh-downloads/${v.job.id}`}
          data-row-link={v.job.id}
          aria-current={selected ? "true" : undefined}
          className="block truncate text-body font-medium text-fg"
          title={v.job.name}
        >
          {v.job.name}
        </Link>
        <div className="machine truncate text-caption text-fg-tertiary" title={targetText(v.job)}>
          {targetText(v.job)}
        </div>
      </Td>
      <Td className="w-[128px]">
        <StatusPill look={jobLook(v)} title={s?.reason ? localized(s.reason) : undefined} />
      </Td>
      <Td className="w-[220px] max-w-[220px] max-md:hidden">
        <Work v={v} />
      </Td>
      <Td align="right" className="hidden w-[112px] lg:table-cell">
        <WireRate s={s} />
      </Td>
      <Td align="right" className="w-[76px]">
        <RowActions actions={actions} name={v.job.name} />
      </Td>
    </Tr>
  );
}

export function SshDownloadsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const jobs = useSshDownloads();
  const gateways = useGateways();
  const instances = useInstances();
  const [q, setQ] = useQueryParam("q");
  const [state, setState] = useQueryParam("state");
  const [sortParam, setSort] = useQueryParam("sort");
  const [newOpen, setNewOpen] = useQueryParam("new");
  // The inspector's tab: selecting another object keeps it (where that object has the tab).
  const [tabParam] = useQueryParam("tab");
  const setQueryParams = useSetQueryParams();
  const filter = (JOB_FILTERS.some((f) => f.value === state) ? state : "all") as JobFilter;
  const sort = (JOB_SORTS.some((s) => s.value === sortParam) ? sortParam : "name") as JobSort;
  const gatewayOf = useMemo(() => new Map((gateways.data ?? []).map((g) => [g.id, g])), [gateways.data]);
  const noGateway = gateways.isSuccess && !gateways.data.some(socksCapable);
  const createReason = gateways.isPending ? m.page.readingGateways : noGateway ? m.page.needsGateway : null;

  const all = useMemo(() => jobs.data ?? [], [jobs.data]);
  const rows = useMemo(() => {
    const t = (q ?? "").trim().toLowerCase();
    const shown = all.filter(
      (v) =>
        matchesJobFilter(v, filter) &&
        (!t ||
          `${v.job.name} ${v.job.host} ${v.job.user} ${v.job.source_dir} ${v.job.local_dir}`.toLowerCase().includes(t)),
    );
    return sortJobs(shown, sort);
  }, [all, q, filter, sort]);
  const selected = all.find((v) => v.job.id === id);
  useCrumb(selected?.job.name);
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
    void navigate(`/ssh-downloads/${next}${search}`);
  };
  const onKeyDown = useRowNavigation(
    rows.map((v) => v.job.id),
    id,
    select,
  );
  const owner = (g: GatewaySpec | undefined) =>
    g ? instances.data?.find((v) => v.spec.id === g.instance_id) : undefined;

  let list: ReactNode;
  if (jobs.isPending) list = <LoadingRows label={m.list.loading} />;
  else if (jobs.isError && !jobs.data)
    list = <ErrorState error={jobs.error} onRetry={() => void jobs.refetch()} retrying={jobs.isFetching} />;
  else if (!all.length)
    list = (
      <EmptyState
        brand
        icon={FolderDown}
        title={m.list.emptyTitle}
        actions={
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
        }
      >
        {noGateway ? m.list.emptyNeedsGateway : m.list.emptyBody}
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
            options={JOB_FILTERS.map((f) => ({ ...f, count: all.filter((v) => matchesJobFilter(v, f.value)).length }))}
            className={FIT_WIDTH}
          />
          <SortMenu
            value={sort}
            options={JOB_SORTS}
            onChange={(v) => {
              setSort(v === "name" ? null : v);
            }}
          />
          <Count shown={rows.length} total={all.length} unit={m.list.unit(all.length)} />
        </ToolStrip>
        {jobs.isError ? (
          <div className="shrink-0 border-b border-line-subtle px-3 py-2">
            <ErrorCallout
              error={jobs.error}
              title={m.list.stale(new Date(jobs.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void jobs.refetch()}
              retrying={jobs.isFetching}
            />
          </div>
        ) : null}
        {rows.length ? (
          <TableFrame label={m.list.table} onKeyDown={onKeyDown} selectionMarker tableClassName="max-sm:min-w-0">
            <thead>
              <tr>
                <Th>{ui.common.name}</Th>
                <Th>{ui.common.status}</Th>
                <Th className="max-md:hidden">{m.list.progress}</Th>
                <Th align="right" className="hidden lg:table-cell">
                  {m.rate}
                </Th>
                <Th align="right">
                  <span className="sr-only">{ui.common.actions}</span>
                </Th>
              </tr>
            </thead>
            <TBody items={rows} keyOf={(v) => v.job.id}>
              {(v, row) => (
                <JobRow
                  v={v}
                  gateway={gatewayOf.get(v.job.gateway_id)}
                  index={row.index}
                  exiting={row.exiting}
                  selected={v.job.id === id}
                  onSelect={() => {
                    select(v.job.id);
                  }}
                />
              )}
            </TBody>
          </TableFrame>
        ) : (
          <EmptyState
            compact
            icon={FolderDown}
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

  const gw = selected ? gatewayOf.get(selected.job.gateway_id) : undefined;
  return (
    <Page>
      <JobActionHost jobs={all}>
        <PageHeader
          title={shell.nav.sshDownloads.label}
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
              {m.page.add}
            </ActionButton>
          }
        />
        <SplitView
          list={list}
          inspector={
            selected ? <JobInspector key={selected.job.id} v={selected} gateway={gw} owner={owner(gw)} /> : null
          }
          inspectorTitle={selected ? m.list.detailsOf(selected.job.name) : m.list.details}
          onCloseInspector={() => void navigate(`/ssh-downloads${search}`)}
          placeholder={
            <EmptyState compact icon={FolderDown} title={id && jobs.isSuccess ? m.list.notFound : m.list.select}>
              {id && jobs.isSuccess ? ui.common.mayHaveBeenDeleted : m.list.selectHint}
            </EmptyState>
          }
        />
        <JobDialog
          open={newOpen === "1"}
          onOpenChange={(o) => {
            setNewOpen(o ? "1" : null);
          }}
          onSaved={(v) => void navigate(`/ssh-downloads/${v.job.id}${search}`)}
        />
      </JobActionHost>
    </Page>
  );
}
