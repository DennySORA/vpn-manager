// Per-connection totals for the range and their parts — each 代理埠 (its ordinary proxy traffic: SSH apart), SSH 下載,
// SSH 代理 and App 沙箱 — ranked. Each name links to its object; the row (or its 只看…的圖表 button) narrows the page to
// that object — an App sandbox's or an SSH part's to its connection, whose charts carry that traffic — and the row of the
// object the page shows carries the selection line, which slides when the scope changes.
// Sorting by a column header reorders the rows in place (they slide to their new places, Motion layout); rows that leave the
// scope fade out, rows that join rise in (docs/frontend-design.md §8.1).

import { ArrowDown, ArrowUp, ArrowUpDown, ChartLine, Rows3 } from "lucide-react";
import { type CSSProperties, useMemo } from "react";
import { Link } from "react-router";
import type { AppView, GatewaySpec, InstanceView, MetricsSeries } from "@/api/types";
import { ChangeValue } from "@/components/ui/change-value";
import { STAGGER_IN, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { EmptyState } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr } from "@/components/ui/table";
import { ToolButton } from "@/components/ui/tool-strip";
import { SSH_PROXY_COLOR, SSH_PULL_COLOR } from "@/features/gateways/ssh-traffic";
import { cn } from "@/lib/cn";
import { formatBps, formatBytes, joinList } from "@/lib/format";
import {
  availability,
  type BreakdownRow,
  breakdownRows,
  coverage,
  formatRatio,
  latencyText,
  type Scope,
  scopeParam,
  type SortKey,
} from "./model";
import { m } from "./messages";

const COLUMN = m.breakdown.columns;

/** The metric columns; on a narrow screen the less used ones give way to the name (`hide`), widest first. */
const COLUMNS: { key: SortKey; label: string; hint: string; hide?: string }[] = [
  { key: "rx", label: ui.common.download, hint: COLUMN.rx.hint },
  { key: "tx", label: ui.common.upload, hint: COLUMN.tx.hint },
  { key: "peak", label: COLUMN.peak.label, hint: COLUMN.peak.hint, hide: "max-md:hidden" },
  { key: "p95", label: COLUMN.p95.label, hint: COLUMN.p95.hint, hide: "max-sm:hidden" },
  { key: "avail", label: m.availability, hint: COLUMN.avail.hint, hide: "max-sm:hidden" },
];

const hideOf = (k: SortKey) => COLUMNS.find((c) => c.key === k)?.hide;

/** Larger first, except latency (faster first). */
const direction = (k: SortKey) => (k === "p95" ? "ascending" : "descending");

function SortHeader({
  column,
  sort,
  onSort,
}: {
  column: (typeof COLUMNS)[number];
  sort: SortKey;
  onSort: (k: SortKey) => void;
}) {
  const active = sort === column.key;
  const Icon = !active ? ArrowUpDown : direction(column.key) === "ascending" ? ArrowUp : ArrowDown;
  return (
    <Th align="right" sort={active ? direction(column.key) : "none"} className={column.hide}>
      <button
        type="button"
        title={column.hint}
        onClick={() => {
          onSort(column.key);
        }}
        className={cn(
          "pressable -mx-1 inline-flex min-h-7 items-center gap-1 rounded-sm px-1 outline-none focus-visible:ring-2 focus-visible:ring-focus",
          active ? "text-fg" : "text-fg-tertiary hover:text-fg",
        )}
      >
        {column.label}
        <Icon aria-hidden className={cn("size-3.5 shrink-0", !active && "opacity-60")} />
        <span className="sr-only">{m.breakdown.sortBy(column.label)}</span>
      </button>
    </Th>
  );
}

function Unknown({ children = ui.common.unknown }: { children?: string }) {
  return <span className="font-sans text-caption text-fg-tertiary">{children}</span>;
}

function Cells({ row }: { row: BreakdownRow }) {
  const t = row.totals;
  if (!t) {
    // Td's own classes, across the metric columns.
    return (
      <td
        colSpan={COLUMNS.length}
        className="h-12 border-b border-line-subtle px-3 py-1.5 text-right align-middle text-caption text-fg-tertiary"
      >
        {m.noDataInRange}
      </td>
    );
  }
  const sandbox = row.kind === "sandbox";
  const ssh = row.kind === "pull" || row.kind === "ssh";
  const p95 = latencyText(t.connect_p95_us, t.connect_count);
  const avail = availability(t);
  const cell = "machine align-top whitespace-nowrap";
  return (
    <>
      <Td align="right" className={cell}>
        {t.payload_rx_bytes === null ? <Unknown /> : formatBytes(t.payload_rx_bytes)}
      </Td>
      <Td align="right" className={cell}>
        {t.payload_tx_bytes === null ? <Unknown /> : formatBytes(t.payload_tx_bytes)}
      </Td>
      <Td align="right" className={cn(cell, hideOf("peak"))}>
        {t.peak_payload_rx_bps === null ? <Unknown /> : formatBps(t.peak_payload_rx_bps)}
      </Td>
      <Td align="right" className={cn(cell, hideOf("p95"))}>
        {sandbox ? (
          <Unknown>{m.breakdown.notThroughProxy}</Unknown>
        ) : ssh ? (
          <Unknown>{m.breakdown.inGateway}</Unknown>
        ) : (
          (p95.value ?? <Unknown>{p95.reason ?? ui.common.unknown}</Unknown>)
        )}
      </Td>
      <Td align="right" className={cn(cell, hideOf("avail"))}>
        {sandbox || ssh ? (
          <Unknown>{m.breakdown.sameAsConnection}</Unknown>
        ) : avail === null ? (
          <Unknown />
        ) : (
          formatRatio(avail)
        )}
        <span className="block text-micro text-fg-tertiary">{m.breakdown.coverage(formatRatio(coverage(t)))}</span>
      </Td>
    </>
  );
}

/** The scope a row narrows the page to: an App sandbox and the SSH parts have none of their own, their connection's
 * charts carry their traffic. */
function scopeOf(row: BreakdownRow): Scope {
  return row.kind === "gateway" ? { kind: "gateway", id: row.id } : { kind: "instance", id: row.instanceId };
}

/** Where a row's name leads: the object's page; an App sandbox's, its (first) App; an SSH part's, its page. */
function linkOf(row: BreakdownRow): string | null {
  if (row.kind === "gateway") return `/gateways/${row.id}`;
  if (row.kind === "instance") return `/instances/${row.id}`;
  if (row.kind === "pull") return "/ssh-downloads";
  if (row.kind === "ssh") return "/ssh";
  return row.appId ? `/apps/${row.appId}` : null;
}

function subtitle(row: BreakdownRow): string {
  const rows = m.breakdown.rows;
  if (row.kind === "gateway") return rows.gateway(row.detail, row.withoutSsh);
  if (row.kind === "sandbox") return row.detail ? rows.sandboxApps(row.detail) : rows.sandbox;
  if (row.kind === "pull") return rows.pull;
  if (row.kind === "ssh") return rows.ssh;
  return rows.connection;
}

/** The SSH parts' colour key, as in 流量路徑 and 總覽's chart. */
const PART_COLOR: Partial<Record<BreakdownRow["kind"], string>> = { pull: SSH_PULL_COLOR, ssh: SSH_PROXY_COLOR };

function BreakdownRowView({
  row,
  owner,
  current,
  index,
  exiting,
  onScope,
}: {
  row: BreakdownRow;
  /** The connection's name, for a part's chart button. */
  owner: string;
  current: string;
  index: number;
  exiting: boolean;
  onScope: (s: Scope) => void;
}) {
  const part = row.kind !== "instance";
  // A part with no scope of its own: its connection's charts carry it.
  const carried = row.kind === "sandbox" || row.kind === "pull" || row.kind === "ssh";
  const selected = `${row.kind}:${row.id}` === current;
  const showsOwner = carried && `instance:${row.instanceId}` === current;
  const color = PART_COLOR[row.kind];
  // A deleted object keeps its totals here; the API answers a series only for configured ones.
  const reason = !row.exists
    ? m.breakdown.deleted
    : selected
      ? m.breakdown.showing
      : showsOwner
        ? m.breakdown.showingOwner(row.name)
        : null;
  const to = row.exists ? linkOf(row) : null;
  return (
    <Tr
      selected={selected}
      onSelect={
        reason
          ? undefined
          : () => {
              onScope(scopeOf(row));
            }
      }
      index={index}
      exiting={exiting}
    >
      <Td className={cn("align-top max-sm:max-w-0 max-sm:w-full", part && "first:pl-9")}>
        {color ? (
          <span
            aria-hidden
            className="swatch mr-1.5 inline-block size-1.5 rounded-full align-middle"
            style={{ background: color }}
          />
        ) : null}
        {to ? (
          <Link
            to={to}
            className={cn(
              TEXT_LINK,
              "text-data [overflow-wrap:anywhere]",
              part ? "text-fg-secondary" : "font-medium text-fg",
            )}
          >
            {row.name}
          </Link>
        ) : (
          <span
            className={cn("text-data [overflow-wrap:anywhere]", row.exists ? "text-fg-secondary" : "text-fg-tertiary")}
          >
            {row.name}
          </span>
        )}
        <span className="block text-micro text-fg-tertiary [overflow-wrap:anywhere]">{subtitle(row)}</span>
      </Td>
      <Cells row={row} />
      <Td align="right" className="w-[52px] align-top">
        <ToolButton
          label={carried ? m.breakdown.chartsOfOwner(owner, row.name) : m.breakdown.chartsOf(row.name)}
          icon={<ChartLine aria-hidden />}
          disabledReason={reason}
          onClick={() => {
            onScope(scopeOf(row));
          }}
        />
      </Td>
    </Tr>
  );
}

export function Breakdown({
  s,
  views,
  gateways,
  apps,
  scope,
  sort,
  onSort,
  onScope,
  style,
}: {
  s: MetricsSeries;
  views: InstanceView[];
  gateways: GatewaySpec[];
  /** Every managed App: a connection's strict ones get its App sandbox row. */
  apps: AppView[];
  scope: Scope;
  sort: SortKey;
  onSort: (k: SortKey) => void;
  onScope: (s: Scope) => void;
  style?: CSSProperties;
}) {
  const current = scopeParam(scope);
  // The same rows for the same answer: the shared cursor re-renders the page on every pointer move, and the rows (with
  // their presence and reflow) must not churn for it. `scope` is a new object on every render: its ids stand for it.
  const instanceId = scope.kind === "instance" ? scope.id : undefined;
  const gatewayId = scope.kind === "gateway" ? scope.id : undefined;
  const rows = useMemo(() => {
    let groups = breakdownRows(views, gateways, s.instances, s.gateways, sort, instanceId, apps);
    if (gatewayId !== undefined) {
      // One 代理埠: only its own row.
      groups = groups
        .map((g) => ({ ...g, parts: g.parts.filter((x) => x.kind === "gateway" && x.id === gatewayId) }))
        .filter((g) => g.parts.length);
    }
    return groups.flatMap((g) => (gatewayId !== undefined ? g.parts : [g.row, ...g.parts]));
  }, [views, gateways, apps, s.instances, s.gateways, sort, instanceId, gatewayId]);
  const sandboxes = rows.some((r) => r.kind === "sandbox");
  const sshParts = rows.some((r) => r.kind === "pull" || r.kind === "ssh");
  const titleParts = m.breakdown.titleParts;
  const title = joinList([
    titleParts.connections,
    titleParts.gateways,
    ...(sshParts ? ["SSH"] : []),
    ...(sandboxes ? [titleParts.sandboxes] : []),
  ]);
  const ownerName = (r: BreakdownRow) =>
    views.find((v) => v.spec.id === r.instanceId)?.spec.name ?? m.scope.connectionId(r.instanceId.slice(0, 8));
  return (
    <section
      aria-labelledby="breakdown-title"
      style={style}
      className={cn("panel flex flex-col overflow-hidden", STAGGER_IN)}
    >
      <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line-subtle px-4 py-2.5">
        <h2 id="breakdown-title" className="flex items-center gap-2 text-data font-semibold text-fg">
          <Rows3 aria-hidden className="size-4 text-fg-tertiary" />
          {title}
          <ChangeValue value={rows.length} className="machine text-caption font-normal text-fg-tertiary" />
        </h2>
        <p className="text-caption text-fg-tertiary">{m.breakdown.hint(s.entities_truncated)}</p>
      </header>
      {rows.length ? (
        <TableFrame
          label={m.breakdown.tableLabel(title)}
          selectionMarker
          // The columns left on a narrow screen fit without scrolling.
          tableClassName="min-w-[760px] max-md:min-w-[600px] max-sm:min-w-0"
        >
          <thead>
            <tr>
              <Th>{m.breakdown.nameColumn(sshParts, sandboxes)}</Th>
              {COLUMNS.map((c) => (
                <SortHeader key={c.key} column={c} sort={sort} onSort={onSort} />
              ))}
              <Th align="right">
                <span className="sr-only">{ui.common.actions}</span>
              </Th>
            </tr>
          </thead>
          <TBody items={rows} keyOf={(r) => `${r.kind}:${r.instanceId}:${r.id}`}>
            {(row, r) => (
              <BreakdownRowView
                row={row}
                owner={ownerName(row)}
                current={current}
                index={r.index}
                exiting={r.exiting}
                onScope={onScope}
              />
            )}
          </TBody>
        </TableFrame>
      ) : (
        <EmptyState compact icon={Rows3} title={m.breakdown.empty} />
      )}
    </section>
  );
}
