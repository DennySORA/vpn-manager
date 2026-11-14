// 連線與代理埠 of 效能統計: every connection with its live figures, its proxy ports on demand. The table recipe of
// docs/frontend-design.md §8.1: one sliding selection line (the connection whose trends show below, in the URL), rows
// that rise in once and never replay on the 5-second refresh, proxy-port rows that come and go with presence when a
// connection is expanded or collapsed (the rows below slide to their places), ↑／↓／Home／End move the selection.

import { ChevronDown, MemoryStick, Network } from "lucide-react";
import { type CSSProperties, useMemo, useState } from "react";
import type { GatewayPerformance } from "@/api/generated/GatewayPerformance";
import type { InstancePerformance } from "@/api/generated/InstancePerformance";
import type { PerformanceOverview } from "@/api/generated/PerformanceOverview";
import { StatusPill } from "@/components/ui/badge";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Panel } from "@/components/ui/panel";
import { EmptyState } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr, useRowNavigation } from "@/components/ui/table";
import { Tip } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { formatBps } from "@/lib/format";
import { PHASE } from "@/lib/status";
import { m } from "./messages";
import { bytesObs, obs, pct } from "./model";
import { Latency, Pair, Val } from "./values";

const COLUMNS: [string, string?][] = [
  [m.connections.columns.connection],
  ["Payload"],
  ["WireGuard"],
  [m.connections.columns.dataFlows, m.connections.columns.tcpUdp],
  [m.connections.columns.probeControl],
  [m.connections.columns.refused],
  [m.connections.columns.latency, m.connections.columns.quantiles],
  [m.connections.columns.coverage],
  [m.connections.columns.cpuRss],
];

/** On a narrow screen the secondary columns give way (header and cells alike), so the table scrolls less. */
const HIDE = ["", "", "max-md:hidden", "", "max-lg:hidden", "max-md:hidden", "", "max-sm:hidden", ""];

type Row =
  | { kind: "instance"; key: string; i: InstancePerformance }
  | { kind: "gateway"; key: string; g: GatewayPerformance }
  | { kind: "none"; key: string };

/** The rows in order: each connection, then — when expanded — its proxy ports (or a line saying it has none). */
export function connectionRows(instances: readonly InstancePerformance[], open: ReadonlySet<string>): Row[] {
  const out: Row[] = [];
  for (const i of instances) {
    out.push({ kind: "instance", key: `i:${i.instance_id}`, i });
    if (!open.has(i.instance_id)) continue;
    if (i.gateways.length)
      for (const g of i.gateways) out.push({ kind: "gateway", key: `g:${i.instance_id}:${g.gateway_id}`, g });
    else out.push({ kind: "none", key: `n:${i.instance_id}` });
  }
  return out;
}

function GatewayRow({ g, index, exiting }: { g: GatewayPerformance; index: number; exiting: boolean }) {
  const s = g.summary;
  return (
    <Tr index={index} exiting={exiting} className="bg-sunken/40">
      <Td className="first:pl-12">
        <span className="text-data text-fg-secondary">{g.name}</span>{" "}
        <span className="machine text-caption text-fg-tertiary">:{g.port}</span>
      </Td>
      <Td align="right">
        <Pair
          a={[ui.common.download, <Val key="d" v={obs(s.payload_download_bps, formatBps)} />]}
          b={[ui.common.upload, <Val key="u" v={obs(s.payload_upload_bps, formatBps)} />]}
        />
      </Td>
      <Td align="right" className={cn("text-caption text-fg-tertiary", HIDE[2])}>
        {m.connections.notApplicable}
      </Td>
      <Td align="right" className="machine">
        <span className="whitespace-nowrap">
          {g.data_flows.tcp ?? "—"} / {g.data_flows.udp ?? "—"}
        </span>
        <span className="block whitespace-nowrap text-caption text-fg-tertiary">
          {m.connections.limit(g.max_connections)}
        </span>
      </Td>
      <Td align="right" className={cn("machine text-fg-tertiary", HIDE[4])}>
        —
      </Td>
      <Td align="right" className={cn("machine", HIDE[5])}>
        {g.admission_rejected ?? "—"}
      </Td>
      <Td align="right">
        <span className="whitespace-nowrap">
          <span className="mr-1.5 text-caption text-fg-tertiary">{m.connections.connect}</span>
          <Latency l={s.latencies.find((x) => x.kind === "proxy_connect")} />
        </span>
        {/* Connects that failed sit with the connect latency (the row has no DNS line). */}
        {g.connect_failures && g.connect_failures !== "0" ? (
          <span className="block whitespace-nowrap text-caption text-fg-tertiary">
            {m.connections.failures(
              g.connect_failures,
              g.connect_not_found && g.connect_not_found !== "0" ? g.connect_not_found : null,
            )}
          </span>
        ) : null}
      </Td>
      <Td align="right" className={cn("machine whitespace-nowrap", HIDE[7])}>
        {(s.coverage_ratio * 100).toFixed(0)} %
      </Td>
      <Td align="right" className="whitespace-nowrap text-caption text-fg-tertiary">
        {m.connections.countedInConnection}
      </Td>
    </Tr>
  );
}

function InstanceRow({
  i,
  open,
  onToggle,
  selected,
  onSelect,
  index,
  exiting,
}: {
  i: InstancePerformance;
  open: boolean;
  onToggle: () => void;
  selected: boolean;
  onSelect: () => void;
  index: number;
  exiting: boolean;
}) {
  const s = i.summary;
  const missing = Math.round(Number(s.missing_duration_ms) / 1000);
  return (
    <Tr selected={selected} onSelect={onSelect} index={index} exiting={exiting}>
      <Td className="max-w-[240px]">
        <div className="flex min-w-0 items-center gap-1.5">
          <button
            type="button"
            aria-expanded={open}
            aria-label={open ? m.connections.collapseGatewaysOf(i.name) : m.connections.expandGatewaysOf(i.name)}
            title={open ? m.connections.collapseGateways : m.connections.expandGateways}
            onClick={onToggle}
            className="pressable inline-flex size-6 shrink-0 items-center justify-center rounded-md text-fg-tertiary hover:bg-raised hover:text-fg active:bg-sunken"
          >
            <ChevronDown
              aria-hidden
              className={cn(
                "size-4 transition-[rotate] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)",
                !open && "-rotate-90",
              )}
            />
          </button>
          <button
            type="button"
            data-row-link={i.instance_id}
            aria-current={selected ? "true" : undefined}
            onClick={onSelect}
            className="min-w-0 rounded-sm text-left outline-none focus-visible:ring-2 focus-visible:ring-focus"
          >
            <span className="block truncate text-data font-medium text-fg" title={i.name}>
              {i.name}
            </span>
            <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
              <StatusPill look={PHASE[i.phase]} className="min-h-5 text-micro" />
              {i.generation !== null ? (
                <span className="machine text-micro whitespace-nowrap text-fg-tertiary">
                  {m.generation(i.generation)}
                </span>
              ) : null}
            </span>
          </button>
        </div>
      </Td>
      <Td align="right">
        <Pair
          a={[ui.common.download, <Val key="d" v={obs(s.payload_download_bps, formatBps)} />]}
          b={[ui.common.upload, <Val key="u" v={obs(s.payload_upload_bps, formatBps)} />]}
        />
      </Td>
      <Td align="right" className={HIDE[2]}>
        <Pair
          a={[m.connections.receive, <Val key="r" v={obs(s.wireguard_rx_bps, formatBps)} />]}
          b={[m.connections.send, <Val key="t" v={obs(s.wireguard_tx_bps, formatBps)} />]}
        />
      </Td>
      <Td align="right" className="machine">
        <span className="whitespace-nowrap">
          {i.data_flows.tcp ?? "—"} / {i.data_flows.udp ?? "—"}
        </span>
        <span className="flex items-center justify-end gap-1 font-sans text-caption whitespace-nowrap text-fg-tertiary">
          {m.connections.capacity(<span className="machine">{i.capacity.tcp_capacity}</span>)}
          {i.capacity.tcp_capacity_by_memory ? (
            <Tip content={m.connections.capacityByMemory}>
              {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a tooltip trigger: keyboard users focus it to read the tooltip */}
              <span tabIndex={0} className="cursor-help" aria-label={m.connections.byMemory}>
                <MemoryStick aria-hidden className="size-3" />
              </span>
            </Tip>
          ) : null}
        </span>
      </Td>
      <Td align="right" className={cn("machine", HIDE[4])}>
        {s.active_probe_flows ?? "—"} / {s.active_control_flows ?? "—"}
      </Td>
      <Td align="right" className={cn("machine", HIDE[5])}>
        {i.admission_rejected ?? "—"}
        {i.underlay_blocked && i.underlay_blocked !== "0" ? (
          <span className="block font-sans text-caption text-warning">
            {m.connections.underlayBlocked(i.underlay_blocked)}
          </span>
        ) : null}
      </Td>
      <Td align="right">
        <Pair
          a={[m.connections.connect, <Latency key="c" l={s.latencies.find((x) => x.kind === "proxy_connect")} />]}
          b={["DNS", <Latency key="d" l={s.latencies.find((x) => x.kind === "dns_resolution")} />]}
        />
      </Td>
      <Td align="right" className={cn("machine whitespace-nowrap", HIDE[7])}>
        {(s.coverage_ratio * 100).toFixed(0)} %
        {missing > 0 ? (
          <span className="block font-sans text-caption text-fg-tertiary">{m.connections.missing(missing)}</span>
        ) : null}
      </Td>
      <Td align="right" className="whitespace-nowrap">
        <Val v={obs(s.cpu_core_pct, pct)} />
        <span className="block text-caption">
          <Val v={bytesObs(s.rss_bytes)} />
        </span>
      </Td>
    </Tr>
  );
}

export function Connections({
  s,
  selected,
  onSelect,
  style,
}: {
  s: PerformanceOverview;
  /** The connection whose trends show (the URL's `instance`). */
  selected: string | null;
  onSelect: (id: string) => void;
  style?: CSSProperties;
}) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const rows = useMemo(() => connectionRows(s.instances, open), [s.instances, open]);
  const ids = useMemo(() => s.instances.map((i) => i.instance_id), [s.instances]);
  const onKeyDown = useRowNavigation(ids, selected ?? undefined, onSelect);
  const toggle = (id: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const description = m.connections.description(s.rate_window_secs, s.latency_window_secs / 60);
  if (!s.instances.length) {
    return (
      <Panel icon={Network} title={m.connections.title} description={description} style={style} className={STAGGER_IN}>
        <EmptyState compact icon={Network} title={m.connections.empty}>
          {m.connections.emptyBody}
        </EmptyState>
      </Panel>
    );
  }
  return (
    <Panel
      flush
      icon={Network}
      title={m.connections.title}
      count={s.instances.length}
      description={description}
      style={style}
      className={cn("overflow-hidden", STAGGER_IN)}
    >
      <TableFrame
        label={m.connections.title}
        selectionMarker
        onKeyDown={onKeyDown}
        tableClassName="min-w-[880px] max-lg:min-w-[760px] max-md:min-w-[600px] max-sm:min-w-[480px]"
      >
        <thead>
          <tr>
            {COLUMNS.map(([h, sub], k) => (
              <Th key={k} align={k === 0 ? "left" : "right"} className={cn("h-auto py-2 align-bottom", HIDE[k])}>
                {h}
                {sub ? <span className="block text-micro font-normal">{sub}</span> : null}
              </Th>
            ))}
          </tr>
        </thead>
        <TBody items={rows} keyOf={(r) => r.key}>
          {(r, row) =>
            r.kind === "instance" ? (
              <InstanceRow
                i={r.i}
                open={open.has(r.i.instance_id)}
                onToggle={() => {
                  toggle(r.i.instance_id);
                }}
                selected={selected === r.i.instance_id}
                onSelect={() => {
                  onSelect(r.i.instance_id);
                }}
                index={row.index}
                exiting={row.exiting}
              />
            ) : r.kind === "gateway" ? (
              <GatewayRow g={r.g} index={row.index} exiting={row.exiting} />
            ) : (
              <Tr index={row.index} exiting={row.exiting} className="bg-sunken/40">
                <td
                  colSpan={COLUMNS.length}
                  className="h-10 border-b border-line-subtle py-2 pl-12 text-caption text-fg-tertiary"
                >
                  {m.connections.noGateways}
                </td>
              </Tr>
            )
          }
        </TBody>
      </TableFrame>
      <p className="border-t border-line-subtle px-4 py-2 text-caption text-fg-tertiary">{m.connections.footer}</p>
    </Panel>
  );
}
