// The top bar's traffic strip (before the service pill, like a download client's network strip): one chip-style button
// with the download and upload of every running connection summed and the TCP connections and UDP flows open in their
// tunnels. The segments fold away as the window narrows (the flows below 1280 px; the whole strip below 840 px, where
// 總覽 shows the same rates); the button's accessible name is the whole sentence. Pressing it opens a popover with one
// row per running connection — its rates, flows, state and its parts apart from ordinary proxy traffic: SSH 下載, SSH
// 代理 (with their colours and counts, as in 流量路徑) and the App sandbox — and a link to 連線. It reads the live-rate
// stream the other views already keep in the cache (no polling of its own); unknown is a dash, never 0.
import { ArrowDown, ArrowRight, ArrowUp, Cable } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { useInstances, useLiveRatesMap } from "@/api/queries";
import { StatusPill } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Popover } from "@/components/ui/popover";
import { type Flow, flowing, portKinds, SSH_PROXY_COLOR, SSH_PULL_COLOR } from "@/features/gateways/ssh-traffic";
import { instanceLook } from "@/features/instances/model";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { formatBps } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { m } from "./messages";
import {
  runningViews,
  type TrafficRow,
  type TrafficTotal,
  totalText,
  trafficRows,
  trafficSentence,
  trafficTotal,
} from "./traffic";

const SEGMENT =
  "inline-flex h-full min-w-0 items-center gap-1 px-2 first:pl-2.5 last:pr-2.5 [&_svg]:size-3.5 [&_svg]:shrink-0";

/** 「其中 SSH 下載 ↓x ↑y · 1 個工作進行中」: a part of the connection's rates, its colour as in 流量路徑. */
function Part({ label, color, flow, note }: { label: string; color?: string; flow: Flow; note?: string | null }) {
  return (
    <p className="flex items-start gap-1.5 text-caption text-fg-tertiary">
      {color ? (
        <span aria-hidden className="swatch mt-1.5 size-1.5 shrink-0 rounded-full" style={{ background: color }} />
      ) : null}
      <span>
        {m.row.part(label)} <span className="machine whitespace-nowrap">↓ {formatBps(flow.rx)}</span>{" "}
        <span className="machine whitespace-nowrap">↑ {formatBps(flow.tx)}</span>
        {note ? ` · ${note}` : ""}
      </span>
    </p>
  );
}

function Row({ row, onNavigate }: { row: TrafficRow; onNavigate: () => void }) {
  const { view, rates } = row;
  const to = `/instances/${view.spec.id}`;
  const kinds = rates ? portKinds(rates.gateways) : null;
  return (
    <li className="grid grid-cols-1 gap-1 px-3 py-2.5">
      <div className="flex min-w-0 items-center justify-between gap-3">
        <Link
          to={to}
          onClick={onNavigate}
          className="min-w-0 truncate text-data font-medium text-fg underline-offset-2 hover:underline active:opacity-70"
        >
          {view.spec.name}
        </Link>
        <StatusPill look={instanceLook(view)} className="shrink-0" />
      </div>
      {rates ? (
        <>
          <p className="machine flex flex-wrap items-center gap-x-3 gap-y-0.5 text-caption text-fg-secondary">
            <span className="whitespace-nowrap">
              <span className="text-series-rx">↓</span> {formatBps(rates.payload_rx_bps)}
            </span>
            <span className="whitespace-nowrap">
              <span className="text-series-tx">↑</span> {formatBps(rates.payload_tx_bps)}
            </span>
            <span className="whitespace-nowrap">
              TCP {rates.active_tcp.toLocaleString(intlLocale)} · UDP {rates.active_udp.toLocaleString(intlLocale)}
            </span>
          </p>
          {kinds && flowing(kinds.pull) ? (
            <Part label={m.row.sshDownloads} color={SSH_PULL_COLOR} flow={kinds.pull} />
          ) : null}
          {kinds && (flowing(kinds.proxy) || kinds.sessions) ? (
            <Part
              label={m.row.sshProxy}
              color={SSH_PROXY_COLOR}
              flow={kinds.proxy}
              note={kinds.sessions ? m.row.sshSessions(kinds.sessions) : null}
            />
          ) : null}
          {rates.sandbox ? (
            <Part label={m.row.appSandbox} flow={{ rx: rates.sandbox.rx_bps, tx: rates.sandbox.tx_bps }} />
          ) : null}
        </>
      ) : (
        <p className="text-caption text-fg-tertiary">{m.row.noData}</p>
      )}
    </li>
  );
}

function Panel({ rows, total, onNavigate }: { rows: TrafficRow[]; total: TrafficTotal; onNavigate: () => void }) {
  const v = totalText(total);
  return (
    <div className="grid grid-cols-1">
      <div className="grid gap-0.5 px-3 pt-3 pb-2.5">
        <p className="text-data font-semibold text-fg">{m.title}</p>
        <p className="text-caption text-fg-tertiary">
          {!total.running
            ? m.panel.none
            : total.fresh
              ? m.panel.total(total.fresh, v.rx, v.tx, v.flows, total.running - total.fresh)
              : m.panel.waiting}
        </p>
        <p className="text-caption text-fg-tertiary">{m.panel.scope}</p>
      </div>
      {rows.length ? (
        <ul aria-label={m.panel.connections} className="divide-y divide-line-subtle border-t border-line-subtle">
          {rows.map((r) => (
            <Row key={r.view.spec.id} row={r} onNavigate={onNavigate} />
          ))}
        </ul>
      ) : null}
      <div className="sticky bottom-0 border-t border-line-subtle bg-raised/95 px-3 py-2.5 forced-colors:bg-[Canvas]">
        <Link
          to="/instances"
          onClick={onNavigate}
          className={cn(buttonVariants({ variant: "secondary", size: "sm" }), "w-full")}
        >
          {m.panel.viewAll}
          <ArrowRight aria-hidden />
        </Link>
      </div>
    </div>
  );
}

export function TrafficStrip() {
  const instances = useInstances();
  const views = instances.data ?? [];
  // The connections that should run; the stream appends each one's samples to the same cache the overview reads.
  const live = useLiveRatesMap(runningViews(views).map((v) => v.spec.id));
  const now = useServerNow();
  const rows = trafficRows(views, live, now);
  const total = trafficTotal(rows);
  const v = totalText(total);
  const [open, setOpen] = useState(false);
  return (
    <Popover
      label={m.title}
      open={open}
      onOpenChange={setOpen}
      trigger={
        <button
          type="button"
          className={cn(
            "pressable hidden h-7 max-w-[46vw] items-center overflow-hidden rounded-full border border-line bg-sunken/70 text-caption text-fg-secondary md:inline-flex",
            "hover:border-line-strong hover:bg-raised/60 aria-expanded:border-action/50 aria-expanded:bg-raised/60",
          )}
        >
          <span className="sr-only">{trafficSentence(total)}</span>
          <span aria-hidden className="flex h-full min-w-0 items-center divide-x divide-line-subtle">
            {/* Rates change every second: tabular digits and a minimum width keep the strip from twitching. */}
            <span className={SEGMENT}>
              <ArrowDown strokeWidth={2} className="text-series-rx" />
              <span className="machine min-w-[8ch]">{v.rx}</span>
            </span>
            <span className={SEGMENT}>
              <ArrowUp strokeWidth={2} className="text-series-tx" />
              <span className="machine min-w-[8ch]">{v.tx}</span>
            </span>
            <span className={cn(SEGMENT, "max-lg:hidden")}>
              <Cable strokeWidth={2} className="text-fg-tertiary" />
              <span className="machine">{v.flows}</span>
            </span>
          </span>
        </button>
      }
    >
      <Panel
        rows={rows}
        total={total}
        onNavigate={() => {
          setOpen(false);
        }}
      />
    </Popover>
  );
}
