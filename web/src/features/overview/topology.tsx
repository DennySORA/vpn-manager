// Effect region A — traffic topology: what feeds each connection → the Instance → encrypted WireGuard tunnel → exit.
// A connection's sources, top to bottom: its local proxy ports (their ordinary proxy traffic only), SSH 下載 (VPN
// Manager's SSH download jobs through its ports), SSH 代理 (SSH sessions through its ports: `vpnctl ssh-proxy` and any
// connection to port 22) and, in strict isolation, its Apps' sandbox. Every source is a node with its live ↓／↑ and a
// lane of its own into the connection; SSH 下載 and SSH 代理 have their own colour (the series tokens), so they never
// read as ordinary proxy traffic, and nothing is counted twice (the SSH parts leave the ports' figures). Dashes flow
// along a lane while its source carries traffic and along a tunnel only while it is Ready and carrying traffic,
// faster with more traffic. Pause causes are independent: the user's toggle, a hidden page, the region scrolled out
// of view. These flows are the interface's only animation loop. Lanes come and go with the connections (presence)
// and slide into place (Motion layout); the nodes are tiles that lift on hover and press.

import { AppWindow, FolderDown, LogIn, Lock, MapPin, Pause, SquareTerminal, Workflow } from "lucide-react";
import { type CSSProperties, type ReactNode, useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router";
import { useLiveRatesMap, useSshHosts } from "@/api/queries";
import { useSshDownloads } from "@/api/ssh-downloads";
import type { AppView, InstanceView, LiveRates, SshHost } from "@/api/types";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import { latest } from "@/components/charts/rate-chart";
import { StatusPill } from "@/components/ui/badge";
import { DockHeader, DockPanel } from "@/components/ui/dock";
import { LIFT, STAGGER_IN } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { PresenceList } from "@/components/ui/presence-list";
import { CHIP_TONE } from "@/components/ui/tones";
import { ToolButton } from "@/components/ui/tool-strip";
import { sandboxApps, sandboxAppsLabel } from "@/features/apps/model";
import { KIND_LABEL } from "@/features/gateways/gateway-dialog";
import { type Flow, flowing, portKinds, SSH_PROXY_COLOR, SSH_PULL_COLOR } from "@/features/gateways/ssh-traffic";
import { instanceLook, locationText } from "@/features/instances/model";
import { entryAddressLabel } from "@/features/providers/model";
import { cityName } from "@/lib/places";
import { cn } from "@/lib/cn";
import { formatBps, joinList } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { usePageVisible } from "@/lib/use-media";
import { m } from "./messages";

/** A source node: its name (and count), then ↓ and ↑ on one line (the 196 px column holds the widest pair). */
const NODE_H = 44;
const GAP = 8;

/** A node of the path: a tile that lifts 1 px on hover and presses. */
const NODE = cn(LIFT, "active:scale-[0.98]");

/** What feeds a connection; each kind's lane has its colour (proxy ports and the App sandbox the brand blue). */
type SourceKind = "port" | "pull" | "proxy" | "sandbox";

const LANE_COLOR: Record<SourceKind, string> = {
  port: "var(--color-brand-blue)",
  pull: SSH_PULL_COLOR,
  proxy: SSH_PROXY_COLOR,
  sandbox: "var(--color-brand-blue)",
};

/** A source's lane: its kind and what it carries now (bit/s both ways; null: unknown). */
interface Lane {
  key: string;
  kind: SourceKind;
  bps: number | null;
}

/** States of an SSH download job that use its connection now (connecting, listing, downloading). */
const PULLING = new Set(["connecting", "scanning", "downloading"]);

/** Seconds per dash period: quantized so small rate changes do not restart the animation. */
function flowDuration(bps: number): number | null {
  if (bps < 8_000) return null;
  if (bps < 1_000_000) return 2.2;
  if (bps < 20_000_000) return 1.4;
  if (bps < 200_000_000) return 0.9;
  return 0.6;
}

function useInView<T extends Element>() {
  const ref = useRef<T>(null);
  const [inView, setInView] = useState(true);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      const e = entries[entries.length - 1];
      if (e) setInView(e.isIntersecting);
    });
    io.observe(el);
    return () => {
      io.disconnect();
    };
  }, []);
  return [ref, inView] as const;
}

/** Height of a column of `n` source nodes. */
function stackHeight(n: number): number {
  return n * NODE_H + Math.max(0, n - 1) * GAP;
}

/**
 * Curves from the middle of each source node (top to bottom) to the connection's tile, each in its kind's colour once
 * the connection is ready; dashes travel along the lane of a source that carries traffic.
 */
function FanIn({ lanes, height, active }: { lanes: readonly Lane[]; height: number; active: boolean }) {
  const yc = height / 2;
  const top = (height - stackHeight(lanes.length)) / 2;
  return (
    <svg aria-hidden width={44} height={height} className="hidden shrink-0 overflow-visible @min-[680px]:block">
      {lanes.map((lane, i) => {
        const y = top + i * (NODE_H + GAP) + NODE_H / 2;
        const d = `M0,${y} C22,${y} 22,${yc} 44,${yc}`;
        const color = active ? LANE_COLOR[lane.kind] : "var(--color-line-strong)";
        const duration = active && lane.bps !== null ? flowDuration(lane.bps) : null;
        return (
          <g key={lane.key}>
            <path
              d={d}
              className="topo-line transition-[stroke,stroke-opacity] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)"
              fill="none"
              stroke={color}
              strokeOpacity={active ? 0.55 : 1}
              strokeWidth={1.5}
            />
            {duration ? (
              <path
                d={d}
                fill="none"
                stroke={color}
                strokeWidth={2}
                strokeLinecap="round"
                strokeDasharray="4 8"
                className="topo-line topo-flow"
                style={{ "--flow-duration": `${duration}s` } as CSSProperties}
              />
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}

function Tunnel({ view, rates }: { view: InstanceView; rates: LiveRates | null }) {
  const gid = `tg${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const s = view.status;
  const ready = s?.phase === "ready" && !s.intent.emergency_latched;
  const total = rates ? rates.payload_rx_bps + rates.payload_tx_bps : 0;
  const duration = ready ? flowDuration(total) : null;
  const look = instanceLook(view);
  return (
    <div className="relative h-full min-w-24 flex-1 @max-[420px]:min-w-16">
      <svg aria-hidden className="absolute inset-0 h-full w-full overflow-visible">
        <defs>
          <linearGradient id={gid} gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="100%" y2="0">
            <stop offset="0" stopColor="var(--color-brand-blue)" />
            <stop offset="0.5" stopColor="var(--color-brand-iris)" />
            <stop offset="1" stopColor="var(--color-brand-cyan)" />
          </linearGradient>
        </defs>
        <line
          x1="0"
          y1="50%"
          x2="100%"
          y2="50%"
          className="topo-line"
          stroke={ready ? `url(#${gid})` : "var(--color-line-strong)"}
          strokeOpacity={ready ? 0.45 : 1}
          strokeWidth={ready ? 2 : 1.5}
          strokeDasharray={ready ? undefined : "4 6"}
        />
        {duration ? (
          <line
            x1="0"
            y1="50%"
            x2="100%"
            y2="50%"
            stroke={`url(#${gid})`}
            strokeWidth={3}
            strokeLinecap="round"
            strokeDasharray="6 18"
            className="topo-line topo-flow"
            style={{ "--flow-duration": `${duration}s` } as CSSProperties}
          />
        ) : null}
      </svg>
      {ready ? (
        <>
          {/* Above the line, so the whole tunnel (and its flow) stays visible. */}
          <div className="absolute inset-x-0 bottom-1/2 hidden justify-center px-2 pb-1.5 @min-[680px]:flex">
            <span className="machine inline-flex max-w-full items-center gap-1.5 truncate text-micro text-fg-secondary">
              <Lock aria-hidden className="size-3 shrink-0 text-action-fg" strokeWidth={2} />↓{" "}
              {formatBps(rates?.payload_rx_bps)} ↑ {formatBps(rates?.payload_tx_bps)}
            </span>
          </div>
          {/* Narrow: download above the line and upload below it, so neither number is cut. */}
          <div className="absolute inset-x-0 bottom-1/2 flex justify-center px-1 pb-1 @min-[680px]:hidden">
            <span className="machine inline-flex items-center gap-1 text-micro whitespace-nowrap text-fg-secondary">
              <Lock aria-hidden className="size-3 shrink-0 text-action-fg" strokeWidth={2} />↓{" "}
              {formatBps(rates?.payload_rx_bps)}
            </span>
          </div>
          <div className="absolute inset-x-0 top-1/2 flex justify-center px-1 pt-1 @min-[680px]:hidden">
            <span className="machine text-micro whitespace-nowrap text-fg-secondary">
              ↑ {formatBps(rates?.payload_tx_bps)}
            </span>
          </div>
        </>
      ) : (
        // A stopped or blocked tunnel is broken at the point where the state is named (in a narrow lane only its icon:
        // the connection's tile beside it names the state).
        <div className="absolute inset-0 flex items-center justify-center px-2">
          <StatusPill look={look} className="h-5.5 bg-surface @max-[420px]:hidden" />
          <span
            aria-hidden
            title={look.label}
            className={cn(
              "hidden size-6 place-items-center rounded-full border bg-surface @max-[420px]:grid",
              CHIP_TONE[look.tone],
            )}
          >
            <look.icon className={cn("size-3.5", look.busy && "animate-spin")} strokeWidth={2} />
          </span>
        </div>
      )}
    </div>
  );
}

/**
 * One source of a connection: a tile with its name (an icon or the port first, a count last) and its live ↓／↑ on a
 * second line; without a fresh sample the rates are unknown (—), never 0. `idle`: nothing it would carry runs.
 */
function SourceNode({
  to,
  title,
  label,
  lead,
  aside,
  flow,
  idle = false,
  failed = false,
}: {
  to: string;
  /** Tooltip and accessible name. */
  title: string;
  label: ReactNode;
  lead?: ReactNode;
  aside?: string | undefined;
  flow: Flow | null;
  idle?: boolean;
  failed?: boolean;
}) {
  const down = flow ? formatBps(flow.rx) : "—";
  const up = flow ? formatBps(flow.tx) : "—";
  return (
    <Link
      to={to}
      style={{ height: NODE_H }}
      title={title}
      aria-label={m.node(title, down, up)}
      className={cn(
        NODE,
        "flex min-w-0 flex-col justify-center gap-0.5 rounded-md border bg-sunken px-2.5 no-underline hover:border-line-control",
        failed ? "border-danger/45" : idle ? "border-dashed border-line-strong" : "border-line",
      )}
    >
      <span className="flex min-w-0 items-center gap-1.5">
        {lead}
        <span className={cn("min-w-0 flex-1 truncate text-caption", idle ? "text-fg-tertiary" : "text-fg-secondary")}>
          {label}
        </span>
        {aside ? <span className="machine shrink-0 text-micro text-fg-tertiary">{aside}</span> : null}
      </span>
      <span className="machine flex gap-x-2 text-micro whitespace-nowrap text-fg-secondary">
        <span>↓ {down}</span>
        <span>↑ {up}</span>
      </span>
    </Link>
  );
}

/** The SSH sources of a connection: its SSH download jobs and the SSH hosts set to go through its proxy ports. */
function sshSources(view: InstanceView, jobs: readonly SshDownloadView[], hosts: readonly SshHost[]) {
  const ports = new Set(view.gateways.map((g) => g.id));
  return {
    jobs: jobs.filter((j) => ports.has(j.job.gateway_id)),
    hosts: hosts.filter((h) => h.gateway_id !== null && ports.has(h.gateway_id)),
  };
}

function ConnectionLane({
  view,
  apps,
  jobs,
  hosts,
  samples,
  now,
}: {
  view: InstanceView;
  apps: AppView[];
  jobs: readonly SshDownloadView[];
  hosts: readonly SshHost[];
  samples: LiveRates[] | undefined;
  now: number;
}) {
  const s = view.status;
  const ready = s?.phase === "ready" && !s.intent.emergency_latched;
  const rates = latest(samples, now);
  const kinds = rates ? portKinds(rates.gateways) : null;
  const sandbox = sandboxApps(apps, view.spec.id);
  const ssh = sshSources(view, jobs, hosts);
  const pulling = ssh.jobs.filter((j) => PULLING.has(j.status?.state ?? "")).length;
  const showPull = ssh.jobs.length > 0 || (kinds !== null && flowing(kinds.pull));
  const showProxy = ssh.hosts.length > 0 || (kinds !== null && (flowing(kinds.proxy) || kinds.sessions > 0));
  const both = (f: Flow | null) => (f ? f.rx + f.tx : null);

  const nodes: { lane: Lane; node: ReactNode }[] = view.gateways.map((g) => {
    const failed = s?.gateways.find((r) => r.gateway_id === g.id)?.state === "failed";
    const own = rates?.gateways.find((r) => r.gateway_id === g.id);
    // The port's ordinary proxy traffic: its SSH parts have nodes of their own.
    const flow = own ? portKinds([own]).other : null;
    return {
      lane: { key: `port:${g.id}`, kind: "port", bps: both(flow) },
      node: (
        <SourceNode
          key={g.id}
          to={`/gateways/${g.id}`}
          title={m.port.title(g.name, g.port, KIND_LABEL[g.kind], failed, g.enabled)}
          lead={
            <span
              className={cn(
                "machine shrink-0 text-data leading-none",
                failed ? "text-danger" : g.enabled ? "text-fg" : "text-fg-tertiary",
              )}
            >
              :{g.port}
            </span>
          }
          label={g.name}
          flow={flow}
          idle={!g.enabled}
          failed={failed}
        />
      ),
    };
  });
  if (showPull) {
    const first = ssh.jobs.length === 1 ? ssh.jobs[0] : undefined;
    const count = ssh.jobs.length ? m.pull.count(pulling, ssh.jobs.length) : undefined;
    nodes.push({
      lane: { key: "pull", kind: "pull", bps: both(kinds?.pull ?? null) },
      node: (
        <SourceNode
          key="pull"
          to={first ? `/ssh-downloads/${first.job.id}` : "/ssh-downloads"}
          title={m.pull.title(ssh.jobs.length, pulling)}
          lead={<FolderDown aria-hidden className="size-3.5 shrink-0 text-series-ssh-pull" strokeWidth={2} />}
          label={m.pull.label}
          aside={count}
          flow={kinds?.pull ?? null}
          idle={!pulling && !(kinds && flowing(kinds.pull))}
        />
      ),
    });
  }
  if (showProxy) {
    const sessions = kinds ? kinds.sessions : null;
    nodes.push({
      lane: { key: "proxy", kind: "proxy", bps: both(kinds?.proxy ?? null) },
      node: (
        <SourceNode
          key="proxy"
          to="/ssh"
          title={m.proxy.title(sessions)}
          lead={<SquareTerminal aria-hidden className="size-3.5 shrink-0 text-series-ssh-proxy" strokeWidth={2} />}
          label={m.proxy.label}
          aside={sessions === null ? undefined : m.proxy.sessions(sessions)}
          flow={kinds?.proxy ?? null}
          idle={!sessions && !(kinds && flowing(kinds.proxy))}
        />
      ),
    });
  }
  const first = sandbox[0];
  if (first) {
    const running = sandbox.filter((a) => a.status?.state === "running").length;
    const flow = rates?.sandbox ? { rx: rates.sandbox.rx_bps, tx: rates.sandbox.tx_bps } : null;
    nodes.push({
      lane: { key: "sandbox", kind: "sandbox", bps: both(flow) },
      node: (
        <SourceNode
          key="sandbox"
          to={`/apps/${first.spec.id}`}
          title={m.sandbox.title(
            sandbox.map((a) => a.spec.name),
            running,
          )}
          lead={
            <AppWindow
              aria-hidden
              className={cn("size-3.5 shrink-0", running ? "text-entity" : "text-fg-tertiary")}
              strokeWidth={2}
            />
          }
          label={sandboxAppsLabel(sandbox)}
          flow={flow}
          idle={!running}
        />
      ),
    });
  }
  const lanes = nodes.length ? nodes.map((n) => n.lane) : [{ key: "none", kind: "port" as const, bps: null }];
  const height = Math.max(56, stackHeight(lanes.length));
  const where = locationText(view);
  const endpoint = s?.tunnel?.endpoint ?? view.profile?.endpoint;
  return (
    <div
      className="flex flex-col @min-[680px]:h-(--lane-h) @min-[680px]:flex-row @min-[680px]:items-center"
      style={{ "--lane-h": `${height}px` } as CSSProperties}
    >
      {/* Wide: one column of exactly 196 px. It must not wrap: a wrapping column takes its widest node's full text
          width, and the nodes (stretched to it) would run into the connection's tile instead of truncating. */}
      <div className="flex flex-wrap gap-2 @min-[680px]:w-[196px] @min-[680px]:shrink-0 @min-[680px]:flex-col @min-[680px]:flex-nowrap">
        {nodes.length ? (
          nodes.map((n) => n.node)
        ) : (
          <div
            style={{ height: NODE_H }}
            className="flex items-center justify-center rounded-md border border-dashed border-line-strong text-caption text-fg-tertiary"
          >
            {m.lane.noGateways}
          </div>
        )}
      </div>
      {/* Narrow: the sources sit above the connection, joined by a short stem. */}
      <div
        aria-hidden
        className={cn(
          "ml-6 h-3 border-l-[1.5px] @min-[680px]:hidden forced-colors:border-[CanvasText]",
          ready ? "border-brand-blue/55" : "border-line-strong",
        )}
      />
      <FanIn lanes={lanes} height={height} active={ready} />
      <div className="flex h-14 min-w-0 items-center @min-[680px]:h-full @min-[680px]:flex-1">
        <Link
          to={`/instances/${view.spec.id}`}
          title={view.spec.name}
          className={cn(
            NODE,
            "flex h-14 w-[188px] min-w-[136px] flex-col justify-center gap-1 rounded-lg border bg-raised px-3 no-underline hover:border-line-control @max-[420px]:min-w-[112px] @max-[420px]:px-2.5",
            ready ? "border-brand-blue/50" : "border-line-strong",
          )}
        >
          <span className="truncate text-data font-medium text-fg">{view.spec.name}</span>
          <span className="truncate text-micro text-fg-tertiary">
            {instanceLook(view).label}
            {s?.running ? ` · ${m.lane.generation(s.running.generation)}` : ""}
          </span>
        </Link>
        <Tunnel view={view} rates={rates} />
        <ExitNodes view={view} ready={ready} where={where} endpoint={endpoint ?? null} />
      </div>
    </div>
  );
}

const PLACE_NODE =
  "flex h-14 min-w-0 flex-col justify-center gap-0.5 rounded-lg border px-3 transition-colors duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) @max-[420px]:px-2.5";

/**
 * Where the tunnel goes in and comes out: one exit node when it enters at the exit server (its entry address, when
 * another than the default, on the second line: same server), or 入口 → 出口 when it enters at another relay
 * (multihop).
 */
function ExitNodes({
  view,
  ready,
  where,
  endpoint,
}: {
  view: InstanceView;
  ready: boolean;
  where: string | null;
  endpoint: string | null;
}) {
  const entry = view.profile?.entry ?? null;
  const exitServer = view.profile?.location?.server ?? null;
  const look = ready ? "border-brand-cyan/40 bg-sunken" : "border-line bg-sunken/60";
  const pin = (Icon: typeof MapPin) => (
    <Icon
      aria-hidden
      className={cn("size-3.5 shrink-0", ready ? "text-brand-cyan" : "text-fg-tertiary")}
      strokeWidth={2}
    />
  );
  if (entry?.kind === "relay") {
    const entryPlace = entry.city ? cityName(entry.city) : (entry.country ?? entry.server_id);
    return (
      <div className="flex min-w-0 items-center" aria-label={m.exit.route(entry.server_id, exitServer ?? where ?? "")}>
        <div
          title={`${m.exit.entryTitle(entry.server_id)}${endpoint ? `\n${endpoint}` : ""}`}
          className={cn(PLACE_NODE, "w-[128px] min-w-[104px] gap-0", look)}
        >
          <span className="text-micro leading-tight text-fg-tertiary">{m.exit.entry}</span>
          <span className="flex items-center gap-1.5 truncate text-data leading-tight text-fg">
            {pin(LogIn)}
            <span className="truncate">{entryPlace}</span>
          </span>
          <span className="machine truncate text-micro leading-tight text-fg-tertiary">{entry.server_id}</span>
        </div>
        <div
          aria-hidden
          className={cn(
            "h-[1.5px] w-3 shrink-0 forced-colors:bg-[CanvasText]",
            ready ? "bg-brand-cyan/55" : "bg-line-strong",
          )}
        />
        <div
          title={[where, exitServer].filter(Boolean).join("\n") || undefined}
          className={cn(PLACE_NODE, "w-[140px] min-w-[112px] gap-0", look)}
        >
          <span className="text-micro leading-tight text-fg-tertiary">{m.exit.exit}</span>
          <span className="flex items-center gap-1.5 truncate text-data leading-tight text-fg">
            {pin(MapPin)}
            <span className="truncate">{where ?? m.exit.noPlace}</span>
          </span>
          <span className="machine truncate text-micro leading-tight text-fg-tertiary">{exitServer ?? "—"}</span>
        </div>
      </div>
    );
  }
  // AirVPN has no multihop: another entry is another address and port of the same server.
  const second = entry?.kind === "address" ? entryAddressLabel(entry) : endpoint;
  return (
    <div
      title={
        [where, entry?.kind === "address" ? m.exit.sameServer(entryAddressLabel(entry)) : null, endpoint]
          .filter(Boolean)
          .join("\n") || undefined
      }
      className={cn(PLACE_NODE, "w-[180px] min-w-[136px] @max-[420px]:min-w-[104px]", look)}
    >
      <span className="flex items-center gap-1.5 truncate text-data text-fg">
        {pin(MapPin)}
        <span className="truncate">{where ?? m.exit.noPlace}</span>
      </span>
      <span className="machine truncate text-micro text-fg-tertiary">{second ?? "—"}</span>
    </div>
  );
}

export function Topology({
  views,
  apps,
  liveIds,
  index = 0,
}: {
  views: InstanceView[];
  /** Every managed App: a connection's strict ones are drawn as its App sandbox. */
  apps: AppView[];
  /** The running connections whose live rates the lanes show (read here, so only the topology re-renders per tick). */
  liveIds: string[];
  index?: number;
}) {
  const live = useLiveRatesMap(liveIds);
  // SSH download jobs (their statuses arrive with the event stream) and SSH hosts: the lanes' SSH sources.
  const jobs = useSshDownloads().data ?? [];
  const hosts = useSshHosts().data ?? [];
  const [ref, inView] = useInView<HTMLElement>();
  const visible = usePageVisible();
  const [userPaused, setUserPaused] = useState(false);
  const now = useServerNow();
  const playing = !userPaused && visible && inView;
  const kinds = [m.path.ports];
  if (views.some((v) => sshSources(v, jobs, []).jobs.length)) kinds.push(m.pull.label);
  if (views.some((v) => sshSources(v, [], hosts).hosts.length)) kinds.push(m.proxy.label);
  if (views.some((v) => sandboxApps(apps, v.spec.id).length)) kinds.push(m.sandbox.label);
  return (
    <DockPanel ref={ref} aria-labelledby="topo-title" style={staggerStyle(index)} className={STAGGER_IN}>
      <DockHeader
        icon={<Workflow aria-hidden />}
        title={m.path.title}
        titleId="topo-title"
        actions={
          // A toggle: pressed = the flow is paused by you (hidden pages and an off-screen region pause it on their own).
          <ToolButton
            label={m.path.pause}
            text={m.path.pause}
            icon={<Pause aria-hidden />}
            pressed={userPaused}
            onClick={() => {
              setUserPaused((p) => !p);
            }}
          />
        }
      />
      <p className="px-3 pt-2 text-caption text-fg-tertiary">
        {m.path.legend(
          joinList(kinds),
          views.some((v) => v.profile?.entry?.kind === "relay"),
        )}
      </p>
      <div className="relative @container overflow-x-auto px-4 pt-3 pb-4 md:px-5">
        <PresenceList
          items={views}
          keyOf={(v) => v.spec.id}
          className={cn("space-y-4", !playing && "topo-paused")}
          label={m.path.lanes}
        >
          {(v) => (
            <ConnectionLane view={v} apps={apps} jobs={jobs} hosts={hosts} samples={live.get(v.spec.id)} now={now} />
          )}
        </PresenceList>
      </div>
    </DockPanel>
  );
}
