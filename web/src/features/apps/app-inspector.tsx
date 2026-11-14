// The evidence inspector of one managed App (docs/frontend-design.md §8.1): what runs (identity, tree, listeners,
// denials, output, and for a strict App its sandbox's live traffic) and why it is not running when it should; every
// fact says where it came from, and what was not measured says so. The EntityHeader carries the App's state and its frequent actions (停止／啟動, 編輯, the ⋯ menu — the
// same menu as its list row); the fixed footer is the executable check, the view's primary action. In between, the
// views are tabs (`?tab=`): 概況 (the conclusion and 執行), 流量 (a strict App's sandbox), 程序 (tree and limits), 連接埠
// (what it listens on, how the host and the provider reach it), 輸出 and 設定 (executable and settings). A problem
// (an error, settings not applied, a connection not ready, an unprotected mode) leads every tab.

import {
  Activity,
  AppWindow,
  FileCode2,
  Gauge,
  ListTree,
  RadioTower,
  RefreshCw,
  ScrollText,
  Settings2,
  Waypoints,
} from "lucide-react";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router";
import { useAppLog, useAppProcesses, useCapabilities, useForwards, useSystemStatus } from "@/api/queries";
import type { AppIsolation, AppProcess, AppView, GatewaySpec, InstanceView } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import type { EntityAction } from "@/components/ui/action-model";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ChangeValue } from "@/components/ui/change-value";
import { CopyButton } from "@/components/ui/copy";
import { FooterActions, HeaderActions } from "@/components/ui/entity-actions";
import { HelpButton, HelpText } from "@/components/ui/help-tip";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  InspectorTab,
  InspectorTabs,
  PropertyGrid,
  PropertyRow,
  PropertySection,
} from "@/components/ui/inspector";
import { TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorCallout, Skeleton } from "@/components/ui/states";
import { TBody, Tr } from "@/components/ui/table";
import { ToolButton } from "@/components/ui/tool-strip";
import { forwardLook, PROTOCOL_LABEL } from "@/features/forwards/model";
import { KIND_LABEL } from "@/features/gateways/gateway-dialog";
import { instanceLook } from "@/features/instances/model";
import { limitsText } from "@/features/limits/model";
import { ResourceFacts } from "@/features/limits/resource-facts";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, formatBytes, relativeTime } from "@/lib/format";
import { useTabParam } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { AccessPortsSection } from "./access-status";
import { useAppActions } from "./action-host";
import { SandboxRateRow, SandboxTraffic } from "./sandbox-traffic";
import type { AppActionId } from "./actions";
import { m as inspector } from "./inspector/messages";
import { m } from "./messages";
import {
  appLook,
  approvalProblem,
  appTraffic,
  CLASS_LABEL,
  classArgs,
  classNote,
  ISOLATION,
  mayHandOff,
  modeAvailability,
  pendingConfig,
  plainText,
  shortDigest,
  usesWritable,
} from "./model";

const LOG_LINES = 200;

function formatCpu(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 600) return `${s.toFixed(1)} s`;
  const minutes = Math.floor(s / 60);
  return minutes < 600
    ? inspector.minutesSeconds(minutes, Math.round(s % 60))
    : inspector.hours(Math.round(minutes / 60));
}

function exitText(code: number | null, signal: number | null): string {
  if (code !== null) return inspector.exitCode(code);
  if (signal !== null) {
    const names: Record<number, string> = { 9: "SIGKILL", 15: "SIGTERM", 2: "SIGINT", 6: "SIGABRT", 11: "SIGSEGV" };
    return inspector.signal(signal, names[signal]);
  }
  return inspector.exitUnknown;
}

/** Depth of each process in its tree (by parent pid within the listed processes). */
function depths(list: AppProcess[]): Map<number, number> {
  const parent = new Map(list.map((p) => [p.pid, p.ppid]));
  const out = new Map<number, number>();
  for (const p of list) {
    let d = 0;
    let cur = p.ppid;
    while (parent.has(cur) && d < 8) {
      d += 1;
      cur = parent.get(cur) ?? 0;
    }
    out.set(p.pid, d);
  }
  return out;
}

/** The same action as the header's or the menu's, offered next to what it fixes (one name, icon and run). */
function InlineAction({ action }: { action: EntityAction | undefined }) {
  if (!action) return null;
  return (
    <ActionButton
      size="sm"
      icon={action.icon}
      pending={action.pending}
      pendingLabel={action.pendingLabel}
      disabledReason={action.pending ? null : action.disabledReason}
      onClick={action.run}
    >
      {action.label}
    </ActionButton>
  );
}

const CELL = "border-b border-line-subtle px-2 py-1 align-middle";

function ProcessTree({ app, running }: { app: AppView; running: boolean }) {
  const procs = useAppProcesses(app.spec.id, running);
  const list = procs.data?.processes ?? [];
  const depth = depths(list);
  if (!running && !list.length) return <p className="text-caption text-fg-tertiary">{inspector.noProcesses}</p>;
  if (procs.isPending)
    return (
      <div role="status" aria-label={inspector.readingProcesses} className="grid grid-cols-1 gap-1.5">
        <Skeleton className="w-full" />
        <Skeleton className="w-2/3" />
      </div>
    );
  if (procs.isError && !procs.data)
    return (
      <ErrorCallout
        error={procs.error}
        title={inspector.processesFailed}
        onRetry={() => void procs.refetch()}
        retrying={procs.isFetching}
      />
    );
  return (
    <div className="grid grid-cols-1 gap-1.5">
      <div className="scroll-x-fade relative overflow-x-auto rounded-md border border-line-subtle">
        <table
          className="w-full min-w-[280px] border-separate border-spacing-0 text-caption"
          aria-label={inspector.processTree}
        >
          <thead>
            {/* The numeric columns shrink to their values; the program name takes the rest. */}
            <tr className="bg-sunken text-fg-tertiary">
              <th scope="col" className={cn(CELL, "w-px py-1.5 text-left font-medium whitespace-nowrap")}>
                PID
              </th>
              <th scope="col" className={cn(CELL, "py-1.5 text-left font-medium")}>
                {inspector.program}
              </th>
              <th scope="col" className={cn(CELL, "w-px py-1.5 text-right font-medium whitespace-nowrap")}>
                {inspector.cpuTime}
              </th>
              <th scope="col" className={cn(CELL, "w-px py-1.5 text-right font-medium whitespace-nowrap")}>
                {inspector.memory}
              </th>
            </tr>
          </thead>
          <TBody items={list} keyOf={(p) => `${p.pid}:${p.started_at}`}>
            {(p, row) => (
              <Tr index={row.index} exiting={row.exiting} className="[&:last-child>td]:border-b-0">
                <td className={cn(CELL, "machine w-px whitespace-nowrap text-fg-secondary")}>{p.pid}</td>
                <td
                  className={cn(CELL, "max-w-0")}
                  title={inspector.processTitle(p.name, p.ppid, absoluteTime(p.started_at))}
                >
                  <span className="block truncate text-fg" style={{ paddingLeft: `${(depth.get(p.pid) ?? 0) * 12}px` }}>
                    {(depth.get(p.pid) ?? 0) > 0 ? <span className="text-fg-disabled">└ </span> : null}
                    {p.name}
                  </span>
                </td>
                <td className={cn(CELL, "machine w-px text-right whitespace-nowrap text-fg-secondary")}>
                  {formatCpu(p.cpu_ms)}
                </td>
                <td className={cn(CELL, "machine w-px text-right whitespace-nowrap text-fg-secondary")}>
                  {p.rss_bytes === null ? "—" : formatBytes(p.rss_bytes)}
                </td>
              </Tr>
            )}
          </TBody>
        </table>
      </div>
      <p className="text-caption text-fg-tertiary">
        {inspector.processSummary(
          <ChangeValue value={list.length} className="machine" />,
          relativeTime(procs.data.observed_at),
          procs.data.truncated,
          list.length,
        )}
      </p>
    </div>
  );
}

function Listeners({ app }: { app: AppView }) {
  const s = app.status;
  if (!s?.listeners) return <p className="text-caption text-fg-tertiary">{inspector.notMeasured}</p>;
  return (
    <div className="grid grid-cols-1 gap-2">
      {s.listeners.length ? (
        <PresenceList
          items={s.listeners}
          keyOf={(l) => `${l.pid}-${l.address}`}
          className="grid grid-cols-1 gap-1"
          label={inspector.listenersOf(app.spec.name)}
        >
          {(l) => (
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span className="machine text-data text-fg">{l.address}</span>
              {l.loopback ? <Tag tone="neutral">{m.loopbackOnly}</Tag> : <Tag tone="danger">{inspector.reachable}</Tag>}
              <span className="machine ml-auto text-micro text-fg-tertiary">PID {l.pid}</span>
            </div>
          )}
        </PresenceList>
      ) : (
        <p className="text-caption text-fg-tertiary">{inspector.noListeners}</p>
      )}
      {s.isolation === "enforced_proxy" ? (
        <p className="text-caption text-fg-tertiary">{inspector.enforcedListeners}</p>
      ) : null}
    </div>
  );
}

/** Port forwards that deliver inbound connections to this App; the section's action is the menu's 新增轉發. */
function ForwardsSection({ app, add }: { app: AppView; add: EntityAction<AppActionId> | undefined }) {
  const forwards = useForwards();
  const mine = (forwards.data ?? []).filter((f) => f.binding.target_app_id === app.spec.id);
  return (
    <PropertySection
      title={inspector.forwards}
      icon={<Waypoints aria-hidden />}
      count={forwards.data ? mine.length : null}
      actions={
        add ? (
          <ToolButton
            label={add.label}
            icon={<add.icon aria-hidden />}
            disabledReason={add.disabledReason}
            onClick={add.run}
          />
        ) : null
      }
    >
      {forwards.isPending ? (
        <Skeleton className="w-2/3" />
      ) : mine.length ? (
        <PresenceList
          items={mine}
          keyOf={(f) => f.binding.id}
          className="grid grid-cols-1 gap-2"
          label={inspector.forwardsTo(app.spec.name)}
        >
          {(f) => (
            <div className="grid grid-cols-1 gap-1 rounded-lg border border-line-subtle bg-sunken/50 px-3 py-2.5">
              <div className="flex min-w-0 items-center gap-2">
                <Link
                  to={`/forwards/${f.binding.id}`}
                  className="min-w-0 truncate text-data font-medium text-fg underline-offset-2 hover:underline active:opacity-70"
                >
                  {f.binding.name}
                </Link>
                <span className="ml-auto shrink-0">
                  <StatusPill look={forwardLook(f)} />
                </span>
              </div>
              <p className="machine text-caption text-fg-secondary">
                {PROTOCOL_LABEL[f.binding.protocol]} tunnel :{f.binding.tunnel_port} → 127.0.0.1:{f.binding.target_port}
              </p>
            </div>
          )}
        </PresenceList>
      ) : (
        <EmptyState compact icon={Waypoints} title={inspector.noForwards}>
          {inspector.noForwardsHint}
        </EmptyState>
      )}
    </PropertySection>
  );
}

function OutputLog({ app, running }: { app: AppView; running: boolean }) {
  const log = useAppLog(app.spec.id, running, LOG_LINES);
  const box = useRef<HTMLPreElement>(null);
  const [follow, setFollow] = useState(true);
  const lines = log.data?.lines;
  // New lines keep the view at the bottom unless the reader scrolled up.
  useEffect(() => {
    const el = box.current;
    if (el && follow) el.scrollTop = el.scrollHeight;
  }, [lines, follow]);
  return (
    <PropertySection
      title={inspector.outputLog}
      icon={<ScrollText aria-hidden />}
      actions={
        <ToolButton
          label={inspector.refreshLog}
          icon={<RefreshCw aria-hidden />}
          pending={log.isFetching && !log.isPending}
          onClick={() => void log.refetch()}
        />
      }
    >
      {log.isPending ? (
        <div role="status" aria-label={inspector.readingLog} className="grid grid-cols-1 gap-1.5">
          <Skeleton className="w-full" />
          <Skeleton className="w-4/5" />
          <Skeleton className="w-3/5" />
        </div>
      ) : log.isError && !log.data ? (
        <ErrorCallout
          error={log.error}
          title={inspector.logFailed}
          onRetry={() => void log.refetch()}
          retrying={log.isFetching}
        />
      ) : !lines?.length ? (
        <p className="text-caption text-fg-tertiary">{inspector.noOutput}</p>
      ) : (
        <div className="grid grid-cols-1 gap-1.5">
          <pre
            ref={box}
            // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable log must be reachable to scroll it from the keyboard
            tabIndex={0}
            aria-label={inspector.outputLabel}
            onScroll={(e) => {
              const el = e.currentTarget;
              setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
            }}
            // Its own tab: the log takes about the height the tab leaves it (at least 18 rem), so one scroll owner shows.
            className="relative max-h-[max(18rem,calc(100dvh-35rem))] overflow-auto rounded-md border border-line-subtle bg-sunken px-2.5 py-2 font-mono text-micro whitespace-pre-wrap text-fg-secondary [overflow-wrap:anywhere] focus-visible:outline-2 focus-visible:outline-focus"
          >
            {lines.map((line, i) => (
              // Lines repeat and have no identity of their own: their position within one answer is it.
              <div key={i} className={cn(line.startsWith("--- vpn-manager:") && "text-fg-tertiary")}>
                {plainText(line) || " "}
              </div>
            ))}
          </pre>
          <p className="text-caption text-fg-tertiary">{inspector.logSummary(lines.length, log.data.truncated)}</p>
        </div>
      )}
    </PropertySection>
  );
}

/** The isolation applied to the running tree; what it does not do sits behind its (?) instead of a long paragraph. */
function IsolationValue({ mode }: { mode: AppIsolation }) {
  const info = ISOLATION[mode];
  const [open, setOpen] = useState(false);
  const helpId = useId();
  return (
    <>
      <span className="flex items-center gap-1">
        {info.title}
        <HelpButton
          open={open}
          onToggle={() => {
            setOpen((o) => !o);
          }}
          controls={helpId}
          label={info.title}
          text={info.limit}
          className="-my-1"
        />
      </span>
      <HelpText id={helpId} open={open}>
        {info.limit}
      </HelpText>
    </>
  );
}

/** The footer's line: what the executable check compares with (the approved file), or why a start waits for it. */
function ApprovalNote({ app }: { app: AppView }) {
  const problem = approvalProblem(app);
  const a = app.spec.approval;
  if (problem) return <span className="text-warning">{m.approvalProblem.sentence(problem)}</span>;
  if (!a) return null;
  return (
    <span>
      {inspector.approvedNote(<span className="machine">{shortDigest(a.sha256)}</span>, absoluteTime(a.approved_at))}
    </span>
  );
}

export type AppTab = "overview" | "traffic" | "processes" | "ports" | "output" | "settings";

const APP_TAB_LABEL: Record<AppTab, string> = {
  overview: ui.common.overview,
  traffic: m.traffic,
  processes: m.processes,
  ports: inspector.tab.ports,
  output: inspector.tab.output,
  settings: m.settings,
};

/** The inspector's tabs: 流量 only for a strict App (the only one with a sandbox of its own connection). */
export function appTabs(isolation: AppIsolation): AppTab[] {
  return isolation === "strict_netns"
    ? ["overview", "traffic", "processes", "ports", "output", "settings"]
    : ["overview", "processes", "ports", "output", "settings"];
}

export function AppInspector({
  app,
  owner,
  gateway,
}: {
  app: AppView;
  owner: InstanceView | undefined;
  gateway: GatewaySpec | undefined;
}) {
  const now = useServerNow();
  const caps = useCapabilities();
  const sys = useSystemStatus();
  const actions = useAppActions(app);
  const action = (id: AppActionId) => actions.find((a) => a.id === id);

  const s = app.status;
  const look = appLook(app);
  const mode = ISOLATION[app.spec.isolation];
  const strict = app.spec.isolation === "strict_netns";
  const running = s?.state === "running";
  const traffic = appTraffic(app, owner?.spec.name ?? null);
  const pending = pendingConfig(app);
  const needsApproval = approvalProblem(app) !== null;
  const home = sys.data?.data_dir ? `${sys.data.data_dir}/apps/${app.spec.id}/home` : null;
  // What the approved file was recognised as (every start checks the file again).
  const appClass = app.spec.approval?.app_class ?? null;
  const injected = classArgs(appClass?.class).map((a) => (home ? a.replace("{app_home}", home) : a));
  const ownerLook = owner ? instanceLook(owner) : null;
  // The connection is not ready: what the proxy refuses meanwhile (a strict App has no proxy).
  const waitsForConnection = running && owner && owner.status?.phase !== "ready" && !strict;
  const availability = modeAvailability(app.spec.isolation, caps.data);
  const tabs = appTabs(app.spec.isolation);
  const [tab, setTab] = useTabParam<AppTab>("tab", tabs);

  // The conclusion. A problem, and the warning of a mode that protects nothing by itself, lead every tab; the plain
  // explanation of what the isolation does leads 概況.
  const explained = !s?.last_error || app.spec.isolation === "proxy_env" ? traffic : null;
  const lead = (overview: boolean): ReactNode[] | null => {
    const items = [
      s?.last_error ? (
        <Callout
          key="error"
          tone={look.tone === "danger" ? "danger" : "warning"}
          icon={look.icon}
          title={look.label}
          actions={
            needsApproval ? (
              <InlineAction action={action("approve")} />
            ) : s.last_error.code === "APP_STOP_UNCONFIRMED" ? (
              <InlineAction action={action("stop")} />
            ) : undefined
          }
        >
          <p className="[overflow-wrap:anywhere]">{localized(s.last_error.message)}</p>
          <p className="machine mt-1 text-micro text-fg-tertiary">
            {s.last_error.code} · {relativeTime(s.last_error.at, now)}
          </p>
        </Callout>
      ) : null,
      explained && (overview || explained.tone === "warning") ? (
        <Callout key="traffic" tone={explained.tone} title={explained.title}>
          {explained.text}
        </Callout>
      ) : null,
      waitsForConnection && ownerLook ? (
        <Callout key="waits" tone="info" title={inspector.connectionState(owner.spec.name, ownerLook.label)}>
          {inspector.waitsForConnection}
        </Callout>
      ) : null,
      pending ? (
        <Callout
          key="pending"
          tone="warning"
          title={inspector.notApplied}
          actions={<InlineAction action={action("restart")} />}
        >
          {pending}
        </Callout>
      ) : null,
    ].filter(Boolean);
    return items.length ? items : null;
  };

  return (
    <InspectorFrame
      tabbed
      header={
        <EntityHeader
          icon={AppWindow}
          tone="entity"
          title={app.spec.name}
          status={<StatusPill look={look} title={s?.last_error ? localized(s.last_error.message) : undefined} />}
          description={
            <span className="grid grid-cols-1 gap-1.5">
              <span className="machine truncate" title={app.spec.executable}>
                {app.spec.executable}
              </span>
              <span className="flex flex-wrap items-center gap-1.5">
                <Tag tone={app.spec.isolation === "proxy_env" ? "warning" : "neutral"} icon={mode.icon}>
                  {mode.short}
                </Tag>
                {appClass ? (
                  <Tag tone={mayHandOff(appClass.class) ? "warning" : "neutral"}>{CLASS_LABEL[appClass.class]}</Tag>
                ) : null}
                {s?.pid ? <span className="machine text-micro text-fg-tertiary">PID {s.pid}</span> : null}
              </span>
            </span>
          }
          id={app.spec.id}
          idLabel={inspector.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={inspector.actionsOf(app.spec.name)} />}
        />
      }
      footer={
        <InspectorFooter note={<ApprovalNote app={app} />}>
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      <InspectorTabs
        label={inspector.viewsOf(app.spec.name)}
        value={tab}
        onChange={setTab}
        items={tabs.map((t) => ({ value: t, label: APP_TAB_LABEL[t] }))}
      >
        <InspectorTab value="overview" lead={lead(true)}>
          <PropertySection title={inspector.runtime} icon={<Activity aria-hidden />}>
            <PropertyGrid>
              <PropertyRow
                label={ui.common.status}
                hint={s ? inspector.observed(relativeTime(s.observed_at, now)) : undefined}
              >
                {s ? look.label : inspector.unknownState}
              </PropertyRow>
              <PropertyRow
                label={inspector.rootProcess}
                mono
                hint={s?.started_at ? inspector.startedAt(absoluteTime(s.started_at), Boolean(s.pid)) : undefined}
              >
                {s?.pid ? `PID ${s.pid}` : "—"}
              </PropertyRow>
              <PropertyRow label={inspector.processCount} mono>
                <ChangeValue value={s?.process_count ?? null}>{s?.process_count ?? "—"}</ChangeValue>
              </PropertyRow>
              {strict ? <SandboxRateRow owner={owner} /> : null}
              <PropertyRow label={inspector.isolation}>
                {s?.isolation ? <IsolationValue mode={s.isolation} /> : m.noRunningProcess}
              </PropertyRow>
              {!strict ? (
                <PropertyRow label={m.gateway} mono>
                  {s?.gateway_port ? (
                    gateway ? (
                      <Link to={`/gateways/${gateway.id}`} className={TEXT_LINK}>
                        127.0.0.1:{s.gateway_port}
                      </Link>
                    ) : (
                      `127.0.0.1:${s.gateway_port}`
                    )
                  ) : (
                    "—"
                  )}
                </PropertyRow>
              ) : null}
              {s?.isolation === "enforced_proxy" || app.spec.isolation === "enforced_proxy" ? (
                <PropertyRow label={inspector.seatbeltDenials} mono hint={inspector.seatbeltDenialsHint}>
                  {s?.isolation !== "enforced_proxy" ? (
                    "—"
                  ) : s.sandbox_denials === null ? (
                    <span className="font-sans">{inspector.systemLogUnreadable}</span>
                  ) : (
                    <ChangeValue value={s.sandbox_denials}>{inspector.denials(s.sandbox_denials)}</ChangeValue>
                  )}
                </PropertyRow>
              ) : null}
              <PropertyRow label={inspector.lastExit} hint={s?.last_exit ? absoluteTime(s.last_exit.at) : undefined}>
                {s?.last_exit
                  ? `${exitText(s.last_exit.code, s.last_exit.signal)} · ${relativeTime(s.last_exit.at, now)}`
                  : "—"}
              </PropertyRow>
              <PropertyRow label={inspector.intent}>
                {s
                  ? `${inspector.desired[s.desired]} · ${inspector.persistence[s.intent_persistence]}`
                  : inspector.notObserved}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>
        </InspectorTab>

        {strict ? (
          <InspectorTab value="traffic" lead={lead(false)}>
            <SandboxTraffic app={app} owner={owner} />
          </InspectorTab>
        ) : null}

        <InspectorTab value="processes" lead={lead(false)}>
          <PropertySection
            title={inspector.processTree}
            icon={<ListTree aria-hidden />}
            count={s?.process_count ?? null}
          >
            <ProcessTree app={app} running={running} />
          </PropertySection>

          <PropertySection title={m.resourceLimits} icon={<Gauge aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={inspector.limitsSet}>{limitsText(app.spec.limits) ?? inspector.noLimits}</PropertyRow>
              {s?.resources ? (
                <ResourceFacts r={s.resources} now={now} variant="properties" />
              ) : (
                <PropertyRow label={inspector.limitsInForce}>
                  {running ? inspector.notReported : m.noRunningProcess}
                </PropertyRow>
              )}
            </PropertyGrid>
          </PropertySection>
        </InspectorTab>

        <InspectorTab value="ports" lead={lead(false)}>
          <PropertySection
            title={inspector.listeningPorts}
            icon={<RadioTower aria-hidden />}
            count={s?.listeners ? s.listeners.length : null}
          >
            <Listeners app={app} />
          </PropertySection>

          {app.spec.access_ports.length ? (
            <AccessPortsSection app={app} hostAddresses={sys.data?.host_addresses ?? []} now={now} />
          ) : null}

          <ForwardsSection app={app} add={action("add_forward")} />
        </InspectorTab>

        <InspectorTab value="output" lead={lead(false)}>
          <OutputLog app={app} running={running} />
        </InspectorTab>

        <InspectorTab value="settings" lead={lead(false)}>
          <PropertySection title={m.executable} icon={<FileCode2 aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={inspector.path} mono>
                {app.spec.executable}
              </PropertyRow>
              {app.spec.approval ? (
                <>
                  {app.spec.approval.path !== app.spec.executable ? (
                    <PropertyRow label={inspector.resolved} mono>
                      {app.spec.approval.path}
                    </PropertyRow>
                  ) : null}
                  <PropertyRow
                    label="SHA-256"
                    mono
                    hint={m.approvedAt(
                      absoluteTime(app.spec.approval.approved_at),
                      formatBytes(app.spec.approval.size),
                    )}
                  >
                    <span className="inline-flex items-center gap-1">
                      <span title={app.spec.approval.sha256}>{shortDigest(app.spec.approval.sha256)}</span>
                      <CopyButton value={app.spec.approval.sha256} label="SHA-256" />
                    </span>
                  </PropertyRow>
                  {appClass ? (
                    <PropertyRow label={inspector.recognisedAs} hint={appClass.bundle_id ?? undefined}>
                      <Tag tone={mayHandOff(appClass.class) ? "warning" : "neutral"}>{CLASS_LABEL[appClass.class]}</Tag>
                      <span className="text-caption text-fg-secondary">{classNote(appClass)}</span>
                    </PropertyRow>
                  ) : null}
                </>
              ) : (
                <PropertyRow label={inspector.approval}>
                  <span className="text-warning">{m.notApproved}</span>
                </PropertyRow>
              )}
            </PropertyGrid>
          </PropertySection>

          <PropertySection title={m.settings} icon={<Settings2 aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={m.connection} hint={ownerLook?.label}>
                {owner ? (
                  <Link to={`/instances/${owner.spec.id}`} className={TEXT_LINK}>
                    {owner.spec.name}
                  </Link>
                ) : (
                  "—"
                )}
              </PropertyRow>
              {!strict ? (
                <PropertyRow label={m.gateway} mono hint={gateway ? KIND_LABEL[gateway.kind] : undefined}>
                  {gateway ? (
                    <Link to={`/gateways/${gateway.id}`} className={TEXT_LINK}>
                      127.0.0.1:{gateway.port}
                    </Link>
                  ) : (
                    "—"
                  )}
                </PropertyRow>
              ) : null}
              {injected.length ? (
                <PropertyRow label={inspector.addedByManager} mono hint={inspector.addedByManagerHint}>
                  <ol className="grid grid-cols-1 gap-0.5">
                    {injected.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ol>
                </PropertyRow>
              ) : null}
              <PropertyRow label={m.args} mono>
                {app.spec.args.length ? (
                  <ol className="grid grid-cols-1 gap-0.5">
                    {app.spec.args.map((a, i) => (
                      // Arguments may repeat; their position in argv is their identity.
                      <li key={i}>
                        {a || <span className="font-sans text-fg-tertiary">{inspector.emptyArgument}</span>}
                      </li>
                    ))}
                  </ol>
                ) : (
                  <span className="font-sans text-fg-tertiary">{ui.common.none}</span>
                )}
              </PropertyRow>
              <PropertyRow label={m.workingDir} mono>
                {app.spec.working_dir ?? <span className="font-sans text-fg-tertiary">{m.privateHome}</span>}
              </PropertyRow>
              <PropertyRow label={inspector.homeLabel} mono hint={inspector.homeHint}>
                {home ?? <span className="font-sans text-fg-tertiary">{inspector.homeNotReported}</span>}
              </PropertyRow>
              <PropertyRow label={m.environment} mono>
                {app.spec.env.length ? (
                  <ul className="grid grid-cols-1 gap-0.5">
                    {app.spec.env.map((e) => (
                      <li key={e.name}>
                        {e.name}={e.value}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="font-sans text-fg-tertiary">{inspector.onlyManagerEnv}</span>
                )}
              </PropertyRow>
              {app.spec.isolation === "strict_netns" && !app.spec.confine_writes ? (
                <PropertyRow label={inspector.writable} hint={inspector.writesNotConfined}>
                  {inspector.writableAnywhere}
                </PropertyRow>
              ) : null}
              {usesWritable({ isolation: app.spec.isolation, confineWrites: app.spec.confine_writes }) ? (
                <PropertyRow
                  label={inspector.writable}
                  mono
                  hint={app.spec.isolation === "strict_netns" ? inspector.landlockHint : undefined}
                >
                  {app.spec.writable_paths.length ? (
                    <ul className="grid grid-cols-1 gap-0.5">
                      <li className="font-sans text-fg-secondary">{inspector.privateDirs}</li>
                      {app.spec.writable_paths.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                  ) : (
                    <span className="font-sans text-fg-tertiary">{inspector.onlyPrivateDirs}</span>
                  )}
                </PropertyRow>
              ) : null}
              <PropertyRow label={inspector.stopGrace}>
                <span>
                  {inspector.killedAfter(
                    <span className="machine">{app.spec.stop_grace_secs}</span>,
                    app.spec.stop_grace_secs,
                  )}
                </span>
              </PropertyRow>
              <PropertyRow label={inspector.recovery}>
                {app.spec.restart_on_recovery ? m.restartOnRecovery : inspector.noRestartOnRecovery}
              </PropertyRow>
              <PropertyRow
                label={inspector.isolationMode}
                hint={
                  availability.available || !caps.data ? (
                    mode.text
                  ) : (
                    <span className="text-warning">{inspector.modeUnavailable(availability.reason)}</span>
                  )
                }
              >
                {mode.title}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>
        </InspectorTab>
      </InspectorTabs>
    </InspectorFrame>
  );
}
