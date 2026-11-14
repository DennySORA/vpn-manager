// The evidence inspector for one Instance (signature 2): every fact says where it came from and how
// old it is; anything not observed says so instead of looking healthy. Layout (docs/frontend-design.md
// §8.1): the EntityHeader carries the connection's state and its frequent actions (the lifecycle
// control, 編輯, the ⋯ menu — the same menu as its list row); the fixed footer is the exit check, the
// view's primary action. In between, the views are tabs (`?tab=`): 概況 (the conclusion, live traffic
// and the proxy ports), 證據 (the observed facts and automatic recovery), 資源 (bandwidth caps and OS
// limits) and 設定. A problem (traffic blocked, settings not applied) leads every tab.

import { Activity, ChartLine, EthernetPort, Gauge, Network, RotateCcw, Settings2, ShieldCheck } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Link } from "react-router";
import {
  useBuiltinBlocklists,
  useBuiltinTransports,
  useDnsProfiles,
  useInstanceIpCheck,
  useLiveRates,
  useSecurityProfiles,
  useTransportProfiles,
} from "@/api/queries";
import type {
  GatewayRuntime,
  GatewaySpec,
  InstanceView,
  LiveRates,
  ProviderIpCheck,
  TransportStatus,
} from "@/api/types";
import { latest, RateChart } from "@/components/charts/rate-chart";
import { m as shell } from "@/components/shell/messages";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ButtonLink } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { FooterActions, HeaderActions } from "@/components/ui/entity-actions";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  InspectorTab,
  InspectorTabs,
  PropertyGrid,
  PropertyRow,
  PropertySection,
  SectionLink,
} from "@/components/ui/inspector";
import { TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState } from "@/components/ui/states";
import { reportFailure } from "@/components/ui/toast";
import { ToolButton } from "@/components/ui/tool-strip";
import { KIND_LABEL } from "@/features/gateways/gateway-dialog";
import { gatewayLook } from "@/features/gateways/model";
import { SshShare } from "@/features/gateways/ssh-share";
import { portKinds } from "@/features/gateways/ssh-traffic";
import { CheckLine } from "@/features/providers/egress";
import { appliedListName, overlayState } from "@/features/security/model";
import { bufferText, choices, congestionNow, findChoice, sizeText, tcpStartBytes } from "@/features/transport/model";
import { capText } from "@/features/limits/model";
import { ResourceFacts } from "@/features/limits/resource-facts";
import { type Locale, type ServerText, locale, localized } from "@/i18n";
import { absoluteTime, formatBps, formatBytes, formatPercent, relativeTime } from "@/lib/format";
import { ENFORCEMENT, type Tone, trafficExplanation } from "@/lib/status";
import { useTabParam } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { useInstanceActions } from "./action-host";
import type { InstanceActionId } from "./actions";
import { m } from "./inspector/messages";
import { instanceLook, isRunning, locationText, recoveryWayOut, staleConfig, tcpCapacity } from "./model";

// How the worker writes its DNS probe report in each language (crates/instance/src/dns): the conclusion ends at the
// first `head` separator, and `server` separates the servers (full-width in Chinese and Japanese). They are the
// report's separators, not text of this page.
const FULL_WIDTH_COLON = String.fromCharCode(0xff1a);
const FULL_WIDTH_SEMICOLON = String.fromCharCode(0xff1b);
const REPORT_SEPARATORS: Readonly<Record<Locale, { head: string; server: string }>> = {
  en: { head: ": ", server: "; " },
  "zh-TW": { head: FULL_WIDTH_COLON, server: FULL_WIDTH_SEMICOLON },
  ja: { head: FULL_WIDTH_COLON, server: FULL_WIDTH_SEMICOLON },
};

/**
 * The worker's DNS probe report, `DNS query failed (…): DoH 45.90.28.0:443 no answer within 4.0 s; DoT …`: the
 * conclusion, then one line per server. A report of the servers alone has no conclusion.
 */
export function DnsReport({ text }: { text: ServerText }) {
  const separators = REPORT_SEPARATORS[locale];
  const report = localized(text);
  const at = report.indexOf(separators.head);
  const head = at < 0 ? null : report.slice(0, at);
  const servers = (at < 0 ? report : report.slice(at + separators.head.length))
    .split(separators.server)
    .filter(Boolean);
  return (
    <span className="grid grid-cols-1 gap-0.5">
      {head ? <span>{head}</span> : null}
      <ul aria-label={m.dnsReport.servers} className="grid grid-cols-1 gap-0.5">
        {servers.map((line) => (
          <li key={line} className="text-caption text-fg-secondary tabular-nums">
            {line}
          </li>
        ))}
      </ul>
    </span>
  );
}

/** Earlier home of the gateway state words (they live in features/gateways/model.ts). */
export { GATEWAY_STATE } from "@/features/gateways/model";

/** The blocklist overlay this connection's worker enforces, as it reported it. */
function PolicyFact({ v }: { v: InstanceView }) {
  const catalogue = useBuiltinBlocklists();
  const s = overlayState(v);
  const p = v.status?.running?.policy;
  if (s.kind === "not_running" || !p) return <>{m.noWorker}</>;
  const lists = p.blocklists.length
    ? m.policy.names(p.blocklists.map((b) => appliedListName(b, catalogue.data)))
    : m.policy.noBlocklists;
  switch (s.kind) {
    case "applied":
      return (
        <span>
          <span className="text-success">{m.policy.applied(s.revision)}</span>
          <span className="text-fg-secondary"> · {lists}</span>
        </span>
      );
    case "pending":
      return (
        <span>
          <span className="text-info">{m.policy.pending(s.revision)}</span>
          <span className="text-fg-secondary">
            {s.applied ? ` · ${m.policy.running(s.applied)}` : ""} · {lists}
          </span>
        </span>
      );
    case "error":
      return <span className="text-danger">{s.message}</span>;
  }
}

/** Share of the last interval a capped direction waited, and UDP it dropped (unknown: —). */
function shapingText(r: LiveRates | null, dir: "download" | "upload"): string {
  const s = r?.shaping;
  if (!s) return "—";
  if (s[`${dir}_bps`] === null) return "—";
  const limited = s[`${dir}_limited`];
  const dropped = s[`${dir}_dropped_per_sec`];
  const share = limited === null ? "—" : m.shaping.limited(Math.round(limited * 100));
  return dropped ? m.shaping.dropped(share, dropped.toFixed(1)) : share;
}

/** What the running worker's transport does now, in one line: the set in force, the round trip, what grew. */
function transportNow(t: TransportStatus): string {
  const parts = [
    t.automatic ? m.transport.band(localized(t.band)) : null,
    t.rtt_ms === null ? m.transport.noRoundTrip : m.transport.roundTrip(t.rtt_ms),
    m.transport.newFlows(
      bufferText(t.flow.tcp_send_start_kib, t.flow.tcp_send_kib),
      bufferText(t.flow.tcp_recv_start_kib, t.flow.tcp_recv_kib),
    ),
    t.buffers_grown ? m.transport.grown(t.buffers_grown) : null,
    t.growth_refused ? m.transport.refused(t.growth_refused) : null,
    t.kernel_limits ? m.transport.kernel(sizeText(t.kernel_limits.recv_kib), sizeText(t.kernel_limits.send_kib)) : null,
    congestionNow(t),
  ];
  return parts.filter((p) => p !== null).join(" · ");
}

/** Bandwidth caps (as the worker confirmed them) and the worker's OS limits. */
function ResourcesSection({ view, cur, now }: { view: InstanceView; cur: LiveRates | null; now: number }) {
  const run = view.status?.running;
  const saved = { download_bps: view.spec.limits.download_bps, upload_bps: view.spec.limits.upload_bps };
  const caps = run?.bandwidth ?? saved;
  const pending =
    Boolean(run) &&
    (run?.bandwidth?.download_bps !== saved.download_bps || run.bandwidth.upload_bps !== saved.upload_bps);
  const capped = caps.download_bps !== null || caps.upload_bps !== null;
  return (
    <PropertySection title={m.resources.title} icon={<Gauge aria-hidden />}>
      <PropertyGrid>
        <PropertyRow
          label={m.resources.caps}
          mono
          hint={run ? (pending ? m.resources.capsPending : m.resources.capsApplied) : m.resources.capsSaved}
        >
          ↓ {capText(caps.download_bps)} · ↑ {capText(caps.upload_bps)}
        </PropertyRow>
        {run && capped ? (
          <PropertyRow label={m.resources.shaping} hint={m.resources.shapingHint}>
            <span>{m.resources.download(shapingText(cur, "download"))}</span>
            <span>{m.resources.upload(shapingText(cur, "upload"))}</span>
          </PropertyRow>
        ) : null}
        {run?.resources ? (
          <ResourceFacts r={run.resources} now={now} variant="properties" />
        ) : (
          <PropertyRow label={m.resources.process}>{run ? m.resources.notReported : m.noWorker}</PropertyRow>
        )}
      </PropertyGrid>
    </PropertySection>
  );
}

function calloutTone(t: Tone): "info" | "success" | "warning" | "danger" {
  return t === "success" || t === "warning" || t === "danger" ? t : "info";
}

function GatewayItem({
  g,
  runtime,
  rates,
}: {
  g: GatewaySpec;
  runtime: GatewayRuntime | undefined;
  rates: LiveRates | null;
}) {
  const r = rates?.gateways.find((x) => x.gateway_id === g.id);
  return (
    <div className="grid grid-cols-1 gap-1 rounded-lg border border-line-subtle bg-sunken/50 px-3 py-2.5">
      <div className="flex min-w-0 items-center gap-2">
        <Tag tone="file">{KIND_LABEL[g.kind]}</Tag>
        <Link
          to={`/gateways/${g.id}`}
          className="min-w-0 truncate text-data font-medium text-fg underline-offset-2 hover:underline active:opacity-70"
        >
          {g.name}
        </Link>
        <span className="ml-auto shrink-0">
          <StatusPill look={gatewayLook(g, runtime)} />
        </span>
      </div>
      <div className="flex items-center gap-1 font-mono text-data text-fg-secondary">
        127.0.0.1:{g.port}
        <CopyButton value={`127.0.0.1:${g.port}`} label={m.gateways.address} />
      </div>
      {runtime ? (
        <p className="machine text-caption text-fg-tertiary">
          TCP {runtime.active_tcp} · UDP {runtime.active_udp}
          {r ? ` · ↓ ${formatBps(r.rx_bps)} ↑ ${formatBps(r.tx_bps)}` : ""}
        </p>
      ) : null}
      {runtime?.error ? <p className="text-caption text-danger">{localized(runtime.error)}</p> : null}
      {!g.enabled ? <p className="text-caption text-fg-tertiary">{m.gateways.disabled}</p> : null}
    </div>
  );
}

/** The footer's explanation, or the answer once the exit was checked (announced politely). */
function ExitNote({
  ready,
  result,
  exitServer,
}: {
  ready: boolean;
  result: ProviderIpCheck | null;
  /** The exit server the profile names (compared with the one the provider's checker names). */
  exitServer: string | null;
}) {
  const named = result?.exit_server ?? null;
  return (
    <div aria-live="polite" className="grid grid-cols-1 gap-1">
      {result ? (
        <div className="grid grid-cols-1 gap-1 rounded-md border border-line-subtle bg-sunken/60 px-2.5 py-1.5 animate-reveal">
          <CheckLine c={result} />
          {named && exitServer ? (
            named === exitServer ? (
              <p className="text-success">{m.exit.same(named)}</p>
            ) : (
              <p className="text-warning">{m.exit.differs(named, exitServer)}</p>
            )
          ) : null}
          <p>{m.exit.via(result.latency_ms)}</p>
        </div>
      ) : (
        <p>{ready ? m.exit.hint : m.exit.notReady}</p>
      )}
    </div>
  );
}

export type InstanceTab = "overview" | "evidence" | "resources" | "settings";

export const INSTANCE_TABS: InstanceTab[] = ["overview", "evidence", "resources", "settings"];

const INSTANCE_TAB_LABEL: Record<InstanceTab, string> = {
  overview: ui.common.overview,
  evidence: m.tabs.evidence,
  resources: m.tabs.resources,
  settings: m.tabs.settings,
};

export function InstanceInspector({ view }: { view: InstanceView }) {
  const now = useServerNow();
  const live = useLiveRates(view.spec.id);
  const dns = useDnsProfiles();
  const security = useSecurityProfiles();
  const builtinTransports = useBuiltinTransports();
  const savedTransports = useTransportProfiles();
  const check = useInstanceIpCheck();
  const [exit, setExit] = useState<ProviderIpCheck | null>(null);
  const actions = useInstanceActions(view, {
    check_exit: {
      pending: check.isPending,
      run: () => {
        check.mutate(view.spec.id, {
          onSuccess: (r) => {
            setExit(r.data);
          },
          onError: (e) => {
            reportFailure(m.exit.intent, e);
          },
        });
      },
    },
  });
  const action = (id: InstanceActionId) => actions.find((a) => a.id === id);
  const restart = action("restart");
  const addGateway = action("add_gateway");

  const s = view.status;
  const look = instanceLook(view);
  const running = isRunning(view);
  const latched = s?.intent.emergency_latched ?? false;
  // Held closed until the user decides (a stop from before the manager restarted is not on disk).
  const wayOut = recoveryWayOut(view);
  const stale = staleConfig(view);
  // Every server of the DNS profile fails: the WireGuard profile's own resolvers answer meanwhile, or — the profile
  // fails closed — names do not resolve at all (a running worker only).
  const dnsFallback = s?.running ? (s.dns?.fallback ?? null) : null;
  const dnsInterrupted = s?.running ? (s.dns?.interrupted ?? null) : null;
  const transports = choices(builtinTransports.data ?? [], savedTransports.data ?? []);
  const transport = findChoice(transports, view.spec.transport);
  const capacity = tcpCapacity(view.spec.limits, tcpStartBytes(transport, transports));
  const cur = latest(live.data, now);
  const enforcement = s ? ENFORCEMENT[s.enforcement] : null;
  const dnsName = dns.data?.find((d) => d.id === view.spec.dns_profile_id)?.name;
  const securityName = security.data?.find((d) => d.id === view.spec.security_profile_id)?.name;
  const endpoint = s?.tunnel?.endpoint ?? view.profile?.endpoint;
  // Tunnel facts of a stopped Instance describe its last run, not the present.
  const lastRun = Boolean(s?.tunnel) && !s?.running;
  const where = locationText(view) ?? view.profile?.name ?? m.header.profileMissing;
  const [tab, setTab] = useTabParam<InstanceTab>("tab", INSTANCE_TABS);
  const tone = calloutTone(look.tone);

  // The conclusion: what happens to the connection's traffic leads 概況, and every tab while it is a problem; settings
  // that wait for a restart and a status that cannot be read lead every tab.
  const lead = (overview: boolean): ReactNode[] | null => {
    const items = [
      overview || tone === "warning" || tone === "danger" ? (
        <Callout key="traffic" tone={tone} icon={look.icon}>
          {trafficExplanation(s)}
        </Callout>
      ) : null,
      stale ? (
        <Callout
          key="stale"
          tone="warning"
          title={m.lead.staleTitle}
          actions={
            restart && running && !latched ? (
              <ActionButton
                size="sm"
                icon={restart.icon}
                pending={restart.pending}
                pendingLabel={restart.pendingLabel}
                disabledReason={restart.pending ? null : restart.disabledReason}
                onClick={restart.run}
              >
                {restart.label}
              </ActionButton>
            ) : null
          }
        >
          {stale}
        </Callout>
      ) : null,
      dnsInterrupted ? (
        <Callout
          key="dns-interrupted"
          tone="danger"
          title={m.lead.dnsInterruptedTitle}
          actions={
            view.spec.dns_profile_id ? (
              <ButtonLink size="sm" to={`/dns/${view.spec.dns_profile_id}`}>
                {m.lead.checkDns}
              </ButtonLink>
            ) : null
          }
        >
          <span className="grid grid-cols-1 gap-1.5">
            <span>{m.lead.dnsInterrupted(dnsName)}</span>
            <DnsReport text={dnsInterrupted} />
          </span>
        </Callout>
      ) : null,
      dnsFallback ? (
        <Callout
          key="dns-fallback"
          tone="warning"
          title={m.lead.dnsFallbackTitle}
          actions={
            view.spec.dns_profile_id ? (
              <ButtonLink size="sm" to={`/dns/${view.spec.dns_profile_id}`}>
                {m.lead.checkDns}
              </ButtonLink>
            ) : null
          }
        >
          <span className="grid grid-cols-1 gap-1.5">
            <span>{m.lead.dnsFallback(dnsName)}</span>
            <DnsReport text={dnsFallback} />
          </span>
        </Callout>
      ) : null,
      !s ? (
        <p key="unknown" className="text-caption text-fg-tertiary">
          {m.lead.unknown}
        </p>
      ) : null,
    ].filter(Boolean);
    return items.length ? items : null;
  };

  return (
    <InspectorFrame
      tabbed
      header={
        <EntityHeader
          icon={Network}
          tone="info"
          title={view.spec.name}
          status={<StatusPill look={look} />}
          description={
            <span className="grid grid-cols-1 gap-1.5">
              <span className="[overflow-wrap:anywhere]">
                {where}
                {endpoint ? (
                  <>
                    {" · "}
                    <span className="machine">{endpoint}</span>
                  </>
                ) : null}
              </span>
              {enforcement || s?.running ? (
                <span className="flex flex-wrap items-center gap-1.5">
                  {enforcement ? (
                    <Tag tone={enforcement.tone} icon={enforcement.icon}>
                      {enforcement.label}
                    </Tag>
                  ) : null}
                  {s?.running ? (
                    <span className="machine text-micro text-fg-tertiary">
                      {m.header.generation(s.running.generation)}
                    </span>
                  ) : null}
                </span>
              ) : null}
            </span>
          }
          id={view.spec.id}
          idLabel={m.header.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={ui.action.menuOf(view.spec.name)} />}
        />
      }
      footer={
        <InspectorFooter
          note={
            <ExitNote ready={s?.phase === "ready"} result={exit} exitServer={view.profile?.location?.server ?? null} />
          }
        >
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      <InspectorTabs
        label={m.tabs.label(view.spec.name)}
        value={tab}
        onChange={setTab}
        items={INSTANCE_TABS.map((t) => ({ value: t, label: INSTANCE_TAB_LABEL[t] }))}
      >
        <InspectorTab value="overview" lead={lead(true)}>
          <PropertySection
            title={m.live.title}
            icon={<Activity aria-hidden />}
            actions={
              <SectionLink to={`/metrics?scope=instance:${view.spec.id}`} icon={ChartLine}>
                {m.live.history}
              </SectionLink>
            }
          >
            <div className="grid grid-cols-1 gap-3">
              <RateChart samples={live.data} emptyText={running ? m.live.waiting : m.live.notRunning} />
              {cur ? <SshShare kinds={portKinds(cur.gateways)} scope="instance" /> : null}
              <dl className="grid grid-cols-2 gap-2 2xl:grid-cols-4">
                {[
                  ["TCP", cur ? String(cur.active_tcp) : "—", undefined],
                  ["UDP", cur ? String(cur.active_udp) : "—", undefined],
                  ["CPU", formatPercent(cur?.cpu_core_pct), undefined],
                  // The whole worker process, not the connection buffer budget in 設定.
                  [m.live.rss, cur?.rss_bytes ? formatBytes(cur.rss_bytes) : "—", m.live.rssHint],
                ].map(([k, v, hint]) => (
                  <div
                    key={k}
                    title={hint}
                    className="flex items-baseline justify-between gap-2 rounded-md border border-line-subtle bg-sunken/60 px-2.5 py-1.5 2xl:block"
                  >
                    <dt className="text-caption text-fg-tertiary">{k}</dt>
                    <dd className="machine truncate text-data text-fg">{v}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </PropertySection>

          <PropertySection
            title={shell.nav.gateways.label}
            icon={<EthernetPort aria-hidden />}
            count={view.gateways.length}
            actions={
              addGateway ? (
                <ToolButton
                  label={addGateway.label}
                  icon={<addGateway.icon aria-hidden />}
                  disabledReason={addGateway.disabledReason}
                  onClick={addGateway.run}
                />
              ) : null
            }
          >
            {view.gateways.length ? (
              <PresenceList
                items={view.gateways}
                keyOf={(g) => g.id}
                className="grid grid-cols-1 gap-2"
                label={m.gateways.label(view.spec.name)}
              >
                {(g) => <GatewayItem g={g} runtime={s?.gateways.find((r) => r.gateway_id === g.id)} rates={cur} />}
              </PresenceList>
            ) : (
              <EmptyState compact icon={EthernetPort} title={m.gateways.emptyTitle}>
                {m.gateways.emptyBody}
              </EmptyState>
            )}
          </PropertySection>
        </InspectorTab>

        <InspectorTab value="evidence" lead={lead(false)}>
          <PropertySection title={m.tabs.evidence} icon={<ShieldCheck aria-hidden />}>
            <PropertyGrid>
              <PropertyRow
                label={m.evidence.lastHandshake}
                hint={
                  s?.tunnel?.last_handshake_at
                    ? `WireGuard · ${absoluteTime(s.tunnel.last_handshake_at)}${lastRun ? ` · ${m.evidence.lastRun}` : ""}`
                    : undefined
                }
              >
                {s?.tunnel
                  ? s.tunnel.last_handshake_at
                    ? relativeTime(s.tunnel.last_handshake_at, now)
                    : m.evidence.noHandshake
                  : m.evidence.notObserved}
              </PropertyRow>
              <PropertyRow
                label={m.evidence.dnsProbe}
                hint={
                  s?.dns?.last_probe_at ? m.evidence.dnsProbeHint(relativeTime(s.dns.last_probe_at, now)) : undefined
                }
              >
                {s?.dns?.interrupted ? (
                  <span className="grid grid-cols-1 gap-0.5">
                    <span className="text-danger">{m.evidence.dnsInterrupted}</span>
                    {/* A failing tunnel says more; otherwise, while it runs, the callout above lists the reasons. */}
                    {s.dns.last_error ? (
                      <DnsReport text={s.dns.last_error} />
                    ) : dnsInterrupted ? null : (
                      <DnsReport text={s.dns.interrupted} />
                    )}
                  </span>
                ) : s?.dns?.healthy === true && s.dns.fallback ? (
                  <span className="grid grid-cols-1 gap-0.5">
                    <span className="text-warning">{m.evidence.dnsFallback}</span>
                    {/* While it runs, the callout above (every tab leads with it) lists the reasons. */}
                    {dnsFallback ? null : <DnsReport text={s.dns.fallback} />}
                  </span>
                ) : s?.dns?.healthy === true ? (
                  <span className="text-success">{m.evidence.passed}</span>
                ) : s?.dns?.healthy === false ? (
                  <span className="grid grid-cols-1 gap-0.5">
                    <span className="text-danger">{m.evidence.failed}</span>
                    {s.dns.last_error ? <DnsReport text={s.dns.last_error} /> : null}
                  </span>
                ) : (
                  m.evidence.notObserved
                )}
              </PropertyRow>
              <PropertyRow label={m.evidence.exitEndpoint} mono>
                {endpoint ? (
                  <span className="inline-flex items-center gap-1">
                    {endpoint}
                    <CopyButton value={endpoint} label={m.evidence.endpoint} />
                  </span>
                ) : (
                  "—"
                )}
              </PropertyRow>
              <PropertyRow label="IPv6" hint={lastRun ? m.evidence.lastRun : undefined}>
                {s?.tunnel ? (s.tunnel.ipv6 ? m.evidence.ipv6Set : m.evidence.ipv4Only) : m.evidence.notObserved}
              </PropertyRow>
              {view.spec.strict ? (
                <PropertyRow
                  label={m.evidence.strict}
                  mono={Boolean(s?.sandbox)}
                  hint={s?.sandbox ? m.evidence.sandbox(s.sandbox.holder_pid, s.sandbox.tun_name) : undefined}
                >
                  {!s
                    ? m.evidence.notObserved
                    : s.sandbox
                      ? s.sandbox.addresses.join("  ")
                      : m.evidence.sandboxNotBuilt}
                </PropertyRow>
              ) : null}
              <PropertyRow
                label={m.evidence.wgTraffic}
                mono
                hint={lastRun ? m.evidence.wgLastRun : m.evidence.wgPackets}
              >
                {s?.tunnel ? `↓ ${formatBytes(s.tunnel.wg_rx_bytes)}  ↑ ${formatBytes(s.tunnel.wg_tx_bytes)}` : "—"}
              </PropertyRow>
              <PropertyRow label={ui.common.running} hint={s?.running?.pid ? `PID ${s.running.pid}` : undefined}>
                {s?.running
                  ? m.evidence.running(
                      s.running.generation,
                      relativeTime(s.running.started_at, now),
                      s.running.ready_at ? relativeTime(s.running.ready_at, now) : null,
                    )
                  : m.noWorker}
              </PropertyRow>
              <PropertyRow
                label={shell.nav.blocklists.label}
                hint={
                  s?.running?.policy ? (
                    <Link to={`/security/bans?instance=${view.spec.id}`} className={TEXT_LINK}>
                      {shell.nav.bans.label}
                    </Link>
                  ) : undefined
                }
              >
                <PolicyFact v={view} />
              </PropertyRow>
              <PropertyRow label={m.evidence.intent}>
                {s
                  ? wayOut
                    ? m.evidence.intentWaiting(
                        latched ? m.evidence.intentWord.emergency : m.evidence.intentWord.stopped,
                      )
                    : s.intent.persistence === "durable"
                      ? m.evidence.intentDurable(
                          s.intent.emergency_latched
                            ? m.evidence.intentWord.emergency
                            : s.intent.desired === "running"
                              ? m.evidence.intentWord.running
                              : m.evidence.intentWord.stopped,
                        )
                      : s.intent.persistence === "pending"
                        ? m.evidence.intentWriting
                        : m.evidence.intentFailed
                  : m.evidence.notObserved}
              </PropertyRow>
              <PropertyRow label={m.evidence.observedAt}>
                {s ? m.evidence.observed(relativeTime(s.observed_at, now)) : m.evidence.notObserved}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>

          {s && (s.recovery.attempt > 0 || s.recovery.last_fault) ? (
            <PropertySection title={m.recovery.title} icon={<RotateCcw aria-hidden />}>
              <PropertyGrid>
                <PropertyRow label={m.recovery.attempts} mono>
                  {s.recovery.attempt}
                </PropertyRow>
                <PropertyRow label={m.recovery.next}>
                  {s.recovery.next_retry_at ? relativeTime(s.recovery.next_retry_at, now) : m.recovery.notScheduled}
                </PropertyRow>
                {s.recovery.last_fault ? (
                  <PropertyRow
                    label={m.recovery.lastFault}
                    hint={`${s.recovery.last_fault.code} · ${relativeTime(s.recovery.last_fault.at, now)}`}
                  >
                    {localized(s.recovery.last_fault.message)}
                  </PropertyRow>
                ) : null}
              </PropertyGrid>
            </PropertySection>
          ) : null}
        </InspectorTab>

        <InspectorTab value="resources" lead={lead(false)}>
          <ResourcesSection view={view} cur={cur} now={now} />
        </InspectorTab>

        <InspectorTab value="settings" lead={lead(false)}>
          <PropertySection title={m.tabs.settings} icon={<Settings2 aria-hidden />}>
            <PropertyGrid>
              <PropertyRow
                label="WireGuard"
                hint={view.profile ? <span className="font-mono">{view.profile.endpoint}</span> : undefined}
              >
                {view.profile ? (
                  <Link to={`/profiles/${view.profile.id}`} className={TEXT_LINK}>
                    {view.profile.name}
                  </Link>
                ) : (
                  <span className="text-danger">{m.settings.gone}</span>
                )}
              </PropertyRow>
              <PropertyRow label="DNS">
                {view.spec.dns_profile_id ? (
                  <Link to={`/dns/${view.spec.dns_profile_id}`} className={TEXT_LINK}>
                    {dnsName ?? m.settings.dnsProfile}
                  </Link>
                ) : (
                  m.settings.profileDns
                )}
              </PropertyRow>
              <PropertyRow label={m.settings.security}>
                {view.spec.security_profile_id ? (
                  <Link to={`/security/${view.spec.security_profile_id}`} className={TEXT_LINK}>
                    {securityName ?? m.settings.security}
                  </Link>
                ) : (
                  <span>
                    {m.settings.defaultSecurity((text) => (
                      <Link to="/security/blocklists" className={TEXT_LINK}>
                        {text}
                      </Link>
                    ))}
                  </span>
                )}
              </PropertyRow>
              <PropertyRow
                label={m.settings.transport}
                hint={
                  s?.running?.transport
                    ? transportNow(s.running.transport)
                    : s?.running
                      ? m.settings.transportNotReported
                      : m.settings.transportApplies
                }
              >
                {transport ? (
                  <Link to={`/transport/${transport.value}`} className={TEXT_LINK}>
                    {transport.name}
                  </Link>
                ) : builtinTransports.isPending || savedTransports.isPending ? (
                  m.settings.loading
                ) : (
                  <span className="text-danger">{m.settings.gone}</span>
                )}
              </PropertyRow>
              <PropertyRow
                label={m.settings.limits}
                mono
                hint={m.settings.limitsHint(capacity.limit, capacity.byMemory)}
              >
                {m.settings.limitsValue(
                  view.spec.limits.max_tcp_flows,
                  view.spec.limits.max_udp_flows,
                  view.spec.limits.memory_mib,
                )}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>
        </InspectorTab>
      </InspectorTabs>
    </InspectorFrame>
  );
}
