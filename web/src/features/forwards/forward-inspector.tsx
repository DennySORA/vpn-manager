// The evidence inspector of one port forward (docs/frontend-design.md §8.1): whether it listens and why not, what was
// observed from outside (never green on configuration alone), its target and lease, this generation's counts, and its
// settings (where the source address goes: PROXY protocol v2 or not; whether UDP goes straight into the sandbox). The
// EntityHeader carries its state and its frequent actions (停用／啟用, 編輯, the ⋯ menu — the same menu as its list
// row); the conclusion comes first, then collapsible property sections; the fixed footer is AirVPN's test of the port,
// the view's primary action, whose answer shows in the footer.
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  CircleCheck,
  CircleDashed,
  CircleQuestionMark,
  CircleSlash,
  CircleX,
  Gauge,
  PlugZap,
  Settings2,
  TriangleAlert,
  Waypoints,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { describeFailure } from "@/api/client";
import { useProfiles, useProviderAccounts, useTestForwardedPort } from "@/api/queries";
import type { AppView, ForwardedPortTest, ForwardView, InstanceView, PortTestState } from "@/api/types";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ChangeValue } from "@/components/ui/change-value";
import { FooterActions, HeaderActions } from "@/components/ui/entity-actions";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  PropertyGrid,
  PropertyRow,
  PropertySection,
} from "@/components/ui/inspector";
import { TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { instanceLook } from "@/features/instances/model";
import { airvpnAccountOf, ipLayerLabel, PORT_PROTOCOL, serverText, testLook } from "@/features/providers/ports";
import { intlLocale, localized } from "@/i18n";
import { absoluteTime, formatBytes, relativeTime } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { useForwardActions } from "./action-host";
import { m } from "./messages";
import { forwardLook, lastObserved, PROTOCOL_LABEL, providerGuide, reachLook, testedPort } from "./model";

/** How the App learns who connected: the PROXY protocol header on TCP, and UDP's own source when it goes straight in. */
function sourceHint(b: ForwardView["binding"]): string {
  const direct = b.udp_direct && b.protocol !== "tcp";
  if (b.proxy_protocol)
    return m.settings.sourceHint.proxy(b.protocol === "both" ? (direct ? "direct" : "relayed") : null);
  if (direct && b.protocol === "udp") return m.settings.sourceHint.udpOnlyDirect;
  if (direct) return m.settings.sourceHint.udpDirect;
  return m.settings.sourceHint.local;
}

function count(c: string | undefined): string {
  return c === undefined ? "—" : Number(c).toLocaleString(intlLocale);
}

const TEST_ICON: Record<PortTestState, LucideIcon> = {
  open: CircleCheck,
  closed: CircleX,
  warning: TriangleAlert,
  unknown: CircleQuestionMark,
  not_tested: CircleDashed,
};

/** The footer's line: what the test does, or AirVPN's answer once it ran (announced politely). */
function TestNote({
  port,
  available,
  pending,
  result,
  failure,
}: {
  port: number;
  available: boolean;
  pending: boolean;
  result: ForwardedPortTest | null;
  failure: unknown;
}) {
  let body;
  if (pending) body = <p>{m.test.pending(port)}</p>;
  else if (failure) body = <p className="text-danger animate-reveal">{m.test.failed(describeFailure(failure))}</p>;
  else if (result && !result.sessions.length) body = <p className="animate-reveal">{m.test.noSessions(port)}</p>;
  else if (result)
    body = (
      <ul
        className="grid grid-cols-1 gap-1.5 rounded-md border border-line-subtle bg-sunken/60 px-2.5 py-1.5 animate-reveal"
        aria-label={m.test.resultsLabel}
      >
        {result.sessions.map((s, i) => {
          const look = testLook(s);
          return (
            <li key={`${s.server_ip}-${s.protocol}-${s.ip_layer}-${i}`} className="grid grid-cols-1 gap-0.5">
              <span className="flex flex-wrap items-center gap-1.5">
                <StatusPill look={{ ...look, icon: TEST_ICON[s.state] }} />
                <span className="text-fg-secondary">
                  {PORT_PROTOCOL[s.protocol]} {ipLayerLabel(s.ip_layer)} · {serverText(s)}
                </span>
              </span>
              {s.message ? <span className="[overflow-wrap:anywhere]">{localized(s.message)}</span> : null}
            </li>
          );
        })}
        <li className="text-fg-tertiary">
          {m.test.proof(testLook({ state: "open", word: null }).label, relativeTime(result.observed_at))}
        </li>
      </ul>
    );
  else body = <p>{available ? m.test.request(port) : m.test.evidenceOnly}</p>;
  return (
    <div aria-live="polite" className="grid grid-cols-1 gap-1">
      {body}
    </div>
  );
}

/** The conclusion: whether it listens and, if not, the manager's reason (its words and code). */
function Conclusion({
  forward,
  owner,
  app,
}: {
  forward: ForwardView;
  owner: InstanceView | undefined;
  app: AppView | undefined;
}) {
  const s = forward.status;
  const b = forward.binding;
  const look = forwardLook(forward);
  const guide = providerGuide(owner);
  if (!s)
    return (
      <Callout tone="warning" title={m.conclusion.unknown}>
        {m.conclusion.unknownBody}
      </Callout>
    );
  if (guide.unsupported || s.reason_code === "PROVIDER_UNSUPPORTED")
    return (
      <Callout tone="warning" title={m.conclusion.unsupported}>
        {guide.unsupported ?? (s.reason ? localized(s.reason) : null)}
      </Callout>
    );
  if (s.state === "disabled")
    return (
      <Callout tone="info" icon={CircleSlash} title={ui.common.disabled}>
        {m.conclusion.disabledBody}
      </Callout>
    );
  if (s.state === "listening") {
    const delivery = {
      owner: owner?.spec.name ?? null,
      app: app?.spec.name ?? null,
      tunnelPort: b.tunnel_port,
      targetPort: b.target_port,
      proxy: b.proxy_protocol,
    };
    // UDP straight into the sandbox: the App's own socket receives it, with the real source.
    const direct = b.udp_direct && b.protocol !== "tcp";
    return (
      <Callout tone="info" icon={PlugZap}>
        {!direct
          ? m.conclusion.relayed(delivery, PROTOCOL_LABEL[b.protocol])
          : b.protocol === "both"
            ? m.conclusion.tcpRelayedUdpDirect(delivery)
            : m.conclusion.udpDirect(delivery)}
      </Callout>
    );
  }
  return (
    <Callout tone={s.state === "target_not_owned" ? "danger" : "warning"} icon={look.icon} title={look.label}>
      {s.reason ? <p className="[overflow-wrap:anywhere]">{localized(s.reason)}</p> : null}
      {s.reason_code ? <p className="machine mt-1 text-micro text-fg-tertiary">{s.reason_code}</p> : null}
    </Callout>
  );
}

export function ForwardInspector({
  forward,
  owner,
  app,
}: {
  forward: ForwardView;
  owner: InstanceView | undefined;
  app: AppView | undefined;
}) {
  const now = useServerNow();
  const profiles = useProfiles();
  const accounts = useProviderAccounts();
  const tester = useTestForwardedPort();
  const [result, setResult] = useState<ForwardedPortTest | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const b = forward.binding;
  const port = testedPort(forward);
  const account = airvpnAccountOf(owner, profiles.data ?? [], accounts.data ?? []);
  const actions = useForwardActions(forward, {
    test: {
      pending: tester.isPending,
      run: () => {
        if (!account) return;
        setFailure(null);
        tester.mutate(
          { account: account.id, port },
          {
            onSuccess: (r) => {
              setResult(r);
            },
            onError: (e) => {
              setResult(null);
              setFailure(e);
            },
          },
        );
      },
    },
  });
  const s = forward.status;
  const look = forwardLook(forward);
  const reach = reachLook(s);
  const seen = lastObserved(s);
  const c = s?.counters ?? null;
  const guide = providerGuide(owner);
  const testAvailable = actions.find((a) => a.id === "test")?.disabledReason === null;

  return (
    <InspectorFrame
      header={
        <EntityHeader
          icon={Waypoints}
          tone="file"
          title={b.name}
          status={<StatusPill look={look} title={s?.reason ? localized(s.reason) : undefined} />}
          description={
            <span className="grid grid-cols-1 gap-1.5">
              <span className="machine [overflow-wrap:anywhere]">
                {PROTOCOL_LABEL[b.protocol]} tunnel :{b.tunnel_port} → {app?.spec.name ?? "App"} :{b.target_port}
              </span>
              <span className="flex flex-wrap items-center gap-1.5">
                <StatusPill look={reach} />
                {b.public_port ? <Tag tone="neutral">{m.page.publicAt(b.public_port)}</Tag> : null}
                {!b.enabled ? <Tag tone="warning">{ui.common.disabled}</Tag> : null}
              </span>
            </span>
          }
          id={b.id}
          idLabel={m.inspector.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={m.actionsOf(b.name)} />}
        />
      }
      footer={
        <InspectorFooter
          note={
            <TestNote
              port={port}
              available={testAvailable}
              pending={tester.isPending}
              result={result}
              failure={failure}
            />
          }
        >
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">
        <Conclusion forward={forward} owner={owner} app={app} />
      </div>

      <PropertySection title={ui.common.status} icon={<Activity aria-hidden />}>
        <PropertyGrid>
          <PropertyRow
            label={m.column.forward}
            hint={s ? m.inspector.observedAt(relativeTime(s.observed_at, now)) : undefined}
          >
            {s ? look.label : ui.common.unknown}
          </PropertyRow>
          <PropertyRow
            label={m.column.reach}
            hint={seen ? m.inspector.lastSeen(absoluteTime(seen), relativeTime(seen, now)) : m.inspector.reachHint}
          >
            <span className={s?.reachability.state === "observed" ? "text-success" : undefined}>
              {s ? reach.label : ui.common.unknown}
              {s?.reachability.tcp_observed_at && s.reachability.udp_observed_at
                ? m.inspector.observedOver.both
                : s?.reachability.tcp_observed_at
                  ? m.inspector.observedOver.tcp
                  : s?.reachability.udp_observed_at
                    ? m.inspector.observedOver.udp
                    : null}
            </span>
          </PropertyRow>
          <PropertyRow
            label={m.column.target}
            mono
            hint={
              s?.target
                ? m.inspector.targetHint(s.target.pid, relativeTime(s.target.verified_at, now), s.target.wildcard)
                : m.inspector.targetPending
            }
          >
            {s?.target
              ? m.list([s.target.tcp_address, s.target.udp_address].filter((a): a is string => Boolean(a)))
              : "—"}
          </PropertyRow>
          <PropertyRow
            label={m.inspector.lease}
            mono
            hint={s?.lease ? m.inspector.leaseHint(s.lease.generation, absoluteTime(s.lease.granted_at)) : undefined}
          >
            {s?.lease ? s.lease.lease_id : ui.common.none}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>

      <PropertySection title={m.counters.title} icon={<Gauge aria-hidden />}>
        {c ? (
          <PropertyGrid>
            <PropertyRow label={m.counters.accepted} mono hint={m.counters.active(c.active_tcp, c.active_udp)}>
              <ChangeValue value={c.accepted}>{count(c.accepted)}</ChangeValue>
            </PropertyRow>
            <PropertyRow label={m.counters.traffic} mono hint={m.counters.trafficHint}>
              {m.counters.bytes(formatBytes(c.bytes_in), formatBytes(c.bytes_out))}
            </PropertyRow>
            <PropertyRow label={m.counters.refused} mono>
              <dl className="grid w-full grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5">
                {(
                  [
                    ["blocklisted", m.counters.blocklisted, count(c.refused_blocklisted)],
                    [
                      "banned",
                      m.counters.banned,
                      (Number(c.refused_banned) + Number(c.refused_rate_limited)).toLocaleString(intlLocale),
                    ],
                    ["limit", m.limit, count(c.refused_limit)],
                    ["closed", m.counters.closed, count(c.refused_closed)],
                    ["target", m.counters.targetFailed, count(c.target_failed)],
                  ] as const
                ).map(([id, k, v]) => (
                  <div key={id} className="contents">
                    <dt className="font-sans text-caption text-fg-tertiary">{k}</dt>
                    <dd>
                      <ChangeValue value={v}>{v}</ChangeValue>
                    </dd>
                  </div>
                ))}
              </dl>
            </PropertyRow>
            {Number(c.udp_dropped) > 0 ? (
              <PropertyRow label={m.counters.udpDropped} mono>
                <ChangeValue value={c.udp_dropped}>{count(c.udp_dropped)}</ChangeValue>
              </PropertyRow>
            ) : null}
          </PropertyGrid>
        ) : (
          <p className="text-data text-fg-tertiary">{s ? m.counters.noWorker : m.counters.unknown}</p>
        )}
      </PropertySection>

      <PropertySection title={m.settings.title} icon={<Settings2 aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.column.connection} hint={owner ? instanceLook(owner).label : undefined}>
            {owner ? (
              <Link to={`/instances/${owner.spec.id}`} className={TEXT_LINK}>
                {owner.spec.name}
              </Link>
            ) : (
              "—"
            )}
          </PropertyRow>
          <PropertyRow
            label={m.settings.app}
            hint={
              <span className="font-mono">
                {b.udp_direct && b.protocol === "udp"
                  ? m.settings.appUdpDirect(b.tunnel_port)
                  : b.udp_direct && b.protocol === "both"
                    ? m.settings.appBothDirect(b.target_port, b.tunnel_port)
                    : `127.0.0.1:${b.target_port}`}
              </span>
            }
          >
            {app ? (
              <Link to={`/apps/${app.spec.id}`} className={TEXT_LINK}>
                {app.spec.name}
              </Link>
            ) : (
              "—"
            )}
          </PropertyRow>
          <PropertyRow label={m.tunnelPort} mono>
            {PROTOCOL_LABEL[b.protocol]} {b.tunnel_port}
          </PropertyRow>
          <PropertyRow label={m.publicPort} mono hint={m.settings.publicPortHint}>
            {b.public_port ?? m.settings.notSet}
          </PropertyRow>
          <PropertyRow label={m.limit} mono hint={m.settings.limitHint}>
            {b.max_connections}
          </PropertyRow>
          <PropertyRow label={m.settings.source} hint={sourceHint(b)}>
            {b.proxy_protocol
              ? m.settings.sourceValue.proxy
              : b.udp_direct && b.protocol === "udp"
                ? m.settings.sourceValue.real
                : b.udp_direct && b.protocol === "both"
                  ? m.settings.sourceValue.udpOnly
                  : m.settings.sourceValue.none}
          </PropertyRow>
          {b.protocol !== "tcp" ? (
            <PropertyRow label="UDP" hint={b.udp_direct ? m.settings.udpDirectHint : m.settings.udpRelayedHint}>
              {b.udp_direct ? m.settings.udpDirect : m.settings.udpRelayed}
            </PropertyRow>
          ) : null}
          <PropertyRow label={m.settings.provider} hint={account ? m.settings.providerHint : undefined}>
            {guide.unsupported ? (
              <span className="text-warning">{guide.unsupported}</span>
            ) : account ? (
              <Link to={`/providers/${account.id}?tab=ports`} className={TEXT_LINK}>
                AirVPN · {account.label}
              </Link>
            ) : owner?.profile?.provider === "airvpn" ? (
              m.settings.airvpnWithoutAccount
            ) : (
              m.settings.generic
            )}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>
    </InspectorFrame>
  );
}
