// The inspector of one local proxy port (docs/frontend-design.md §8.1): the EntityHeader carries the port's state and
// its frequent actions (停用／啟用, 編輯, the ⋯ menu — the same menu as its list row); the sections are its live counts,
// how to use it and its settings; the fixed footer is the view's primary task, copying the address.
import { Activity, ChartLine, EthernetPort, Settings2, SquareTerminal } from "lucide-react";
import { Link } from "react-router";
import { useLiveRates } from "@/api/queries";
import type { GatewaySpec, InstanceView } from "@/api/types";
import { latest } from "@/components/charts/rate-chart";
import { StatusPill, Tag } from "@/components/ui/badge";
import { CopyButton } from "@/components/ui/copy";
import { FooterActions, HeaderActions } from "@/components/ui/entity-actions";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  PropertyGrid,
  PropertyRow,
  PropertySection,
  SectionLink,
} from "@/components/ui/inspector";
import { TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { instanceLook } from "@/features/instances/model";
import { localized } from "@/i18n";
import { absoluteTime, formatBps } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { useGatewayActions } from "./action-host";
import { proxyAddress } from "./actions";
import { KIND_LABEL } from "./gateway-dialog";
import { gatewayLook, gatewayRuntime } from "./model";
import { SshShare } from "./ssh-share";
import { portKinds } from "./ssh-traffic";
import { m } from "./messages";

/** A command to copy: never broken inside a token; a long one scrolls. */
function Snippet({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-1 gap-1">
      <p className="text-caption text-fg-tertiary">{label}</p>
      <div className="flex items-center gap-1 rounded-md border border-line bg-sunken py-1 pr-1 pl-2.5">
        <code className="relative min-w-0 flex-1 overflow-x-auto py-0.5 font-mono text-caption leading-5 whitespace-pre text-fg-secondary">
          {value}
        </code>
        <CopyButton value={value} label={label} />
      </div>
    </div>
  );
}

/** How to use the port: each command under an id of its own (the list's key), with its caption. */
function usage(g: GatewaySpec): { id: string; label: string; value: string }[] {
  const addr = proxyAddress(g);
  const socks = g.kind !== "http";
  const http = g.kind !== "socks5";
  const out: { id: string; label: string; value: string }[] = [];
  if (socks) {
    out.push({
      id: "curl-socks",
      label: m.inspector.usageCurlSocks,
      value: `curl --proxy socks5h://${addr} https://ifconfig.co`,
    });
    out.push({ id: "env-socks", label: m.inspector.usageEnvSocks, value: `export ALL_PROXY=socks5h://${addr}` });
  }
  if (http) {
    out.push({
      id: "curl-http",
      label: m.inspector.usageCurlHttp,
      value: `curl --proxy http://${addr} https://ifconfig.co`,
    });
    out.push({
      id: "env-http",
      label: m.inspector.usageEnvHttp,
      value: `export HTTPS_PROXY=http://${addr} HTTP_PROXY=http://${addr}`,
    });
  }
  return out;
}

export function GatewayInspector({ g, owner }: { g: GatewaySpec; owner: InstanceView | undefined }) {
  const now = useServerNow();
  const live = useLiveRates(owner?.status?.intent.desired === "running" ? owner.spec.id : undefined);
  const actions = useGatewayActions(g, owner);
  const runtime = gatewayRuntime(g, owner);
  const rates = latest(live.data, now)?.gateways.find((r) => r.gateway_id === g.id);
  const look = gatewayLook(g, runtime);
  const ownerLook = owner ? instanceLook(owner) : null;

  return (
    <InspectorFrame
      header={
        <EntityHeader
          icon={EthernetPort}
          tone="file"
          title={g.name}
          status={<StatusPill look={look} />}
          description={
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="machine text-data text-fg">{proxyAddress(g)}</span>
              <Tag tone="file">{KIND_LABEL[g.kind]}</Tag>
              {!g.enabled ? <Tag tone="warning">{ui.common.disabled}</Tag> : null}
            </span>
          }
          id={g.id}
          idLabel={m.inspector.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={m.inspector.actionsOf(g.name)} />}
        />
      }
      footer={
        <InspectorFooter
          note={
            owner && ownerLook ? (
              <span>{m.inspector.sentThrough(owner.spec.name, ownerLook.label)}</span>
            ) : (
              m.ownerNotFound
            )
          }
        >
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      {runtime?.error || !g.enabled ? (
        <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">
          {runtime?.error ? (
            <Callout tone="danger" title={m.inspector.cannotEnable}>
              <span className="[overflow-wrap:anywhere]">{localized(runtime.error)}</span>
            </Callout>
          ) : null}
          {!g.enabled ? (
            <Callout tone="warning" title={ui.common.disabled}>
              {m.inspector.disabledBody}
            </Callout>
          ) : null}
        </div>
      ) : null}

      <PropertySection
        title={m.inspector.live}
        icon={<Activity aria-hidden />}
        actions={
          <SectionLink to={`/metrics?scope=gateway:${g.id}`} icon={ChartLine}>
            {m.inspector.history}
          </SectionLink>
        }
      >
        <PropertyGrid>
          <PropertyRow label={m.connectionCount} mono hint={runtime ? m.inspector.connectionCountHint : undefined}>
            {runtime ? `TCP ${runtime.active_tcp} · UDP ${runtime.active_udp}` : "—"}
          </PropertyRow>
          <PropertyRow label={m.rate} mono>
            <span>{rates ? `↓ ${formatBps(rates.rx_bps)}  ↑ ${formatBps(rates.tx_bps)}` : "—"}</span>
            {rates ? <SshShare kinds={portKinds([rates])} scope="gateway" /> : null}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>

      <PropertySection title={m.inspector.usage} icon={<SquareTerminal aria-hidden />}>
        <div className="grid grid-cols-1 gap-3">
          {usage(g).map((u) => (
            <Snippet key={u.id} label={u.label} value={u.value} />
          ))}
          <p className="text-caption text-fg-tertiary">{m.inspector.browserHint(g.port)}</p>
        </div>
      </PropertySection>

      <PropertySection title={m.inspector.settings} icon={<Settings2 aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.owner} hint={ownerLook?.label}>
            {owner ? (
              <Link to={`/instances/${owner.spec.id}`} className={TEXT_LINK}>
                {owner.spec.name}
              </Link>
            ) : (
              "—"
            )}
          </PropertyRow>
          <PropertyRow label={m.protocol}>{KIND_LABEL[g.kind]}</PropertyRow>
          <PropertyRow label="UDP">
            {g.kind === "http" ? m.inspector.udpUnsupported : g.udp ? m.inspector.udpAllowed : m.inspector.udpRefused}
          </PropertyRow>
          <PropertyRow label={m.inspector.connectionLimit} mono>
            {g.max_connections}
          </PropertyRow>
          <PropertyRow label={m.inspector.enabledWithConnection}>
            {g.enabled ? m.inspector.enabledYes : m.inspector.enabledNo}
          </PropertyRow>
          <PropertyRow label={m.inspector.created}>{absoluteTime(g.created_at)}</PropertyRow>
        </PropertyGrid>
      </PropertySection>
    </InspectorFrame>
  );
}
