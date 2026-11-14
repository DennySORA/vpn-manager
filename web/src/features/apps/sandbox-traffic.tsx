// The live traffic of a strict App: its connection's App sandbox — the Apps' TCP and UDP payload on their own flows as the
// sandbox's TUN filter counts it, plus what the connection's port forwards relayed to and from them (a strict connection's
// forwards all end in the sandbox). The connection's proxy ports and DNS are not in it. Every strict App of the connection
// shares the sandbox, so with more than one App the figures are theirs together and the section says so first.

import { ArrowDownUp, ChartLine } from "lucide-react";
import { useApps, useLiveRates } from "@/api/queries";
import type { AppView, InstanceView, SandboxRates } from "@/api/types";
import { latest } from "@/components/charts/rate-chart";
import { PropertyGrid, PropertyRow, PropertySection, SectionLink } from "@/components/ui/inspector";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { intlLocale } from "@/i18n";
import { formatBps } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { m as inspector } from "./inspector/messages";
import { m } from "./messages";
import { sandboxApps } from "./model";

/** What the flow tables did this generation, when they did anything (a full table refuses new flows: a warning). */
function tableNote(evicted: number, refused: number): { text: string; warning: boolean } | null {
  if (!evicted && !refused) return null;
  const parts = [
    evicted ? inspector.sandbox.evicted(evicted) : null,
    refused ? inspector.sandbox.tableFull(refused) : null,
  ].filter((p) => p !== null);
  return { text: inspector.sandbox.notes(parts), warning: refused > 0 };
}

/**
 * The sandbox's latest second, and why it is missing when it is: unknown is never 0, so without a fresh sample the
 * figures say why. Re-renders every second (its own clock and live rates).
 */
function useSandboxRates(owner: InstanceView | undefined): { rates: SandboxRates | null; missing: string | null } {
  const now = useServerNow();
  const running = owner?.status?.intent.desired === "running";
  const live = useLiveRates(running ? owner.spec.id : undefined);
  const rates = latest(live.data, now)?.sandbox ?? null;
  const missing = !owner
    ? inspector.sandbox.noConnection
    : !running
      ? inspector.sandbox.connectionNotRunning(owner.spec.name)
      : rates
        ? null
        : inspector.sandbox.noLiveData;
  return { rates, missing };
}

/** ↓ and ↑ as two units that wrap whole. */
function Rates({ rates }: { rates: SandboxRates }) {
  return (
    <span>
      <span className="whitespace-nowrap">↓ {formatBps(rates.rx_bps)}</span>{" "}
      <span className="whitespace-nowrap">↑ {formatBps(rates.tx_bps)}</span>
    </span>
  );
}

/** 概況's one-line traffic of a strict App: the sandbox's live ↓／↑ that 流量 breaks down. */
export function SandboxRateRow({ owner }: { owner: InstanceView | undefined }) {
  const { rates, missing } = useSandboxRates(owner);
  return (
    <PropertyRow label={m.traffic} mono hint={rates ? inspector.sandbox.latestSecondAll : missing}>
      {rates ? <Rates rates={rates} /> : "—"}
    </PropertyRow>
  );
}

export function SandboxTraffic({ app, owner }: { app: AppView; owner: InstanceView | undefined }) {
  const apps = useApps();
  const { rates, missing } = useSandboxRates(owner);
  const others = (owner ? sandboxApps(apps.data ?? [], owner.spec.id) : []).filter((a) => a.spec.id !== app.spec.id);
  const table = rates ? tableNote(rates.evicted, rates.table_full) : null;
  return (
    <PropertySection
      title={m.traffic}
      icon={<ArrowDownUp aria-hidden />}
      actions={
        owner ? (
          <SectionLink to={`/metrics?scope=instance:${owner.spec.id}`} icon={ChartLine}>
            {inspector.sandbox.history}
          </SectionLink>
        ) : null
      }
    >
      <div className="grid grid-cols-1 gap-2.5">
        {others.length && owner ? (
          <Callout tone="info" title={inspector.sandbox.shared(others.length + 1)}>
            {inspector.sandbox.sharedDetail(
              owner.spec.name,
              app.spec.name,
              others.map((a) => a.spec.name),
            )}
          </Callout>
        ) : null}
        <PropertyGrid>
          <PropertyRow label={ui.common.download} mono hint={rates ? inspector.sandbox.latestSecond : missing}>
            {rates ? formatBps(rates.rx_bps) : "—"}
          </PropertyRow>
          <PropertyRow label={ui.common.upload} mono>
            {rates ? formatBps(rates.tx_bps) : "—"}
          </PropertyRow>
          <PropertyRow
            label={inspector.sandbox.trackedFlows}
            mono
            hint={rates ? inspector.sandbox.trackedFlowsHint : undefined}
          >
            {rates
              ? `TCP ${rates.active_tcp.toLocaleString(intlLocale)} · UDP ${rates.active_udp.toLocaleString(intlLocale)}`
              : "—"}
          </PropertyRow>
          {table ? (
            <PropertyRow label={inspector.sandbox.flowTable} hint={inspector.sandbox.flowTableHint}>
              <span className={table.warning ? "text-warning" : undefined}>{table.text}</span>
            </PropertyRow>
          ) : null}
        </PropertyGrid>
        <p className="text-caption text-fg-tertiary">{inspector.sandbox.counted}</p>
      </div>
    </PropertySection>
  );
}
