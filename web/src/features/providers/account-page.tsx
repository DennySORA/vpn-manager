// One provider account (the detail of /providers/:id), laid out like an inspector (docs/frontend-design.md §8.1): the
// EntityHeader carries the account's paid-until state and its frequent action (重新讀取帳號, then the ⋯ menu — the same
// menu as its list row); the fixed footer is the page's primary task, 建立連線 (a dialog with the server list). In
// between, the views are tabs (`?tab=`): 概況 (the connections it built and its facts), 連入埠 (AirVPN), 裝置 and 功能檢查;
// what is read from the provider is read when its tab opens. The conclusion (the egress cannot be used, a direct grant
// is open, the account has expired) leads every tab.
import { Building2, KeyRound, ListChecks, Network, Settings2 } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import { useInstances, useProfiles, useProviderDevices, useRevokeProviderDevice } from "@/api/queries";
import type { InstanceView, ProviderAccount, ProviderDevice, ProviderGate } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/dialog";
import { FooterActions, HeaderActions, RowActions } from "@/components/ui/entity-actions";
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
import { LIST_ROW, LIST_ROW_IDLE } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorCallout, LoadingRows } from "@/components/ui/states";
import { reportFailure, toast } from "@/components/ui/toast";
import { instanceLook } from "@/features/instances/model";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime } from "@/lib/format";
import { useTabParam } from "@/lib/url";
import { useServerNow } from "@/lib/server-clock";
import { useAccountActions } from "./action-host";
import { type DeviceActionId, deviceActions } from "./actions";
import { GATE_OWNER, GateList } from "./egress";
import { m as egressText } from "./egress/messages";
import { ForwardedPortsSection } from "./forwarded-ports";
import { m } from "./messages";
import { accountLook, expiryLook, gatesOf, PROVIDER_NAME, profilesOnDevice } from "./model";
import { connectionsOf } from "./ports";

function ConnectionItem({ v }: { v: InstanceView }) {
  return (
    <Link
      to={`/instances/${v.spec.id}`}
      className={cn(
        LIST_ROW,
        LIST_ROW_IDLE,
        "flex min-w-0 items-center justify-between gap-3 rounded-lg px-2.5 py-2 no-underline",
      )}
    >
      <span className="grid min-w-0">
        <span className="text-data text-fg [overflow-wrap:anywhere]">{v.spec.name}</span>
        {v.gateways.length ? (
          <span className="machine text-micro text-fg-tertiary">{v.gateways.map((g) => `:${g.port}`).join(" ")}</span>
        ) : null}
      </span>
      <StatusPill look={instanceLook(v)} className="shrink-0" />
    </Link>
  );
}

/** One device: its name and key, whose key it is, and (Mullvad) the ⋯ menu with 撤銷裝置. */
function DeviceItem({
  d,
  account,
  actions,
}: {
  d: ProviderDevice;
  account: ProviderAccount;
  actions: EntityAction<DeviceActionId>[];
}) {
  return (
    <div className="flex min-w-0 items-center gap-3 px-1 py-2">
      <KeyRound aria-hidden className={cn("size-4 shrink-0", d.owned ? "text-action-fg" : "text-fg-tertiary")} />
      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-data text-fg">
          {d.label}
          {d.owned ? (
            <Tag tone="entity">{m.devices.keyHere}</Tag>
          ) : account.provider === "airvpn" ? (
            <Tag>{m.devices.keyFromAirvpn}</Tag>
          ) : (
            <Tag>{m.devices.keyElsewhere}</Tag>
          )}
        </p>
        <p title={d.public_key} className="machine truncate text-caption text-fg-tertiary">
          {d.public_key}
          {d.ipv4_address ? ` · ${d.ipv4_address}` : ""}
          {d.ipv6_address ? ` · ${d.ipv6_address}` : ""}
        </p>
      </div>
      {d.created_at ? (
        <span className="shrink-0 text-caption text-fg-tertiary max-sm:hidden">
          {new Date(d.created_at).toLocaleDateString(intlLocale)}
        </span>
      ) : null}
      {actions.length ? <RowActions actions={actions} name={m.devices.named(d.label)} /> : null}
    </div>
  );
}

function Devices({ account, egressUsable }: { account: ProviderAccount; egressUsable: boolean }) {
  const devices = useProviderDevices(account.id, egressUsable);
  const profiles = useProfiles();
  const revoke = useRevokeProviderDevice();
  const blocked = useMutationBlocked();
  const [target, setTarget] = useState<ProviderDevice | null>(null);
  // What the dialog shows: the last chosen device, kept while it animates closed.
  const [shown, setShown] = useState<ProviderDevice | null>(null);
  const revoked = useRef(false);
  const usedBy = (d: ProviderDevice) => profilesOnDevice(profiles.data ?? [], account, d).map((p) => p.name);
  const actionsOf = (d: ProviderDevice): EntityAction<DeviceActionId>[] =>
    deviceActions(account, d, { usedBy: usedBy(d), blocked }).map((spec) => ({
      ...spec,
      pending: revoke.isPending && revoke.variables.device === d.id,
      run: () => {
        setShown(d);
        setTarget(d);
      },
    }));

  let body;
  if (!egressUsable) body = <p className="text-caption text-fg-tertiary">{m.devices.needEgress}</p>;
  else if (devices.isError)
    body = (
      <ErrorCallout
        error={devices.error}
        title={m.devices.unreadable}
        onRetry={() => void devices.refetch()}
        retrying={devices.isFetching}
      />
    );
  else if (!devices.data) body = <LoadingRows rows={2} label={m.devices.loading} />;
  else if (!devices.data.length)
    body = (
      <EmptyState compact icon={KeyRound} title={m.devices.none}>
        {account.provider === "airvpn" ? m.devices.noneAirvpn : m.devices.noneMullvad}
      </EmptyState>
    );
  else
    body = (
      <PresenceList
        items={devices.data}
        keyOf={(d) => d.id}
        className="grid grid-cols-1 divide-y divide-line-subtle"
        label={m.devices.listOf(account.label)}
      >
        {(d) => <DeviceItem d={d} account={account} actions={actionsOf(d)} />}
      </PresenceList>
    );

  return (
    <PropertySection title={m.devices.title} icon={<KeyRound aria-hidden />} count={devices.data?.length ?? null}>
      {body}
      <ConfirmDialog
        open={Boolean(target)}
        onOpenChange={(o) => {
          if (!o) setTarget(null);
        }}
        title={m.devices.revokeTitle(shown?.label ?? "")}
        confirmLabel={m.devices.revoke}
        pending={revoke.isPending}
        onConfirm={() => {
          if (!target) return;
          revoke.mutate(
            { account: account.id, device: target.id, unowned: !target.owned, key: newIdempotencyKey() },
            {
              onSuccess: () => {
                toast.success(
                  m.devices.revoked(target.label),
                  target.owned ? m.devices.revokedOwnedDetail : m.devices.revokedDetail,
                );
                revoked.current = true;
                setTarget(null);
              },
              onError: (e) => {
                reportFailure(m.devices.revokeIntent(target.label), e);
              },
            },
          );
        }}
        // The row that opened it leaves: focus goes to the page title, not to the page.
        onCloseAutoFocus={(e) => {
          if (!revoked.current) return;
          revoked.current = false;
          e.preventDefault();
          document.getElementById("page-title")?.focus({ preventScroll: true });
        }}
      >
        {shown?.owned ? (
          <p>{m.devices.revokeOwned}</p>
        ) : (
          <>
            <p>{m.devices.revokeElsewhere}</p>
            <p className="text-fg-tertiary">{m.devices.revokeElsewhereNote}</p>
          </>
        )}
      </ConfirmDialog>
    </PropertySection>
  );
}

export type AccountTab = "overview" | "ports" | "devices" | "checks";

const ACCOUNT_TAB_LABEL: Record<AccountTab, string> = {
  overview: ui.common.overview,
  ports: m.account.tabs.ports,
  devices: m.account.tabs.devices,
  checks: m.account.tabs.checks,
};

/** An account's tabs: 連入埠 only for AirVPN (Mullvad no longer offers port forwarding). */
export function accountTabs(provider: ProviderAccount["provider"]): AccountTab[] {
  return provider === "airvpn" ? ["overview", "ports", "devices", "checks"] : ["overview", "devices", "checks"];
}

export function AccountPage({
  account,
  egressUsable,
  direct,
  gates,
}: {
  account: ProviderAccount;
  egressUsable: boolean;
  direct: boolean;
  gates: ProviderGate[] | undefined;
}) {
  const now = useServerNow();
  const actions = useAccountActions(account);
  const profiles = useProfiles();
  const instances = useInstances();
  const mine = useMemo(
    () => connectionsOf(account, profiles.data ?? [], instances.data ?? []),
    [account, profiles.data, instances.data],
  );
  const look = accountLook(account, now);
  const expiry = expiryLook(account, now);
  const checks = gatesOf(gates, account.provider);
  const tabs = accountTabs(account.provider);
  const [tab, setTab] = useTabParam<AccountTab>("tab", tabs);
  const lead =
    !egressUsable || direct || expiry.tone === "danger" ? (
      <>
        {!egressUsable ? (
          <Callout tone="warning" title={m.account.egressDown}>
            {m.account.egressDownHint}
          </Callout>
        ) : null}
        {direct ? (
          <Callout tone="info" title={m.account.direct}>
            {m.account.directHint}
          </Callout>
        ) : null}
        {expiry.tone === "danger" ? (
          <Callout tone="danger" title={expiry.text}>
            {m.account.expiredHint}
          </Callout>
        ) : null}
      </>
    ) : null;

  return (
    <InspectorFrame
      tabbed
      header={
        <EntityHeader
          icon={Building2}
          title={account.label}
          status={<StatusPill look={look} />}
          description={
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <Tag>{PROVIDER_NAME[account.provider]}</Tag>
              <span>{expiry.text}</span>
            </span>
          }
          id={account.id}
          idLabel={m.account.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={m.account.actionsOf(account.label)} />}
        />
      }
      footer={
        <InspectorFooter
          note={egressUsable ? m.account.footerNote(PROVIDER_NAME[account.provider]) : m.account.footerNeedsEgress}
        >
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      <InspectorTabs
        label={m.account.viewsOf(account.label)}
        value={tab}
        onChange={setTab}
        items={tabs.map((t) => ({ value: t, label: ACCOUNT_TAB_LABEL[t] }))}
      >
        <InspectorTab value="overview" lead={lead}>
          <PropertySection title={m.account.connections} icon={<Network aria-hidden />} count={mine.length}>
            {mine.length ? (
              <PresenceList
                items={mine}
                keyOf={(v) => v.spec.id}
                className="grid grid-cols-1 gap-0.5"
                label={m.account.connectionsOf(account.label)}
              >
                {(v) => <ConnectionItem v={v} />}
              </PresenceList>
            ) : (
              <EmptyState compact icon={Network} title={m.account.noConnections}>
                {m.account.noConnectionsHint}
              </EmptyState>
            )}
          </PropertySection>

          <PropertySection title={m.account.facts} icon={<Settings2 aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={m.account.provider}>{PROVIDER_NAME[account.provider]}</PropertyRow>
              <PropertyRow
                label={m.account.paidUntil}
                hint={
                  account.observed_at
                    ? m.account.answered(relativeTime(account.observed_at, now))
                    : m.account.notAnswered
                }
              >
                {account.expires_at ? absoluteTime(account.expires_at) : ui.common.unknown}
              </PropertyRow>
              <PropertyRow label={m.account.credentials}>{m.account.credentialsStored}</PropertyRow>
              <PropertyRow label={m.account.added}>{absoluteTime(account.created_at)}</PropertyRow>
            </PropertyGrid>
          </PropertySection>
        </InspectorTab>

        {account.provider === "airvpn" ? (
          <InspectorTab value="ports" lead={lead}>
            <ForwardedPortsSection account={account} egressUsable={egressUsable && !direct} />
          </InspectorTab>
        ) : null}

        <InspectorTab value="devices" lead={lead}>
          <Devices account={account} egressUsable={egressUsable} />
        </InspectorTab>

        <InspectorTab value="checks" lead={lead}>
          <PropertySection
            title={egressText.gate.checksOf(GATE_OWNER[account.provider])}
            icon={<ListChecks aria-hidden />}
            count={checks.length || null}
          >
            <div className="grid grid-cols-1 gap-2">
              <p className="text-caption text-fg-tertiary">{m.account.checksNote}</p>
              <GateList gates={gates} provider={account.provider} />
            </div>
          </PropertySection>
        </InspectorTab>
      </InspectorTabs>
    </InspectorFrame>
  );
}
