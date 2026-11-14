// The inspector of one WireGuard profile (docs/frontend-design.md §8.1): the EntityHeader carries what it is (where it
// leads, its endpoint, provider and source tags) and its frequent actions (編輯, 更換入口／出口, the ⋯ menu — the same menu
// as its list row); the conclusion comes first (an expiry the provider stated, the answer of 檢查設定), then collapsible
// property sections; the fixed footer is the view's primary task, 建立連線, with 檢查設定 beside it.
import { ArrowUpRight, Cable, FileKey, KeyRound, Network, Server, Settings2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { apiGet } from "@/api/client";
import { useProviderAccounts } from "@/api/queries";
import type { InstanceView, RuntimeProfile, ValidationReport } from "@/api/types";
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
} from "@/components/ui/inspector";
import { LIST_ROW, LIST_ROW_IDLE, TEXT_LINK } from "@/components/ui/look";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState } from "@/components/ui/states";
import { reportFailure } from "@/components/ui/toast";
import { instanceLook } from "@/features/instances/model";
import { PROVIDER_NAME, profileEntryText } from "@/features/providers/model";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime } from "@/lib/format";
import { useServerNow } from "@/lib/server-clock";
import { useProfileActions } from "./action-host";
import { m } from "./messages";
import { profileLook, profilePlace } from "./model";

/**
 * A value to copy (keys, the endpoint): mono, the copy button beside it. A key wraps anywhere; a short value (an
 * endpoint) is never broken inside — the button moves to the next line instead.
 */
function Copyable({ value, label }: { value: string; label: string }) {
  const short = value.length <= 24;
  return (
    <span className={cn("inline-flex max-w-full items-start gap-1", short && "flex-wrap")}>
      <span className={short ? "whitespace-nowrap" : "min-w-0 [overflow-wrap:anywhere]"}>{value}</span>
      <CopyButton value={value} label={label} className="-mt-0.5" />
    </span>
  );
}

/** A list of addresses, one per line; nothing declared says so. */
function Lines({ items }: { items: readonly string[] }) {
  if (!items.length) return <span className="font-sans text-fg-tertiary">{m.notDeclared}</span>;
  return (
    <span className="grid grid-cols-1">
      {items.map((x) => (
        <span key={x}>{x}</span>
      ))}
    </span>
  );
}

/** The answer of 檢查設定, as the conclusion at the top (announced politely when it arrives). */
function CheckReport({ report, at }: { report: ValidationReport; at: number }) {
  const time = new Date(at).toLocaleTimeString(intlLocale, { hour12: false });
  if (!report.issues.length) return <Callout tone="success" title={m.check.passed(time)} className="animate-reveal" />;
  return (
    <Callout
      tone={report.valid ? "warning" : "danger"}
      title={report.valid ? m.check.warnings(time) : m.check.errors(time)}
      className="animate-reveal"
    >
      <ul className="list-disc space-y-0.5 pl-4">
        {report.issues.map((i) => (
          <li key={`${i.code}${i.path}`}>{localized(i.message)}</li>
        ))}
      </ul>
    </Callout>
  );
}

function UserItem({ v }: { v: InstanceView }) {
  return (
    <Link
      to={`/instances/${v.spec.id}`}
      className={cn(
        LIST_ROW,
        LIST_ROW_IDLE,
        "flex min-w-0 items-center justify-between gap-3 rounded-lg px-2.5 py-2 no-underline",
      )}
    >
      <span className="min-w-0 text-data text-fg [overflow-wrap:anywhere]">{v.spec.name}</span>
      <StatusPill look={instanceLook(v)} className="shrink-0" />
    </Link>
  );
}

export function ProfileInspector({ profile, users }: { profile: RuntimeProfile; users: InstanceView[] }) {
  const now = useServerNow();
  const accounts = useProviderAccounts();
  const [report, setReport] = useState<{ report: ValidationReport; at: number } | null>(null);
  const [checking, setChecking] = useState(false);
  const check = async () => {
    setChecking(true);
    try {
      setReport({ report: await apiGet<ValidationReport>(`/v1/profiles/${profile.id}/check`), at: Date.now() });
    } catch (e) {
      reportFailure(m.toast.checkIntent, e);
    } finally {
      setChecking(false);
    }
  };
  const actions = useProfileActions(profile, users.length, { check: { pending: checking, run: () => void check() } });

  const look = profileLook(profile, users.length, now);
  const place = profilePlace(profile);
  const source = profile.source.kind === "provider" ? profile.source : null;
  const account = source ? accounts.data?.find((a) => a.id === source.account_id) : undefined;
  const v6 = profile.interface.addresses.some((a) => a.includes(":"));
  const expired = profile.expires_at !== null && Date.parse(profile.expires_at) <= now;

  return (
    <InspectorFrame
      header={
        <EntityHeader
          icon={FileKey}
          tone="entity"
          title={profile.name}
          status={<StatusPill look={look} />}
          description={
            <span className="grid grid-cols-1 gap-1.5">
              <span className="[overflow-wrap:anywhere]">
                {place ?? m.inspector.noPlace}
                {" · "}
                <span className="machine">{profile.peer.endpoint}</span>
              </span>
              <span className="flex flex-wrap items-center gap-1.5">
                <Tag tone="entity">{PROVIDER_NAME[profile.provider]}</Tag>
                <Tag>{source ? m.inspector.fromAccount : m.inspector.imported}</Tag>
                {v6 ? <Tag>IPv6</Tag> : null}
              </span>
            </span>
          }
          id={profile.id}
          idLabel={m.inspector.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={m.actionsOf(profile.name)} />}
        />
      }
      footer={
        <InspectorFooter note={users.length ? m.inspector.footerInUse(users.length) : m.inspector.footerUnused}>
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      {/* The conclusion first; a live region that is always there, so the answer of 檢查設定 is announced. */}
      <div aria-live="polite">
        {expired || look.tone === "warning" || report ? (
          <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">
            {expired ? (
              <Callout tone="danger" title={m.inspector.expired}>
                {m.inspector.expiredBody(absoluteTime(profile.expires_at))}
              </Callout>
            ) : look.tone === "warning" ? (
              <Callout tone="warning" title={m.inspector.expiring(relativeTime(profile.expires_at, now))}>
                {m.inspector.expiringBody(absoluteTime(profile.expires_at))}
              </Callout>
            ) : null}
            {report ? <CheckReport report={report.report} at={report.at} /> : null}
          </div>
        ) : null}
      </div>

      <PropertySection title={m.inspector.identity} icon={<KeyRound aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.publicKey} mono>
            <Copyable value={profile.interface.public_key} label={m.copy.publicKey} />
          </PropertyRow>
          <PropertyRow label={m.privateKey}>{m.inspector.privateKeyNote}</PropertyRow>
          <PropertyRow label={m.presharedKey}>
            {profile.peer.preshared_key ? m.presharedStored : m.presharedNone}
          </PropertyRow>
          <PropertyRow label={m.inspector.expires} hint={profile.expires_at ? m.inspector.expiresHint : undefined}>
            {profile.expires_at
              ? m.inspector.expiresAt(absoluteTime(profile.expires_at), relativeTime(profile.expires_at, now))
              : m.notDeclared}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>

      <PropertySection title={m.inspector.peer} icon={<Server aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.endpoint} mono>
            <Copyable value={profile.peer.endpoint} label={m.copy.endpoint} />
          </PropertyRow>
          <PropertyRow label={m.publicKey} mono>
            <Copyable value={profile.peer.public_key} label={m.copy.peerPublicKey} />
          </PropertyRow>
          <PropertyRow label="AllowedIPs" mono>
            <Lines items={profile.peer.allowed_ips} />
          </PropertyRow>
          <PropertyRow label="Keepalive">
            {profile.peer.persistent_keepalive ? m.secs(profile.peer.persistent_keepalive) : m.off}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>

      <PropertySection title={m.inspector.interface} icon={<Cable aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.addresses} mono>
            <Lines items={profile.interface.addresses} />
          </PropertyRow>
          <PropertyRow label="DNS" mono hint={profile.interface.dns.length ? undefined : m.inspector.dnsHint}>
            <Lines items={profile.interface.dns} />
          </PropertyRow>
          <PropertyRow label="MTU" mono>
            {profile.interface.mtu}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>

      <PropertySection title={m.inspector.users} icon={<Network aria-hidden />} count={users.length}>
        {users.length ? (
          <PresenceList
            items={users}
            keyOf={(v) => v.spec.id}
            className="grid grid-cols-1 gap-0.5"
            label={m.inspector.usersOf(profile.name)}
          >
            {(v) => <UserItem v={v} />}
          </PresenceList>
        ) : (
          <EmptyState compact icon={Network} title={m.inspector.noUsers}>
            {m.inspector.noUsersHint}
          </EmptyState>
        )}
      </PropertySection>

      <PropertySection title={m.inspector.source} icon={<Settings2 aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.inspector.source} hint={source ? undefined : m.inspector.importedHint}>
            {source ? (
              account ? (
                <Link to={`/providers/${account.id}`} className={cn(TEXT_LINK, "inline-flex items-center gap-1")}>
                  {m.inspector.account(PROVIDER_NAME[account.provider], account.label)}
                  <ArrowUpRight aria-hidden className="size-3.5" />
                </Link>
              ) : (
                <span>{m.inspector.accountGone}</span>
              )
            ) : (
              m.inspector.importedConf
            )}
          </PropertyRow>
          {source ? (
            <>
              <PropertyRow label={m.inspector.exit} mono hint={m.inspector.exitHint}>
                {source.server_id}
              </PropertyRow>
              <PropertyRow
                label={m.inspector.entry}
                mono
                hint={
                  source.entry?.kind === "relay"
                    ? m.inspector.entryRelayHint
                    : source.entry?.kind === "address"
                      ? m.inspector.entryAddressHint
                      : undefined
                }
              >
                {profileEntryText(source.entry) ?? m.inspector.sameAsExit}
              </PropertyRow>
              <PropertyRow label={m.inspector.device} mono>
                {source.device_id}
              </PropertyRow>
            </>
          ) : profile.location?.server ? (
            <PropertyRow label={m.server} mono>
              {profile.location.server}
            </PropertyRow>
          ) : null}
          <PropertyRow label={m.created}>{absoluteTime(profile.created_at)}</PropertyRow>
          <PropertyRow label={m.inspector.revision} hint={m.inspector.updatedAt(absoluteTime(profile.updated_at))}>
            {m.inspector.revisionN(profile.revision)}
          </PropertyRow>
        </PropertyGrid>
      </PropertySection>
    </InspectorFrame>
  );
}
