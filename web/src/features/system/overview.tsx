// 狀態: is this installation healthy (one verdict and the facts behind it), how the web UI is reached, this
// installation, its metrics settings and the vault; 能力 (its own tab): what this host can do. The conclusion comes
// first (the view's one raised summary), the facts after it as property rows with their source underneath; the
// sections rise in once when the view opens and update in place (docs/frontend-design.md §8.1). The only action here
// is saving the metrics settings (the form's one primary button).

import {
  CircleCheck,
  CircleX,
  Database,
  Globe,
  KeyRound,
  LoaderCircle,
  Package,
  Radio,
  ShieldCheck,
  SlidersHorizontal,
  Unplug,
} from "lucide-react";
import { type CSSProperties, Fragment, useId, useState } from "react";
import { useConnection } from "@/api/events";
import { useSecrets, useSettings, useSystemStatus, useUpdateSettings } from "@/api/queries";
import type { Capability, SecretMetadata, Settings, SettingsInput, StoreHealth, SystemStatus } from "@/api/types";
import { type ServiceState, useServiceState } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill } from "@/components/ui/badge";
import { CopyButton } from "@/components/ui/copy";
import { Disclosure } from "@/components/ui/disclosure";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { PropertyGrid, PropertyRow } from "@/components/ui/inspector";
import { ICON_TILE, STAGGER_IN } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { Panel } from "@/components/ui/panel";
import { PresenceList } from "@/components/ui/presence-list";
import { m as ui } from "@/components/ui/messages";
import { Callout, EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime } from "@/lib/format";
import { parseIntField } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import type { StateLook } from "@/lib/status";
import { useServerNow } from "@/lib/server-clock";
import {
  CAPABILITY,
  SECRET_KIND,
  capabilityLimited,
  capabilitySummary,
  controllerUrls,
  groupCapabilities,
  lanOpen,
  systemVerdict,
} from "./model";
import { m } from "./messages";
import { SummaryBand, SummaryCell } from "./summary";

type Stream = ReturnType<typeof useConnection>["stream"];

function managerLook(connected: boolean | undefined): StateLook | null {
  if (connected === undefined) return null;
  return connected
    ? { label: m.health.connected, tone: "success", icon: CircleCheck }
    : { label: m.health.disconnected, tone: "danger", icon: Unplug };
}

function streamLook(stream: Stream): StateLook {
  if (stream === "open") return { label: m.health.live, tone: "success", icon: Radio };
  if (stream === "connecting") return { label: m.health.connecting, tone: "neutral", icon: LoaderCircle, busy: true };
  return { label: m.health.interrupted, tone: "warning", icon: Unplug };
}

function databaseLook(ok: boolean, failure: "danger" | "warning"): StateLook {
  return ok
    ? { label: m.health.writable, tone: "success", icon: Database }
    : { label: m.health.notWritable, tone: failure, icon: CircleX };
}

function Health({
  s,
  store,
  service,
  stream,
  style,
}: {
  s: SystemStatus | undefined;
  store: StoreHealth | undefined;
  service: ServiceState;
  stream: Stream;
  style?: CSSProperties;
}) {
  const now = useServerNow();
  const v = systemVerdict(service, store);
  return (
    <SummaryBand
      label={m.health.label}
      tone={v.tone}
      icon={v.icon}
      busy={v.icon === LoaderCircle}
      title={v.title}
      detail={v.detail}
      style={style}
      aside={
        s ? (
          <span className="text-caption text-fg-tertiary" title={absoluteTime(s.observed_at)}>
            {m.health.observed(relativeTime(s.observed_at, now))}
          </span>
        ) : null
      }
    >
      <dl className="grid grid-cols-2 md:grid-cols-5 md:divide-x md:divide-line-subtle">
        <SummaryCell label={m.health.manager} look={managerLook(s?.manager_connected)} detail="Instance Manager" />
        <SummaryCell
          label={m.health.stream}
          look={streamLook(stream)}
          detail={stream === "open" ? m.health.events : m.health.polling}
        />
        <SummaryCell
          label={m.health.controlDb}
          look={store ? databaseLook(store.control_ok, "danger") : null}
          detail={m.health.controlDbDetail}
        />
        <SummaryCell
          label={m.health.metricsDb}
          look={store ? databaseLook(store.metrics_ok, "warning") : null}
          detail={m.health.metricsDbDetail}
        />
        <SummaryCell
          label={m.health.keystore}
          look={store ? CAPABILITY[store.keystore] : null}
          detail={m.health.keystoreDetail}
        />
      </dl>
    </SummaryBand>
  );
}

function CapabilityItem({ c }: { c: Capability & { label: string } }) {
  const look = CAPABILITY[c.state];
  const name = (
    <span className={cn("min-w-0 text-data", c.state === "unsupported" ? "text-fg-secondary" : "text-fg")}>
      {c.label}
    </span>
  );
  if (!c.reason) {
    return (
      <li className="flex min-h-10 items-center justify-between gap-4 py-1.5 pl-5">
        {name}
        <StatusPill look={look} className="shrink-0" />
      </li>
    );
  }
  return (
    <li>
      {/* Limits explain themselves at once; the rest open on request. */}
      <Disclosure
        defaultOpen={capabilityLimited(c.state)}
        summaryClassName="min-h-10 rounded-md py-1.5 hover:bg-raised/40 [&>span]:flex-1"
        summary={
          <span className="flex items-center justify-between gap-4">
            {name}
            <StatusPill look={look} className="shrink-0" />
          </span>
        }
      >
        <p className="-mt-1 pr-2 pb-3 pl-5 text-caption text-fg-secondary">{localized(c.reason)}</p>
      </Disclosure>
    </li>
  );
}

function Capabilities({ caps, style }: { caps: Capability[] | undefined; style?: CSSProperties }) {
  return (
    <Panel
      icon={ShieldCheck}
      title={m.capabilities.title}
      description={caps ? capabilitySummary(caps) : m.capabilities.description}
      style={style}
      className={STAGGER_IN}
    >
      {caps ? (
        // Its own tab is as wide as the page: the groups sit side by side.
        <div className="grid grid-cols-1 items-start gap-x-8 gap-y-4 md:grid-cols-2">
          {groupCapabilities(caps).map((g) => (
            <section key={g.id} aria-label={g.title}>
              <h3 className="pb-1 text-caption font-semibold text-fg-tertiary">{g.title}</h3>
              <ul className="divide-y divide-line-subtle border-y border-line-subtle">
                {g.items.map((c) => (
                  <CapabilityItem key={c.name} c={c} />
                ))}
              </ul>
            </section>
          ))}
        </div>
      ) : (
        <div className="space-y-3" role="status" aria-label={m.capabilities.loading}>
          <Skeleton className="w-56" />
          <Skeleton className="w-48" />
          <Skeleton className="w-64" />
        </div>
      )}
    </Panel>
  );
}

function listenText(address: string, port: number): string {
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

/** A shell command that wraps only between words, never inside a `--flag`. */
function Command({ text }: { text: string }) {
  return (
    <code className="block rounded-md border border-line-subtle bg-sunken px-2.5 py-1.5 font-mono text-caption text-fg-secondary">
      {text.split(" ").map((word, i) => (
        <Fragment key={i}>
          {i ? " " : null}
          <span className="whitespace-nowrap">{word}</span>
        </Fragment>
      ))}
    </code>
  );
}

function Access({ s, style }: { s: SystemStatus; style?: CSSProperties }) {
  const open = lanOpen(s);
  const urls = controllerUrls(s);
  return (
    <Panel
      icon={Globe}
      title={m.access.title}
      description={open ? m.access.lanDescription : m.access.hostOnly}
      style={style}
      className={STAGGER_IN}
    >
      {urls.length ? (
        <ul aria-label={m.access.addresses} className="space-y-1.5">
          {urls.map((u) => (
            <li
              key={u}
              className="flex min-w-0 items-center gap-2 rounded-md border border-line-subtle bg-sunken py-1 pr-1 pl-3"
            >
              <span className="machine min-w-0 flex-1 text-data text-fg">{u}</span>
              <CopyButton value={u} label={` ${u}`} />
            </li>
          ))}
        </ul>
      ) : (
        <Callout tone="warning">{m.access.noAddress}</Callout>
      )}
      <PropertyGrid className="mt-3">
        <PropertyRow label={m.access.listening} mono>
          {listenText(s.controller_listen, s.controller_port)}
        </PropertyRow>
        {open ? (
          <PropertyRow label={m.access.allowed} hint={m.access.allowedHint}>
            <span className="machine">{m.list(s.controller_allow_clients)}</span>
          </PropertyRow>
        ) : null}
      </PropertyGrid>
      <div className="mt-3 space-y-2 border-t border-line-subtle pt-3">
        <p className="text-caption text-fg-tertiary">{m.access.change}</p>
        <Command text={`vpn-installer upgrade --port <${m.access.port}>`} />
        {open ? (
          <Command
            text={`vpn-installer upgrade --listen-address <${m.access.address}> --allow-client <${m.access.network}>`}
          />
        ) : null}
      </div>
    </Panel>
  );
}

function Installation({ s, style }: { s: SystemStatus; style?: CSSProperties }) {
  return (
    <Panel icon={Package} title={m.installation.title} style={style} className={STAGGER_IN}>
      <PropertyGrid>
        <PropertyRow label={m.version} mono>
          {s.version}
        </PropertyRow>
        <PropertyRow label={m.build} mono>
          <span className="inline-flex max-w-full min-w-0 items-center gap-1">
            <span className="truncate" title={s.build_id}>
              {s.build_id}
            </span>
            <CopyButton value={s.build_id} label="Build ID" />
          </span>
        </PropertyRow>
        <PropertyRow label={m.installation.os} mono>
          {s.os}
        </PropertyRow>
        <PropertyRow label="SQLite" mono>
          {s.store.sqlite_version}
        </PropertyRow>
        <PropertyRow label={m.installationId} mono={Boolean(s.installation_id)}>
          {s.installation_id ?? <span className="text-fg-tertiary">{m.installation.idUnknown}</span>}
        </PropertyRow>
        <PropertyRow label={m.installation.afterRestart}>{m.installation.afterRestartValue}</PropertyRow>
        {s.data_dir ? (
          <PropertyRow label={m.dataDir} mono hint={m.installation.dataDirHint}>
            <span className="inline-flex max-w-full min-w-0 items-start gap-1">
              <span className="min-w-0">{s.data_dir}</span>
              <CopyButton value={s.data_dir} label={m.copyDataDir} />
            </span>
          </PropertyRow>
        ) : null}
      </PropertyGrid>
    </Panel>
  );
}

function SettingsForm({ settings }: { settings: Settings }) {
  const update = useUpdateSettings();
  const intent = useIntentKey("settings.update");
  const formId = useId();
  const [retention, setRetention] = useState(String(settings.metrics_retention_raw_hours));
  const [quota, setQuota] = useState(String(settings.metrics_quota_mib));
  const [error, setError] = useState<unknown>(null);

  const retN = parseIntField(retention);
  const quotaN = parseIntField(quota);
  // Same ranges as the server.
  const errors = {
    retention: retN === null || retN < 1 || retN > 168 ? m.settings.retentionRange : null,
    quota: quotaN === null || quotaN < 16 || quotaN > 65536 ? "16–65536 MiB" : null,
  };
  const next: SettingsInput = {
    metrics_retention_raw_hours: retN ?? settings.metrics_retention_raw_hours,
    metrics_quota_mib: quotaN ?? settings.metrics_quota_mib,
  };
  const dirty =
    next.metrics_retention_raw_hours !== settings.metrics_retention_raw_hours ||
    next.metrics_quota_mib !== settings.metrics_quota_mib;
  const valid = !errors.retention && !errors.quota;
  const saveReason = !valid ? m.settings.fixFields : !dirty ? m.settings.noChanges : null;

  return (
    <form
      id={formId}
      noValidate
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (!valid || !dirty || update.isPending) return;
        setError(null);
        update.mutate(
          { input: next, revision: settings.revision, key: intent.next(next) },
          {
            onSuccess: () => {
              intent.settle();
              toast.success(m.settings.saved);
            },
            onError: (err) => {
              intent.settle(err);
              setError(err);
            },
          },
        );
      }}
    >
      <FormFailure error={error} />
      <Field label={m.settings.retention} hint={m.settings.retentionHint} error={errors.retention}>
        {({ id, describedBy, invalid }) => (
          <Input
            id={id}
            mono
            inputMode="numeric"
            aria-describedby={describedBy}
            aria-invalid={invalid}
            value={retention}
            onChange={(e) => {
              setRetention(e.target.value);
            }}
          />
        )}
      </Field>
      <Field label={m.settings.quota} hint={m.settings.quotaHint} error={errors.quota}>
        {({ id, describedBy, invalid }) => (
          <Input
            id={id}
            mono
            inputMode="numeric"
            aria-describedby={describedBy}
            aria-invalid={invalid}
            value={quota}
            onChange={(e) => {
              setQuota(e.target.value);
            }}
          />
        )}
      </Field>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-caption text-fg-tertiary" aria-live="polite">
          {dirty ? m.settings.dirty : m.settings.current}
        </p>
        <ActionButton
          type="submit"
          variant="primary"
          disabledReason={saveReason}
          pending={update.isPending}
          pendingLabel={ui.common.saving}
        >
          {m.settings.save}
        </ActionButton>
      </div>
    </form>
  );
}

function SettingsPanel({ style }: { style?: CSSProperties }) {
  const settings = useSettings();
  return (
    <Panel
      icon={SlidersHorizontal}
      title={m.settings.title}
      description={m.settings.description}
      style={style}
      className={STAGGER_IN}
    >
      {settings.data ? (
        <SettingsForm key={settings.data.revision} settings={settings.data} />
      ) : settings.isError ? (
        <ErrorState
          compact
          error={settings.error}
          onRetry={() => void settings.refetch()}
          retrying={settings.isFetching}
        />
      ) : (
        <div className="space-y-3" role="status" aria-label={m.settings.loading}>
          <Skeleton className="w-48" />
          <Skeleton className="w-40" />
        </div>
      )}
    </Panel>
  );
}

function SecretRow({ k, now }: { k: SecretMetadata; now: number }) {
  const kind = SECRET_KIND[k.kind] ?? k.kind;
  return (
    <div className="flex items-center gap-3 py-2.5">
      <span aria-hidden className={cn(ICON_TILE, "size-8 [&_svg]:size-4")}>
        <KeyRound />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate text-data text-fg">{k.label ?? kind}</p>
        <p className="truncate text-caption text-fg-tertiary">
          {kind}
          {k.public_fingerprint
            ? m.vault.fingerprint(
                <span className="machine" title={k.public_fingerprint}>
                  {k.public_fingerprint.slice(0, 16)}
                </span>,
              )
            : null}
        </p>
      </div>
      <span className="shrink-0 text-caption text-fg-tertiary" title={absoluteTime(k.created_at)}>
        {m.vault.created(relativeTime(k.created_at, now))}
      </span>
    </div>
  );
}

function Vault({ style }: { style?: CSSProperties }) {
  const secrets = useSecrets();
  const now = useServerNow();
  const note = m.vault.note;
  return (
    <Panel
      icon={KeyRound}
      title={m.vault.title}
      count={secrets.data?.length}
      description={secrets.data?.length ? m.vault.count(secrets.data.length, note) : note}
      style={style}
      className={STAGGER_IN}
    >
      {secrets.data ? (
        secrets.data.length ? (
          <PresenceList
            items={secrets.data}
            keyOf={(k) => k.secret_ref}
            className="-my-2.5 divide-y divide-line-subtle"
            label={m.vault.keys}
          >
            {(k) => <SecretRow k={k} now={now} />}
          </PresenceList>
        ) : (
          <EmptyState compact icon={KeyRound} title={m.vault.empty}>
            {m.vault.emptyBody}
          </EmptyState>
        )
      ) : secrets.isError ? (
        <ErrorState
          compact
          error={secrets.error}
          onRetry={() => void secrets.refetch()}
          retrying={secrets.isFetching}
        />
      ) : (
        <div className="space-y-3" role="status" aria-label={m.vault.loading}>
          <Skeleton className="w-48" />
          <Skeleton className="w-56" />
        </div>
      )}
    </Panel>
  );
}

/** Lays a view out when the status cannot be read at all. */
function StatusError({ q }: { q: ReturnType<typeof useSystemStatus> }) {
  return (
    <div className="px-4 pt-5 pb-8 md:px-6">
      <div className={cn("panel", STAGGER_IN)}>
        <ErrorState error={q.error} onRetry={() => void q.refetch()} retrying={q.isFetching} />
      </div>
    </div>
  );
}

export function OverviewView() {
  const sys = useSystemStatus();
  const service = useServiceState();
  const conn = useConnection();
  const s = sys.data;

  if (sys.isError && !s) return <StatusError q={sys} />;
  return (
    <div className="space-y-4 px-4 pt-5 pb-8 md:px-6">
      {s && lanOpen(s) ? (
        <div style={staggerStyle(0)} className={STAGGER_IN}>
          <Callout tone="warning" title={m.lan.title}>
            {m.lan.body(m.list(s.controller_allow_clients))}
          </Callout>
        </div>
      ) : null}
      <Health s={s} store={s?.store} service={service} stream={conn.stream} style={staggerStyle(1)} />
      <div className="grid items-start gap-4 md:grid-cols-2">
        <div className="min-w-0 space-y-4">
          {s ? (
            <>
              <Access s={s} style={staggerStyle(2)} />
              <Installation s={s} style={staggerStyle(4)} />
            </>
          ) : (
            <div
              style={staggerStyle(2)}
              className={cn("panel space-y-3 px-5 py-4", STAGGER_IN)}
              role="status"
              aria-label={m.loadingAccess}
            >
              <Skeleton className="w-40" />
              <Skeleton className="w-56" />
              <Skeleton className="w-48" />
            </div>
          )}
        </div>
        <div className="min-w-0 space-y-4">
          <SettingsPanel style={staggerStyle(3)} />
          <Vault style={staggerStyle(5)} />
        </div>
      </div>
    </div>
  );
}

/** 能力: what this host can do, grouped; a limit explains itself at once. */
export function CapabilitiesView() {
  const sys = useSystemStatus();
  if (sys.isError && !sys.data) return <StatusError q={sys} />;
  return (
    <div className="space-y-4 px-4 pt-5 pb-8 md:px-6">
      <Capabilities caps={sys.data?.capabilities} style={staggerStyle(0)} />
    </div>
  );
}
