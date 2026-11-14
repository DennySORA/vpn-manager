// 診斷 and 執行環境: the diagnostics report in two tabs — each starts with the conclusion (the view's one raised summary,
// with the report's actions: 重新診斷 and 下載 JSON, from one action model), then the facts behind it as property rows:
// the checks, owned resources and databases (診斷), or the processes, disk, programs, files and metrics (執行環境).
// Downloadable as exactly the JSON shown. It holds no secrets, destinations or account numbers. Lists come and go with
// presence; a refresh updates in place; a failed refresh keeps the last report and says so (docs/frontend-design.md §8.1).

import {
  Activity as ActivityIcon,
  Boxes,
  CircleCheck,
  Cpu,
  Database,
  FileCode2,
  FolderTree,
  HardDrive,
  LifeBuoy,
  Stethoscope,
} from "lucide-react";
import type { CSSProperties } from "react";
import { useApps, useInstances } from "@/api/queries";
import { useDiagnostics } from "@/api/system";
import type {
  BinaryDigest,
  CheckStatus,
  DatabaseReport,
  DiagnosticCheck,
  DiagnosticReport,
  DiskReport,
  ManagerReport,
  ProcessReport,
} from "@/api/types";
import { UsageMeter } from "@/components/charts/meter";
import type { EntityAction } from "@/components/ui/action-model";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ChangeValue } from "@/components/ui/change-value";
import { CopyButton } from "@/components/ui/copy";
import { HeaderActions } from "@/components/ui/entity-actions";
import { m as ui } from "@/components/ui/messages";
import { PropertyGrid, PropertyRow, SectionLink } from "@/components/ui/inspector";
import { STAGGER_IN } from "@/components/ui/look";
import { staggerStyle } from "@/components/ui/motion";
import { Panel } from "@/components/ui/panel";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorCallout, ErrorState, Skeleton } from "@/components/ui/states";
import { TableFrame, TBody, Td, Th, Tr } from "@/components/ui/table";
import { AppResourceList } from "@/features/apps/resources";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, formatBytes, relativeTime, shortId } from "@/lib/format";
import { PHASE } from "@/lib/status";
import { useServerNow } from "@/lib/server-clock";
import { type DiagnosticsActionId, diagnosticsActions } from "./actions";
import { HostClock } from "./clock";
import { m } from "./diagnostics/messages";
import { m as system } from "./messages";
import {
  CHECK,
  DISK_SPACE,
  RESERVE,
  VAULT_KEY,
  checksHeadline,
  diagnosticsFileName,
  diskShare,
  gapText,
  orderChecks,
  summarizeChecks,
  uptime,
} from "./model";
import { SummaryBand, SummaryCount } from "./summary";

const clock = new Intl.DateTimeFormat(intlLocale, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

/** Save the report shown, as JSON, under its own timestamp. */
function download(r: DiagnosticReport) {
  const blob = new Blob([`${JSON.stringify(r, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = diagnosticsFileName(r);
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}

/** The report's actions, bound: 重新診斷 runs it again (pending while it runs), 下載 JSON saves the report shown. */
function useDiagnosticsActions(q: ReturnType<typeof useDiagnostics>): EntityAction<DiagnosticsActionId>[] {
  const r = q.data;
  return diagnosticsActions(r).map((spec) => ({
    ...spec,
    pending: spec.id === "rerun" && q.isFetching,
    run: () => {
      if (spec.id === "rerun") void q.refetch();
      else if (r) download(r);
    },
  }));
}

const COUNT_ORDER: CheckStatus[] = ["failed", "unknown", "warning", "ok"];

function Verdict({ r, actions, style }: { r: DiagnosticReport; actions: EntityAction[]; style?: CSSProperties }) {
  const now = useServerNow();
  const s = summarizeChecks(r.checks);
  const look = CHECK[s.worst];
  return (
    <SummaryBand
      label={m.verdict.label}
      tone={look.tone}
      icon={look.icon}
      title={checksHeadline(s)}
      detail={
        <>
          <span title={absoluteTime(r.generated_at)}>{m.verdict.generated(relativeTime(r.generated_at, now))}</span> ·{" "}
          {r.os} {r.arch} · {m.verdict.noSecrets}
        </>
      }
      aside={<HeaderActions actions={actions} menuLabel={m.actions.menu} />}
      style={style}
    >
      <dl className="grid grid-cols-2 md:grid-cols-4 md:divide-x md:divide-line-subtle">
        {COUNT_ORDER.map((st) => (
          <SummaryCount key={st} label={CHECK[st].label} icon={CHECK[st].icon} count={s[st]} tone={CHECK[st].tone} />
        ))}
      </dl>
    </SummaryBand>
  );
}

function CheckList({ checks, style }: { checks: DiagnosticCheck[]; style?: CSSProperties }) {
  const ordered = orderChecks(checks);
  const problems = ordered.filter((c) => c.status !== "ok");
  const fine = ordered.filter((c) => c.status === "ok");
  return (
    <Panel
      icon={Stethoscope}
      title={m.checks.title}
      count={checks.length}
      description={m.checks.description}
      style={style}
      className={STAGGER_IN}
    >
      {checks.length ? (
        <div className="space-y-4">
          {problems.length ? (
            <section aria-label={m.checks.attention}>
              <h3 className="pb-1 text-caption font-semibold text-fg-tertiary">{m.checks.attention}</h3>
              <PresenceList
                items={problems}
                keyOf={(c) => c.id}
                className="divide-y divide-line-subtle border-y border-line-subtle"
                label={m.checks.attentionList}
              >
                {(c) => (
                  <div className="flex items-start gap-3 py-2.5">
                    <StatusPill look={CHECK[c.status]} className="mt-px shrink-0" />
                    <span className="min-w-0 text-data text-fg [overflow-wrap:anywhere]">{localized(c.message)}</span>
                  </div>
                )}
              </PresenceList>
            </section>
          ) : null}
          {fine.length ? (
            <section aria-label={m.check.ok}>
              {problems.length ? (
                <h3 className="pb-1 text-caption font-semibold text-fg-tertiary">{m.check.ok}</h3>
              ) : null}
              <PresenceList
                items={fine}
                keyOf={(c) => c.id}
                className={cn("divide-y divide-line-subtle", problems.length > 0 && "border-y border-line-subtle")}
                label={m.checks.fineList}
              >
                {(c) => (
                  <div className="flex items-start gap-2.5 py-2">
                    <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-success" />
                    <span className="sr-only">{m.checks.fineLead}</span>
                    <span className="min-w-0 text-data text-fg-secondary [overflow-wrap:anywhere]">
                      {localized(c.message)}
                    </span>
                  </div>
                )}
              </PresenceList>
            </section>
          ) : null}
        </div>
      ) : (
        <EmptyState compact icon={Stethoscope} title={m.headline.none} />
      )}
    </Panel>
  );
}

function Stat({ label, value, detail }: { label: string; value: number; detail?: string | undefined }) {
  return (
    <div className="min-w-0 bg-surface px-3 py-2.5">
      <dt className="truncate text-caption text-fg-tertiary">{label}</dt>
      <dd className="flex items-baseline gap-1.5">
        <ChangeValue value={value} className="machine text-title text-fg" />
        {detail ? <span className="truncate text-caption text-fg-tertiary">{detail}</span> : null}
      </dd>
    </div>
  );
}

function Resources({ mgr, name, style }: { mgr: ManagerReport; name: (id: string) => string; style?: CSSProperties }) {
  const res = mgr.resources;
  const leftovers = mgr.recovery_items > 0 || mgr.recovery_gaps.length > 0;
  return (
    <Panel
      icon={Boxes}
      title={system.owned.title}
      description={
        mgr.recovery_gaps.length
          ? m.resources.gaps(mgr.recovery_gaps.length, mgr.recovery_items)
          : mgr.recovery_items
            ? m.resources.leftovers(mgr.recovery_items)
            : m.resources.none
      }
      action={
        leftovers ? (
          <SectionLink to="/system?view=recovery" icon={LifeBuoy}>
            {m.resources.toRecovery}
          </SectionLink>
        ) : null
      }
      style={style}
      className={STAGGER_IN}
    >
      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line-subtle bg-line-subtle md:grid-cols-3">
        <Stat label={system.owned.workers} value={res.workers.length} />
        <Stat label={system.owned.managedApps} value={res.apps.length} />
        <Stat
          label={system.owned.gateways}
          value={res.listeners.length}
          detail={res.unanswered.length ? m.resources.incomplete : undefined}
        />
        <Stat
          label={system.owned.keyLocks}
          value={res.key_locks.length}
          detail={m.resources.inUse(res.key_locks.filter((l) => l.used_by).length)}
        />
        <Stat
          label={system.owned.connectors}
          value={res.connector_sockets.length}
          detail={m.resources.running(res.connector_sockets.filter((s) => s.live).length)}
        />
        <Stat label={system.owned.sandboxes} value={res.sandboxes.length} />
      </dl>
      <PropertyGrid className="mt-3">
        <PropertyRow label={system.owned.workers}>
          {res.workers.length ? (
            res.workers.map((w) => (
              <span key={w.pid}>
                {name(w.instance_id)}{" "}
                <span className="machine text-fg-secondary">{m.resources.worker(w.generation, w.pid)}</span>
                {w.phase ? <span className="ml-1.5 text-fg-tertiary">{PHASE[w.phase].label}</span> : null}
              </span>
            ))
          ) : (
            <span className="text-fg-tertiary">{system.owned.noWorkers}</span>
          )}
        </PropertyRow>
        <PropertyRow label={system.owned.managedApps}>
          <AppResourceList apps={res.apps} name={name} />
        </PropertyRow>
        <PropertyRow
          label={system.owned.gateways}
          hint={
            res.unanswered.length ? (
              <span className="text-warning">{system.owned.unanswered(res.unanswered.map(name))}</span>
            ) : undefined
          }
        >
          {res.listeners.length ? (
            <span className="machine">
              {system.list(res.listeners.map((l) => m.resources.port(l.port, l.state === "serving")))}
            </span>
          ) : res.unanswered.length ? (
            <span className="text-warning">{ui.common.unknown}</span>
          ) : (
            <span className="text-fg-tertiary">{system.owned.noGateways}</span>
          )}
        </PropertyRow>
        {mgr.recovery_gaps.length ? (
          <PropertyRow label={system.owned.notChecked}>
            {mgr.recovery_gaps.map((g) => (
              <span key={`${g.what.en}-${g.path ?? ""}`} className="text-warning">
                {gapText(g)}
              </span>
            ))}
          </PropertyRow>
        ) : null}
      </PropertyGrid>
    </Panel>
  );
}

function Databases({ dbs, style }: { dbs: DatabaseReport[]; style?: CSSProperties }) {
  return (
    <Panel
      icon={Database}
      title={m.databases.title}
      description={m.databases.description}
      flush
      style={style}
      className={cn("overflow-hidden", STAGGER_IN)}
    >
      <TableFrame label={m.databases.title}>
        <thead>
          <tr>
            <Th>{m.databases.column}</Th>
            <Th align="right">{m.databases.size}</Th>
            <Th align="right">WAL</Th>
            <Th align="right">{m.databases.schema}</Th>
            <Th>{m.databases.integrity}</Th>
            <Th align="right">{m.databases.queue}</Th>
          </tr>
        </thead>
        <TBody items={dbs} keyOf={(d) => d.name}>
          {(d, row) => (
            <Tr index={row.index} exiting={row.exiting}>
              <Td className="text-fg">{d.name === "control" ? m.databases.control : m.databases.metrics}</Td>
              <Td align="right" className="machine text-fg-secondary">
                {formatBytes(d.size_bytes)}
              </Td>
              <Td align="right" className="machine text-fg-secondary">
                {formatBytes(d.wal_bytes)}
              </Td>
              <Td align="right" className="machine text-fg-secondary">
                <span title={m.databases.supported(d.supported_version)}>
                  {d.schema_version ?? "—"} / {d.supported_version}
                </span>
              </Td>
              <Td>
                {d.quick_check_ok === true ? (
                  <Tag tone="success" icon={CircleCheck}>
                    {m.databases.intact}
                  </Tag>
                ) : d.quick_check_ok === false ? (
                  <span className="text-danger [overflow-wrap:anywhere]">{localized(d.quick_check)}</span>
                ) : (
                  <span className="text-warning">{localized(d.quick_check)}</span>
                )}
              </Td>
              <Td align="right" className="machine text-fg-secondary">
                {d.queue.depth}/{d.queue.capacity}
                {d.queue.busy_refusals > 0 ? (
                  <span className="ml-1 font-sans text-warning">{m.databases.refusals(d.queue.busy_refusals)}</span>
                ) : null}
              </Td>
            </Tr>
          )}
        </TBody>
      </TableFrame>
    </Panel>
  );
}

const ROLE: Record<string, string> = m.processes.role;

function ProcessItem({ p }: { p: ProcessReport }) {
  return (
    <div className="py-3">
      <div className="flex items-baseline justify-between gap-3">
        <p className="min-w-0 text-data text-fg">
          {ROLE[p.role] ?? p.role} <span className="machine text-caption text-fg-tertiary">{p.role}</span>
        </p>
        <span className="machine shrink-0 text-caption text-fg-tertiary">pid {p.pid}</span>
      </div>
      <dl className="mt-1.5 grid grid-cols-3 gap-3">
        <div className="min-w-0">
          <dt className="text-micro text-fg-tertiary">{m.processes.uptime}</dt>
          <dd
            className="truncate text-data text-fg-secondary"
            title={p.started_at ? system.startedAt(absoluteTime(p.started_at)) : m.processes.startUnknown}
          >
            {uptime(p.uptime_secs)}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-micro text-fg-tertiary">{m.processes.memory}</dt>
          <dd className="machine truncate text-data text-fg-secondary">{formatBytes(p.rss_bytes)}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-micro text-fg-tertiary">{m.processes.cpuTime}</dt>
          <dd className="machine truncate text-data text-fg-secondary">
            {m.processes.cpuSeconds((p.cpu_ms / 1000).toFixed(1))}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function Processes({ r, style }: { r: DiagnosticReport; style?: CSSProperties }) {
  const list = [r.controller, ...(r.manager ? [r.manager.process] : [])];
  return (
    <Panel icon={Cpu} title={m.processes.title} count={list.length} style={style} className={STAGGER_IN}>
      <PresenceList
        items={list}
        keyOf={(p) => p.role}
        className="-my-3 divide-y divide-line-subtle"
        label={m.processes.title}
      >
        {(p) => <ProcessItem p={p} />}
      </PresenceList>
    </Panel>
  );
}

function Disk({ d, style }: { d: DiskReport; style?: CSSProperties }) {
  const now = useServerNow();
  const share = diskShare(d);
  const used = d.total_bytes !== null && d.free_bytes !== null ? d.total_bytes - d.free_bytes : null;
  return (
    <Panel
      icon={HardDrive}
      title={m.disk.title}
      action={<StatusPill look={DISK_SPACE[d.state]} />}
      style={style}
      className={STAGGER_IN}
    >
      {share && used !== null && d.total_bytes !== null ? (
        <div className="space-y-2">
          <UsageMeter
            label={m.disk.meter}
            value={used}
            max={d.total_bytes}
            valueText={m.disk.usage(Math.round(share.used * 100), formatBytes(d.free_bytes))}
            tone={d.state === "low" ? "warning" : "normal"}
            mark={share.low}
          />
          <p className="flex flex-wrap justify-between gap-x-3 text-caption text-fg-tertiary">
            <span>
              {m.disk.used(<span className="machine text-fg-secondary">{Math.round(share.used * 100)}%</span>)}
            </span>
            <span>
              {m.disk.free(
                <span className="machine text-fg-secondary">{formatBytes(d.free_bytes)}</span>,
                <span className="machine">{formatBytes(d.total_bytes)}</span>,
              )}
            </span>
          </p>
        </div>
      ) : null}
      <PropertyGrid className={share ? "mt-3" : undefined}>
        {d.low_threshold_bytes !== null ? (
          <PropertyRow label={m.disk.low} hint={m.disk.lowHint}>
            <span>
              <span className="machine">{formatBytes(d.low_threshold_bytes)}</span>
              {d.low_since ? (
                <span className="ml-1.5 text-warning">{m.disk.lowSince(relativeTime(d.low_since, now))}</span>
              ) : null}
            </span>
          </PropertyRow>
        ) : null}
        <PropertyRow label={m.disk.reserve} hint={m.disk.reserveHint}>
          {(
            [
              ["control", d.reserve],
              ["metrics", d.metrics_reserve],
            ] as const
          ).map(([what, state]) => (
            <span key={what}>
              {m.disk.reserveOf[what]} <span className="machine">{formatBytes(d.reserve_bytes)}</span>
              <span className={cn("ml-1.5", state === "held" ? "text-fg-secondary" : "text-warning")}>
                {RESERVE[state]}
              </span>
            </span>
          ))}
        </PropertyRow>
        {d.samples_skipped || d.rows_pruned ? (
          <PropertyRow label={m.disk.pruned} mono>
            {m.disk.prunedValue(d.rows_pruned, d.samples_skipped)}
          </PropertyRow>
        ) : null}
        {d.metrics_full_at ? (
          <PropertyRow label={m.disk.lastFull}>{absoluteTime(d.metrics_full_at)}</PropertyRow>
        ) : null}
        {d.error ? (
          <PropertyRow label={m.disk.error}>
            <span className="text-warning">{localized(d.error)}</span>
          </PropertyRow>
        ) : null}
      </PropertyGrid>
    </Panel>
  );
}

function Digest({ name, d }: { name: string; d: BinaryDigest }) {
  return (
    <PropertyRow label={name} hint={<span className="[overflow-wrap:anywhere]">{d.path}</span>}>
      {d.sha256 ? (
        <span className="machine inline-flex max-w-full min-w-0 items-center gap-1">
          <span className="truncate" title={d.sha256}>
            sha256:{d.sha256.slice(0, 16)}…
          </span>
          <CopyButton value={d.sha256} label={m.programs.sha256Of(name)} />
        </span>
      ) : (
        <span className="text-warning">{d.error ? localized(d.error) : m.unreadable}</span>
      )}
    </PropertyRow>
  );
}

function Programs({ r, style }: { r: DiagnosticReport; style?: CSSProperties }) {
  return (
    <Panel
      icon={FileCode2}
      title={m.programs.title}
      description={m.programs.description}
      style={style}
      className={STAGGER_IN}
    >
      <PropertyGrid>
        <PropertyRow label={system.version} mono>
          <span>
            {r.controller.version}
            <span className="ml-1.5 text-fg-tertiary">{r.controller.git_rev}</span>
          </span>
        </PropertyRow>
        <PropertyRow label={m.programs.components} mono>
          <span>GotaTun {r.components.gotatun}</span>
          <span>smoltcp {r.components.smoltcp}</span>
          <span>SQLite {r.components.sqlite ?? ui.common.unknown}</span>
        </PropertyRow>
        <Digest name="vpnd" d={r.controller.binary} />
        {r.manager ? <Digest name="vpnctl" d={r.manager.vpnctl} /> : null}
      </PropertyGrid>
    </Panel>
  );
}

function Places({ mgr, style }: { mgr: ManagerReport; style?: CSSProperties }) {
  // undefined: not reported; null: the file does not exist.
  const vaultSize = mgr.files.find((f) => f.name === "vault.key")?.size_bytes;
  return (
    <Panel
      icon={FolderTree}
      title={m.places.title}
      description={m.places.description}
      style={style}
      className={STAGGER_IN}
    >
      <PropertyGrid>
        <PropertyRow label={system.installationId} mono>
          {mgr.installation_id}
        </PropertyRow>
        <PropertyRow label={system.dataDir} mono>
          <span className="inline-flex max-w-full min-w-0 items-start gap-1">
            <span className="min-w-0">{mgr.data_dir}</span>
            <CopyButton value={mgr.data_dir} label={system.copyDataDir} />
          </span>
        </PropertyRow>
        <PropertyRow label={m.places.socketDir} mono>
          {mgr.run_dir}
        </PropertyRow>
        <PropertyRow
          label="vault.key"
          hint={
            <>
              {mgr.vault_key.detail ?? m.places.vaultMatches}
              {vaultSize !== undefined ? m.places.vaultFile(vaultSize === null ? null : formatBytes(vaultSize)) : ""}
            </>
          }
        >
          <StatusPill look={VAULT_KEY[mgr.vault_key.state]} />
        </PropertyRow>
        {mgr.files
          .filter((f) => f.name !== "vault.key")
          .map((f) => (
            <PropertyRow key={f.name} label={f.name} mono={f.size_bytes !== null}>
              {f.size_bytes === null ? <span className="text-warning">{m.missing}</span> : formatBytes(f.size_bytes)}
            </PropertyRow>
          ))}
        <PropertyRow
          label={ui.common.logs}
          mono={!mgr.logs_error}
          hint={mgr.logs_error || mgr.logs.length ? undefined : m.places.noLogFile}
        >
          {mgr.logs_error ? (
            <span className="text-warning">{localized(mgr.logs_error)}</span>
          ) : mgr.logs.length ? (
            mgr.logs.map((l) => (
              <span key={l.name}>
                {l.name} <span className="text-fg-tertiary">{formatBytes(l.size_bytes)}</span>
              </span>
            ))
          ) : (
            "—"
          )}
        </PropertyRow>
      </PropertyGrid>
    </Panel>
  );
}

function Activity({ mgr, style }: { mgr: ManagerReport; style?: CSSProperties }) {
  const ingress = mgr.metrics_ingress;
  return (
    <Panel
      icon={ActivityIcon}
      title={m.activity.title}
      description={m.activity.description}
      style={style}
      className={STAGGER_IN}
    >
      <PropertyGrid>
        <PropertyRow label={m.activity.writes} mono>
          <span>{m.activity.written(ingress.written, ingress.queued_now)}</span>
          {ingress.dropped || ingress.write_failures ? (
            <span className="text-warning">{m.activity.dropped(ingress.dropped, ingress.write_failures)}</span>
          ) : (
            <span className="font-sans text-fg-tertiary">{m.activity.clean}</span>
          )}
        </PropertyRow>
        <PropertyRow label={m.activity.connections}>
          {mgr.instances.length
            ? system.list(mgr.instances.map((p) => `${PHASE[p.phase].label} ${p.count}`))
            : m.activity.noConnections}
        </PropertyRow>
        <PropertyRow label={m.activity.ssh}>
          {mgr.ssh ? (
            <>
              {mgr.ssh.hosts === null ? (
                <span className="text-warning">
                  {m.activity.hostsUnknown(mgr.ssh.hosts_error ? localized(mgr.ssh.hosts_error) : null)}
                </span>
              ) : (
                <span>{m.activity.hosts(mgr.ssh.hosts)}</span>
              )}
              {mgr.ssh.file === "modified" ? <span className="text-warning">{m.activity.edited}</span> : null}
              {mgr.ssh.last_error ? (
                <span className="text-warning">{m.activity.lastWriteFailed(localized(mgr.ssh.last_error))}</span>
              ) : null}
            </>
          ) : (
            <span className="text-fg-tertiary">{m.activity.noSsh}</span>
          )}
        </PropertyRow>
      </PropertyGrid>
    </Panel>
  );
}

/**
 * One part of the diagnostics report, each in its own tab and each led by the report's verdict and its actions:
 * `checks` (診斷: the checks, the owned resources, the databases) or `runtime` (執行環境: processes, disk space, the
 * host's clock, programs and versions, locations and files, metrics and SSH).
 */
export function DiagnosticsView({ part }: { part: "checks" | "runtime" }) {
  const q = useDiagnostics();
  const instances = useInstances();
  const apps = useApps();
  const actions = useDiagnosticsActions(q);
  const r = q.data;
  const names = new Map((instances.data ?? []).map((v) => [v.spec.id, v.spec.name]));
  for (const a of apps.data ?? []) names.set(a.spec.id, a.spec.name);
  const name = (id: string) => names.get(id) ?? shortId(id);

  if (!r) {
    return (
      <div className="px-4 pt-5 pb-8 md:px-6">
        {q.isError ? (
          <div className={cn("panel", STAGGER_IN)}>
            <ErrorState
              error={q.error}
              onRetry={() => void q.refetch()}
              retrying={q.isFetching}
              title={m.view.failed}
            />
          </div>
        ) : (
          <div
            className={cn("panel-raised space-y-3 px-5 py-5", STAGGER_IN)}
            role="status"
            aria-label={m.view.generating}
          >
            <p className="text-data text-fg-tertiary">{m.view.generatingDetail}</p>
            <Skeleton className="w-72" />
            <Skeleton className="w-56" />
          </div>
        )}
      </div>
    );
  }
  const mgr = r.manager;
  return (
    <div className="space-y-4 px-4 pt-5 pb-8 md:px-6">
      <Verdict r={r} actions={actions} style={staggerStyle(0)} />
      {q.isError ? (
        <ErrorCallout
          error={q.error}
          title={m.view.stale(clock.format(Date.parse(r.generated_at)))}
          onRetry={() => void q.refetch()}
          retrying={q.isFetching}
        />
      ) : null}
      {mgr ? null : (
        <div style={staggerStyle(1)} className={STAGGER_IN}>
          <Callout tone="danger" title={m.view.managerDown}>
            {r.manager_error ? localized(r.manager_error) : m.view.noAnswer}
          </Callout>
        </div>
      )}
      {part === "checks" ? (
        <div className="grid items-start gap-4 md:grid-cols-2">
          <CheckList checks={r.checks} style={staggerStyle(2)} />
          {mgr ? (
            <div className="min-w-0 space-y-4">
              <Resources mgr={mgr} name={name} style={staggerStyle(3)} />
              <Databases dbs={mgr.databases} style={staggerStyle(4)} />
            </div>
          ) : null}
        </div>
      ) : (
        <div className="grid items-start gap-4 md:grid-cols-2">
          <div className="min-w-0 space-y-4">
            <Processes r={r} style={staggerStyle(2)} />
            {mgr?.disk ? <Disk d={mgr.disk} style={staggerStyle(4)} /> : null}
            {mgr ? <Activity mgr={mgr} style={staggerStyle(6)} /> : null}
          </div>
          <div className="min-w-0 space-y-4">
            <HostClock style={staggerStyle(3)} />
            <Programs r={r} style={staggerStyle(5)} />
            {mgr ? <Places mgr={mgr} style={staggerStyle(7)} /> : null}
          </div>
        </div>
      )}
    </div>
  );
}
