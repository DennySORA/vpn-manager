// The SSH download job dialog (create and edit). The fail-closed rule comes first: every connection goes through the
// chosen proxy port's VPN, and without it the job waits. Then the server and the login (secrets go to the vault and are
// never shown again: on an edit an empty field keeps the stored one), the remote folders (the working and failed folders
// default to `doing` / `failed` beside the source), the local folder (checked by the manager while typing), and the
// behaviour. The rules mirror the server's (model.ts `formErrors`); server field errors show at their fields.
import { ShieldCheck } from "lucide-react";
import { useEffect, useId, useMemo, useState } from "react";
import { apiGet } from "@/api/client";
import type { GatewaySpec } from "@/api/generated/GatewaySpec";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import { useGateways, useInstances, useSshHosts } from "@/api/queries";
import { useSaveSshDownload, useSshDownloadDirCheck } from "@/api/ssh-downloads";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { CARD } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { Callout } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { m } from "./dialog/messages";
import { m as shared } from "./messages";
import {
  emptyForm,
  FILTER_LABEL,
  formErrors,
  formOf,
  inputOf,
  type JobForm,
  localPathOk,
  siblingDir,
  socksCapable,
} from "./model";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Edit this job; create when absent. */
  job?: SshDownloadView | undefined;
  onSaved?: (v: SshDownloadView) => void;
}

export function JobDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <JobDialogBody key={session} {...props} />;
}

/** The local folder as the manager sees it, after the typing pauses. */
function useDirCheck(path: string) {
  const [settled, setSettled] = useState<string | null>(null);
  useEffect(() => {
    const p = path.trim();
    const t = setTimeout(() => {
      setSettled(localPathOk(p) ? p : null);
    }, 400);
    return () => {
      clearTimeout(t);
    };
  }, [path]);
  return useSshDownloadDirCheck(settled);
}

function gatewayLabel(g: GatewaySpec, instanceName: string | undefined): string {
  const kind = g.kind === "mixed" ? "Mixed" : g.kind === "socks5" ? "SOCKS5" : "HTTP";
  const note = g.kind === "http" ? "http" : g.enabled ? null : "disabled";
  return m.gateway.option(g.name, g.port, kind, instanceName, note);
}

function JobDialogBody({ open, onOpenChange, job, onSaved }: Props) {
  const gateways = useGateways();
  const instances = useInstances();
  const hosts = useSshHosts(open);
  const save = useSaveSshDownload();
  const intent = useIntentKey(`ssh_download.save:${job?.job.id ?? "new"}`);
  const formId = useId();
  const [form, setForm] = useState<JobForm>(() => (job ? formOf(job.job) : emptyForm(gateways.data ?? [])));
  const [revision, setRevision] = useState(job?.job.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [reloading, setReloading] = useState(false);
  const set = <K extends keyof JobForm>(k: K, v: JobForm[K]) => {
    setForm((f) => ({ ...f, [k]: v }));
  };
  // A new job picks the first proxy port that can carry SSH once the ports have loaded.
  const firstSocks = gateways.data?.find(socksCapable)?.id ?? "";
  if (!job && !form.gateway_id && firstSocks) set("gateway_id", firstSocks);

  const names = useMemo(() => new Map((instances.data ?? []).map((v) => [v.spec.id, v.spec.name])), [instances.data]);
  const gateway = gateways.data?.find((g) => g.id === form.gateway_id);
  const owner = gateway ? instances.data?.find((v) => v.spec.id === gateway.instance_id) : undefined;
  const hasPassword = Boolean(job?.job.password);
  const hasPassphrase = Boolean(job?.job.key_passphrase);
  const local = formErrors(form, { hasPassword, hasPassphrase });
  const server = serverFieldErrors(error);
  const err = (path: string) => (submitted || error ? (local.get(path) ?? server.get(path) ?? null) : null);
  const dir = useDirCheck(form.local_dir);
  const workDefault = siblingDir(form.source_dir, "doing");
  const failedDefault = siblingDir(form.source_dir, "failed");
  const usable = (hosts.data ?? []).filter((h) => h.kind === "host" && h.host_name);

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (local.size) return;
    const input = inputOf(form, !job);
    const key = intent.next({ id: job?.job.id, rev, input });
    setError(null);
    save.mutate(
      { id: job?.job.id, revision: rev, input, key },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(
            job ? m.updated(r.data.job.name) : m.created(r.data.job.name),
            r.data.status?.state === "paused" ? m.createdPaused : shared.sent.vpnOnly,
          );
          onSaved?.(r.data);
          onOpenChange(false);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const latest = async (apply: boolean) => {
    if (!job) return;
    setReloading(true);
    try {
      const v = await apiGet<SshDownloadView>(`/v1/ssh-downloads/${job.job.id}`);
      setRevision(v.job.revision);
      if (apply) {
        setForm(formOf(v.job));
        setError(null);
      } else submit(v.job.revision);
    } catch (e) {
      setError(e);
    } finally {
      setReloading(false);
    }
  };

  const secret = (kind: "password" | "key_passphrase", stored: boolean) => {
    const clear = kind === "password" ? "clear_password" : "clear_key_passphrase";
    const text = m.secret[kind];
    return (
      <Field
        label={text.label}
        hint={stored ? (form[clear] ? m.secret.removedOnSave : m.secret.stored) : text.hint}
        error={err(`/${kind}`)}
      >
        {({ id, describedBy, invalid }) => (
          <div className="grid grid-cols-1 gap-2">
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              aria-describedby={describedBy}
              aria-invalid={invalid}
              placeholder={stored ? m.secret.storedPlaceholder : undefined}
              disabled={form[clear]}
              value={form[kind]}
              onChange={(e) => {
                set(kind, e.target.value);
              }}
            />
            {stored ? (
              <label className="flex items-center gap-2 text-caption text-fg-secondary">
                <input
                  type="checkbox"
                  checked={form[clear]}
                  onChange={(e) => {
                    setForm((f) => ({ ...f, [clear]: e.target.checked, [kind]: "" }));
                  }}
                />
                {text.remove}
              </label>
            ) : null}
          </div>
        )}
      </Field>
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={640}
      title={job ? m.editTitle(job.job.name) : shared.page.add}
      description={m.description}
      footer={
        <>
          <Button
            variant="ghost"
            onClick={() => {
              onOpenChange(false);
            }}
          >
            {ui.common.cancel}
          </Button>
          <Button
            type="submit"
            form={formId}
            variant="primary"
            pending={save.isPending}
            pendingLabel={job ? ui.common.saving : ui.common.creating}
          >
            {job ? ui.common.save : m.create}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="space-y-5"
      >
        <FormFailure
          error={error}
          onReload={() => void latest(true)}
          onOverwrite={() => void latest(false)}
          pending={reloading}
        />
        <Callout tone="info" icon={ShieldCheck} title={shared.onlyVpn}>
          {m.vpn}
        </Callout>

        <Field label={ui.common.name} required error={err("/name")}>
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              maxLength={64}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={form.name}
              onChange={(e) => {
                set("name", e.target.value);
              }}
            />
          )}
        </Field>

        <Field
          label={shared.field.gateway}
          required
          hint={owner ? m.gateway.via(owner.spec.name) : m.gateway.hint}
          error={err("/gateway_id")}
        >
          {({ id, describedBy, invalid }) => (
            <Select
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={form.gateway_id}
              onChange={(e) => {
                set("gateway_id", e.target.value);
              }}
            >
              {!form.gateway_id ? <option value="">{m.gateway.choose}</option> : null}
              {(gateways.data ?? []).map((g) => (
                <option key={g.id} value={g.id} disabled={!socksCapable(g)}>
                  {gatewayLabel(g, names.get(g.instance_id))}
                </option>
              ))}
            </Select>
          )}
        </Field>

        <fieldset className="space-y-4">
          <legend className="mb-2 text-data font-semibold text-fg">{shared.field.server}</legend>
          {usable.length && !job ? (
            <Field label={m.fromHost.label} hint={m.fromHost.hint}>
              {({ id, describedBy }) => (
                <Select
                  id={id}
                  aria-describedby={describedBy}
                  value=""
                  onChange={(e) => {
                    const h = usable.find((x) => x.id === e.target.value);
                    if (!h) return;
                    setForm((f) => ({
                      ...f,
                      name: f.name || h.alias,
                      host: h.host_name ?? f.host,
                      port: String(h.port ?? 22),
                      user: h.user ?? f.user,
                      identity_file: h.identity_file ?? f.identity_file,
                      gateway_id: h.gateway_id ?? f.gateway_id,
                    }));
                  }}
                >
                  <option value="">{m.fromHost.choose}</option>
                  {usable.map((h) => (
                    <option key={h.id} value={h.id}>
                      {m.fromHost.option(h.alias, `${h.user ? `${h.user}@` : ""}${h.host_name}`)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_7rem]">
            <Field label={m.host} required hint={m.hostHint} error={err("/host")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={form.host}
                  onChange={(e) => {
                    set("host", e.target.value);
                  }}
                />
              )}
            </Field>
            <Field label={m.port} required error={err("/port")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  inputMode="numeric"
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={form.port}
                  onChange={(e) => {
                    set("port", e.target.value);
                  }}
                />
              )}
            </Field>
          </div>
          <Field label={m.user} required error={err("/user")}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                autoComplete="off"
                spellCheck={false}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={form.user}
                onChange={(e) => {
                  set("user", e.target.value);
                }}
              />
            )}
          </Field>
        </fieldset>

        <fieldset className="space-y-4">
          <legend className="mb-2 text-data font-semibold text-fg">{shared.field.login}</legend>
          <Field label={m.identityFile} hint={m.identityFileHint} error={err("/identity_file")}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                autoComplete="off"
                spellCheck={false}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                placeholder="~/.ssh/id_ed25519"
                value={form.identity_file}
                onChange={(e) => {
                  set("identity_file", e.target.value);
                }}
              />
            )}
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            {secret("key_passphrase", hasPassphrase)}
            {secret("password", hasPassword)}
          </div>
          <p className="text-caption text-fg-tertiary">{m.vaultNote}</p>
        </fieldset>

        <fieldset className="space-y-4">
          <legend className="mb-2 text-data font-semibold text-fg">{m.remote}</legend>
          <Field label={m.source} required hint={m.sourceHint} error={err("/source_dir")}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                spellCheck={false}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                placeholder="/data/todo"
                value={form.source_dir}
                onChange={(e) => {
                  set("source_dir", e.target.value);
                }}
              />
            )}
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={m.work} hint={workDefault ? m.emptyUses(workDefault) : m.workHint} error={err("/work_dir")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  spellCheck={false}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  placeholder={workDefault ?? undefined}
                  value={form.work_dir}
                  onChange={(e) => {
                    set("work_dir", e.target.value);
                  }}
                />
              )}
            </Field>
            <Field
              label={m.failed}
              hint={failedDefault ? m.emptyUses(failedDefault) : m.failedHint}
              error={err("/failed_dir")}
            >
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  spellCheck={false}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  placeholder={failedDefault ?? undefined}
                  value={form.failed_dir}
                  onChange={(e) => {
                    set("failed_dir", e.target.value);
                  }}
                />
              )}
            </Field>
          </div>
        </fieldset>

        <Field
          label={m.local}
          required
          hint={
            dir.data ? (dir.data.problem ? undefined : dir.data.would_create ? m.localCreates : m.localOk) : m.localHint
          }
          warning={dir.data?.problem ? localized(dir.data.problem) : null}
          error={err("/local_dir")}
        >
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              mono
              spellCheck={false}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              placeholder="~/Downloads/incoming"
              value={form.local_dir}
              onChange={(e) => {
                set("local_dir", e.target.value);
              }}
            />
          )}
        </Field>

        <fieldset className="space-y-4">
          <legend className="mb-2 text-data font-semibold text-fg">{m.behavior}</legend>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={m.connections} units={m.connectionsUnit} hint={m.connectionsHint} error={err("/connections")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  inputMode="numeric"
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={form.connections}
                  onChange={(e) => {
                    set("connections", e.target.value);
                  }}
                />
              )}
            </Field>
            <Field label={shared.field.attempts} units={m.attemptsUnit} hint={m.attemptsHint} error={err("/retries")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  inputMode="numeric"
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={form.retries}
                  onChange={(e) => {
                    set("retries", e.target.value);
                  }}
                />
              )}
            </Field>
            <Field
              label={shared.field.backoff}
              units={ui.common.seconds}
              hint={shared.field.backoffHint}
              error={err("/retry_backoff_secs")}
            >
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  inputMode="numeric"
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={form.retry_backoff_secs}
                  onChange={(e) => {
                    set("retry_backoff_secs", e.target.value);
                  }}
                />
              )}
            </Field>
            <Field
              label={shared.field.scanInterval}
              units={ui.common.seconds}
              hint={m.scanIntervalHint}
              error={err("/scan_interval_secs")}
            >
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  inputMode="numeric"
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={form.scan_interval_secs}
                  onChange={(e) => {
                    set("scan_interval_secs", e.target.value);
                  }}
                />
              )}
            </Field>
          </div>
          <div className="grid grid-cols-1 gap-1.5">
            <span className="text-data font-medium text-fg-secondary">{shared.field.nameFilter}</span>
            <Segmented
              label={shared.field.nameFilter}
              value={form.name_filter}
              onChange={(v) => {
                set("name_filter", v);
              }}
              options={(Object.keys(FILTER_LABEL) as (keyof typeof FILTER_LABEL)[]).map((k) => ({
                value: k,
                label: FILTER_LABEL[k].title,
                title: FILTER_LABEL[k].text,
              }))}
            />
            <p className="text-caption text-fg-tertiary">{FILTER_LABEL[form.name_filter].text}</p>
          </div>
          <div className={cn(CARD, "space-y-3 px-3.5 py-3")}>
            <Switch
              checked={form.skip_hidden}
              onCheckedChange={(v) => {
                set("skip_hidden", v);
              }}
              label={m.skipHidden}
              description={m.skipHiddenHint}
            />
            {!job ? (
              <Switch
                checked={form.paused}
                onCheckedChange={(v) => {
                  set("paused", v);
                }}
                label={m.startPaused}
                description={m.startPausedHint}
              />
            ) : null}
          </div>
        </fieldset>

        <fieldset className="space-y-4">
          <legend className="mb-2 text-data font-semibold text-fg">{shared.field.records}</legend>
          <div className={cn(CARD, "px-3.5 py-3")}>
            <Switch
              checked={form.record_names}
              onCheckedChange={(v) => {
                set("record_names", v);
              }}
              label={m.recordNames}
              description={form.record_names ? m.recordNamesOn : m.recordNamesOff}
            />
            {job?.job.record_names && !form.record_names ? (
              <p className="mt-2 text-caption text-warning">{m.namesStillThere}</p>
            ) : null}
          </div>
          <Field label={m.keepDays} units={m.keepDaysUnit} hint={m.keepDaysHint} error={err("/history_days")}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                placeholder={m.keepDaysPlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={form.history_days}
                onChange={(e) => {
                  set("history_days", e.target.value);
                }}
                className="max-w-40"
              />
            )}
          </Field>
        </fieldset>
      </form>
    </Dialog>
  );
}
