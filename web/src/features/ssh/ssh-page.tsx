// SSH 主機 (/ssh, /ssh/:id, /ssh/new, /ssh?existing=<alias>): the list of entries VPN Manager writes and of the user's own
// ~/.ssh/config blocks beside the editor of one (MasterDetail), following the page recipe of docs/frontend-design.md
// §8.1. The status strip above says whether ssh uses what is written (the Include line, the generated file) and offers
// the one fix for each problem. The editor is an inspector: the EntityHeader (alias, kind, route, ID, 測試連線, the ⋯
// menu — the same menu as the list row), the conclusion first (the probe's result, why an entry is not in effect), the
// host, route and file sections, and the fixed footer with the one primary action, 儲存.
import { CircleCheck, FileCode, FilePen, Plus, Route, Server, SquareTerminal, TriangleAlert } from "lucide-react";
import { type ReactNode, useId, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";
import { apiGet, newIdempotencyKey } from "@/api/client";
import {
  type SshFileAction,
  useGateways,
  useInstances,
  useSaveSshHost,
  useSshFileAction,
  useSshHosts,
  useSshStatus,
  useSshTest,
} from "@/api/queries";
import type { GatewaySpec, SshExistingHost, SshHost, SshIncludeState, SshStatus, SshTestResult } from "@/api/types";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { ListItem, MasterDetail, MasterList, MasterListHeading, Page, PageHeader } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import type { EntityAction } from "@/components/ui/action-model";
import { StatusChip, Tag } from "@/components/ui/badge";
import { ButtonLink } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { ConfirmDialog } from "@/components/ui/dialog";
import { ActionMenu, FooterActions, HeaderActions } from "@/components/ui/entity-actions";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  PropertyGrid,
  PropertyRow,
  PropertySection,
} from "@/components/ui/inspector";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { reportFailure, toast } from "@/components/ui/toast";
import { KIND_LABEL } from "@/features/gateways/gateway-dialog";
import { instanceLook } from "@/features/instances/model";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { serverFieldErrors } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { allowNextNavigation, UnsavedGuard } from "@/components/unsaved";
import { type ExistingActionId, existingActions, FILE_ACTION } from "./actions";
import { SshActionHost, useSshActions } from "./action-host";
import { m } from "./messages";
import { type Draft, fromHost, hostLabel, overlayNames, previewBlock, toInput, validate } from "./model";

interface Issue {
  tone: "danger" | "warning";
  text: string;
}

/** Why ssh does not use an entry as configured right now (from where the Include stands), or
 * null. An overlay without the Include falls back to the user's own block: a direct connection. */
function notInEffect(kind: SshHost["kind"], include: SshIncludeState | undefined): Issue | null {
  if (!include || include === "present") return null;
  // ssh may refuse such a config outright, or ignore it: nothing certain to say per entry.
  if (include === "unsafe") return { tone: "warning", text: m.issue.configUnreadable };
  if (kind === "overlay")
    return include === "late"
      ? { tone: "warning", text: m.issue.overlayLate }
      : { tone: "danger", text: m.issue.overlayMissing };
  return include === "late" ? null : { tone: "warning", text: m.issue.hostMissing };
}

/** The words of a sentence that carry its warning. */
function strong(text: string) {
  return <strong className="font-medium text-fg">{text}</strong>;
}

function IssueMeta({ issue }: { issue: Issue }) {
  return (
    <span className={cn("inline-flex items-center gap-1", issue.tone === "danger" ? "text-danger" : "text-warning")}>
      <TriangleAlert aria-hidden className="size-3 shrink-0" />
      {issue.text}
    </span>
  );
}

/** The overlay entry (if any) that covers one of the block's names. */
function overlayFor(x: SshExistingHost, overlays: Map<string, SshHost>): SshHost | undefined {
  for (const p of x.patterns) {
    const o = overlays.get(p);
    if (o) return o;
  }
  return undefined;
}

/** A command or line to copy: never broken inside a token; a long one scrolls. */
function CopyLine({ value, label }: { value: string; label: string }) {
  return (
    <span className="mt-1.5 flex items-center gap-1 rounded-md border border-line bg-sunken py-1 pr-1 pl-2.5">
      <code className="relative min-w-0 flex-1 overflow-x-auto font-mono text-caption leading-5 whitespace-pre text-fg-secondary">
        {value}
      </code>
      <CopyButton value={value} label={label} />
    </span>
  );
}

/** The files: where the Include stands, whether our file is current, and the one fix for each (the strip's action). */
function FileStatus({ status, overlays, hostCount }: { status: SshStatus; overlays: string[]; hostCount: number }) {
  const action = useSshFileAction();
  const intent = useIntentKey("ssh.file");
  const blocked = useMutationBlocked();
  const [confirmOverwrite, setConfirmOverwrite] = useState(false);
  const running = action.isPending ? action.variables.action : undefined;
  const run = (which: SshFileAction, done?: () => void) => {
    const body = { which };
    const hadConfig = status.include !== "no_config";
    action.mutate(
      { action: which, key: intent.next(body) },
      {
        onSuccess: (r) => {
          intent.settle();
          done?.();
          const backup = r.data.backup;
          if (which === "include")
            toast.success(
              m.file.includeAdded,
              backup ? m.file.configBackedUp(backup) : hadConfig ? undefined : m.file.configCreated,
            );
          else if (which === "overwrite")
            toast.success(m.file.overwritten, backup ? m.file.contentBackedUp(backup) : undefined);
          else toast.success(m.file.applied);
        },
        onError: (e) => {
          intent.settle(e);
          reportFailure(m.file.intent[which], e);
        },
      },
    );
  };
  /** The strip's fix: the file action's one name and icon; one runs at a time. */
  const fix = (which: SshFileAction, primary: boolean, onClick: () => void) => (
    <ActionButton
      size="sm"
      variant={primary ? "primary" : "secondary"}
      icon={FILE_ACTION[which].icon}
      pending={running === which}
      pendingLabel={m.file.working}
      disabledReason={running === which ? null : (blocked ?? (running ? m.file.otherRunning : null))}
      onClick={onClick}
    >
      {FILE_ACTION[which].label}
    </ActionButton>
  );
  const line = <CopyLine value={status.include_line} label={m.file.includeLine} />;
  const items: ReactNode[] = [];
  if (!status.available) {
    items.push(
      <Callout key="na" tone="danger" title={m.file.unavailable}>
        {status.unavailable_reason ? localized(status.unavailable_reason) : null}
      </Callout>,
    );
  }
  // A config kept with dotfiles is read through its symlink but never edited.
  const byHand = status.config_linked ? <p className="mt-1">{m.file.configLinked}</p> : null;
  switch (status.include) {
    case "present":
      break;
    case "late":
      items.push(
        <Callout
          key="inc"
          tone="danger"
          title={m.file.late.title}
          actions={
            byHand
              ? undefined
              : fix("include", false, () => {
                  run("include");
                })
          }
        >
          {m.file.late.body(strong)}
          {line}
          {byHand}
        </Callout>,
      );
      break;
    case "missing":
    case "no_config":
      items.push(
        <Callout
          key="inc"
          // Overlays fail open without the Include: those hosts connect directly right now.
          tone={overlays.length ? "danger" : "warning"}
          title={
            overlays.length
              ? m.file.missing.overlaysDirect(overlays)
              : status.include === "no_config"
                ? m.file.missing.noConfig
                : m.file.missing.notIncluded
          }
          actions={
            byHand
              ? undefined
              : fix("include", true, () => {
                  run("include");
                })
          }
        >
          {status.include === "no_config" ? m.file.missing.createsConfig : m.file.missing.backsUpConfig}
          {line}
          {byHand}
        </Callout>,
      );
      break;
    case "unsafe":
      items.push(
        <Callout
          key="inc"
          tone={overlays.length ? "danger" : "warning"}
          title={m.file.unsafe.title(status.config_problem ? localized(status.config_problem) : null)}
        >
          {m.file.unsafe.body(overlays)}
          {line}
        </Callout>,
      );
  }
  if (status.file === "modified") {
    items.push(
      <Callout
        key="file"
        tone="danger"
        title={m.file.modified.title}
        actions={fix("overwrite", false, () => {
          setConfirmOverwrite(true);
        })}
      >
        {m.file.modified.body}
        {status.current_text ? (
          <details className="disclosure mt-2">
            <summary className="cursor-pointer text-caption text-fg-tertiary hover:text-fg-secondary">
              {m.file.modified.current}
            </summary>
            <pre className="relative mt-1 max-h-60 overflow-auto rounded-md border border-line bg-sunken p-2 font-mono text-caption text-fg-secondary">
              {status.current_text}
            </pre>
          </details>
        ) : null}
      </Callout>,
    );
  } else if (status.file === "unsafe") {
    items.push(
      <Callout key="file" tone="danger" title={m.file.unsafeFile.title}>
        {m.file.unsafeFile.body}
      </Callout>,
    );
  } else if (status.last_error) {
    items.push(
      <Callout
        key="err"
        tone="warning"
        title={m.file.lastWriteFailed}
        actions={fix("apply", false, () => {
          run("apply");
        })}
      >
        {localized(status.last_error)}
      </Callout>,
    );
  } else if (status.pending && status.include === "present") {
    items.push(
      <Callout
        key="pending"
        tone="warning"
        title={m.file.stale.title}
        actions={fix("apply", true, () => {
          run("apply");
        })}
      >
        {m.file.stale.body}
      </Callout>,
    );
  }
  return (
    <>
      <div style={staggerStyle(1)} className={cn("shrink-0 px-4 pb-4 md:px-6", STAGGER_IN)}>
        {items.length ? (
          <div className="grid grid-cols-1 gap-2">{items}</div>
        ) : (
          <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-caption text-fg-tertiary">
            <span className="inline-flex items-center gap-1.5 text-success">
              <CircleCheck aria-hidden className="size-3.5 shrink-0" />
              {hostCount ? m.file.inPlaceAndCurrent : m.file.inPlace}
            </span>
            <span className="machine min-w-0 truncate" title={status.managed_path}>
              {status.managed_path}
            </span>
          </p>
        )}
      </div>
      <ConfirmDialog
        open={confirmOverwrite}
        onOpenChange={setConfirmOverwrite}
        title={m.file.overwriteConfirm.title}
        tone="primary"
        confirmLabel={m.file.overwriteConfirm.confirm}
        pending={running === "overwrite"}
        onConfirm={() => {
          run("overwrite", () => {
            setConfirmOverwrite(false);
          });
        }}
      >
        <p>{m.file.overwriteConfirm.body}</p>
        <p>{m.file.overwriteConfirm.after}</p>
      </ConfirmDialog>
    </>
  );
}

function gatewayLabel(g: GatewaySpec, owner: string | undefined): string {
  // Two Gateways of one connection differ only by name and port: lead with the name.
  return m.route.gatewayOption(g.name, g.port, owner, KIND_LABEL[g.kind], g.enabled);
}

/** What the probe proves: this installation's Gateway reaches the host's SSH service. Whether
 * `ssh <alias>` uses this entry depends on the Include (shown above), not on the probe. */
function TestResult({ r }: { r: SshTestResult }) {
  return r.ok ? (
    <Callout tone="success" title={m.test.reached}>
      <span className="font-mono text-caption [overflow-wrap:anywhere]">{r.banner}</span>
      {r.latency_ms !== null ? (
        <span className="ml-2 text-caption text-fg-tertiary">{r.latency_ms < 1 ? "< 1" : r.latency_ms} ms</span>
      ) : null}
    </Callout>
  ) : (
    <Callout tone="danger" title={m.test.unreachable}>
      <span className="[overflow-wrap:anywhere]">{r.error ? localized(r.error) : null}</span>
    </Callout>
  );
}

function SshEditor({
  host,
  overlayOf,
  status,
  issue,
}: {
  host: SshHost | null;
  overlayOf: SshExistingHost | null;
  status: SshStatus;
  issue: Issue | null;
}) {
  const save = useSaveSshHost();
  const test = useSshTest();
  const gateways = useGateways();
  const instances = useInstances();
  const blocked = useMutationBlocked();
  const navigate = useNavigate();
  const formId = useId();
  const intent = useIntentKey(`ssh_host.save:${host?.id ?? "new"}`);
  const initial: Draft = host
    ? fromHost(host)
    : {
        kind: overlayOf ? "overlay" : "host",
        alias: overlayOf?.patterns[0] ?? "",
        hostName: "",
        user: "",
        port: "",
        identityFile: "",
        identitiesOnly: false,
        gatewayId: gateways.data?.find((g) => g.kind !== "http")?.id ?? "",
        interval: "60",
      };
  const [draft, setDraft] = useState<Draft>(initial);
  const [baseline, setBaseline] = useState(JSON.stringify(initial));
  const [revision, setRevision] = useState(host?.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [result, setResult] = useState<SshTestResult | null>(null);
  const set = (p: Partial<Draft>) => {
    setDraft((d) => ({ ...d, ...p }));
  };

  const owners = new Map((instances.data ?? []).map((v) => [v.spec.id, v]));
  const gateway = gateways.data?.find((g) => g.id === draft.gatewayId);
  const owner = gateway ? owners.get(gateway.instance_id) : undefined;
  const { errors, warnings } = validate(draft);
  const server = serverFieldErrors(error);
  const fieldError = (k: keyof Draft, path: string) =>
    submitted || error ? (errors[k] ?? server.get(path) ?? null) : (server.get(path) ?? null);
  const valid = Object.keys(errors).length === 0;
  const dirty = JSON.stringify(draft) !== baseline;
  const target =
    draft.kind === "overlay" ? (overlayOf ?? status.existing.find((x) => x.patterns.includes(draft.alias))) : null;
  const names = draft.kind === "overlay" ? overlayNames(draft.alias, target) : [draft.alias];

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (!valid) return;
    const input = toInput(draft);
    setError(null);
    save.mutate(
      { id: host?.id, revision: rev, input, key: intent.next({ rev, input }) },
      {
        onSuccess: (r) => {
          intent.settle();
          setRevision(r.data.revision);
          setBaseline(JSON.stringify(draft));
          // Neutral: whether the file was written shows in the status strip above.
          toast.success(host ? m.editor.saved(input.alias) : m.editor.added(input.alias));
          if (!host) {
            allowNextNavigation();
            void navigate(`/ssh/${r.data.id}`, { replace: true });
          }
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const latest = async (apply: boolean) => {
    if (!host) return;
    try {
      const h = await apiGet<SshHost>(`/v1/ssh-hosts/${host.id}`);
      setRevision(h.revision);
      if (apply) {
        setDraft(fromHost(h));
        setBaseline(JSON.stringify(fromHost(h)));
        setError(null);
      } else submit(h.revision);
    } catch (e) {
      setError(e);
    }
  };

  const runTest = () => {
    if (!host) return;
    setResult(null);
    test.mutate(
      { id: host.id, key: newIdempotencyKey() },
      {
        onSuccess: (r) => {
          setResult(r.data);
        },
        onError: (e) => {
          reportFailure(m.intent.test, e);
        },
      },
    );
  };

  const actions = useSshActions(host, {
    dirty,
    own: {
      test: { run: runTest, pending: test.isPending },
      save: {
        run: () => {
          submit();
        },
        pending: save.isPending,
      },
    },
  });
  const title = host ? host.alias : draft.kind === "overlay" ? m.editor.routeTitle(draft.alias) : m.addHost;
  const route = draft.gatewayId ? m.editor.viaGateway(gateway?.port ?? "?") : m.editor.direct;

  return (
    <form
      id={formId}
      noValidate
      className="flex h-full min-h-0 flex-col"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <InspectorFrame
        header={
          <EntityHeader
            icon={SquareTerminal}
            tone="info"
            title={title}
            status={issue ? <StatusChip tone={issue.tone} label={m.issue.notInEffect} title={issue.text} /> : null}
            description={
              <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <Tag tone={draft.kind === "overlay" ? "warning" : "brand"}>
                  {draft.kind === "overlay" ? m.editor.existingHost : m.editor.managedHost}
                </Tag>
                <span>{route}</span>
              </span>
            }
            id={host?.id}
            idLabel={m.editor.idLabel}
            actions={host ? <HeaderActions actions={actions} menuLabel={m.actionsOf(host.alias)} /> : undefined}
          />
        }
        footer={
          <InspectorFooter
            note={
              <span aria-live="polite">
                {dirty ? (
                  <span className="text-warning">{ui.common.unsavedChanges}</span>
                ) : host ? (
                  m.editor.savedNote
                ) : (
                  m.editor.newNote
                )}
              </span>
            }
          >
            {host ? (
              <FooterActions actions={actions} />
            ) : (
              <ActionButton
                type="submit"
                size="sm"
                variant="primary"
                icon={Plus}
                pending={save.isPending}
                pendingLabel={m.editor.adding}
                disabledReason={save.isPending ? null : blocked}
              >
                {m.editor.add}
              </ActionButton>
            )}
          </InspectorFooter>
        }
      >
        {/* The conclusion first; the probe's result is announced when it arrives (the live region stays mounted). */}
        <div aria-live="polite">
          {error || result || issue || draft.kind === "overlay" ? (
            <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">
              <FormFailure error={error} onReload={() => void latest(true)} onOverwrite={() => void latest(false)} />
              {result ? <TestResult r={result} /> : null}
              {issue ? (
                <Callout tone={issue.tone} title={issue.text}>
                  {draft.kind === "overlay" ? m.issue.overlayFix : m.issue.hostFix}
                </Callout>
              ) : null}
              {draft.kind === "overlay" ? (
                <Callout tone="warning" title={m.editor.overlay.title}>
                  {m.editor.overlay.body(strong)}
                  {target?.proxied ? <p className="mt-1">{m.editor.overlay.replacesProxy}</p> : null}
                </Callout>
              ) : null}
            </div>
          ) : null}
        </div>

        <PropertySection title={m.host.title} icon={<Server aria-hidden />}>
          {draft.kind === "overlay" ? (
            <PropertyGrid>
              <PropertyRow label={m.host.alias} mono>
                {draft.alias}
              </PropertyRow>
              {names.length > 1 ? (
                <PropertyRow label={m.host.otherNames} mono>
                  {m.host.nameList(names.slice(1))}
                </PropertyRow>
              ) : null}
              <PropertyRow label={m.host.address} mono hint={target ? m.host.configLine(target.line) : undefined}>
                {target?.host_name ?? draft.alias}
              </PropertyRow>
              {target?.user ? (
                <PropertyRow label={m.host.user} mono>
                  {target.user}
                </PropertyRow>
              ) : null}
            </PropertyGrid>
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field
                label={m.host.alias}
                required
                hint={m.host.aliasHint}
                warning={warnings.alias}
                error={fieldError("alias", "/alias")}
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    placeholder="work"
                    value={draft.alias}
                    onChange={(e) => {
                      set({ alias: e.target.value });
                    }}
                  />
                )}
              </Field>
              <Field
                label={m.host.address}
                required
                warning={warnings.hostName}
                error={fieldError("hostName", "/host_name")}
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    placeholder="git.example.com"
                    value={draft.hostName}
                    onChange={(e) => {
                      set({ hostName: e.target.value });
                    }}
                  />
                )}
              </Field>
              <Field label={m.host.user} error={fieldError("user", "/user")}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    placeholder={m.host.sshDefault}
                    value={draft.user}
                    onChange={(e) => {
                      set({ user: e.target.value });
                    }}
                  />
                )}
              </Field>
              <Field label={m.host.port} error={fieldError("port", "/port")}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    placeholder="22"
                    value={draft.port}
                    onChange={(e) => {
                      set({ port: e.target.value });
                    }}
                  />
                )}
              </Field>
              <Field
                label={m.host.identityFile}
                className="sm:col-span-2"
                error={fieldError("identityFile", "/identity_file")}
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    placeholder={m.host.identityFilePlaceholder}
                    value={draft.identityFile}
                    onChange={(e) => {
                      set({
                        identityFile: e.target.value,
                        identitiesOnly: e.target.value ? draft.identitiesOnly : false,
                      });
                    }}
                  />
                )}
              </Field>
              <div className="sm:col-span-2">
                <Switch
                  checked={draft.identitiesOnly}
                  disabled={!draft.identityFile}
                  onCheckedChange={(v) => {
                    set({ identitiesOnly: v });
                  }}
                  label={m.host.identitiesOnly}
                  description={draft.identityFile ? m.host.identitiesOnlyOn : m.host.identitiesOnlyNeedsKey}
                />
              </div>
            </div>
          )}
        </PropertySection>

        <PropertySection title={m.route.title} icon={<Route aria-hidden />}>
          <div className="grid grid-cols-1 gap-3">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field
                label={m.route.via}
                hint={draft.gatewayId ? m.route.viaHint : undefined}
                error={fieldError("gatewayId", "/gateway_id")}
              >
                {({ id, describedBy, invalid }) => (
                  <Select
                    id={id}
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={draft.gatewayId}
                    onChange={(e) => {
                      set({ gatewayId: e.target.value });
                    }}
                  >
                    {draft.kind === "host" ? (
                      <option value="">{m.route.directOption}</option>
                    ) : (
                      <option value="">{m.route.chooseGateway}</option>
                    )}
                    {(gateways.data ?? [])
                      .filter((g) => g.kind !== "http")
                      .map((g) => (
                        <option key={g.id} value={g.id}>
                          {gatewayLabel(g, owners.get(g.instance_id)?.spec.name)}
                        </option>
                      ))}
                  </Select>
                )}
              </Field>
              <Field
                label={m.route.interval}
                required={Boolean(draft.gatewayId)}
                hint={draft.gatewayId ? m.route.intervalViaVpn : m.route.intervalDirect}
                error={fieldError("interval", "/server_alive_interval")}
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={draft.interval}
                    onChange={(e) => {
                      set({ interval: e.target.value });
                    }}
                  />
                )}
              </Field>
            </div>
            {gateway && !gateway.enabled ? (
              <Callout
                tone="warning"
                title={m.route.gatewayDisabled}
                actions={
                  <ButtonLink size="sm" to={`/gateways/${gateway.id}`}>
                    {m.route.openGateway}
                  </ButtonLink>
                }
              >
                {m.route.gatewayDisabledBody}
              </Callout>
            ) : gateway ? (
              <p className="text-caption text-fg-tertiary">
                {m.route.owner(owner?.spec.name, owner ? instanceLook(owner).label : undefined)}
              </p>
            ) : null}
          </div>
        </PropertySection>

        <PropertySection title={m.preview.title} icon={<FileCode aria-hidden />}>
          <div className="grid grid-cols-1 gap-2">
            <pre className="relative overflow-x-auto rounded-lg border border-line bg-sunken px-3 py-2.5 font-mono text-caption leading-5 text-fg-secondary">
              {previewBlock(draft, gateway?.port, status, names)}
            </pre>
            {draft.gatewayId ? (
              <p className="text-caption text-fg-tertiary">{m.preview.controlPath(Boolean(host))}</p>
            ) : null}
            {draft.gatewayId && host ? <CopyLine value={`ssh -G ${host.alias}`} label={m.preview.command} /> : null}
          </div>
        </PropertySection>
      </InspectorFrame>
      <UnsavedGuard dirty={dirty && !save.isPending} />
    </form>
  );
}

/** A block of the user's own ~/.ssh/config: read only; its one action routes it through the VPN. */
function ExistingInfo({ x, overlay }: { x: SshExistingHost; overlay: SshHost | undefined }) {
  const navigate = useNavigate();
  const run = (id: ExistingActionId) =>
    navigate(
      id === "open_overlay" && overlay
        ? `/ssh/${overlay.id}`
        : `/ssh/new?overlay=${encodeURIComponent(x.patterns[0] ?? "")}`,
    );
  const actions: EntityAction<ExistingActionId>[] = existingActions(x, overlay).map((spec) => ({
    ...spec,
    pending: false,
    run: () => run(spec.id),
  }));
  return (
    <InspectorFrame
      header={
        <EntityHeader
          icon={FilePen}
          tone="neutral"
          title={hostLabel(x)}
          status={<Tag>~/.ssh/config</Tag>}
          description={m.existing.description(x.line)}
        />
      }
      footer={
        <InspectorFooter
          note={
            overlay ? m.existing.routedBy(overlay.alias) : x.wildcard ? m.existing.wildcardNote : m.existing.routeNote
          }
        >
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      {overlay || x.wildcard ? (
        <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">
          {overlay ? (
            <Callout tone="info" icon={Route} title={m.existing.routed} />
          ) : (
            <Callout tone="info" title={m.existing.wildcard}>
              {m.existing.wildcardBody}
            </Callout>
          )}
        </div>
      ) : null}
      <PropertySection title={m.host.title} icon={<Server aria-hidden />}>
        <PropertyGrid>
          <PropertyRow label={m.host.address} mono>
            {x.host_name ?? m.existing.sameAsAlias}
          </PropertyRow>
          <PropertyRow label={m.host.user} mono>
            {x.user ?? m.host.sshDefault}
          </PropertyRow>
          <PropertyRow label={m.host.port} mono>
            {x.port ?? 22}
          </PropertyRow>
          <PropertyRow label={m.existing.jump}>{x.proxied ? m.existing.jumpSet : ui.common.none}</PropertyRow>
        </PropertyGrid>
      </PropertySection>
    </InspectorFrame>
  );
}

/** A managed entry in the list: its route or why it is not in effect, and the same ⋯ menu as its editor. */
function HostRow({ h, issue, selected }: { h: SshHost; issue: Issue | null; selected: boolean }) {
  const actions = useSshActions(h);
  return (
    <ListItem
      to={`/ssh/${h.id}`}
      selected={selected}
      title={h.alias}
      meta={
        issue ? (
          <IssueMeta issue={issue} />
        ) : (
          <span className="inline-flex items-center gap-1">
            {h.gateway_id ? (
              <Route aria-hidden className="size-3 shrink-0 text-action-fg" />
            ) : (
              <Server aria-hidden className="size-3 shrink-0" />
            )}
            {h.kind === "overlay"
              ? m.list.overlayViaVpn
              : h.gateway_id
                ? m.list.hostViaVpn(h.host_name)
                : m.list.hostDirect(h.host_name)}
          </span>
        )
      }
      actions={
        <ActionMenu actions={actions} label={m.actionsOf(h.alias)} triggerLabel={m.moreActionsOf(h.alias)} size="sm" />
      }
    />
  );
}

export function SshPage() {
  const { id } = useParams();
  const [params] = useSearchParams();
  const status = useSshStatus();
  const hosts = useSshHosts();
  const all = useMemo(() => [...(hosts.data ?? [])].sort((a, b) => a.alias.localeCompare(b.alias)), [hosts.data]);
  const existingAlias = params.get("existing");
  const overlayAlias = params.get("overlay");
  const selected = id && id !== "new" ? all.find((h) => h.id === id) : undefined;
  const existing = status.data?.existing ?? [];
  const overlays = useMemo(() => new Map(all.filter((h) => h.kind === "overlay").map((h) => [h.alias, h])), [all]);
  const gateways = useGateways();
  const disabledGateways = useMemo(
    () => new Set((gateways.data ?? []).filter((g) => !g.enabled).map((g) => g.id)),
    [gateways.data],
  );
  // Why ssh does not use an entry as configured right now, or null.
  const entryIssue = (h: SshHost): Issue | null =>
    h.gateway_id && disabledGateways.has(h.gateway_id)
      ? { tone: "warning", text: m.issue.gatewayDisabled }
      : notInEffect(h.kind, status.data?.include);
  useCrumb(
    id === "new"
      ? overlayAlias
        ? m.page.crumbRoute(overlayAlias)
        : m.addHost
      : (selected?.alias ?? existingAlias ?? undefined),
  );

  const create = (
    <ButtonLink to="/ssh/new" variant="primary" icon={Plus}>
      {m.addHost}
    </ButtonLink>
  );

  let detail: ReactNode;
  if (!status.data) {
    detail = status.isError ? (
      <ErrorState error={status.error} onRetry={() => void status.refetch()} retrying={status.isFetching} />
    ) : (
      <LoadingRows rows={3} label={m.page.readingStatus} />
    );
  } else if (id === "new") {
    const overlayOf = overlayAlias
      ? (existing.find((x) => !x.wildcard && x.patterns.includes(overlayAlias)) ?? null)
      : null;
    detail =
      overlayAlias && !overlayOf ? (
        <EmptyState icon={FilePen} title={m.empty.notInConfig}>
          {m.empty.notInConfigBody}
        </EmptyState>
      ) : (
        <SshEditor
          key={`new:${overlayAlias ?? ""}`}
          host={null}
          overlayOf={overlayOf}
          status={status.data}
          issue={null}
        />
      );
  } else if (selected) {
    detail = (
      <SshEditor key={selected.id} host={selected} overlayOf={null} status={status.data} issue={entryIssue(selected)} />
    );
  } else if (existingAlias) {
    const x = existing.find((e) => e.patterns.includes(existingAlias));
    detail = x ? (
      <ExistingInfo key={`${x.line}:${existingAlias}`} x={x} overlay={overlayFor(x, overlays)} />
    ) : (
      <EmptyState icon={FilePen} title={m.empty.notInConfig}>
        {m.empty.notInConfigBody}
      </EmptyState>
    );
  } else if (id && hosts.isSuccess) {
    detail = (
      <EmptyState icon={SquareTerminal} title={m.empty.notFound}>
        {m.empty.notFoundBody}
      </EmptyState>
    );
  } else {
    detail = (
      <EmptyState
        brand={!(all.length || existing.length)}
        icon={SquareTerminal}
        title={all.length || existing.length ? m.empty.choose : m.empty.intro}
        actions={all.length || existing.length ? undefined : create}
      >
        {m.empty.body}
      </EmptyState>
    );
  }

  const list = (
    <MasterList label={shell.nav.ssh.label}>
      <MasterListHeading id="ssh-managed">{m.list.managed}</MasterListHeading>
      {hosts.isPending ? (
        <LoadingRows rows={2} label={m.list.loadingHosts} />
      ) : hosts.isError && !hosts.data ? (
        <ErrorState compact error={hosts.error} onRetry={() => void hosts.refetch()} retrying={hosts.isFetching} />
      ) : all.length ? (
        <PresenceList items={all} keyOf={(h) => h.id} className="grid grid-cols-1 gap-0.5" label={m.list.managedHosts}>
          {(h) => <HostRow h={h} issue={entryIssue(h)} selected={h.id === id} />}
        </PresenceList>
      ) : (
        <p className="px-3 py-2 text-caption text-fg-tertiary">{m.list.noEntries}</p>
      )}
      <MasterListHeading id="ssh-existing">{m.list.existing}</MasterListHeading>
      {status.isPending ? (
        <LoadingRows rows={2} label={m.list.readingConfig} />
      ) : existing.length ? (
        <PresenceList
          items={existing}
          keyOf={(x) => `${x.line}:${x.patterns[0] ?? ""}`}
          className="grid grid-cols-1 gap-0.5"
          label={m.list.existingHosts}
        >
          {(x) => {
            const alias = x.patterns[0] ?? "";
            const overlay = overlayFor(x, overlays);
            const issue = overlay ? entryIssue(overlay) : null;
            return (
              <ListItem
                to={`/ssh?existing=${encodeURIComponent(alias)}`}
                selected={!id && existingAlias === alias}
                title={hostLabel(x)}
                meta={
                  issue ? (
                    <IssueMeta issue={issue} />
                  ) : overlay ? (
                    <span className="inline-flex items-center gap-1 text-action-fg">
                      <CircleCheck aria-hidden className="size-3 shrink-0" />
                      {m.list.viaVpn}
                    </span>
                  ) : x.wildcard ? (
                    m.list.wildcard
                  ) : (
                    (x.host_name ?? "—")
                  )
                }
              />
            );
          }}
        </PresenceList>
      ) : (
        <p className="px-3 py-2 text-caption text-fg-tertiary">
          {status.data?.include === "no_config" ? m.list.noConfig : m.list.noBlocks}
        </p>
      )}
    </MasterList>
  );

  return (
    <Page>
      <SshActionHost hosts={all}>
        <PageHeader
          title={shell.nav.ssh.label}
          description={m.page.description}
          help={m.page.help}
          helpText={m.page.helpText}
          actions={create}
        />
        {status.data ? (
          <FileStatus
            status={status.data}
            overlays={all.filter((h) => h.kind === "overlay").map((h) => h.alias)}
            hostCount={all.length}
          />
        ) : null}
        <MasterDetail
          listLabel={m.page.listLabel}
          detailLabel={selected ? m.page.settingsOf(selected.alias) : shell.nav.ssh.label}
          selected={Boolean(id) || Boolean(existingAlias)}
          backTo="/ssh"
          backLabel={m.page.allHosts}
          list={list}
          detail={detail}
        />
      </SshActionHost>
    </Page>
  );
}
