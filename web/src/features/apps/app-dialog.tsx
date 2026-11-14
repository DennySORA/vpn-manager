// The managed-App dialog (new and edit): connection, isolation mode (choice cards; a mode this host cannot run says
// why), the proxy port or — strict isolation — the local access ports, the executable as the manager checked it, the
// argv and environment editors (rows rise in, fade out and slide when moved), writable directories, resource limits and
// recovery. The rules mirror the server's (model.ts); the server still decides.
import { ArrowDown, ArrowUp, CircleCheck, LoaderCircle, Plus, TriangleAlert, X } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { apiGet } from "@/api/client";
import {
  useCapabilities,
  useExecutableCheck,
  useGateways,
  useInstances,
  useSaveApp,
  useSystemStatus,
} from "@/api/queries";
import type { AppIsolation, AppSpec, AppView, ExecutableApproval, ExecutableCheck, GatewaySpec } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { Tag } from "@/components/ui/badge";
import { Button, IconButton } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { Dialog } from "@/components/ui/dialog";
import { Disclosure } from "@/components/ui/disclosure";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { CARD, CHOICE_BASE, CHOICE_IDLE, CHOICE_SELECTED, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, ErrorCallout } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { KIND_LABEL } from "@/features/gateways/gateway-dialog";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { formatBytes } from "@/lib/format";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { APP_LIMIT_FIELDS, limitAvailability } from "@/features/limits/model";
import { useIntentKey } from "@/lib/intent";
import { AccessPortsEditor } from "./access-editor";
import { m as dialog } from "./dialog/messages";
import { m } from "./messages";
import {
  absolutePath,
  argvPreview,
  CLASS_LABEL,
  classArgs,
  classNote,
  type Draft,
  emptyDraft,
  type EnvRow,
  fromSpec,
  ISOLATION,
  ISOLATIONS,
  MAX_ARGS,
  MAX_ENV,
  MAX_WRITABLE,
  mayHandOff,
  modeAvailability,
  PLACEHOLDER_HOME,
  PLACEHOLDER_PORT,
  proxyVariables,
  type Row,
  rowKey,
  STOP_GRACE_DEFAULT,
  STOP_GRACE_MAX,
  STOP_GRACE_MIN,
  shortDigest,
  toInput,
  usesWritable,
  validate,
} from "./model";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Edit this App; create when absent. */
  app?: AppSpec;
  /** The App runs: saved changes apply at its next start. */
  running?: boolean;
  /** Takes over after a save, closing included (e.g. one navigation that selects the new App). */
  onSaved?: (v: AppView) => void;
}

export function AppDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <AppDialogBody key={session} {...props} />;
}

function gatewaysOf(all: GatewaySpec[] | undefined, instanceId: string): GatewaySpec[] {
  return (all ?? []).filter((g) => g.instance_id === instanceId).sort((a, b) => a.port - b.port);
}

/** Shell-like display of one argv (quotes only where a value would otherwise be ambiguous). */
function quoted(arg: string): string {
  return arg === "" || /[\s"'\\$`]/.test(arg) ? `"${arg.replace(/(["\\$`])/g, "\\$1")}"` : arg;
}

/**
 * Focus follows list edits: a new row's first field takes it, and after a removal the add button
 * does (after the commit, so a button re-enabled by the removal can take it).
 */
function useRowFocus() {
  const [added, setAdded] = useState<string | null>(null);
  const [removals, setRemovals] = useState(0);
  const addRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (removals) addRef.current?.focus();
  }, [removals]);
  return {
    /** `autoFocus` for a row's first field: only the row just added. */
    autoFocus: (key: string) => key === added,
    addRef,
    added: (key: string) => {
      setAdded(key);
    },
    removed: () => {
      setRemovals((n) => n + 1);
    },
  };
}

/**
 * An icon button that stays focusable when it cannot act (aria-disabled + the reason as its name's description), so
 * focus never drops to the page when, say, a row reaches the top.
 */
function RowButton({
  label,
  icon,
  reason,
  onClick,
}: {
  label: string;
  icon: typeof X;
  reason?: string | null;
  onClick: () => void;
}) {
  return (
    <IconButton
      label={label}
      icon={icon}
      aria-disabled={reason ? true : undefined}
      title={reason ? m.labelAndDetail(label, reason) : label}
      onClick={() => {
        if (!reason) onClick();
      }}
    />
  );
}

/** A row's error, or else its warning, under it. */
function RowNote({ error, warning, className }: { error: string | null; warning?: string | null; className?: string }) {
  if (error)
    return (
      <p className={cn("text-caption text-danger animate-reveal", className)} role="alert">
        {error}
      </p>
    );
  if (warning)
    return (
      <p className={cn("flex gap-1.5 text-caption text-warning animate-reveal", className)}>
        <TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0" />
        {warning}
      </p>
    );
  return null;
}

/** The accessible names of a list's rows, by the row's number (or `removedRow` while it leaves). */
interface RowNames {
  item: (n: string) => string;
  remove: (n: string) => string;
  /** A list whose order matters: its rows move up and down. */
  move?: { up: (n: string) => string; down: (n: string) => string };
}

/**
 * A list of single values (arguments, directories), each its own row; order is kept. Rows rise in when added, fade
 * out when removed, and slide to their new places when moved or when another row leaves (PresenceList).
 */
function RowsEditor({
  names,
  rows,
  onChange,
  max,
  placeholder,
  addLabel,
  errorAt,
  warningAt,
}: {
  names: RowNames;
  rows: Row[];
  onChange: (rows: Row[]) => void;
  max: number;
  placeholder: string;
  addLabel: string;
  errorAt: (i: number) => string | null;
  warningAt?: (i: number) => string | null;
}) {
  const focus = useRowFocus();
  const { addRef } = focus;
  const set = (key: string, value: string) => {
    onChange(rows.map((r) => (r.key === key ? { ...r, value } : r)));
  };
  const move = (i: number, by: number) => {
    const next = [...rows];
    const [r] = next.splice(i, 1);
    if (r) next.splice(i + by, 0, r);
    onChange(next);
  };
  return (
    <div className="grid grid-cols-1 gap-1.5">
      {rows.length ? (
        <PresenceList items={rows} keyOf={(r) => r.key} className="grid grid-cols-1 gap-1.5">
          {(r) => {
            const i = rows.findIndex((x) => x.key === r.key);
            // A removed row keeps its look while it fades out (inert), under a name of its own.
            const n = i >= 0 ? String(i + 1) : m.removedRow;
            return (
              <div className="grid grid-cols-1 gap-1">
                <div className="flex items-center gap-1.5">
                  <span aria-hidden className="machine w-6 shrink-0 text-right text-micro text-fg-tertiary">
                    {i >= 0 ? i + 1 : ""}
                  </span>
                  <Input
                    mono
                    compact
                    aria-label={names.item(n)}
                    aria-invalid={i >= 0 && Boolean(errorAt(i))}
                    spellCheck={false}
                    autoComplete="off"
                    // eslint-disable-next-line jsx-a11y/no-autofocus -- only the row the user just added takes focus
                    autoFocus={focus.autoFocus(r.key)}
                    placeholder={placeholder}
                    value={r.value}
                    onChange={(e) => {
                      set(r.key, e.target.value);
                    }}
                  />
                  {names.move ? (
                    <>
                      <RowButton
                        label={names.move.up(n)}
                        icon={ArrowUp}
                        reason={i === 0 ? dialog.alreadyFirst : null}
                        onClick={() => {
                          move(i, -1);
                        }}
                      />
                      <RowButton
                        label={names.move.down(n)}
                        icon={ArrowDown}
                        reason={i === rows.length - 1 ? dialog.alreadyLast : null}
                        onClick={() => {
                          move(i, 1);
                        }}
                      />
                    </>
                  ) : null}
                  <RowButton
                    label={names.remove(n)}
                    icon={X}
                    onClick={() => {
                      onChange(rows.filter((x) => x.key !== r.key));
                      focus.removed();
                    }}
                  />
                </div>
                {i >= 0 ? <RowNote error={errorAt(i)} warning={warningAt?.(i) ?? null} className="pl-7.5" /> : null}
              </div>
            );
          }}
        </PresenceList>
      ) : null}
      <div>
        <ActionButton
          ref={addRef}
          size="sm"
          variant="quiet"
          icon={Plus}
          disabledReason={rows.length >= max ? dialog.atMost(max) : null}
          onClick={() => {
            const key = rowKey();
            focus.added(key);
            onChange([...rows, { key, value: "" }]);
          }}
        >
          {addLabel}
        </ActionButton>
      </div>
    </div>
  );
}

/** Environment variables, a name and a value per row (the same row motion as RowsEditor). */
function EnvEditor({
  rows,
  onChange,
  errorAt,
}: {
  rows: EnvRow[];
  onChange: (rows: EnvRow[]) => void;
  errorAt: (i: number) => string | null;
}) {
  const focus = useRowFocus();
  const { addRef } = focus;
  const set = (key: string, p: Partial<EnvRow>) => {
    onChange(rows.map((r) => (r.key === key ? { ...r, ...p } : r)));
  };
  return (
    <div className="grid grid-cols-1 gap-1.5">
      {rows.length ? (
        <PresenceList items={rows} keyOf={(r) => r.key} className="grid grid-cols-1 gap-1.5">
          {(r) => {
            const i = rows.findIndex((x) => x.key === r.key);
            const n = i >= 0 ? String(i + 1) : m.removedRow;
            const error = i >= 0 ? errorAt(i) : null;
            return (
              <div className="grid grid-cols-1 gap-1">
                <div className="flex items-center gap-1.5">
                  <Input
                    mono
                    compact
                    aria-label={dialog.env.name(n)}
                    aria-invalid={Boolean(error)}
                    spellCheck={false}
                    autoComplete="off"
                    // eslint-disable-next-line jsx-a11y/no-autofocus -- only the row the user just added takes focus
                    autoFocus={focus.autoFocus(r.key)}
                    placeholder="NAME"
                    className="w-[40%] shrink-0"
                    value={r.name}
                    onChange={(e) => {
                      set(r.key, { name: e.target.value });
                    }}
                  />
                  <span aria-hidden className="font-mono text-data text-fg-tertiary">
                    =
                  </span>
                  <Input
                    mono
                    compact
                    aria-label={dialog.env.value(n)}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder={dialog.env.valuePlaceholder}
                    value={r.value}
                    onChange={(e) => {
                      set(r.key, { value: e.target.value });
                    }}
                  />
                  <RowButton
                    label={dialog.env.remove(n)}
                    icon={X}
                    onClick={() => {
                      onChange(rows.filter((x) => x.key !== r.key));
                      focus.removed();
                    }}
                  />
                </div>
                <RowNote error={error} />
              </div>
            );
          }}
        </PresenceList>
      ) : null}
      <div>
        <ActionButton
          ref={addRef}
          size="sm"
          variant="quiet"
          icon={Plus}
          disabledReason={rows.length >= MAX_ENV ? dialog.atMost(MAX_ENV) : null}
          onClick={() => {
            const key = rowKey();
            focus.added(key);
            onChange([...rows, { key, name: "", value: "" }]);
          }}
        >
          {dialog.env.add}
        </ActionButton>
      </div>
    </div>
  );
}

/** A form section's heading and its one-line explanation. */
function SectionHead({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-0.5">
      <h3 className="text-data font-medium text-fg-secondary">{title}</h3>
      {children ? <p className="text-caption text-fg-tertiary">{children}</p> : null}
    </div>
  );
}

/** What the manager found at the typed path: the file that would run, its SHA-256 and problems. */
export function ExecutableReport({
  check,
  checking,
  failure,
  approval,
  onRetry,
}: {
  check: ExecutableCheck | null;
  checking: boolean;
  failure: unknown;
  approval?: ExecutableApproval | null;
  onRetry?: () => void;
}): ReactNode {
  if (checking && !check)
    return (
      <p className="flex items-center gap-1.5 text-caption text-fg-tertiary animate-fade-in" aria-live="polite">
        <LoaderCircle aria-hidden className="size-3.5 animate-spin" />
        {dialog.executable.checking}
      </p>
    );
  if (failure && !check)
    return <ErrorCallout error={failure} title={dialog.executable.checkFailed} onRetry={onRetry} retrying={checking} />;
  if (!check) return null;
  if (!check.ok)
    return (
      <ul className="grid grid-cols-1 gap-0.5 text-caption text-danger animate-reveal" role="alert">
        {check.issues.map((i) => (
          <li key={i.code}>{localized(i.message)}</li>
        ))}
      </ul>
    );
  const sameAsApproved = approval ? approval.sha256 === check.sha256 && approval.path === check.resolved : null;
  return (
    <div className={cn(CARD, "grid grid-cols-1 gap-1.5 px-3 py-2 animate-reveal")}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1 text-caption text-success">
          <CircleCheck aria-hidden className="size-3.5" />
          {dialog.executable.canRun}
        </span>
        <Tag tone="neutral">{check.kind === "app_bundle" ? dialog.executable.bundleMain : m.executable}</Tag>
        {check.app_class ? (
          <Tag tone={mayHandOff(check.app_class.class) ? "warning" : "neutral"}>
            {CLASS_LABEL[check.app_class.class]}
          </Tag>
        ) : null}
        {check.size !== null ? (
          <span className="machine text-micro text-fg-tertiary">{formatBytes(check.size)}</span>
        ) : null}
        {sameAsApproved === true ? <span className="text-caption text-fg-tertiary">{m.sameAsApproved}</span> : null}
        {sameAsApproved === false ? (
          <span className="inline-flex items-center gap-1 text-caption text-warning">
            <TriangleAlert aria-hidden className="size-3.5" />
            {dialog.executable.differs}
          </span>
        ) : null}
      </div>
      {check.resolved && check.resolved !== check.path ? (
        <p className="font-mono text-caption text-fg-secondary [overflow-wrap:anywhere]">
          <span className="font-sans whitespace-nowrap text-fg-tertiary">{dialog.executable.resolved}</span>
          {check.resolved}
        </p>
      ) : null}
      {check.sha256 ? (
        <p className="flex items-center gap-1 font-mono text-caption text-fg-secondary">
          <span className="font-sans text-fg-tertiary">SHA-256</span>
          <span title={check.sha256}>{shortDigest(check.sha256)}</span>
          <CopyButton value={check.sha256} label="SHA-256" />
        </p>
      ) : null}
      {check.app_class ? <p className="text-caption text-fg-secondary">{classNote(check.app_class)}</p> : null}
    </div>
  );
}

function bestMode(caps: Parameters<typeof modeAvailability>[1]): AppIsolation {
  for (const mode of ["enforced_proxy", "strict_netns"] as const)
    if (modeAvailability(mode, caps).available) return mode;
  return "proxy_env";
}

function AppDialogBody({ open, onOpenChange, app, running, onSaved }: Props) {
  const instances = useInstances();
  const gateways = useGateways();
  const caps = useCapabilities();
  const sys = useSystemStatus();
  const save = useSaveApp();
  const intent = useIntentKey(`app.save:${app?.id ?? "new"}`);
  const formId = useId();

  // What the user entered; an empty connection or Gateway and an unset mode mean "the default".
  const [edits, setEdits] = useState<Draft>(() => (app ? fromSpec(app) : emptyDraft("", "", "proxy_env")));
  const [isolationChoice, setIsolationChoice] = useState<AppIsolation | null>(app?.isolation ?? null);
  const [revision, setRevision] = useState(app?.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [waitingCheck, setWaitingCheck] = useState(false);
  const set = (p: Partial<Draft>) => {
    setEdits((d) => ({ ...d, ...p }));
  };

  // Defaults follow the data as it arrives (the dialog may open from the URL before it loads):
  // the first connection, its first Gateway and the strongest mode this host runs. A choice the
  // user made always wins.
  const instanceId = edits.instanceId || (instances.data?.[0]?.spec.id ?? "");
  const draft: Draft = {
    ...edits,
    instanceId,
    gatewayId: edits.gatewayId || (gatewaysOf(gateways.data, instanceId)[0]?.id ?? ""),
    isolation: isolationChoice ?? bestMode(caps.data),
  };

  // The typed path is checked by the manager once typing pauses.
  const typed = draft.executable.trim();
  const [checkedPath, setCheckedPath] = useState<string | null>(app?.executable ?? null);
  // A path that is not absolute is not checked: forget the last one as soon as it changes (during render, not in
  // an effect).
  const [typedBefore, setTypedBefore] = useState(typed);
  if (typed !== typedBefore) {
    setTypedBefore(typed);
    if (!absolutePath(typed)) setCheckedPath(null);
  }
  useEffect(() => {
    if (!absolutePath(typed)) return;
    const t = window.setTimeout(() => {
      setCheckedPath(typed);
    }, 400);
    return () => {
      window.clearTimeout(t);
    };
  }, [typed]);
  const check = useExecutableCheck(open ? checkedPath : null);
  const current = check.data?.path === typed ? check.data : null;
  const checking = absolutePath(typed) && (checkedPath !== typed || check.isFetching);

  const instanceGateways = gatewaysOf(gateways.data, draft.instanceId);
  const gateway = instanceGateways.find((g) => g.id === draft.gatewayId);
  // What the program is (a browser gets a data directory of its own; a macOS app cannot be confined).
  const appClass = current?.ok ? current.app_class : null;
  const problems = validate(draft, appClass, gateways.data ?? []);
  const server = serverFieldErrors(error);
  const show = (path: string) =>
    submitted || error ? (problems.errors.get(path) ?? server.get(path) ?? null) : (server.get(path) ?? null);
  // A field, or the server's word on one of its entries (`/access_ports/0/allow/1`).
  const showWithin = (path: string) =>
    show(path) ?? [...server.entries()].find(([p]) => p.startsWith(`${path}/`))?.[1] ?? null;
  const pathChanged = typed !== app?.executable;
  const availability = useMemo(
    () => Object.fromEntries(ISOLATIONS.map((mode) => [mode, modeAvailability(mode, caps.data)])),
    [caps.data],
  ) as Record<AppIsolation, ReturnType<typeof modeAvailability>>;
  const strict = draft.isolation === "strict_netns";
  const home = app && sys.data?.data_dir ? `${sys.data.data_dir}/apps/${app.id}/home` : dialog.args.previewHome;
  const preview = argvPreview(draft, gateway?.port ?? null, home, appClass?.class ?? null);
  const injected = classArgs(appClass?.class).length;
  // Refused for this program whatever else is entered: said at once, not only after a submit.
  const unenforceable = draft.isolation === "enforced_proxy" ? (problems.errors.get("/isolation") ?? null) : null;
  // Resource limits fold away; the summary names what is set, and they open where one is set or has a problem.
  const setLimits = APP_LIMIT_FIELDS.filter((f) => draft.limits[f.key].trim());
  const limitsSummary = setLimits.length
    ? m.list(
        setLimits.map(
          (f) => `${f.label} ${draft.limits[f.key].trim()}${f.unit === "%" || !f.unit ? f.unit : ` ${f.unit}`}`,
        ),
      )
    : ui.common.unlimited;
  const limitsOpen = setLimits.length > 0 || APP_LIMIT_FIELDS.some((f) => server.has(`/limits/${f.key}`));

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (problems.errors.size) return;
    let sha: string | null = null;
    if (pathChanged) {
      // What is approved is exactly what was shown: the check of this path, finished.
      if (!current) {
        setWaitingCheck(true);
        return;
      }
      if (!current.ok) return;
      sha = current.sha256;
    }
    setWaitingCheck(false);
    const input = toInput(draft, sha);
    setError(null);
    save.mutate(
      { id: app?.id, revision: rev, input, key: intent.next({ id: app?.id, rev, input }) },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(
            app ? dialog.saved(r.data.spec.name) : dialog.created(r.data.spec.name),
            app && running ? dialog.savedWhileRunning : undefined,
          );
          if (onSaved) onSaved(r.data);
          else onOpenChange(false);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const latest = async (apply: boolean) => {
    if (!app) return;
    setReloading(true);
    try {
      const v = await apiGet<AppView>(`/v1/apps/${app.id}`);
      setRevision(v.spec.revision);
      if (apply) {
        setEdits(fromSpec(v.spec));
        setIsolationChoice(v.spec.isolation);
        setError(null);
      } else submit(v.spec.revision);
    } catch (e) {
      setError(e);
    } finally {
      setReloading(false);
    }
  };

  const executableError =
    show("/executable") ??
    (submitted && pathChanged && current && !current.ok ? dialog.executable.cannotApprove : null);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={720}
      title={app ? dialog.editTitle(app.name) : dialog.addTitle}
      description={dialog.description}
      footer={
        <>
          <Button
            variant="quiet"
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
            pendingLabel={app ? ui.common.saving : ui.common.creating}
          >
            {app ? ui.common.save : dialog.create}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        className="space-y-6"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <FormFailure
          error={error}
          onReload={() => void latest(true)}
          onOverwrite={() => void latest(false)}
          pending={reloading}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={ui.common.name} required error={show("/name")}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                maxLength={64}
                placeholder={dialog.namePlaceholder}
                value={draft.name}
                onChange={(e) => {
                  set({ name: e.target.value });
                }}
              />
            )}
          </Field>
          <Field label={m.connection} required error={show("/instance_id")}>
            {({ id, describedBy, invalid }) => (
              <Select
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={draft.instanceId}
                // Another connection: its own first Gateway, unless the user picks one.
                onChange={(e) => {
                  set({ instanceId: e.target.value, gatewayId: "" });
                }}
              >
                {!draft.instanceId ? <option value="">{dialog.chooseConnection}</option> : null}
                {(instances.data ?? []).map((v) => (
                  <option key={v.spec.id} value={v.spec.id}>
                    {v.spec.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>

        <fieldset className="space-y-2">
          <legend className="text-data font-medium text-fg-secondary">{dialog.isolationMode}</legend>
          <RadioGroup.Root
            name="isolation"
            value={draft.isolation}
            onValueChange={(v) => {
              setIsolationChoice(v as AppIsolation);
            }}
            className="grid gap-2 sm:grid-cols-3"
            aria-label={dialog.isolationMode}
          >
            {ISOLATIONS.map((mode) => {
              const info = ISOLATION[mode];
              const a = availability[mode];
              const Icon = info.icon;
              // A saved App keeps showing its own mode even where this host cannot run it.
              const disabled = !a.available && draft.isolation !== mode;
              const chosen = draft.isolation === mode;
              return (
                <RadioGroup.Item
                  key={mode}
                  value={mode}
                  disabled={disabled}
                  aria-describedby={`${formId}-${mode}`}
                  className={cn(
                    CHOICE_BASE,
                    "flex flex-col items-start gap-1 rounded-lg px-3 py-2.5 text-left",
                    chosen ? CHOICE_SELECTED : CHOICE_IDLE,
                    "disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:border-line-subtle disabled:hover:bg-canvas",
                  )}
                >
                  <span className="flex items-center gap-1.5 text-body font-medium text-fg">
                    <Icon
                      aria-hidden
                      className={cn("size-4 shrink-0", chosen ? "text-brand-cyan" : "text-fg-tertiary")}
                    />
                    {info.short}
                  </span>
                  <span id={`${formId}-${mode}`} className="text-caption text-fg-tertiary">
                    {a.available ? info.text : dialog.notOnThisHost(a.reason)}
                  </span>
                </RadioGroup.Item>
              );
            })}
          </RadioGroup.Root>
          {!availability[draft.isolation].available && caps.data ? (
            <Callout tone="danger" title={dialog.hostCannotRun(ISOLATION[draft.isolation].title)}>
              {availability[draft.isolation].reason}
            </Callout>
          ) : unenforceable ? (
            <Callout tone="danger" title={dialog.cannotEnforce}>
              {unenforceable}
            </Callout>
          ) : draft.isolation === "proxy_env" ? (
            <Callout tone="warning" title={ISOLATION.proxy_env.title}>
              {ISOLATION.proxy_env.limit}
            </Callout>
          ) : (
            <p className="text-caption text-fg-tertiary">
              {m.labelAndDetail(ISOLATION[draft.isolation].title, ISOLATION[draft.isolation].limit)}
            </p>
          )}
          {show("/isolation") && show("/isolation") !== unenforceable ? (
            <p className="text-caption text-danger animate-reveal" role="alert">
              {show("/isolation")}
            </p>
          ) : null}
        </fieldset>

        {strict ? (
          <AccessPortsEditor
            rows={draft.access}
            onChange={(access) => {
              set({ access });
            }}
            errorAt={showWithin}
            hostAddresses={sys.data?.host_addresses ?? []}
            newKey={rowKey}
          />
        ) : instanceGateways.length ? (
          <Field
            label={m.gateway}
            required
            error={show("/gateway_id")}
            hint={gateway ? proxyVariables(gateway.kind, gateway.port) : undefined}
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
                {!draft.gatewayId ? <option value="">{dialog.chooseGateway}</option> : null}
                {instanceGateways.map((g) => (
                  <option key={g.id} value={g.id}>
                    {dialog.gatewayOption(g.port, g.name, KIND_LABEL[g.kind], g.enabled)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : (
          <div className="space-y-1.5">
            <p className="text-data font-medium text-fg-secondary">
              {m.gateway}
              <span className="ml-1 text-danger" aria-hidden>
                *
              </span>
            </p>
            <p className={cn(CARD, "px-3 py-2 text-data text-fg-tertiary")}>
              {draft.instanceId ? dialog.noGateway : dialog.connectionFirst}
              {draft.instanceId ? (
                <Link to="/gateways?new=1" className={cn(TEXT_LINK, "ml-1")}>
                  {dialog.addGateway}
                </Link>
              ) : null}
            </p>
            {show("/gateway_id") ? (
              <p className="text-caption text-danger animate-reveal" role="alert">
                {show("/gateway_id")}
              </p>
            ) : null}
          </div>
        )}

        <div className="space-y-2">
          <Field
            label={m.executable}
            required
            error={executableError}
            hint={
              waitingCheck && !current
                ? dialog.executable.waitingForCheck
                : app && !pathChanged
                  ? dialog.executable.keepsApproval
                  : dialog.executable.hint
            }
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                aria-describedby={describedBy}
                aria-invalid={invalid}
                spellCheck={false}
                autoComplete="off"
                placeholder={dialog.executable.placeholder}
                value={draft.executable}
                onChange={(e) => {
                  set({ executable: e.target.value });
                }}
              />
            )}
          </Field>
          {absolutePath(typed) ? (
            <ExecutableReport
              check={current}
              checking={checking}
              failure={check.error}
              approval={app && !pathChanged ? app.approval : null}
              onRetry={() => void check.refetch()}
            />
          ) : null}
          <RowNote error={null} warning={problems.warnings.get("/executable") ?? null} />
        </div>

        <section className="space-y-2" aria-label={m.args}>
          <SectionHead title={m.args}>
            {dialog.args.help(
              <code className="font-mono text-fg-secondary">{PLACEHOLDER_PORT}</code>,
              <code className="font-mono text-fg-secondary">{PLACEHOLDER_HOME}</code>,
            )}
          </SectionHead>
          <RowsEditor
            names={dialog.args}
            rows={draft.args}
            onChange={(args) => {
              set({ args });
            }}
            max={MAX_ARGS}
            placeholder="--profile={app_home}/browser"
            addLabel={dialog.args.add}
            errorAt={(i) => show(`/args/${i}`)}
            warningAt={(i) => problems.warnings.get(`/args/${i}`) ?? null}
          />
          {typed && (draft.args.length || injected) ? (
            <div className="grid grid-cols-1 gap-1 animate-reveal">
              <p className="text-caption text-fg-tertiary">{dialog.args.preview(injected)}</p>
              <code className="block rounded-md border border-line-subtle bg-sunken px-2.5 py-1.5 font-mono text-caption text-fg-secondary [overflow-wrap:anywhere]">
                {preview.map(quoted).join(" ")}
              </code>
            </div>
          ) : null}
        </section>

        <Field label={m.workingDir} error={show("/working_dir")} hint={dialog.workingDirHint}>
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              mono
              aria-describedby={describedBy}
              aria-invalid={invalid}
              spellCheck={false}
              autoComplete="off"
              placeholder="/Users/me/work"
              value={draft.workingDir}
              onChange={(e) => {
                set({ workingDir: e.target.value });
              }}
            />
          )}
        </Field>

        <section className="space-y-2" aria-label={m.environment}>
          <SectionHead title={m.environment}>{dialog.env.help}</SectionHead>
          <Callout tone="warning" title={dialog.env.noSecrets}>
            {dialog.env.noSecretsDetail}
          </Callout>
          <EnvEditor
            rows={draft.env}
            onChange={(env) => {
              set({ env });
            }}
            errorAt={(i) => show(`/env/${i}`)}
          />
        </section>

        {draft.isolation === "strict_netns" ? (
          <div className={cn(CARD, "px-3.5 py-3 animate-reveal")}>
            <Switch
              checked={draft.confineWrites}
              onCheckedChange={(confineWrites) => {
                set({ confineWrites });
              }}
              label={dialog.confineWrites}
              description={dialog.confineWritesHint}
            />
          </div>
        ) : null}

        {usesWritable(draft) ? (
          <section className="space-y-2 animate-reveal" aria-label={dialog.writable.title}>
            <SectionHead title={dialog.writable.title}>
              {draft.isolation === "enforced_proxy" ? dialog.writable.enforcedHelp : dialog.writable.strictHelp}
            </SectionHead>
            <RowsEditor
              names={dialog.writable}
              rows={draft.writable}
              onChange={(writable) => {
                set({ writable });
              }}
              max={MAX_WRITABLE}
              placeholder={
                draft.isolation === "enforced_proxy" ? "/Users/me/Downloads" : "/home/me/.local/share/my-app"
              }
              addLabel={dialog.writable.add}
              errorAt={(i) => show(`/writable_paths/${i}`)}
            />
          </section>
        ) : null}

        <Disclosure
          className={cn(CARD, "px-3.5 py-2")}
          summary={
            <span className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium">{m.resourceLimits}</span>
              <span className="text-caption text-fg-tertiary">{limitsSummary}</span>
            </span>
          }
          defaultOpen={limitsOpen}
        >
          <p className="text-caption text-fg-tertiary">{dialog.limits.help}</p>
          <div className="mt-2.5 grid gap-3 sm:grid-cols-2">
            {APP_LIMIT_FIELDS.map((f) => {
              const a = limitAvailability(f.capability, caps.data);
              const value = draft.limits[f.key];
              // A value saved earlier stays editable where the host cannot enforce it: it can be cleared.
              const disabled = !a.available && !value;
              return (
                <Field
                  key={f.key}
                  label={dialog.limits.field(f.label, f.unit)}
                  error={show(`/limits/${f.key}`)}
                  hint={a.available ? f.hint : dialog.notOnThisHost(a.reason)}
                >
                  {({ id, describedBy, invalid }) => (
                    <Input
                      id={id}
                      mono
                      inputMode="numeric"
                      autoComplete="off"
                      placeholder={disabled ? dialog.limits.unavailable : ui.common.unlimited}
                      disabled={disabled}
                      aria-describedby={describedBy}
                      aria-invalid={invalid}
                      value={value}
                      onChange={(e) => {
                        set({ limits: { ...draft.limits, [f.key]: e.target.value } });
                      }}
                    />
                  )}
                </Field>
              );
            })}
          </div>
        </Disclosure>

        <Field
          label={dialog.stopGrace}
          error={show("/stop_grace_secs")}
          hint={dialog.stopGraceHint(STOP_GRACE_MIN, STOP_GRACE_MAX, STOP_GRACE_DEFAULT)}
        >
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              mono
              inputMode="numeric"
              autoComplete="off"
              className="max-w-40"
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={draft.stopGrace}
              onChange={(e) => {
                set({ stopGrace: e.target.value });
              }}
            />
          )}
        </Field>

        <div className={cn(CARD, "px-3.5 py-3")}>
          <Switch
            checked={draft.restartOnRecovery}
            onCheckedChange={(restartOnRecovery) => {
              set({ restartOnRecovery });
            }}
            label={m.restartOnRecovery}
            description={dialog.restartOnRecoveryHint}
          />
        </div>
      </form>
    </Dialog>
  );
}
