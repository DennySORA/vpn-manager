import { RadioGroup } from "radix-ui";
import { useId, useState } from "react";
import { apiGet } from "@/api/client";
import { useCreateGateway, useGateways, useInstances, useUpdateGateway } from "@/api/queries";
import type { GatewayInput, GatewayKind, GatewaySpec } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { CARD, CHOICE_BASE, CHOICE_IDLE, CHOICE_SELECTED } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";
import { parseIntField, serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { useSuggestedPort } from "./ports";
import { m } from "./messages";

export const KIND_LABEL: Record<GatewayKind, string> = { mixed: "Mixed", socks5: "SOCKS5", http: "HTTP" };

const KINDS: { value: GatewayKind; title: string; text: string }[] = [
  { value: "mixed", title: "Mixed", text: m.dialog.kind.mixed },
  { value: "socks5", title: "SOCKS5", text: m.dialog.kind.socks5 },
  { value: "http", title: "HTTP", text: m.dialog.kind.http },
];

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Edit this Gateway; create when absent. */
  gateway?: GatewaySpec;
  /** Preselected Instance for a new Gateway. */
  instanceId?: string | undefined;
  onSaved?: (g: GatewaySpec) => void;
}

export function GatewayDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <GatewayDialogBody key={session} {...props} />;
}

function GatewayDialogBody({ open, onOpenChange, gateway, instanceId, onSaved }: Props) {
  const instances = useInstances();
  const gateways = useGateways();
  const create = useCreateGateway();
  const update = useUpdateGateway();
  const intent = useIntentKey(`gateway.save:${gateway?.id ?? "new"}`);
  const formId = useId();
  const used = (gateways.data ?? []).filter((g) => g.id !== gateway?.id);

  const [instance, setInstance] = useState(gateway?.instance_id ?? instanceId ?? instances.data?.[0]?.spec.id ?? "");
  const [kind, setKind] = useState<GatewayKind>(gateway?.kind ?? "mixed");
  // A new Gateway shows the suggested port until the user types one (asked only while open).
  const suggested = useSuggestedPort(
    used.map((g) => g.port),
    open && !gateway,
  );
  const [typedPort, setPort] = useState<string | null>(gateway ? String(gateway.port) : null);
  const port = typedPort ?? String(suggested);
  const [name, setName] = useState(gateway?.name ?? "");
  const [enabled, setEnabled] = useState(gateway?.enabled ?? true);
  const [udp, setUdp] = useState(gateway?.udp ?? true);
  const [maxConn, setMaxConn] = useState(String(gateway?.max_connections ?? 1024));
  const [revision, setRevision] = useState(gateway?.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [reloading, setReloading] = useState(false);

  const portN = parseIntField(port);
  const maxN = parseIntField(maxConn);
  const clash = portN !== null ? used.find((g) => g.port === portN) : undefined;
  const server = serverFieldErrors(error);
  const errors = {
    instance: !instance ? m.dialog.error.instance : null,
    port:
      portN === null || portN < 1024 || portN > 65535
        ? m.dialog.error.port
        : clash
          ? m.dialog.error.portTaken(clash.name)
          : (server.get("/port") ?? null),
    max: maxN === null || maxN < 1 || maxN > 16384 ? m.dialog.error.max : (server.get("/max_connections") ?? null),
    name: server.get("/name") ?? null,
  };
  const valid = !errors.instance && !errors.port && !errors.max && !errors.name;
  const pending = create.isPending || update.isPending;
  const effectiveName = name.trim() || m.dialog.defaultName(portN);

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (!valid || portN === null || maxN === null) return;
    const input: GatewayInput = {
      instance_id: instance,
      name: effectiveName,
      kind,
      port: portN,
      enabled,
      udp: kind === "http" ? false : udp,
      max_connections: maxN,
    };
    // The port being saved stays as sent while the saved Gateway changes the suggestion.
    if (typedPort === null) setPort(port);
    const key = intent.next({ id: gateway?.id, rev, input });
    const done = {
      onSuccess: (r: { data: GatewaySpec }) => {
        intent.settle();
        toast.success(gateway ? m.toast.updated(r.data.name) : m.toast.created(`127.0.0.1:${r.data.port}`));
        onSaved?.(r.data);
        onOpenChange(false);
      },
      onError: (e: unknown) => {
        intent.settle(e);
        setError(e);
      },
    };
    setError(null);
    if (gateway && rev !== undefined) update.mutate({ id: gateway.id, revision: rev, input, key }, done);
    else create.mutate({ input, key }, done);
  };

  const latest = async (apply: boolean) => {
    if (!gateway) return;
    setReloading(true);
    try {
      const g = await apiGet<GatewaySpec>(`/v1/gateways/${gateway.id}`);
      setRevision(g.revision);
      if (apply) {
        setInstance(g.instance_id);
        setKind(g.kind);
        setPort(String(g.port));
        setName(g.name);
        setEnabled(g.enabled);
        setUdp(g.udp);
        setMaxConn(String(g.max_connections));
        setError(null);
      } else {
        submit(g.revision);
      }
    } catch (e) {
      setError(e);
    } finally {
      setReloading(false);
    }
  };

  const show = (msg: string | null) => (submitted || error ? msg : null);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={gateway ? m.dialog.editTitle(gateway.name) : m.add}
      description={m.dialog.description}
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
            pending={pending}
            pendingLabel={gateway ? ui.common.saving : ui.common.creating}
          >
            {gateway ? ui.common.save : m.dialog.submit}
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
        <Field label={m.owner} required error={show(errors.instance)}>
          {({ id, describedBy, invalid }) => (
            <Select
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={instance}
              onChange={(e) => {
                setInstance(e.target.value);
              }}
            >
              {!instance ? <option value="">{m.dialog.chooseInstance}</option> : null}
              {(instances.data ?? []).map((v) => (
                <option key={v.spec.id} value={v.spec.id}>
                  {v.spec.name}
                </option>
              ))}
            </Select>
          )}
        </Field>

        <fieldset className="space-y-2">
          <legend className="text-data font-medium text-fg-secondary">{m.protocol}</legend>
          <RadioGroup.Root
            name="kind"
            value={kind}
            onValueChange={(v) => {
              setKind(v as GatewayKind);
            }}
            className="grid gap-2 sm:grid-cols-3"
            aria-label={m.protocol}
          >
            {KINDS.map((k) => (
              <RadioGroup.Item
                key={k.value}
                value={k.value}
                className={cn(
                  CHOICE_BASE,
                  "flex flex-col items-start gap-0.5 rounded-lg px-3 py-2.5 text-left",
                  kind === k.value ? CHOICE_SELECTED : CHOICE_IDLE,
                )}
              >
                <span className="text-body font-medium text-fg">{k.title}</span>
                <span className="text-caption text-fg-tertiary">{k.text}</span>
              </RadioGroup.Item>
            ))}
          </RadioGroup.Root>
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={m.port} required hint={m.dialog.portHint} error={show(errors.port)}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={port}
                onChange={(e) => {
                  setPort(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label={m.dialog.maxConnections} required hint="1–16384" error={show(errors.max)}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={maxConn}
                onChange={(e) => {
                  setMaxConn(e.target.value);
                }}
              />
            )}
          </Field>
        </div>

        <Field
          label={ui.common.name}
          hint={name.trim() ? undefined : m.dialog.nameHint(effectiveName)}
          error={show(errors.name)}
        >
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              maxLength={64}
              placeholder={effectiveName}
              value={name}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          )}
        </Field>

        <div className={cn(CARD, "space-y-3 px-3.5 py-3")}>
          <Switch
            checked={enabled}
            onCheckedChange={setEnabled}
            label={m.dialog.enabled}
            description={m.dialog.enabledHint}
          />
          <Switch
            checked={kind === "http" ? false : udp}
            onCheckedChange={setUdp}
            disabled={kind === "http"}
            label={m.dialog.udp}
            description={kind === "http" ? m.dialog.udpUnavailable : m.dialog.udpHint}
          />
        </div>
      </form>
    </Dialog>
  );
}
