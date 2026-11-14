// The forward dialog (new and edit): the connection; the provider's side — AirVPN's reserved ports to pick from when
// the connection was built from an account in VPN Manager (the port-picker step), the website steps or the server's
// DNAT otherwise, and why a Mullvad connection cannot forward; the protocol (choice cards; an enforced-proxy App takes
// TCP only and the other cards say so); the ports and the receiving App, with the strict-App hint; the name, the limit
// and the switches: 啟用, PROXY protocol v2 (TCP only: off and saying why for a UDP-only forward, the choice kept
// for when TCP comes back), and UDP 直接送進沙箱 (UDP on a strict connection and App only: off and saying why
// elsewhere, the choice kept). The rules mirror the server's (model.ts checkDraft); the server still decides.
import { RadioGroup } from "radix-ui";
import { useId, useMemo, useState } from "react";
import { apiGet } from "@/api/client";
import {
  useApps,
  useForwardedPorts,
  useForwards,
  useInstances,
  useProfiles,
  useProviderAccounts,
  useSaveForward,
} from "@/api/queries";
import type { ForwardProtocol, ForwardView, ForwardedPort } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { CARD, CHOICE_BASE, CHOICE_IDLE, CHOICE_SELECTED } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";
import { ForwardedPortPicker } from "@/features/providers/port-picker";
import { airvpnAccountOf, type ForwardPrefill, remapWarning, sameLocalPort } from "@/features/providers/ports";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { m } from "./messages";
import { checkDraft, type ForwardDraft, PROTOCOL_LABEL, providerGuide, proxyApplies, udpDirectBlocker } from "./model";

/** What a strict App must hold for the forward: TCP on 127.0.0.1 (the forward connects there), UDP on every address when it goes straight in. */
function strictHint(protocol: ForwardProtocol, direct: boolean, port: string): { title: string; body: string } {
  if (!direct) return { title: m.dialog.strict.loopbackTitle(port), body: m.dialog.strict.loopbackBody };
  if (protocol === "udp") return { title: m.dialog.strict.udpTitle(port), body: m.dialog.strict.udpBody };
  return { title: m.dialog.strict.bothTitle(port), body: m.dialog.strict.bothBody };
}

const PROTOCOLS: { value: ForwardProtocol; text: string }[] = [
  { value: "tcp", text: m.dialog.protocolUse.tcp },
  { value: "udp", text: m.dialog.protocolUse.udp },
  { value: "both", text: m.dialog.protocolUse.both },
];

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Edit this forward; create when absent. */
  forward?: ForwardView | undefined;
  /** Preselected App (and its connection) for a new forward. */
  appId?: string | undefined;
  /** A new forward made from one of AirVPN's reserved ports (連入埠). */
  prefill?: ForwardPrefill | undefined;
  /** Takes over after a save, closing included (e.g. one navigation that selects the new forward). */
  onSaved?: (v: ForwardView) => void;
}

export function ForwardDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <ForwardDialogBody key={session} {...props} />;
}

function ForwardDialogBody({ open, onOpenChange, forward, appId, prefill, onSaved }: Props) {
  const instances = useInstances();
  const apps = useApps();
  const forwards = useForwards();
  const profiles = useProfiles();
  const accounts = useProviderAccounts();
  const save = useSaveForward();
  const intent = useIntentKey(`forward.save:${forward?.binding.id ?? "new"}`);
  const formId = useId();
  const b = forward?.binding;
  const preselected = (apps.data ?? []).find((a) => a.spec.id === appId);
  const from = b ? undefined : prefill;

  const [draft, setDraft] = useState<ForwardDraft>({
    instance: b?.instance_id ?? from?.instance ?? preselected?.spec.instance_id ?? instances.data?.[0]?.spec.id ?? "",
    name: b?.name ?? "",
    protocol: b?.protocol ?? from?.protocol ?? "tcp",
    tunnelPort: b ? String(b.tunnel_port) : from ? String(from.tunnelPort) : "",
    publicPort: b?.public_port ? String(b.public_port) : from ? String(from.publicPort) : "",
    app: b?.target_app_id ?? preselected?.spec.id ?? "",
    targetPort: b ? String(b.target_port) : from ? String(from.targetPort) : "",
    enabled: b?.enabled ?? true,
    maxConnections: String(b?.max_connections ?? 256),
    proxyProtocol: b?.proxy_protocol ?? false,
    udpDirect: b?.udp_direct ?? false,
  });
  // The public port came from AirVPN's reserved ports (prefilled or picked): say what the App must do.
  const [reserved, setReserved] = useState<number | null>(from?.publicPort ?? null);
  const [revision, setRevision] = useState(b?.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [reloading, setReloading] = useState(false);
  const set = (p: Partial<ForwardDraft>) => {
    setDraft((d) => ({ ...d, ...p }));
  };
  // Until the user picks them, the preselected App and its connection, else the first
  // connection: the lists may arrive after the dialog opened (a link straight to the dialog).
  const instance =
    (draft.instance || (!b ? preselected?.spec.instance_id : undefined)) ?? instances.data?.[0]?.spec.id ?? "";
  const appPick = draft.app || (!b && preselected?.spec.instance_id === instance ? preselected.spec.id : "");
  // Seatbelt lets an enforced_proxy App receive TCP only (it also may listen on 127.0.0.1 only).
  const enforcedApp = (apps.data ?? []).find((a) => a.spec.id === appPick && a.spec.isolation === "enforced_proxy");
  // A strict App shares the sandbox's network with the worker that listens on the tunnel address.
  const strictApp = (apps.data ?? []).some((a) => a.spec.id === appPick && a.spec.isolation === "strict_netns");
  const owner = (instances.data ?? []).find((v) => v.spec.id === instance);
  // UDP goes straight into the sandbox only for UDP, on a strict connection, to a strict App.
  const udpBlocked = udpDirectBlocker(
    draft.protocol,
    owner,
    (apps.data ?? []).find((a) => a.spec.id === appPick),
  );
  const udpDirect = draft.udpDirect && !udpBlocked;
  const samePort = draft.targetPort.trim() !== "" && draft.targetPort.trim() === draft.tunnelPort.trim();
  const hint = strictApp && samePort ? strictHint(draft.protocol, udpDirect, draft.targetPort.trim()) : null;
  const guide = providerGuide(owner);
  // An AirVPN connection whose account is in VPN Manager: its reserved ports replace the website steps.
  const airAccount = airvpnAccountOf(owner, profiles.data ?? [], accounts.data ?? []);
  const pick = (p: ForwardedPort) => {
    setReserved(p.port);
    set({
      tunnelPort: String(p.local_port),
      publicPort: String(p.port),
      targetPort: String(p.port),
      // Seatbelt lets an enforced_proxy App receive TCP only.
      protocol: enforcedApp ? "tcp" : p.protocol,
    });
  };
  // The account's reserved ports (the picker's own list, from the same cache): an edited forward whose public port is
  // one of them shows it picked, with what the App must do, as a new one made from it does.
  const accountPorts = useForwardedPorts(airAccount?.id, Boolean(airAccount) && !guide.unsupported);
  const listed = accountPorts.data?.ports.some((p) => String(p.port) === draft.publicPort.trim())
    ? Number(draft.publicPort.trim())
    : null;
  const reservedNow = reserved !== null && draft.publicPort.trim() === String(reserved) ? reserved : listed;
  const remap = reservedNow !== null ? remapWarning({ port: reservedNow, local_port: Number(draft.tunnelPort) }) : null;
  const ownApps = useMemo(
    () => (apps.data ?? []).filter((a) => a.spec.instance_id === instance),
    [apps.data, instance],
  );
  const others = (forwards.data ?? []).filter((f) => f.binding.id !== b?.id);
  const check = checkDraft({ ...draft, instance, app: appPick }, apps.data ?? [], others, owner);
  const server = serverFieldErrors(error);
  const show = (k: keyof ForwardDraft, path: string) =>
    submitted || error ? (check.errors[k] ?? server.get(path) ?? null) : null;

  const submit = (rev = revision) => {
    setSubmitted(true);
    const input = check.input;
    if (!input) return;
    const key = intent.next({ id: b?.id, rev, input });
    setError(null);
    save.mutate(
      { id: b?.id, revision: rev, input, key },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(b ? m.toast.updated(r.data.binding.name) : m.toast.created(r.data.binding.name));
          // One navigation closes a dialog opened from the URL and selects the new forward; a second URL change in
          // the same tick would bring back the parameters it removed (`?app=`).
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
    if (!b) return;
    setReloading(true);
    try {
      const v = await apiGet<ForwardView>(`/v1/forward-bindings/${b.id}`);
      setRevision(v.binding.revision);
      if (apply) {
        const n = v.binding;
        setDraft({
          instance: n.instance_id,
          name: n.name,
          protocol: n.protocol,
          tunnelPort: String(n.tunnel_port),
          publicPort: n.public_port ? String(n.public_port) : "",
          app: n.target_app_id,
          targetPort: String(n.target_port),
          enabled: n.enabled,
          maxConnections: String(n.max_connections),
          proxyProtocol: n.proxy_protocol,
          udpDirect: n.udp_direct,
        });
        setError(null);
      } else {
        submit(v.binding.revision);
      }
    } catch (e) {
      setError(e);
    } finally {
      setReloading(false);
    }
  };

  const blocked = guide.unsupported;
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={b ? m.dialog.editTitle(b.name) : m.add}
      description={m.dialog.description}
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
          <ActionButton
            type="submit"
            form={formId}
            variant="primary"
            pending={save.isPending}
            pendingLabel={b ? ui.common.saving : ui.common.creating}
            disabledReason={blocked}
          >
            {b ? ui.common.save : m.dialog.create}
          </ActionButton>
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
        <Field label={m.column.connection} required error={show("instance", "/instance_id")}>
          {({ id, describedBy, invalid }) => (
            <Select
              id={id}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={instance}
              // A forward cannot move to another connection; delete and recreate it there.
              disabled={Boolean(b)}
              onChange={(e) => {
                set({ instance: e.target.value, app: "" });
              }}
            >
              {!instance ? <option value="">{m.dialog.chooseConnection}</option> : null}
              {(instances.data ?? []).map((v) => (
                <option key={v.spec.id} value={v.spec.id}>
                  {v.spec.name}
                </option>
              ))}
            </Select>
          )}
        </Field>

        {/* The provider's side first: where the port comes from (AirVPN's reserved ports, the steps on its website or the server's DNAT). */}
        {blocked ? (
          <Callout tone="warning" title={m.dialog.blocked}>
            {blocked}
          </Callout>
        ) : airAccount ? (
          <ForwardedPortPicker account={airAccount} selected={reservedNow} onPick={pick} />
        ) : guide.steps.length ? (
          <Callout tone="info" title={guide.title}>
            <ol className="list-decimal space-y-1 pl-4">
              {guide.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </Callout>
        ) : null}

        {!blocked && reservedNow !== null ? (
          <div className="animate-reveal">
            <Callout tone="info" title={m.dialog.mustListen(reservedNow)}>
              <p>{sameLocalPort(reservedNow)}</p>
              {remap ? <p className="text-warning">{remap}</p> : null}
            </Callout>
          </div>
        ) : null}

        <fieldset className="space-y-2">
          <legend className="text-data font-medium text-fg-secondary">{m.dialog.protocol}</legend>
          <RadioGroup.Root
            name="protocol"
            value={draft.protocol}
            onValueChange={(v) => {
              set({ protocol: v as ForwardProtocol });
            }}
            className="grid gap-2 sm:grid-cols-3"
            aria-label={m.dialog.protocol}
          >
            {PROTOCOLS.map((p) => {
              // Seatbelt lets an enforced_proxy App receive TCP only: the other choices say so in place.
              const tcpOnly = Boolean(enforcedApp) && p.value !== "tcp";
              const chosen = draft.protocol === p.value;
              return (
                <RadioGroup.Item
                  key={p.value}
                  value={p.value}
                  disabled={tcpOnly}
                  className={cn(
                    CHOICE_BASE,
                    "flex flex-col items-start gap-0.5 rounded-lg px-3 py-2.5 text-left",
                    chosen ? CHOICE_SELECTED : CHOICE_IDLE,
                    "disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:border-line-subtle disabled:hover:bg-canvas",
                  )}
                >
                  <span className="text-body font-medium text-fg">{PROTOCOL_LABEL[p.value]}</span>
                  <span className="text-caption text-fg-tertiary">{tcpOnly ? m.dialog.tcpOnly : p.text}</span>
                </RadioGroup.Item>
              );
            })}
          </RadioGroup.Root>
          {enforcedApp ? (
            <p className="text-caption text-fg-tertiary">{m.dialog.enforcedNote(enforcedApp.spec.name)}</p>
          ) : null}
          {show("protocol", "/protocol") ? (
            <p className="text-caption text-danger animate-reveal" role="alert">
              {show("protocol", "/protocol")}
            </p>
          ) : null}
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label={m.tunnelPort}
            required
            hint={m.dialog.tunnelPortHint}
            error={show("tunnelPort", "/tunnel_port")}
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={draft.tunnelPort}
                onChange={(e) => {
                  set({ tunnelPort: e.target.value });
                }}
              />
            )}
          </Field>
          <Field label={m.publicPort} hint={m.dialog.publicPortHint} error={show("publicPort", "/public_port")}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                placeholder={m.dialog.publicPortPlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={draft.publicPort}
                onChange={(e) => {
                  set({ publicPort: e.target.value });
                }}
              />
            )}
          </Field>
        </div>

        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_140px]">
          <Field
            label={m.dialog.app}
            required
            hint={instance && !ownApps.length ? m.dialog.noApps : undefined}
            error={show("app", "/target_app_id")}
          >
            {({ id, describedBy, invalid }) => (
              <Select
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={appPick}
                onChange={(e) => {
                  // Picking an enforced_proxy App moves the protocol to TCP, the only one it can take.
                  const picked = (apps.data ?? []).find((a) => a.spec.id === e.target.value);
                  set({
                    app: e.target.value,
                    ...(picked?.spec.isolation === "enforced_proxy" ? { protocol: "tcp" as const } : {}),
                  });
                }}
              >
                <option value="">{m.dialog.chooseApp}</option>
                {ownApps.map((a) => (
                  <option key={a.spec.id} value={a.spec.id}>
                    {a.spec.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field
            label={m.dialog.appPort}
            required
            hint={m.dialog.appPortHint}
            error={show("targetPort", "/target_port")}
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={draft.targetPort}
                onChange={(e) => {
                  set({ targetPort: e.target.value });
                }}
              />
            )}
          </Field>
        </div>
        {hint ? (
          <div className="animate-reveal">
            <Callout tone="info" title={hint.title}>
              {hint.body}
            </Callout>
          </div>
        ) : null}

        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label={ui.common.name}
            hint={draft.name.trim() ? undefined : m.dialog.nameHint(check.input?.name ?? m.defaultName(null))}
            error={show("name", "/name")}
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                maxLength={64}
                value={draft.name}
                onChange={(e) => {
                  set({ name: e.target.value });
                }}
              />
            )}
          </Field>
          <Field
            label={m.dialog.maxConnections}
            required
            hint={m.dialog.maxConnectionsHint}
            error={show("maxConnections", "/max_connections")}
          >
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={draft.maxConnections}
                onChange={(e) => {
                  set({ maxConnections: e.target.value });
                }}
              />
            )}
          </Field>
        </div>

        <div className={cn(CARD, "space-y-3 px-3.5 py-3")}>
          <Switch
            checked={draft.enabled}
            onCheckedChange={(enabled) => {
              set({ enabled });
            }}
            label={ui.common.enable}
            description={m.dialog.enabledHint}
          />
          <Switch
            checked={proxyApplies(draft.protocol) && draft.proxyProtocol}
            onCheckedChange={(proxyProtocol) => {
              set({ proxyProtocol });
            }}
            disabled={!proxyApplies(draft.protocol)}
            label={m.dialog.proxy}
            description={
              proxyApplies(draft.protocol)
                ? m.dialog.proxyHint(draft.protocol === "both" ? (udpDirect ? "direct" : "relayed") : null)
                : m.dialog.proxyUdpOnly
            }
          />
          {show("proxyProtocol", "/proxy_protocol") ? (
            <p className="pl-12 text-caption text-danger animate-reveal" role="alert">
              {show("proxyProtocol", "/proxy_protocol")}
            </p>
          ) : null}
          <Switch
            checked={udpDirect}
            onCheckedChange={(on) => {
              set({ udpDirect: on });
            }}
            disabled={Boolean(udpBlocked)}
            label={m.dialog.udpDirect}
            description={udpBlocked ?? m.dialog.udpDirectHint(draft.protocol === "both")}
          />
          {show("udpDirect", "/udp_direct") ? (
            <p className="pl-12 text-caption text-danger animate-reveal" role="alert">
              {show("udpDirect", "/udp_direct")}
            </p>
          ) : null}
        </div>
      </form>
    </Dialog>
  );
}
