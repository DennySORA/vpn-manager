import { useId, useState } from "react";
import { useUpdateForwardedPort } from "@/api/queries";
import type { ForwardedPort, ForwardedPortDevice, ProviderAccount } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { Callout } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import {
  checkSettings,
  DDNS_SUFFIX,
  IP_LAYER_CHOICES,
  localPortWarning,
  MAX_DDNS_NAME,
  MAX_NOTES,
  type PortSettingsDraft,
  PROTOCOL_CHOICES,
  readBack,
  SETTINGS_PATH,
  settingsDraft,
} from "./ports";
import { m } from "./ports/messages";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  account: ProviderAccount;
  /** The port as listed now (it may have gone meanwhile). */
  port: ForwardedPort | undefined;
  /** The account's devices, by the ids a port may name. */
  devices: ForwardedPortDevice[];
  /** A save settled, whatever its outcome (the server recorded the website's answer). */
  onSettled?: () => void;
}

/**
 * A forwarded port's settings on AirVPN's website (連入埠的「設定」): notes, enabled, device,
 * protocol, IP layer, local port and DDNS name. Only what changed is sent, one request per setting
 * as the website does, and AirVPN's list is read back: what the dialog reports is what AirVPN holds.
 */
export function PortSettingsDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <PortSettingsBody key={session} {...props} />;
}

function PortSettingsBody({ open, onOpenChange, account, port, devices, onSettled }: Props) {
  const update = useUpdateForwardedPort();
  const blocked = useMutationBlocked();
  const intent = useIntentKey(`provider.update_port:${account.id}:${port?.port ?? ""}`);
  const formId = useId();
  const summaryId = useId();
  const [draft, setDraft] = useState<PortSettingsDraft | null>(() => (port ? settingsDraft(port) : null));
  const [error, setError] = useState<unknown>(null);
  const set = (p: Partial<PortSettingsDraft>) => {
    setDraft((d) => (d ? { ...d, ...p } : d));
  };

  if (!port || !draft) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange} title={m.settings.title}>
        <Callout tone="warning" title={m.settings.gone}>
          {m.settings.goneHint}
        </Callout>
      </Dialog>
    );
  }

  // Against the port as listed now: after a partial save the list is read again, and what
  // AirVPN kept no longer counts as a change. A changed value is checked as it is typed.
  const check = checkSettings(port, draft);
  const server = serverFieldErrors(error);
  const show = (k: keyof PortSettingsDraft) => check.errors[k] ?? server.get(SETTINGS_PATH[k]) ?? null;
  const invalid = Object.keys(check.errors).length > 0;
  const unchanged = check.changed.length === 0;
  const summary = invalid
    ? m.settings.fixFirst
    : unchanged
      ? m.settings.unchanged
      : m.settings.willChange(check.changed);
  // A device the list no longer names stays selectable as it is.
  const unknownDevice = draft.device !== "all" && !devices.some((d) => d.id === draft.device);

  const submit = () => {
    // Enter in a field while saving does not send it again.
    if (update.isPending || invalid || unchanged) return;
    const key = intent.next({ port: port.port, update: check.update });
    setError(null);
    update.mutate(
      { account: account.id, port: port.port, update: check.update, key },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(m.settings.saved(port.port), m.settings.savedDetail(readBack(r.data, check.update)));
          onOpenChange(false);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
        onSettled: () => {
          onSettled?.();
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.settings.titleOf(port.port)}
      description={m.settings.description}
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
            pending={update.isPending}
            pendingLabel={ui.common.saving}
            disabled={invalid || unchanged || Boolean(blocked)}
            aria-describedby={summaryId}
            title={blocked ?? undefined}
          >
            {ui.common.save}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <FormFailure error={error} />
        <Switch
          autofocus
          checked={draft.enabled}
          onCheckedChange={(enabled) => {
            set({ enabled });
          }}
          label={m.settings.enable}
          description={m.settings.enableHint}
        />
        <div className="flex flex-col items-start gap-1.5">
          <span className="text-data font-medium text-fg-secondary">{m.settings.fields.protocol}</span>
          <Segmented
            label={m.settings.fields.protocol}
            value={draft.protocol}
            onChange={(protocol) => {
              set({ protocol });
            }}
            options={PROTOCOL_CHOICES}
          />
          {show("protocol") ? <p className="text-caption text-danger">{show("protocol")}</p> : null}
        </div>
        <div className="flex flex-col items-start gap-1.5">
          <span className="text-data font-medium text-fg-secondary">{m.settings.fields.ipVersion}</span>
          <Segmented
            label={m.settings.fields.ipVersion}
            value={draft.ipLayer}
            onChange={(ipLayer) => {
              set({ ipLayer });
            }}
            options={IP_LAYER_CHOICES}
          />
          {draft.ipLayer === null ? (
            <p className="text-caption text-fg-tertiary">{m.settings.layerAsIs(port.ip_layer)}</p>
          ) : null}
          {show("ipLayer") ? <p className="text-caption text-danger">{show("ipLayer")}</p> : null}
        </div>
        <Field label={m.settings.fields.device} hint={m.settings.deviceHint} error={show("device")}>
          {({ id, describedBy, invalid: bad }) => (
            <Select
              id={id}
              aria-describedby={describedBy}
              aria-invalid={bad}
              value={draft.device}
              onChange={(e) => {
                set({ device: e.target.value });
              }}
            >
              <option value="all">{m.allDevices}</option>
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
              {unknownDevice ? (
                <option value={draft.device}>{m.settings.unlistedDevice(draft.device.slice(0, 8))}</option>
              ) : null}
            </Select>
          )}
        </Field>
        <Field
          label="Local port"
          hint={m.settings.localPortHint(port.port)}
          warning={localPortWarning(port.port, draft.localPort)}
          error={show("localPort")}
          className="w-full sm:w-56"
        >
          {({ id, describedBy, invalid: bad }) => (
            <Input
              id={id}
              mono
              inputMode="numeric"
              autoComplete="off"
              aria-describedby={describedBy}
              aria-invalid={bad}
              value={draft.localPort}
              onChange={(e) => {
                set({ localPort: e.target.value });
              }}
            />
          )}
        </Field>
        <Field
          label={m.settings.fields.ddnsName}
          hint={m.settings.ddnsHint(DDNS_SUFFIX, MAX_DDNS_NAME)}
          error={show("dnsName")}
        >
          {({ id, describedBy, invalid: bad }) => (
            <div className="flex items-center gap-2">
              <Input
                id={id}
                mono
                autoComplete="off"
                spellCheck={false}
                placeholder="my-box"
                aria-describedby={describedBy}
                aria-invalid={bad}
                value={draft.dnsName}
                onChange={(e) => {
                  set({ dnsName: e.target.value });
                }}
              />
              <span aria-hidden className="shrink-0 font-mono text-data text-fg-tertiary">
                {DDNS_SUFFIX}
              </span>
            </div>
          )}
        </Field>
        <Field label={m.settings.fields.notes} hint={m.settings.notesHint(MAX_NOTES)} error={show("notes")}>
          {({ id, describedBy, invalid: bad }) => (
            <Input
              id={id}
              autoComplete="off"
              maxLength={MAX_NOTES}
              aria-describedby={describedBy}
              aria-invalid={bad}
              value={draft.notes}
              onChange={(e) => {
                set({ notes: e.target.value });
              }}
            />
          )}
        </Field>
        <p id={summaryId} className="text-caption text-fg-tertiary" aria-live="polite">
          {summary}
        </p>
      </form>
    </Dialog>
  );
}
