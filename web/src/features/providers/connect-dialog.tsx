// 建立連線 from a provider account: pick the 出口 and the 入口 (the provider's own list, read through the Provider egress
// when the dialog opens; Mullvad may enter at another relay — multihop —, AirVPN at another address and port of the same
// server), a device (its WireGuard key), a name and the entry's IP version, and optionally a local proxy port.
// One request builds the profile, the connection and the port. While a direct grant is open, the connection built now
// becomes the egress and must start at once. Every opening starts fresh, so a second click never builds a second
// connection on the same server and port by accident.
import { Plus } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { type ReactNode, useId, useState } from "react";
import { useNavigate } from "react-router";
import {
  useGateways,
  useInstances,
  useProfiles,
  useProviderConnect,
  useProviderDevices,
  useProviderServers,
} from "@/api/queries";
import type { IpFamily, ProviderAccount, ProviderDevice, ProviderServer } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { CARD, OPTION_CARD, OPTION_IDLE, OPTION_SELECTED } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { Callout, ErrorCallout, LoadingRows } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { m as gatewayText } from "@/features/gateways/messages";
import { useSuggestedPort } from "@/features/gateways/ports";
import { cn } from "@/lib/cn";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { m } from "./connect/messages";
import { m as providerText } from "./messages";
import {
  connectionName,
  defaultDevice,
  type EntryChoice,
  entryInput,
  PROVIDER_NAME,
  profilesOnDevice,
  ROUTING,
  type Routing,
  SAME_ENTRY,
} from "./model";
import { RoutePicker } from "./route-picker";

/** Mullvad's device quota per account. */
export const MULLVAD_DEVICE_LIMIT = 5;

interface Props {
  account: ProviderAccount;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Provider requests can leave now (the dialog reads the server list through the egress). */
  egressUsable: boolean;
  /** A direct grant is open: the connection built now becomes the egress and must start at once. */
  direct: boolean;
}

/** The dialog's description: what it asks for, per how the provider routes (see RoutePicker). */
const ROUTE_PICK: Record<Routing, (provider: string) => string> = m.dialog.description;

export function ConnectDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <ConnectBody key={session} {...props} />;
}

/** One device to build from: a soft brand fill and hairline when chosen (a form option: no glow, no lift). */
function DeviceOption({
  value,
  chosen,
  disabled,
  title,
  children,
}: {
  value: string;
  chosen: boolean;
  disabled?: boolean;
  title: string;
  children: ReactNode;
}) {
  return (
    <RadioGroup.Item
      value={value}
      disabled={disabled}
      className={cn(
        OPTION_CARD,
        chosen ? OPTION_SELECTED : OPTION_IDLE,
        "group flex w-full items-start gap-3 px-3 py-2.5 text-left outline-none focus-visible:ring-2 focus-visible:ring-focus",
        "disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:border-line-subtle disabled:hover:bg-canvas/60",
      )}
    >
      <span
        aria-hidden
        className="mt-0.5 grid size-4 shrink-0 place-items-center rounded-full border border-line-control group-data-[state=checked]:border-action group-data-[state=checked]:bg-action"
      >
        <span className="size-1.5 rounded-full bg-on-accent opacity-0 group-data-[state=checked]:opacity-100" />
      </span>
      <span className="grid min-w-0 gap-0.5">
        <span className="text-data text-fg">{title}</span>
        {children}
      </span>
    </RadioGroup.Item>
  );
}

function ConnectBody({ account, open, onOpenChange, egressUsable, direct }: Props) {
  const navigate = useNavigate();
  const devices = useProviderDevices(account.id, egressUsable);
  const servers = useProviderServers(account.id, open && egressUsable);
  const profiles = useProfiles();
  const instances = useInstances();
  const gateways = useGateways();
  const connect = useProviderConnect();
  const blocked = useMutationBlocked();
  const intent = useIntentKey(`provider.connect:${account.id}`);
  const formId = useId();
  const mullvad = account.provider === "mullvad";
  // Profiles built on a device's key: one key serves one running connection at a time.
  const builtOn = (d: ProviderDevice) => profilesOnDevice(profiles.data ?? [], account, d);
  const usable = (devices.data ?? []).filter((d) => d.usable);
  const [server, setServer] = useState<ProviderServer | null>(null);
  const [entry, setEntry] = useState<EntryChoice>(SAME_ENTRY);
  const multihop = entry.kind === "relay" && entry.id !== server?.id;
  // Until the user picks one: a device of ours that no connection uses, else a new one (Mullvad).
  const [picked, setDevice] = useState<string | null>(null);
  const suggestedDevice = defaultDevice(mullvad, devices.data, (d) => {
    const ids = new Set(builtOn(d).map((p) => p.id));
    return (instances.data ?? []).some((v) => ids.has(v.spec.profile_id));
  });
  const device =
    picked !== null && (picked === "new" ? mullvad : usable.some((d) => d.id === picked)) ? picked : suggestedDevice;
  const [family, setFamily] = useState<IpFamily>("ipv4");
  const [name, setName] = useState("");
  const [nameEdited, setNameEdited] = useState(false);
  const [withGateway, setWithGateway] = useState(true);
  const [port, setPort] = useState("");
  const [startChoice, setStart] = useState(true);
  const start = direct || startChoice;
  const [error, setError] = useState<unknown>(null);

  const usedPorts = (gateways.data ?? []).map((g) => g.port);
  const suggested = useSuggestedPort(usedPorts, open && egressUsable && withGateway);
  const portValue = port || String(suggested);
  const deviceCount = devices.data?.length ?? 0;
  const atLimit = mullvad && deviceCount >= MULLVAD_DEVICE_LIMIT;
  const chosenAddress =
    entry.kind === "address"
      ? server?.entries.find((e) => e.index === entry.index && e.port === entry.port)
      : undefined;
  const v6 = multihop
    ? false
    : chosenAddress
      ? chosenAddress.ipv6 !== null
      : (server?.endpoints.some((e) => e.startsWith("[")) ?? false);
  const portNum = Number(portValue);
  const portError =
    withGateway && (!/^\d+$/.test(portValue) || portNum < 1024 || portNum > 65535)
      ? "1024–65535"
      : withGateway && usedPorts.includes(portNum)
        ? m.dialog.gatewayPortInUse
        : null;
  const fieldErrors = serverFieldErrors(error);
  const deviceMissing = !device || (device === "new" && atLimit);

  const pick = (s: ProviderServer) => {
    setServer(s);
    if (!nameEdited) setName(connectionName(account.provider, s));
    // AirVPN entries belong to their server; a Mullvad entry relay that became the exit is no multihop.
    if (ROUTING[account.provider] === "entries" || (entry.kind === "relay" && entry.id === s.id)) setEntry(SAME_ENTRY);
    if (!s.endpoints.some((e) => e.startsWith("["))) setFamily("ipv4");
  };
  const chooseEntry = (c: EntryChoice) => {
    setEntry(c);
    if (c.kind === "relay") setFamily("ipv4");
  };

  // The button says why it waits (never a silent disabled control).
  const reason =
    blocked ??
    (!egressUsable
      ? m.dialog.reason.noEgress
      : !server
        ? m.dialog.reason.noExit
        : multihop && !entry.id
          ? m.dialog.reason.noEntry
          : multihop && server.multihop_port === null
            ? m.route.noMultihop
            : deviceMissing
              ? mullvad
                ? m.dialog.reason.deviceLimit(MULLVAD_DEVICE_LIMIT)
                : m.dialog.reason.noDevice
              : portError
                ? m.dialog.reason.gatewayPort(portError)
                : null);

  const submit = () => {
    if (reason || !server || connect.isPending) return;
    const input = {
      device_id: device === "new" ? null : device,
      server_id: server.id,
      entry: entryInput(entry, server),
      name: (name.trim() || connectionName(account.provider, server)).slice(0, 64),
      endpoint_family: family,
      gateway_port: withGateway ? portNum : null,
      // Named in the reader's language, like a proxy port added on its own.
      gateway_name: withGateway ? gatewayText.dialog.defaultName(portNum) : null,
      start,
    };
    setError(null);
    connect.mutate(
      { account: account.id, input, key: intent.next(input) },
      {
        onSuccess: (r) => {
          intent.settle();
          onOpenChange(false);
          const view = {
            label: m.dialog.view,
            run: () => void navigate(`/instances/${r.data.instance_id}`),
          };
          if (r.data.reused) toast.success(m.dialog.reused, m.dialog.reusedDetail, view);
          else toast.success(m.dialog.created(input.name), m.dialog.createdDetail(start, r.data.becomes_egress), view);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  let serverPart;
  if (!egressUsable)
    serverPart = (
      <Callout tone="warning" title={providerText.egressNeeded.none}>
        {m.dialog.serversNeedEgress}
      </Callout>
    );
  else if (servers.isError)
    serverPart = (
      <ErrorCallout
        error={servers.error}
        title={m.dialog.serversUnreadable}
        onRetry={() => void servers.refetch()}
        retrying={servers.isFetching}
      />
    );
  else if (!servers.data) serverPart = <LoadingRows rows={4} label={m.dialog.loadingServers} />;
  else
    serverPart = (
      <div className="animate-fade-in">
        <RoutePicker
          provider={account.provider}
          servers={servers.data}
          exit={server}
          entry={entry}
          family={family}
          onExit={pick}
          onEntry={chooseEntry}
        />
      </div>
    );

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={640}
      title={m.dialog.title(account.label)}
      description={ROUTE_PICK[ROUTING[account.provider]](PROVIDER_NAME[account.provider])}
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
            icon={Plus}
            disabledReason={reason}
            pending={connect.isPending}
            pendingLabel={ui.common.creating}
          >
            {providerText.account.connect}
          </ActionButton>
        </>
      }
    >
      {/* The server list and the devices sit outside the form: Enter in the server search never builds a connection,
          and the radio cards add no hidden inputs that could take the dialog's first focus. */}
      <div className="space-y-5">
        <FormFailure error={error} />
        {direct ? (
          <Callout tone="info" title={m.dialog.becomesEgress}>
            {m.dialog.becomesEgressHint}
          </Callout>
        ) : null}

        <div className="space-y-2">
          {serverPart}
          {["/server_id", "/entry", "/entry/server_id", "/endpoint_family"].map((path) =>
            fieldErrors.get(path) ? (
              <p key={path} className="text-caption text-danger animate-reveal">
                {fieldErrors.get(path)}
              </p>
            ) : null,
          )}
        </div>

        <fieldset className="space-y-2">
          <legend className="mb-2 text-data font-medium text-fg-secondary">{m.dialog.deviceLegend}</legend>
          {devices.isError ? (
            <ErrorCallout
              error={devices.error}
              title={providerText.devices.unreadable}
              onRetry={() => void devices.refetch()}
              retrying={devices.isFetching}
            />
          ) : !devices.data && egressUsable ? (
            <LoadingRows rows={2} label={providerText.devices.loading} />
          ) : (
            <RadioGroup.Root
              value={device}
              onValueChange={setDevice}
              aria-label={m.dialog.device}
              className="grid grid-cols-1 gap-2"
            >
              {mullvad ? (
                <DeviceOption value="new" chosen={device === "new"} disabled={atLimit} title={m.dialog.newDevice}>
                  <span className="text-caption text-fg-tertiary">
                    {atLimit
                      ? m.dialog.newDeviceAtLimit(deviceCount, MULLVAD_DEVICE_LIMIT, usable.length > 0)
                      : m.dialog.newDeviceHint(devices.data ? deviceCount : null, MULLVAD_DEVICE_LIMIT)}
                  </span>
                </DeviceOption>
              ) : null}
              {usable.map((d) => {
                const users = builtOn(d).map((p) => p.name);
                return (
                  <DeviceOption
                    key={d.id}
                    value={d.id}
                    chosen={device === d.id}
                    title={mullvad ? m.dialog.reuseDevice(d.label) : d.label}
                  >
                    <span className="machine truncate text-caption text-fg-tertiary" title={d.public_key}>
                      {d.public_key}
                    </span>
                    {users.length ? (
                      <span className="text-caption text-warning">{m.dialog.deviceUsedBy(users)}</span>
                    ) : null}
                  </DeviceOption>
                );
              })}
            </RadioGroup.Root>
          )}
          {!mullvad && devices.data && !usable.length ? (
            <Callout tone="warning" title={m.dialog.noAirvpnDevice}>
              {m.dialog.noAirvpnDeviceHint}
            </Callout>
          ) : null}
        </fieldset>

        <form
          id={formId}
          noValidate
          aria-label={m.dialog.form}
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="grid grid-cols-1 items-end gap-4 sm:grid-cols-[minmax(0,1fr)_auto]">
            <Field label={ui.common.name} error={fieldErrors.get("/name") ?? null}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  maxLength={64}
                  placeholder={m.dialog.namePlaceholder}
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    setNameEdited(true);
                  }}
                />
              )}
            </Field>
            <div className="flex flex-col items-start gap-1.5">
              <span className="text-data font-medium text-fg-secondary">{m.dialog.entryFamily}</span>
              <Segmented
                label={m.dialog.entryFamilyLabel}
                value={family}
                onChange={setFamily}
                options={[
                  { value: "ipv4", label: "IPv4", title: multihop ? m.dialog.multihopIpv4Only : undefined },
                  ...(v6 ? [{ value: "ipv6" as const, label: "IPv6" }] : []),
                ]}
              />
            </div>
          </div>

          <div className={cn(CARD, "space-y-3 px-4 py-3")}>
            <Switch
              checked={withGateway}
              onCheckedChange={setWithGateway}
              label={m.dialog.withGateway}
              description={m.dialog.withGatewayHint}
            />
            {withGateway ? (
              <Field
                label={m.dialog.gatewayPort}
                error={portError ?? fieldErrors.get("/gateway_port") ?? null}
                className="max-w-40 pl-12"
              >
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={portValue}
                    onChange={(e) => {
                      setPort(e.target.value);
                    }}
                  />
                )}
              </Field>
            ) : null}
            <Switch
              checked={start}
              onCheckedChange={setStart}
              disabled={direct}
              label={m.dialog.startNow}
              description={direct ? m.dialog.startNowDirect : undefined}
            />
          </div>
        </form>
      </div>
    </Dialog>
  );
}
