// Point a profile at another 入口／出口 of its provider account: the device and its key stay, only
// the peer, the assigned addresses and the location change. The exit is a server of the account's
// list; the entry is where the tunnel goes in (Mullvad: the exit relay or another one — multihop;
// AirVPN: one of the exit server's own addresses and ports). A profile built by the provider flow
// belongs to its account; an imported one is adopted by an account of its provider when its key is
// one of that account's devices. Running connections keep the current entry and exit until
// restarted (the saved notice offers that).

import { ArrowLeftRight } from "lucide-react";
import { useState } from "react";
import {
  useChangeProviderServer,
  useProviderAccounts,
  useProviderDevices,
  useProviderEgress,
  useProviderServers,
} from "@/api/queries";
import type { IpFamily, ProviderServer, RuntimeProfile } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { Callout, ErrorCallout, LoadingRows } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { announceSaved } from "@/features/instances/actions";
import {
  connectionName,
  type EntryChoice,
  entryAddressLabel,
  entryChoiceOf,
  entryInput,
  followedName,
  PROVIDER_NAME,
  ROUTING,
  SAME_ENTRY,
  sameEntry,
} from "@/features/providers/model";
import { RoutePicker } from "@/features/providers/route-picker";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { m } from "./messages";

interface Props {
  profile: RuntimeProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Whether `endpoint` (`ip:port` or `[ip]:port`) is `ip` on `port`. */
function endpointIs(endpoint: string, ip: string, port: number): boolean {
  return endpoint === (ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);
}

/** "入口 se-got-wg-001 → 出口 jp-tyo-wg-001", "example · 位址 3 · UDP 47107" or the server alone. */
function currentRoute(exit: string | null, entry: EntryChoice): string | null {
  if (!exit) return null;
  if (entry.kind === "relay" && entry.id !== exit) return m.changeServer.route(entry.id, exit);
  if (entry.kind === "address") return `${exit} · ${entryAddressLabel(entry)}`;
  return exit;
}

export function ChangeServerDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <ChangeServerBody key={session} {...props} />;
}

function ChangeServerBody({ profile, open, onOpenChange }: Props) {
  const source = profile.source.kind === "provider" ? profile.source : null;
  const accounts = useProviderAccounts();
  const egress = useProviderEgress();
  // The account that built it, or for an imported profile every account of its provider.
  const candidates =
    accounts.data?.filter((a) => (source ? a.id === source.account_id : a.provider === profile.provider)) ?? [];
  const [chosen, setChosen] = useState<string | null>(null);
  const account = candidates.find((a) => a.id === chosen) ?? candidates[0];
  const egressUsable = egress.data?.phase === "vpn_ready" || Boolean(egress.data?.bootstrap_expires_at);
  const devices = useProviderDevices(account?.id, open && !source && egressUsable);
  const device = source ? null : devices.data?.find((d) => d.public_key === profile.interface.public_key);
  const servers = useProviderServers(account?.id, open && egressUsable && (source !== null || Boolean(device)));
  const change = useChangeProviderServer();
  const intent = useIntentKey(`provider.change_server:${profile.id}`);
  const currentFamily: IpFamily = profile.peer.endpoint.startsWith("[") ? "ipv6" : "ipv4";
  const [picked, setServer] = useState<ProviderServer | null>(null);
  const [pickedEntry, setEntry] = useState<EntryChoice | null>(null);
  const [family, setFamily] = useState<IpFamily>(currentFamily);
  const [rename, setRename] = useState<boolean | null>(null);
  const [error, setError] = useState<unknown>(null);

  // An imported profile names no server: its peer key tells which one it is.
  const currentId =
    source?.server_id ??
    profile.location?.server ??
    servers.data?.find((s) => s.peer_public_key === profile.peer.public_key)?.id ??
    null;
  const current = servers.data?.find((s) => s.id === currentId);
  // The entry in use: the one the profile records, else (an AirVPN profile from before entries could be chosen, or an
  // imported one) the exit's entry whose address and port its endpoint is.
  const currentEntry: EntryChoice = (() => {
    if (source?.entry) return entryChoiceOf(source.entry);
    const at = current?.entries.find((e) =>
      [e.ipv4, e.ipv6].some((ip) => ip !== null && endpointIs(profile.peer.endpoint, ip, e.port)),
    );
    return at && !at.default ? { kind: "address", index: at.index, port: at.port } : SAME_ENTRY;
  })();
  // The exit and entry start as the profile's: changing only one of them is a change.
  const server = picked ?? current ?? null;
  const entry = pickedEntry ?? currentEntry;
  const multihop = entry.kind === "relay" && entry.id !== server?.id;
  // A name built from the current server follows the new one; a name the user chose stays.
  const followed = account && server ? followedName(profile.name, account.provider, current, server) : null;
  const newName = account && server ? (followed ?? connectionName(account.provider, server)) : null;
  const renaming = (rename ?? followed !== null) && newName !== null && newName !== profile.name;
  const chosenAddress =
    entry.kind === "address"
      ? server?.entries.find((e) => e.index === entry.index && e.port === entry.port)
      : undefined;
  const v6 = multihop
    ? false
    : chosenAddress
      ? chosenAddress.ipv6 !== null
      : (server?.endpoints.some((e) => e.startsWith("[")) ?? false);
  const unchanged =
    !server || (server.id === currentId && family === currentFamily && sameEntry(entry, currentEntry, server));
  const fieldErrors = serverFieldErrors(error);
  const ready = account !== undefined && (source !== null || Boolean(device));

  const pick = (s: ProviderServer) => {
    setServer(s);
    // AirVPN entries belong to their server; a Mullvad entry relay that became the exit is no multihop.
    if (ROUTING[s.provider] === "entries" || (entry.kind === "relay" && entry.id === s.id)) setEntry(SAME_ENTRY);
    if (!s.endpoints.some((e) => e.startsWith("["))) setFamily("ipv4");
  };
  const chooseEntry = (c: EntryChoice) => {
    setEntry(c);
    if (c.kind === "relay") setFamily("ipv4");
  };

  const submit = () => {
    if (!account || !server || unchanged || !ready) return;
    const input = {
      server_id: server.id,
      entry: entryInput(entry, server),
      endpoint_family: family,
      name: renaming ? newName : null,
    };
    setError(null);
    change.mutate(
      { account: account.id, profile: profile.id, revision: profile.revision, input, key: intent.next(input) },
      {
        onSuccess: (r) => {
          intent.settle();
          onOpenChange(false);
          announceSaved({
            title: multihop ? m.changeServer.changedMultihop(entry.id, server.id) : m.changeServer.changed(server.id),
            kind: "profile",
            id: profile.id,
            revision: r.data.revision,
            workerChanged: true,
          });
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const accountPicker =
    !source && candidates.length > 1 ? (
      <Field label={m.changeServer.account} className="max-w-sm">
        {({ id }) => (
          <Select
            id={id}
            value={account?.id ?? ""}
            onChange={(e) => {
              setChosen(e.target.value);
            }}
          >
            {candidates.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </Select>
        )}
      </Field>
    ) : null;

  let body;
  if (accounts.isPending) body = <LoadingRows rows={3} label={m.changeServer.loadingAccounts} />;
  else if (!account)
    body = source ? (
      <Callout tone="warning" title={m.changeServer.accountGone}>
        {m.changeServer.accountGoneBody}
      </Callout>
    ) : profile.provider === "generic" ? (
      <Callout tone="info" title={m.changeServer.imported}>
        {m.changeServer.importedGeneric}
      </Callout>
    ) : (
      <Callout tone="info" title={m.changeServer.imported}>
        {m.changeServer.importedProvider(PROVIDER_NAME[profile.provider])}
      </Callout>
    );
  else if (!egressUsable)
    body = (
      <Callout tone="warning" title={m.changeServer.noEgress}>
        {m.changeServer.noEgressBody(source !== null)}
      </Callout>
    );
  else if (!source && devices.isError)
    body = (
      <div className="space-y-4">
        {accountPicker}
        <ErrorCallout
          error={devices.error}
          title={m.changeServer.devicesFailed}
          onRetry={() => void devices.refetch()}
          retrying={devices.isFetching}
        />
      </div>
    );
  else if (!source && !devices.data)
    body = (
      <div className="space-y-4">
        {accountPicker}
        <LoadingRows rows={2} label={m.changeServer.checkingDevice} />
      </div>
    );
  else if (!source && !device)
    body = (
      <div className="space-y-4">
        {accountPicker}
        <Callout tone="warning" title={m.changeServer.notADevice(account.label)}>
          {m.changeServer.notADeviceBody}
        </Callout>
      </div>
    );
  else if (servers.isError)
    body = (
      <ErrorCallout
        error={servers.error}
        title={m.changeServer.serversFailed}
        onRetry={() => void servers.refetch()}
        retrying={servers.isFetching}
      />
    );
  else if (!servers.data) body = <LoadingRows rows={4} label={m.changeServer.loadingServers} />;
  else
    body = (
      // The list replaces the loading rows in place: a fade, no movement.
      <div className="space-y-4 animate-fade-in">
        {accountPicker}
        {device ? (
          <Callout tone="info" title={m.changeServer.isDevice(device.label)}>
            {m.changeServer.adopted(account.label)}
          </Callout>
        ) : null}
        <FormFailure error={error} />
        <RoutePicker
          provider={account.provider}
          servers={servers.data}
          exit={server}
          entry={entry}
          family={family}
          currentExit={currentId}
          currentEntry={currentEntry}
          onExit={pick}
          onEntry={chooseEntry}
        />
        {["/server_id", "/entry", "/entry/server_id", "/endpoint_family"].map((path) =>
          fieldErrors.get(path) ? (
            <p key={path} className="text-caption text-danger">
              {fieldErrors.get(path)}
            </p>
          ) : null,
        )}
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <span className="text-data font-medium text-fg-secondary">{m.changeServer.family}</span>
          <Segmented
            label={m.changeServer.family}
            value={family}
            onChange={setFamily}
            options={[
              { value: "ipv4", label: "IPv4", title: multihop ? m.changeServer.multihopIpv4Only : undefined },
              ...(v6 ? [{ value: "ipv6" as const, label: "IPv6" }] : []),
            ]}
          />
        </div>
        {newName && newName !== profile.name ? (
          <Switch
            checked={renaming}
            onCheckedChange={setRename}
            label={m.changeServer.rename(newName)}
            description={followed !== null ? m.changeServer.renameFollowed : m.changeServer.renameCustom}
          />
        ) : null}
      </div>
    );

  // The confirm button says why it waits (never a silent disabled control).
  const reason = !ready
    ? m.changeServer.reason.notReady
    : !servers.data
      ? m.changeServer.reason.loading
      : !server
        ? m.changeServer.reason.noExit
        : multihop && !entry.id
          ? m.changeServer.reason.noEntry
          : multihop && server.multihop_port === null
            ? m.changeServer.reason.noMultihop
            : unchanged
              ? m.changeServer.reason.unchanged
              : null;

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={600}
      title={m.changeServer.title(profile.name)}
      description={m.changeServer.description(
        currentRoute(currentId, currentEntry),
        servers.isFetching || accounts.isPending,
      )}
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
            variant="primary"
            icon={ArrowLeftRight}
            disabledReason={reason}
            pending={change.isPending}
            pendingLabel={m.changeServer.changing}
            onClick={submit}
          >
            {m.changeServer.submit}
          </ActionButton>
        </>
      }
    >
      {body}
    </Dialog>
  );
}
