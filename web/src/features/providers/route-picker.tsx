// 入口／出口 of a provider connection (使用者 2026-11-07：「幫我在 VPN Manager 增加每個 Provide 應該能選擇入口跟出口」).
// The exit is where traffic leaves the provider's network (the address websites see); the entry is where the
// tunnel goes in. Mullvad: the entry is the exit relay itself or another relay (multihop — the tunnel goes to the
// entry relay and on to the exit inside Mullvad, on the exit relay's multihop port, IPv4 only). AirVPN has no
// multihop: the entry is one of the exit server's own addresses and ports, so entry and exit are the same server.
// Other providers: one server, chosen by its configuration.
import { ArrowRight } from "lucide-react";
import type { ProviderKind, ProviderServer, ProviderServerEntry } from "@/api/types";
import { Tag } from "@/components/ui/badge";
import { LIST_ROW, LIST_ROW_IDLE, LIST_ROW_SELECTED } from "@/components/ui/look";
import { Segmented } from "@/components/ui/segmented";
import { Callout } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import { cityName, countryName } from "@/lib/places";
import { m } from "./connect/messages";
import { type EntryChoice, entryAddressLabel, ROUTING, SAME_ENTRY } from "./model";
import { ServerPicker } from "./server-picker";

/** "jp-tyo-wg-001 · 東京，日本": a server and where it is. */
function serverText(s: ProviderServer): string {
  const place = m.cityAndCountry(s.city ? cityName(s.city) : null, countryName(s.country_code, s.country));
  return place ? `${s.id} · ${place}` : s.id;
}

/** The AirVPN entries of the exit server, as radio rows (the default first). */
function EntryList({
  exit,
  value,
  current,
  family,
  onChange,
}: {
  exit: ProviderServer;
  value: EntryChoice;
  current: EntryChoice | null;
  family: "ipv4" | "ipv6";
  onChange: (c: EntryChoice) => void;
}) {
  const at = (e: ProviderServerEntry): EntryChoice =>
    e.default ? SAME_ENTRY : { kind: "address", index: e.index, port: e.port };
  const is = (c: EntryChoice | null, e: ProviderServerEntry) =>
    c !== null && (c.kind === "same" ? e.default : c.kind === "address" && c.index === e.index && c.port === e.port);
  return (
    <div role="radiogroup" aria-label={m.route.entryAddresses} className="grid grid-cols-1 gap-1">
      {exit.entries.map((e) => {
        const address = family === "ipv6" ? e.ipv6 : e.ipv4;
        const chosen = is(value, e);
        return (
          <label
            key={`${e.index}:${e.port}`}
            className={cn(
              LIST_ROW,
              "flex items-center gap-3 rounded-md px-2.5 py-1.5",
              chosen ? LIST_ROW_SELECTED : address ? LIST_ROW_IDLE : undefined,
              address ? "cursor-pointer" : "cursor-not-allowed opacity-55",
            )}
            title={address ? undefined : m.route.noAddress(family === "ipv6" ? "IPv6" : "IPv4")}
          >
            <input
              type="radio"
              name={`entry-${exit.id}`}
              className="size-4 shrink-0 accent-action"
              disabled={!address}
              checked={chosen}
              onChange={() => {
                onChange(at(e));
              }}
            />
            <span className="min-w-0 flex-1 text-data text-fg">{entryAddressLabel(e)}</span>
            <span className="machine truncate text-caption text-fg-tertiary">{address ?? "—"}</span>
            {e.default ? <Tag>{m.route.defaultEntry}</Tag> : null}
            {is(current, e) ? <Tag tone="info">{m.route.current}</Tag> : null}
          </label>
        );
      })}
    </div>
  );
}

/**
 * The exit (a server of the provider's list) and the entry (per the provider: another relay, or another address and
 * port of the same server), with a summary of the route. `current*`: what the profile uses now (marked).
 */
export function RoutePicker({
  provider,
  servers,
  exit,
  entry,
  family,
  currentExit = null,
  currentEntry = null,
  onExit,
  onEntry,
}: {
  provider: ProviderKind;
  servers: ProviderServer[];
  exit: ProviderServer | null;
  entry: EntryChoice;
  family: "ipv4" | "ipv6";
  currentExit?: string | null;
  currentEntry?: EntryChoice | null;
  onExit: (s: ProviderServer) => void;
  onEntry: (c: EntryChoice) => void;
}) {
  const routing = ROUTING[provider];
  const entryRelay = entry.kind === "relay" ? servers.find((s) => s.id === entry.id) : undefined;
  const multihop = routing === "multihop" && entry.kind === "relay" && entry.id !== exit?.id;
  const noPort = multihop && exit !== null && exit.multihop_port === null;
  const entryAddress =
    routing === "entries" && exit
      ? (exit.entries.find((e) =>
          entry.kind === "address" ? e.index === entry.index && e.port === entry.port : e.default,
        ) ?? null)
      : null;
  const exitIp = exit?.exit_ips[0] ?? null;

  return (
    <div className="space-y-4">
      <section aria-labelledby="route-exit" className="space-y-2">
        <div className="flex flex-wrap items-baseline justify-between gap-x-3">
          <p id="route-exit" className="text-data font-medium text-fg-secondary">
            {m.route.exit}
          </p>
          <p className="text-caption text-fg-tertiary">{m.route.exitHint}</p>
        </div>
        <ServerPicker
          servers={servers}
          value={exit?.id ?? null}
          current={currentExit}
          onChange={onExit}
          label={m.route.exitServer}
        />
      </section>

      {routing === "multihop" ? (
        <section aria-labelledby="route-entry" className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
            <p id="route-entry" className="text-data font-medium text-fg-secondary">
              {m.route.entry}
            </p>
            <Segmented
              size="sm"
              label={m.route.entry}
              value={entry.kind === "relay" ? "relay" : "same"}
              onChange={(v) => {
                onEntry(v === "same" ? SAME_ENTRY : { kind: "relay", id: entryRelay?.id ?? "" });
              }}
              options={[
                { value: "same", label: m.route.sameAsExit },
                { value: "relay", label: m.route.anotherServer },
              ]}
            />
          </div>
          {entry.kind === "relay" ? (
            <div className="space-y-2 animate-reveal">
              <p className="text-caption text-fg-tertiary">{m.route.multihopHint}</p>
              <ServerPicker
                servers={servers}
                value={entry.id || null}
                current={currentEntry?.kind === "relay" ? currentEntry.id : null}
                onChange={(s) => {
                  onEntry({ kind: "relay", id: s.id });
                }}
                label={m.route.entryServer}
                takesFocus={false}
                unusable={(s) => (s.id === exit?.id ? m.route.isTheExit : null)}
              />
              {noPort ? (
                <Callout tone="warning" title={m.route.noMultihop}>
                  {m.route.noMultihopHint}
                </Callout>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : routing === "entries" ? (
        <section aria-labelledby="route-entry" className="space-y-2">
          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
            <p id="route-entry" className="text-data font-medium text-fg-secondary">
              {m.route.entry}
            </p>
            <p className="text-caption text-fg-tertiary">{m.route.airvpnEntryHint}</p>
          </div>
          {exit ? (
            exit.entries.length ? (
              <EntryList
                exit={exit}
                value={entry}
                current={exit.id === currentExit ? currentEntry : null}
                family={family}
                onChange={onEntry}
              />
            ) : (
              <p className="text-caption text-fg-tertiary">{m.route.oneEntryOnly}</p>
            )
          ) : (
            <p className="text-caption text-fg-tertiary">{m.route.chooseExitFirst}</p>
          )}
        </section>
      ) : null}

      {exit ? (
        <div className="rounded-lg border border-line-subtle bg-sunken/50 px-3 py-2.5" aria-live="polite">
          <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-data text-fg">
            <span className="text-caption text-fg-tertiary">{m.route.entry}</span>
            <span className="[overflow-wrap:anywhere]">
              {multihop
                ? entryRelay
                  ? serverText(entryRelay)
                  : m.route.chooseEntry
                : entryAddress
                  ? `${exit.id} · ${entryAddressLabel(entryAddress)}`
                  : serverText(exit)}
            </span>
            <ArrowRight aria-label={m.route.to} className="size-3.5 text-fg-tertiary" />
            <span className="text-caption text-fg-tertiary">{m.route.exit}</span>
            <span className="[overflow-wrap:anywhere]">{serverText(exit)}</span>
          </p>
          <p className="mt-1 text-caption text-fg-tertiary">
            {routing === "entries"
              ? exitIp
                ? m.route.sameServerWithIp(exitIp)
                : m.route.sameServer
              : multihop
                ? entryRelay
                  ? m.route.twoServers
                  : m.route.afterEntryChosen
                : m.route.sameServer}
          </p>
        </div>
      ) : null}
    </div>
  );
}
