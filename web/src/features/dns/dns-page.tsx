// DNS 設定 (/dns, /dns/:id, /dns/new): the short list of DNS profiles beside the editor of one (MasterDetail), following
// the page recipe of docs/frontend-design.md §8.1. The editor is an inspector: the EntityHeader (name, usage, ID, the ⋯
// menu — the same menu as the list row), the conclusion first (what waits for a restart), collapsible sections, and the
// fixed footer with the one primary action, 儲存. Servers come and go with presence and slide when moved (Motion layout).
import { ArrowDown, ArrowUp, Globe, Network, Plus, Server, ShieldCheck, Sparkles, Timer, X } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { type ReactNode, useId, useMemo, useState } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router";
import { apiGet } from "@/api/client";
import { useDnsProfiles, useInstances, useSaveDnsProfile } from "@/api/queries";
import type { DnsOnFailure, DnsProfile, DnsProfileInput, DnsServer, InstanceView } from "@/api/types";
import { useCrumb } from "@/components/shell/nav";
import { ListItem, MasterDetail, MasterList, Page, PageHeader } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ButtonLink } from "@/components/ui/button";
import { ActionMenu, FooterActions, TitleActions } from "@/components/ui/entity-actions";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { EntityHeader, InspectorFooter, InspectorFrame, PropertySection } from "@/components/ui/inspector";
import { CARD, CHOICE_BASE, CHOICE_IDLE, CHOICE_SELECTED, TEXT_LINK } from "@/components/ui/look";
import { Menu, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Segmented } from "@/components/ui/segmented";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { ToolButton } from "@/components/ui/tool-strip";
import { announceSaved } from "@/features/instances/actions";
import { instanceLook } from "@/features/instances/model";
import { workerInput } from "@/features/instances/worker-input";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { parseIntField, serverFieldErrors } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { allowNextNavigation, UnsavedGuard } from "@/components/unsaved";
import { DnsActionHost, useDnsActions } from "./action-host";
import { m } from "./messages";
import { NextDnsDialog } from "./nextdns-dialog";
import { DNS_DEFAULTS, DNS_PRESETS } from "./presets";
import { pendingUsers, RestartUsers } from "./restart-users";

type Transport = DnsServer["transport"];
const TRANSPORT: Record<Transport, { label: string; port: number }> = {
  udp: { label: "UDP", port: 53 },
  tcp: { label: "TCP", port: 53 },
  tls: { label: "DoT", port: 853 },
  https: { label: "DoH", port: 443 },
};

/** At most this many resolvers per profile (the server's limit). */
const MAX_SERVERS = 4;

/** What a connection does while every server fails (the profile's `on_failure`), and what that means for it. */
const ON_FAILURE: { value: DnsOnFailure; title: string; text: string }[] = [
  {
    value: "wireguard_resolvers",
    title: m.editor.onFailure.wireguard_resolvers.title,
    text: m.editor.onFailure.wireguard_resolvers.text,
  },
  { value: "fail", title: m.editor.onFailure.fail.title, text: m.editor.onFailure.fail.text },
];

interface Row {
  key: string;
  transport: Transport;
  address: string;
  serverName: string;
  url: string;
}

let rowSeq = 0;
function toRow(s: DnsServer): Row {
  rowSeq += 1;
  return {
    key: `r${rowSeq}`,
    transport: s.transport,
    address: s.address,
    serverName: s.transport === "tls" ? s.server_name : "",
    url: s.transport === "https" ? s.url : "",
  };
}

function toServer(r: Row): DnsServer {
  const address = r.address.trim();
  switch (r.transport) {
    case "tls":
      return { transport: "tls", address, server_name: r.serverName.trim() };
    case "https":
      return { transport: "https", address, url: r.url.trim() };
    case "tcp":
    case "udp":
    default:
      return { transport: r.transport, address };
  }
}

const SOCKET = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:.]+\]):\d{1,5}$/;
const BARE_V4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const BARE_V6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;

/** A bare IP gets the transport's default port when the field loses focus. */
function withPort(address: string, t: Transport): string {
  const a = address.trim();
  if (BARE_V4.test(a)) return `${a}:${TRANSPORT[t].port}`;
  if (BARE_V6.test(a)) return `[${a}]:${TRANSPORT[t].port}`;
  if (/^\[[0-9a-fA-F:.]+\]$/.test(a)) return `${a}:${TRANSPORT[t].port}`;
  return a;
}

function summary(p: DnsProfile): string {
  const kinds = [...new Set(p.servers.map((s) => TRANSPORT[s.transport].label))];
  return m.summary(p.servers.length, kinds, p.on_failure === "fail");
}

function UsersSection({ users, pending }: { users: InstanceView[]; pending: InstanceView[] }) {
  return (
    <PropertySection title={m.users.title} icon={<Network aria-hidden />} count={users.length}>
      {users.length ? (
        <PresenceList items={users} keyOf={(v) => v.spec.id} className="grid grid-cols-1 gap-1" label={m.users.label}>
          {(v) => (
            <div className="flex min-h-8 flex-wrap items-center gap-x-2 gap-y-1">
              <Link
                to={`/instances/${v.spec.id}`}
                className={cn(TEXT_LINK, "min-w-0 text-data [overflow-wrap:anywhere]")}
              >
                {v.spec.name}
              </Link>
              <StatusPill look={instanceLook(v)} />
              {pending.includes(v) ? <Tag tone="warning">{m.users.appliesAfterRestart}</Tag> : null}
            </div>
          )}
        </PresenceList>
      ) : (
        <p className="text-data text-fg-tertiary">{m.users.none}</p>
      )}
    </PropertySection>
  );
}

function DnsEditor({ profile, users }: { profile: DnsProfile | null; users: InstanceView[] }) {
  const save = useSaveDnsProfile();
  const intent = useIntentKey(`dns.save:${profile?.id ?? "new"}`);
  const blocked = useMutationBlocked();
  const navigate = useNavigate();
  const formId = useId();
  const base = profile ?? { ...DNS_DEFAULTS, id: "", revision: 0, created_at: "", updated_at: "" };
  const [name, setName] = useState(base.name);
  const [rows, setRows] = useState<Row[]>(() =>
    base.servers.length ? base.servers.map(toRow) : [toRow({ transport: "udp", address: "" })],
  );
  const [maxEntries, setMaxEntries] = useState(String(base.cache.max_entries));
  const [maxTtl, setMaxTtl] = useState(String(base.cache.max_ttl_secs));
  const [negTtl, setNegTtl] = useState(String(base.cache.negative_ttl_secs));
  const [timeout, setTimeoutMs] = useState(String(base.query_timeout_ms));
  const [attempts, setAttempts] = useState(String(base.attempts));
  const [onFailure, setOnFailure] = useState<DnsOnFailure>(base.on_failure);
  const [revision, setRevision] = useState(profile?.revision);
  // The revision whose content `baseline` (or the first render) holds.
  const [baselineRevision, setBaselineRevision] = useState(profile?.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [baseline, setBaseline] = useState<string | null>(null);

  const input = (): DnsProfileInput => ({
    name: name.trim(),
    servers: rows.map(toServer),
    cache: {
      max_entries: parseIntField(maxEntries) ?? base.cache.max_entries,
      max_ttl_secs: parseIntField(maxTtl) ?? base.cache.max_ttl_secs,
      negative_ttl_secs: parseIntField(negTtl) ?? base.cache.negative_ttl_secs,
    },
    query_timeout_ms: parseIntField(timeout) ?? base.query_timeout_ms,
    attempts: parseIntField(attempts) ?? base.attempts,
    on_failure: onFailure,
  });
  // Dirty compares against what was last loaded or saved (a fresh editor starts from its first render).
  const current = JSON.stringify(input());
  const [initial] = useState(current);
  const dirty = current !== (baseline ?? initial);

  const server = serverFieldErrors(error);
  const rowProblem = (r: Row): string | null => {
    if (!SOCKET.test(r.address.trim())) return m.editor.errors.address;
    if (r.transport === "tls" && !r.serverName.trim()) return m.editor.errors.serverName;
    if (r.transport === "https" && !r.url.trim().startsWith("https://")) return m.editor.errors.url;
    return null;
  };
  const rowError = (r: Row, i: number): string | null =>
    rowProblem(r) ??
    server.get(`/servers/${i}`) ??
    server.get(`/servers/${i}/address`) ??
    server.get(`/servers/${i}/server_name`) ??
    server.get(`/servers/${i}/url`) ??
    null;
  const nameError = !name.trim() ? ui.common.enterName : (server.get("/name") ?? null);
  // Server messages are shown but never refuse the next attempt: a conflict with an IP blocklist
  // is resolved in the list, after which the same servers save.
  const rowsValid = rows.length >= 1 && rows.length <= MAX_SERVERS && rows.every((r) => rowProblem(r) === null);
  // A number that does not parse is never replaced by the saved value silently: it is an edit with a problem.
  const whole = (v: string, path: string) =>
    parseIntField(v) === null ? m.editor.errors.wholeNumber : (server.get(path) ?? null);
  const numberErrors = {
    timeout: whole(timeout, "/query_timeout_ms"),
    attempts: whole(attempts, "/attempts"),
    maxEntries: whole(maxEntries, "/cache/max_entries"),
    maxTtl: whole(maxTtl, "/cache/max_ttl_secs"),
    negTtl: whole(negTtl, "/cache/negative_ttl_secs"),
  };
  const numbersValid = [timeout, attempts, maxEntries, maxTtl, negTtl].every((v) => parseIntField(v) !== null);
  const valid = Boolean(name.trim()) && rowsValid && numbersValid;
  const unsaved = dirty || !numbersValid;
  const show = (message: string | null) => (submitted || error ? message : null);
  // A section holding a problem opens when the user tries to save (it may have been collapsed).
  const [serversOpen, setServersOpen] = useState(true);
  const [numbersOpen, setNumbersOpen] = useState(true);

  const patch = (key: string, p: Partial<Row>) => {
    setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...p } : r)));
  };
  const move = (i: number, d: -1 | 1) => {
    setRows((rs) => {
      const next = [...rs];
      const [r] = next.splice(i, 1);
      if (r) next.splice(i + d, 0, r);
      return next;
    });
  };

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (!rowsValid) setServersOpen(true);
    if (!numbersValid) setNumbersOpen(true);
    if (!valid) return;
    const body = input();
    // Only a change to what the worker uses needs a restart (a rename does not).
    const workerChanged =
      rev !== baselineRevision ||
      workerInput.dns(JSON.parse(baseline ?? initial) as DnsProfileInput) !== workerInput.dns(body);
    setError(null);
    save.mutate(
      { id: profile?.id, revision: rev, input: body, key: intent.next({ id: profile?.id, rev, body }) },
      {
        onSuccess: (r) => {
          intent.settle();
          setRevision(r.data.revision);
          setBaselineRevision(r.data.revision);
          setBaseline(JSON.stringify(body));
          if (profile && rev !== undefined) {
            announceSaved({
              title: m.editor.saved(body.name),
              kind: "dns",
              id: r.data.id,
              revision: r.data.revision,
              workerChanged,
            });
          } else {
            toast.success(m.editor.created(body.name));
            allowNextNavigation();
            void navigate(`/dns/${r.data.id}`, { replace: true });
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
    if (!profile) return;
    try {
      const p = await apiGet<DnsProfile>(`/v1/dns-profiles/${profile.id}`);
      setRevision(p.revision);
      if (apply) {
        setBaselineRevision(p.revision);
        setName(p.name);
        setRows(p.servers.map(toRow));
        setMaxEntries(String(p.cache.max_entries));
        setMaxTtl(String(p.cache.max_ttl_secs));
        setNegTtl(String(p.cache.negative_ttl_secs));
        setTimeoutMs(String(p.query_timeout_ms));
        setAttempts(String(p.attempts));
        setOnFailure(p.on_failure);
        setBaseline(
          JSON.stringify({
            name: p.name,
            servers: p.servers,
            cache: p.cache,
            query_timeout_ms: p.query_timeout_ms,
            attempts: p.attempts,
            on_failure: p.on_failure,
          }),
        );
        setError(null);
      } else submit(p.revision);
    } catch (e) {
      setError(e);
    }
  };

  const actions = useDnsActions(profile, users.length, {
    dirty: unsaved,
    own: {
      save: {
        run: () => {
          submit();
        },
        pending: save.isPending,
      },
    },
  });
  const pending = profile ? pendingUsers(users, "dns", profile.id) : [];
  const full = rows.length >= MAX_SERVERS;
  const addPreset = (s: DnsServer) => {
    setRows((rs) => [...rs.filter((r) => r.address.trim()), toRow(s)].slice(0, MAX_SERVERS));
  };
  const [nextDnsOpen, setNextDnsOpen] = useState(false);

  return (
    <form
      id={formId}
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
      className="flex h-full min-h-0 flex-col"
    >
      <InspectorFrame
        header={
          <EntityHeader
            icon={Globe}
            tone="entity"
            title={profile ? profile.name : m.newProfile}
            status={
              profile ? (
                <TitleActions actions={actions} menuLabel={m.actionsOf(profile.name)}>
                  <Tag tone={users.length ? "brand" : "neutral"}>{m.usedBy(users.length)}</Tag>
                </TitleActions>
              ) : null
            }
            description={profile ? summary(profile) : m.editor.description}
            id={profile?.id}
            idLabel={m.editor.idLabel}
          />
        }
        footer={
          <InspectorFooter
            note={
              <span aria-live="polite">
                {unsaved ? (
                  <span className="text-warning">{ui.common.unsavedChanges}</span>
                ) : profile ? (
                  users.length ? (
                    m.editor.appliesOnRestart
                  ) : (
                    m.editor.unused
                  )
                ) : (
                  m.editor.afterCreating
                )}
              </span>
            }
          >
            {profile ? (
              <FooterActions actions={actions} />
            ) : (
              <ActionButton
                type="submit"
                size="sm"
                variant="primary"
                icon={Plus}
                pending={save.isPending}
                pendingLabel={ui.common.creating}
                disabledReason={save.isPending ? null : blocked}
              >
                {ui.common.create}
              </ActionButton>
            )}
          </InspectorFooter>
        }
      >
        <div className="grid grid-cols-1 gap-3 border-b border-line-subtle px-4 py-3.5">
          <FormFailure error={error} onReload={() => void latest(true)} onOverwrite={() => void latest(false)} />
          {profile ? <RestartUsers views={users} kind="dns" id={profile.id} /> : null}
          <Field label={ui.common.name} required error={show(nameError)}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                maxLength={64}
                placeholder={m.editor.namePlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            )}
          </Field>
        </div>

        <PropertySection
          title={m.editor.servers}
          icon={<Server aria-hidden />}
          count={rows.length}
          open={serversOpen}
          onOpenChange={setServersOpen}
          actions={
            <Menu
              label={m.editor.presets}
              trigger={
                <ToolButton label={m.editor.addPreset} icon={<Sparkles aria-hidden />} text={m.editor.presets} />
              }
            >
              {DNS_PRESETS.map((p) => (
                <MenuItem
                  key={`${p.server.transport} ${p.server.address}`}
                  icon={Globe}
                  disabled={full}
                  reason={m.editor.atMost(MAX_SERVERS)}
                  onSelect={() => {
                    addPreset(p.server);
                  }}
                >
                  {p.label}
                </MenuItem>
              ))}
              <MenuSeparator />
              <MenuItem
                icon={ShieldCheck}
                onSelect={() => {
                  setNextDnsOpen(true);
                }}
              >
                {m.editor.nextDns}
              </MenuItem>
            </Menu>
          }
        >
          <div className="grid grid-cols-1 gap-3">
            <p className="text-data text-fg-tertiary">{m.editor.serversNote(MAX_SERVERS)}</p>
            <PresenceList
              as="ol"
              items={rows}
              keyOf={(r) => r.key}
              className="grid grid-cols-1 gap-2"
              label={m.editor.serverList}
            >
              {(r) => {
                const i = rows.findIndex((x) => x.key === r.key);
                const err = i < 0 ? null : show(rowError(r, i));
                const n = i + 1;
                return (
                  <div className={cn(CARD, "grid grid-cols-1 gap-2 p-3")}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span aria-hidden className="machine w-5 text-center text-caption text-fg-tertiary">
                        {i < 0 ? "" : n}
                      </span>
                      <Segmented
                        size="sm"
                        label={m.editor.protocolOf(n)}
                        value={r.transport}
                        onChange={(t) => {
                          patch(r.key, {
                            transport: t,
                            address: r.address ? withPort(r.address.replace(/:\d+$/, ""), t) : r.address,
                          });
                        }}
                        options={(Object.keys(TRANSPORT) as Transport[]).map((t) => ({
                          value: t,
                          label: TRANSPORT[t].label,
                        }))}
                      />
                      <Input
                        mono
                        aria-label={m.editor.addressOf(n)}
                        aria-invalid={Boolean(err)}
                        placeholder={m.editor.addressPlaceholder(TRANSPORT[r.transport].port)}
                        value={r.address}
                        onChange={(e) => {
                          patch(r.key, { address: e.target.value });
                        }}
                        onBlur={(e) => {
                          patch(r.key, { address: withPort(e.target.value, r.transport) });
                        }}
                        size="sm"
                        className="min-w-44 flex-1"
                      />
                      <div className="flex">
                        <ToolButton
                          label={m.editor.moveUp(n)}
                          icon={<ArrowUp aria-hidden />}
                          disabledReason={i === 0 ? m.editor.alreadyFirst : null}
                          onClick={() => {
                            move(i, -1);
                          }}
                        />
                        <ToolButton
                          label={m.editor.moveDown(n)}
                          icon={<ArrowDown aria-hidden />}
                          disabledReason={i === rows.length - 1 ? m.editor.alreadyLast : null}
                          onClick={() => {
                            move(i, 1);
                          }}
                        />
                        <ToolButton
                          label={m.editor.remove(n)}
                          icon={<X aria-hidden />}
                          disabledReason={rows.length === 1 ? m.editor.lastOne : null}
                          onClick={() => {
                            setRows((rs) => rs.filter((x) => x.key !== r.key));
                          }}
                        />
                      </div>
                    </div>
                    {r.transport === "tls" ? (
                      <Input
                        mono
                        aria-label={m.editor.serverNameOf(n)}
                        placeholder={m.editor.serverNamePlaceholder}
                        value={r.serverName}
                        onChange={(e) => {
                          patch(r.key, { serverName: e.target.value });
                        }}
                        size="sm"
                      />
                    ) : null}
                    {r.transport === "https" ? (
                      <Input
                        mono
                        aria-label={m.editor.urlOf(n)}
                        placeholder="https://cloudflare-dns.com/dns-query"
                        value={r.url}
                        onChange={(e) => {
                          patch(r.key, { url: e.target.value });
                        }}
                        size="sm"
                      />
                    ) : null}
                    {err ? (
                      <p role="alert" className="text-caption text-danger animate-reveal">
                        {err}
                      </p>
                    ) : null}
                  </div>
                );
              }}
            </PresenceList>
            <div>
              <ActionButton
                size="sm"
                icon={Plus}
                disabledReason={full ? m.editor.atMost(MAX_SERVERS) : null}
                onClick={() => {
                  setRows((rs) => [...rs, toRow({ transport: "udp", address: "" })]);
                }}
              >
                {m.editor.addServer}
              </ActionButton>
            </div>
            <fieldset className="grid grid-cols-1 gap-2 pt-1">
              <legend className="mb-2 text-data font-medium text-fg-secondary">{m.editor.onFailure.label}</legend>
              <RadioGroup.Root
                name="on_failure"
                value={onFailure}
                onValueChange={(v) => {
                  setOnFailure(v as DnsOnFailure);
                }}
                className="grid gap-2 sm:grid-cols-2"
                aria-label={m.editor.onFailure.label}
              >
                {ON_FAILURE.map((o) => (
                  <RadioGroup.Item
                    key={o.value}
                    value={o.value}
                    className={cn(
                      CHOICE_BASE,
                      "flex flex-col items-start gap-0.5 rounded-lg px-3 py-2.5 text-left",
                      onFailure === o.value ? CHOICE_SELECTED : CHOICE_IDLE,
                    )}
                  >
                    <span className="text-body font-medium text-fg">{o.title}</span>
                    <span className="text-caption text-fg-tertiary">{o.text}</span>
                  </RadioGroup.Item>
                ))}
              </RadioGroup.Root>
            </fieldset>
          </div>
        </PropertySection>

        <PropertySection
          title={m.editor.numbers}
          icon={<Timer aria-hidden />}
          open={numbersOpen}
          onOpenChange={setNumbersOpen}
        >
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {(
              [
                ["timeout", m.editor.timeout, m.editor.timeoutHint, timeout, setTimeoutMs, numberErrors.timeout],
                ["attempts", m.editor.attempts, undefined, attempts, setAttempts, numberErrors.attempts],
                ["maxEntries", m.editor.maxEntries, undefined, maxEntries, setMaxEntries, numberErrors.maxEntries],
                ["maxTtl", m.editor.maxTtl, undefined, maxTtl, setMaxTtl, numberErrors.maxTtl],
                ["negativeTtl", m.editor.negativeTtl, m.editor.negativeTtlHint, negTtl, setNegTtl, numberErrors.negTtl],
              ] as const
            ).map(([field, label, hint, value, setValue, problem]) => (
              <Field key={field} label={label} hint={hint} error={show(problem)}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={value}
                    onChange={(e) => {
                      setValue(e.target.value);
                    }}
                  />
                )}
              </Field>
            ))}
          </div>
        </PropertySection>

        {profile ? <UsersSection users={users} pending={pending} /> : null}
      </InspectorFrame>
      <NextDnsDialog
        open={nextDnsOpen}
        onOpenChange={setNextDnsOpen}
        onApply={(servers, suggested) => {
          setRows(servers.map(toRow));
          if (!name.trim()) setName(suggested);
          setServersOpen(true);
        }}
      />
      <UnsavedGuard dirty={unsaved} />
    </form>
  );
}

/** A list row: the profile, its servers and users, and the same ⋯ menu as its editor. */
function DnsRow({ p, users, selected }: { p: DnsProfile; users: number; selected: boolean }) {
  const actions = useDnsActions(p, users);
  return (
    <ListItem
      to={`/dns/${p.id}`}
      selected={selected}
      title={p.name}
      meta={m.list.meta(summary(p), users)}
      actions={
        <ActionMenu actions={actions} label={m.actionsOf(p.name)} triggerLabel={m.moreActionsOf(p.name)} size="sm" />
      }
    />
  );
}

export function DnsPage() {
  const { id } = useParams();
  const dns = useDnsProfiles();
  const instances = useInstances();
  const all = useMemo(() => dns.data ?? [], [dns.data]);
  const views = useMemo(() => instances.data ?? [], [instances.data]);
  const selected = id && id !== "new" ? all.find((p) => p.id === id) : undefined;
  useCrumb(id === "new" ? m.newProfile : selected?.name);
  const users = useMemo(() => {
    const byProfile = new Map<string, InstanceView[]>();
    for (const v of views) {
      const d = v.spec.dns_profile_id;
      if (d) byProfile.set(d, [...(byProfile.get(d) ?? []), v]);
    }
    return byProfile;
  }, [views]);

  const create = (
    <ButtonLink to="/dns/new" variant="primary" icon={Plus}>
      {m.add}
    </ButtonLink>
  );

  let detail: ReactNode;
  if (id === "new") detail = <DnsEditor key="new" profile={null} users={[]} />;
  else if (selected) detail = <DnsEditor key={selected.id} profile={selected} users={users.get(selected.id) ?? []} />;
  else if (dns.isPending) detail = <LoadingRows rows={3} label={m.loading} />;
  else if (dns.isError && !dns.data)
    detail = <ErrorState error={dns.error} onRetry={() => void dns.refetch()} retrying={dns.isFetching} />;
  else if (id)
    detail = (
      <EmptyState icon={Globe} title={m.notFound}>
        {ui.common.mayHaveBeenDeleted}
      </EmptyState>
    );
  // The only one opens by itself; with several the user picks one.
  else if (all.length === 1 && all[0]) detail = <Navigate replace to={`/dns/${all[0].id}`} />;
  else if (all.length)
    detail = (
      <EmptyState icon={Globe} title={m.list.choose}>
        {m.list.chooseDetail}
      </EmptyState>
    );
  else
    detail = (
      <EmptyState brand icon={Globe} title={m.list.none} actions={create}>
        {m.list.noneDetail}
      </EmptyState>
    );

  let list: ReactNode;
  if (dns.isPending) list = <LoadingRows rows={3} label={m.loading} />;
  else if (dns.isError && !dns.data)
    list = <ErrorState compact error={dns.error} onRetry={() => void dns.refetch()} retrying={dns.isFetching} />;
  else
    list = (
      <>
        {dns.isError ? (
          // Stale: the last list stays, marked, with a retry.
          <div className="shrink-0 border-b border-line-subtle p-2">
            <ErrorCallout
              error={dns.error}
              title={m.stale(new Date(dns.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void dns.refetch()}
              retrying={dns.isFetching}
            />
          </div>
        ) : null}
        {all.length ? (
          <MasterList label={m.list.label}>
            <PresenceList items={all} keyOf={(p) => p.id} className="grid grid-cols-1 gap-0.5" label={m.list.label}>
              {(p) => <DnsRow p={p} users={users.get(p.id)?.length ?? 0} selected={p.id === id} />}
            </PresenceList>
          </MasterList>
        ) : (
          <EmptyState compact icon={Globe} title={m.list.none}>
            {m.list.noneCompact}
          </EmptyState>
        )}
      </>
    );

  return (
    <Page>
      <DnsActionHost profiles={all}>
        <PageHeader title={m.title} description={m.description} help={m.help} helpText={m.helpText} actions={create} />
        <MasterDetail
          listLabel={m.list.listLabel}
          detailLabel={selected ? m.list.settingsOf(selected.name) : m.list.detail}
          backLabel={m.list.all}
          list={list}
          detail={detail}
        />
      </DnsActionHost>
    </Page>
  );
}
