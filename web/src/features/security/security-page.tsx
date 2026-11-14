// 安全設定 (/security, /security/:id, /security/new): the short list of security profiles beside the editor of one
// (MasterDetail), following the page recipe of docs/frontend-design.md §8.1. The editor is an inspector: the EntityHeader
// (name, usage, ID, the ⋯ menu — the same menu as the list row), the fixed footer with the one primary action, 儲存, and
// in between three tabs (`?tab=`): 概況 (the name and the connections that use it), 目的地 (where connections may go:
// private networks, firewall allow rules, blocked ports) and 封鎖 (IP blocklists and auto-ban), one collapsible section
// per kind of rule. The conclusion (a failed save, what waits for a restart) leads every tab; saving with a problem
// opens the first tab holding one and marks every such tab. The order the rules are checked in is the page's help (?).
import { Ban, ListX, Network, Plus, Route, Shield, ShieldBan, ShieldCheck } from "lucide-react";
import { type ReactNode, useId, useMemo, useState } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router";
import { apiGet } from "@/api/client";
import {
  useBlocklists,
  useInboundSummary,
  useInstances,
  useSaveSecurityProfile,
  useSecurityProfiles,
} from "@/api/queries";
import type { AutoBanSettings, BlocklistView, InstanceView, SecurityProfile, SecurityProfileInput } from "@/api/types";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { ListItem, MasterDetail, MasterList, Page, PageHeader } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ButtonLink } from "@/components/ui/button";
import { ActionMenu, FooterActions, TitleActions } from "@/components/ui/entity-actions";
import { FactLine } from "@/components/ui/fact-line";
import { Field, Input, Textarea } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  InspectorTab,
  InspectorTabs,
  PropertySection,
  SectionLink,
} from "@/components/ui/inspector";
import { OPTION_CARD, OPTION_IDLE, OPTION_SELECTED, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { TabCount } from "@/components/ui/tabs";
import { toast } from "@/components/ui/toast";
import { pendingUsers, RestartUsers } from "@/features/dns/restart-users";
import { announceSaved } from "@/features/instances/actions";
import { instanceLook } from "@/features/instances/model";
import { workerInput } from "@/features/instances/worker-input";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { serverFieldErrors } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { allowNextNavigation, UnsavedGuard } from "@/components/unsaved";
import { useTabParam } from "@/lib/url";
import { m } from "./messages";
import {
  AUTO_BAN_BOUNDS,
  AUTO_BAN_DEFAULT,
  autoBanError,
  defaultLists,
  formatCount,
  formatPortRanges,
  forwardsOf,
  isSpecialNet,
  LIMITS,
  listName,
  listSize,
  listState,
  overlayState,
  parseCidrList,
  parsePortRanges,
  parsePorts,
  privateWithoutAllowance,
  sortLists,
  sourceLabel,
} from "./model";
import { SecurityActionHost, useSecurityActions } from "./profile-host";

const PORT_PRESETS: { label: string; ports: number[] }[] = [
  { label: m.ports.presets.smtp, ports: [25, 465, 587] },
  { label: m.ports.presets.windowsSharing, ports: [137, 138, 139, 445] },
  { label: m.ports.presets.remoteDesktop, ports: [3389] },
];

/** Compiled overlay a worker may hold (the server checks the sum of the lists). */
const OVERLAY_LIMIT = 16 * 1024 * 1024;

type AutoBanFields = Record<keyof typeof AUTO_BAN_BOUNDS, string>;

function autoBanFields(a: AutoBanSettings): AutoBanFields {
  return {
    window_secs: String(a.window_secs),
    threshold: String(a.threshold),
    ban_secs: String(a.ban_secs),
    max_bans: String(a.max_bans),
  };
}

/** What a profile does, fact by fact. */
function summaryFacts(p: SecurityProfile): string[] {
  const parts = [p.allow_private.length ? m.summary.allowsPrivate(p.allow_private.length) : m.summary.publicOnly];
  if (p.allowed_destinations.length || p.allowed_ports.length) parts.push(m.summary.allowRules);
  if (p.blocked_ports.length) parts.push(m.summary.blockedPorts(p.blocked_ports.length));
  if (p.blocklists.length) parts.push(m.summary.blocklists(p.blocklists.length));
  if (p.auto_ban.enabled) parts.push(m.summary.autoBan);
  return parts;
}

function inputOf(p: SecurityProfile): SecurityProfileInput {
  return {
    name: p.name,
    allow_private: p.allow_private,
    blocked_ports: p.blocked_ports,
    allowed_destinations: p.allowed_destinations,
    allowed_ports: p.allowed_ports,
    blocklists: p.blocklists,
    auto_ban: p.auto_ban,
  };
}

/** The connection's worker and this profile: what it enforces now, and what waits for a restart. */
function ConnectionState({ v }: { v: InstanceView }) {
  const s = overlayState(v);
  const pendingBase = v.status?.running?.pending_changes.includes("security");
  return (
    <span className="text-caption">
      {s.kind === "not_running" ? <span className="text-fg-tertiary">{m.connection.notRunning}</span> : null}
      {s.kind === "applied" ? <span className="text-success">{m.connection.applied(s.revision)}</span> : null}
      {s.kind === "pending" ? <span className="text-info">{m.connection.applying(s.revision)}</span> : null}
      {s.kind === "error" ? <span className="text-danger">{s.message}</span> : null}
      {pendingBase ? <span className="text-warning">{m.connection.othersAfterRestart}</span> : null}
    </span>
  );
}

function BlocklistPicker({
  lists,
  selected,
  onChange,
  error,
}: {
  lists: ReturnType<typeof useBlocklists>;
  selected: string[];
  onChange: (ids: string[]) => void;
  error: string | null;
}) {
  const all = useMemo(() => sortLists(lists.data ?? []), [lists.data]);
  const toggle = (id: string, on: boolean) => {
    onChange(on ? [...selected.filter((x) => x !== id), id] : selected.filter((x) => x !== id));
  };
  if (lists.isPending) return <LoadingRows rows={2} label={m.picker.loading} />;
  if (lists.isError && !lists.data)
    return (
      <ErrorState
        compact
        error={lists.error}
        onRetry={() => void lists.refetch()}
        retrying={lists.isFetching}
        title={m.picker.loadFailed}
      />
    );
  if (!all.length) {
    return (
      <EmptyState
        compact
        icon={ListX}
        title={m.picker.none}
        actions={
          <ButtonLink to="/security/blocklists/new" size="sm" icon={Plus}>
            {m.picker.add}
          </ButtonLink>
        }
      >
        {m.picker.noneBody}
      </EmptyState>
    );
  }
  return (
    <div className="grid grid-cols-1 gap-2">
      <ul className="grid grid-cols-1 gap-1.5" aria-label={shell.nav.blocklists.label}>
        {all.map((v: BlocklistView) => {
          const b = v.blocklist;
          const id = `bl-${b.id}`;
          const on = selected.includes(b.id);
          const state = listState(v);
          const stale = v.stale && !v.awaiting_content && b.enabled;
          return (
            <li
              key={b.id}
              className={cn(OPTION_CARD, "flex items-start gap-3 px-3 py-2.5", on ? OPTION_SELECTED : OPTION_IDLE)}
            >
              <input
                id={id}
                type="checkbox"
                checked={on}
                onChange={(e) => {
                  toggle(b.id, e.target.checked);
                }}
                className="mt-1 size-4 shrink-0 cursor-pointer accent-action"
              />
              <label htmlFor={id} className="min-w-0 flex-1 cursor-pointer">
                <span className="flex flex-wrap items-center gap-1.5 text-data font-medium text-fg">
                  <span className="[overflow-wrap:anywhere]">{listName(v)}</span>
                  {v.builtin ? <Tag tone="brand">{ui.common.builtIn}</Tag> : null}
                  <Tag tone={b.source.kind === "url" ? "info" : "neutral"}>{sourceLabel(b.source)}</Tag>
                  {stale ? <Tag tone="warning">{m.picker.stale}</Tag> : null}
                  {state && !stale ? <Tag tone={state.tone}>{state.label}</Tag> : null}
                </span>
                <span className="block text-caption text-fg-tertiary tabular-nums">
                  {v.awaiting_content ? m.picker.awaiting : listSize(b.stats)}
                  {!b.enabled ? m.picker.disabledNote : ""}
                </span>
              </label>
              <Link to={`/security/blocklists/${b.id}`} className={cn(TEXT_LINK, "shrink-0 text-caption leading-6")}>
                {m.picker.view}
              </Link>
            </li>
          );
        })}
      </ul>
      {error ? (
        <p className="text-caption text-danger animate-reveal" role="alert">
          {error}
        </p>
      ) : (
        <p className="text-caption text-fg-tertiary">{m.picker.selected(selected.length, LIMITS.blocklists)}</p>
      )}
    </div>
  );
}

type SectionKey = "allow" | "firewall" | "ports" | "lists" | "ban";

export type SecurityTab = "overview" | "destinations" | "blocking";

const SECURITY_TABS: SecurityTab[] = ["overview", "destinations", "blocking"];

const SECURITY_TAB_LABEL: Record<SecurityTab, string> = {
  overview: ui.common.overview,
  destinations: m.tabs.destinations,
  blocking: m.tabs.blocking,
};

/** The tab of each section (and of the name, in 概況): where saving sends the user to a problem. */
const SECTION_TAB: Record<SectionKey | "name", SecurityTab> = {
  name: "overview",
  allow: "destinations",
  firewall: "destinations",
  ports: "destinations",
  lists: "blocking",
  ban: "blocking",
};

/**
 * One security profile, or a new one (`profile` null). A new profile starts like the default policy:
 * the enabled built-in blocklists (`defaults`) selected and auto-ban on. Once saved, a connection
 * using it enforces exactly its selection, not the default policy's.
 */
function SecurityEditor({
  profile,
  users,
  defaults = [],
}: {
  profile: SecurityProfile | null;
  users: InstanceView[];
  defaults?: string[];
}) {
  const save = useSaveSecurityProfile();
  const lists = useBlocklists();
  const inbound = useInboundSummary();
  const intent = useIntentKey(`security.save:${profile?.id ?? "new"}`);
  const blocked = useMutationBlocked();
  const navigate = useNavigate();
  const formId = useId();
  const [name, setName] = useState(profile?.name ?? "");
  const [allow, setAllow] = useState((profile?.allow_private ?? []).join("\n"));
  const [ports, setPorts] = useState((profile?.blocked_ports ?? []).join(", "));
  const [dests, setDests] = useState((profile?.allowed_destinations ?? []).join("\n"));
  const [allowedPorts, setAllowedPorts] = useState(formatPortRanges(profile?.allowed_ports ?? []));
  const [selectedLists, setSelectedLists] = useState<string[]>(profile?.blocklists ?? defaults);
  const [banOn, setBanOn] = useState(profile?.auto_ban.enabled ?? AUTO_BAN_DEFAULT.enabled);
  const [ban, setBan] = useState<AutoBanFields>(autoBanFields(profile?.auto_ban ?? AUTO_BAN_DEFAULT));
  const [revision, setRevision] = useState(profile?.revision);
  // The revision whose content `baseline` (or the first render) holds.
  const [baselineRevision, setBaselineRevision] = useState(profile?.revision);
  const [error, setError] = useState<unknown>(null);
  // The input the current `error` answered.
  const [errorInput, setErrorInput] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [baseline, setBaseline] = useState<string | null>(null);
  // Collapsed sections; one holding a problem opens again when the user tries to save (and its tab with it).
  const [closed, setClosed] = useState<ReadonlySet<SectionKey>>(new Set());
  const [tab, setTab] = useTabParam<SecurityTab>("tab", SECURITY_TABS);
  const section = (key: SectionKey) => ({
    open: !closed.has(key),
    onOpenChange: (open: boolean) => {
      setClosed((c) => {
        const next = new Set(c);
        if (open) next.delete(key);
        else next.add(key);
        return next;
      });
    },
  });

  const allowParsed = parseCidrList(allow);
  const destParsed = parseCidrList(dests);
  const allowedPortsParsed = parsePortRanges(allowedPorts);
  const parsed = parsePorts(ports);
  const banErrors = Object.fromEntries(
    (Object.keys(AUTO_BAN_BOUNDS) as (keyof typeof AUTO_BAN_BOUNDS)[]).map((k) => [k, autoBanError(k, ban[k])]),
  ) as Record<keyof typeof AUTO_BAN_BOUNDS, string | null>;
  const autoBan: AutoBanSettings = {
    enabled: banOn,
    window_secs: Number(ban.window_secs),
    threshold: Number(ban.threshold),
    ban_secs: Number(ban.ban_secs),
    max_bans: Number(ban.max_bans),
  };
  const input = (): SecurityProfileInput => ({
    name: name.trim(),
    allow_private: allowParsed.nets,
    blocked_ports: parsed.ports,
    allowed_destinations: destParsed.nets,
    allowed_ports: allowedPortsParsed.ranges,
    blocklists: selectedLists,
    auto_ban: autoBan,
  });
  const current = JSON.stringify(input());
  const [initial] = useState(current);
  const dirty = current !== (baseline ?? initial);

  // A server field message answers the attempt it came from: it shows while the form still holds
  // that input and never refuses the next attempt (a conflict can be resolved elsewhere, such as
  // in the list itself, and the same input then saves).
  const server = error !== null && errorInput === current ? serverFieldErrors(error) : new Map<string, string>();
  const serverAt = (prefix: string) =>
    [...server.entries()].filter(([k]) => k.startsWith(prefix)).map(([, v]) => v)[0] ?? null;
  const allowSpecial = allowParsed.nets.filter((n) => isSpecialNet(n) || n.endsWith("/0"));
  const destSpecial = destParsed.nets.filter(isSpecialNet);
  const destPrivate = privateWithoutAllowance(destParsed.nets, allowParsed.nets);
  const listBytes = selectedLists.reduce(
    (sum, id) => sum + (lists.data?.find((v) => v.blocklist.id === id)?.blocklist.stats.parsed_bytes ?? 0),
    0,
  );
  const problems = {
    name: !name.trim() ? ui.common.enterName : null,
    allow: allowParsed.bad.length
      ? m.errors.allowFormat(allowParsed.bad)
      : allowSpecial.length
        ? m.errors.allowSpecial(allowSpecial)
        : allowParsed.nets.length > LIMITS.networks
          ? m.errors.atMostNetworks(LIMITS.networks)
          : null,
    dests: destParsed.bad.length
      ? m.errors.format(destParsed.bad)
      : destSpecial.length
        ? m.errors.destSpecial(destSpecial)
        : destParsed.nets.length > LIMITS.networks
          ? m.errors.atMostNetworks(LIMITS.networks)
          : null,
    allowedPorts: allowedPortsParsed.bad.length
      ? m.errors.portRange(allowedPortsParsed.bad)
      : allowedPortsParsed.ranges.length > LIMITS.portRanges
        ? m.errors.atMostRanges(LIMITS.portRanges)
        : null,
    ports: parsed.bad.length
      ? m.errors.port(parsed.bad)
      : parsed.ports.length > LIMITS.blockedPorts
        ? m.errors.atMostPorts(LIMITS.blockedPorts)
        : null,
    lists:
      selectedLists.length > LIMITS.blocklists
        ? m.errors.atMostLists(LIMITS.blocklists)
        : listBytes > OVERLAY_LIMIT
          ? m.errors.overlayTooLarge
          : null,
    ban: Object.values(banErrors).find(Boolean) ?? null,
  };
  const errors = {
    name: problems.name ?? server.get("/name") ?? null,
    allow: problems.allow ?? serverAt("/allow_private"),
    dests: problems.dests ?? serverAt("/allowed_destinations"),
    allowedPorts: problems.allowedPorts ?? serverAt("/allowed_ports"),
    ports: problems.ports ?? server.get("/blocked_ports") ?? null,
    lists: problems.lists ?? serverAt("/blocklists"),
    ban: problems.ban ?? serverAt("/auto_ban"),
  };
  const valid = Object.values(problems).every((e) => !e);
  // Text that does not parse leaves the parsed input as it was, yet it is an edit: saving then shows what is wrong.
  const unsaved =
    dirty || [problems.allow, problems.dests, problems.allowedPorts, problems.ports, problems.ban].some(Boolean);
  const show = (message: string | null) => (submitted || error ? message : null);
  const userIds = users.map((u) => u.spec.id);
  const forwards = forwardsOf(inbound.data, userIds);

  // The sections (and the name) holding a problem now, in the order of the tabs.
  const holding: (SectionKey | "name")[] = [
    ...(errors.name ? (["name"] as const) : []),
    ...(errors.allow ? (["allow"] as const) : []),
    ...(errors.dests || errors.allowedPorts ? (["firewall"] as const) : []),
    ...(errors.ports ? (["ports"] as const) : []),
    ...(errors.lists ? (["lists"] as const) : []),
    ...(errors.ban ? (["ban"] as const) : []),
  ];
  // Once a save was tried (or failed), each tab says how many of its parts hold a problem.
  const problemsIn = (t: SecurityTab) => (submitted || error ? holding.filter((k) => SECTION_TAB[k] === t).length : 0);

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (holding.length) {
      setClosed((c) => new Set([...c].filter((k) => !holding.includes(k))));
      // The problem is shown where it is: the first tab holding one, unless the open tab holds one too.
      const tabs = holding.map((k) => SECTION_TAB[k]);
      if (!tabs.includes(tab) && tabs[0]) setTab(tabs[0]);
    }
    if (!valid) return;
    const body = input();
    const before = JSON.parse(baseline ?? initial) as SecurityProfileInput;
    // Only a change to what the worker uses needs a restart; blocklists apply at once.
    const workerChanged = rev !== baselineRevision || workerInput.security(before) !== workerInput.security(body);
    const listsChanged = JSON.stringify(before.blocklists) !== JSON.stringify(body.blocklists);
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
            if (listsChanged && !workerChanged && users.some((u) => u.status?.running)) {
              toast.success(m.editor.saved(body.name), m.editor.listsSent);
            } else {
              announceSaved({
                title: m.editor.saved(body.name),
                kind: "security",
                id: r.data.id,
                revision: r.data.revision,
                workerChanged,
              });
            }
          } else {
            toast.success(m.editor.created(body.name));
            allowNextNavigation();
            void navigate(`/security/${r.data.id}`, { replace: true });
          }
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
          setErrorInput(JSON.stringify(body));
        },
      },
    );
  };

  const latest = async (apply: boolean) => {
    if (!profile) return;
    try {
      const p = await apiGet<SecurityProfile>(`/v1/security-profiles/${profile.id}`);
      setRevision(p.revision);
      if (apply) {
        setBaselineRevision(p.revision);
        setName(p.name);
        setAllow(p.allow_private.join("\n"));
        setPorts(p.blocked_ports.join(", "));
        setDests(p.allowed_destinations.join("\n"));
        setAllowedPorts(formatPortRanges(p.allowed_ports));
        setSelectedLists(p.blocklists);
        setBanOn(p.auto_ban.enabled);
        setBan(autoBanFields(p.auto_ban));
        setBaseline(JSON.stringify(inputOf(p)));
        setError(null);
      } else submit(p.revision);
    } catch (e) {
      setError(e);
    }
  };

  const actions = useSecurityActions(profile, users.length, {
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
  const pending = profile ? pendingUsers(users, "security", profile.id) : [];
  // The conclusion leads every tab: a save that failed (with its way out) and the connections still on an older version.
  const restartUsers = profile ? <RestartUsers views={users} kind="security" id={profile.id} /> : null;
  const lead =
    error || (profile && pending.length) ? (
      <>
        <FormFailure error={error} onReload={() => void latest(true)} onOverwrite={() => void latest(false)} />
        {restartUsers}
      </>
    ) : null;

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
        tabbed
        header={
          <EntityHeader
            icon={Shield}
            tone="entity"
            title={profile ? profile.name : m.newProfile}
            status={
              profile ? (
                <TitleActions actions={actions} menuLabel={ui.action.menuOf(profile.name)}>
                  <Tag tone={users.length ? "brand" : "neutral"}>{m.usedBy(users.length)}</Tag>
                </TitleActions>
              ) : null
            }
            description={profile ? summaryFacts(profile).join(" · ") : m.editor.description}
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
                    m.editor.appliesWhen
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
        <InspectorTabs
          label={profile ? m.editor.views(profile.name) : m.editor.newViews}
          value={tab}
          onChange={setTab}
          items={SECURITY_TABS.map((t) => {
            const n = problemsIn(t);
            return {
              value: t,
              label: SECURITY_TAB_LABEL[t],
              badge: n ? <TabCount value={n} tone="danger" label={m.editor.problems(n)} /> : undefined,
            };
          })}
        >
          <InspectorTab value="overview" lead={lead}>
            <div className="grid grid-cols-1 gap-3 border-b border-line-subtle px-4 py-3.5">
              {!profile ? (
                <Callout tone="info" title={m.editor.defaultsTitle}>
                  {m.editor.defaultsBody}
                </Callout>
              ) : null}
              <Field label={ui.common.name} required error={show(errors.name)}>
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
            {profile ? (
              <PropertySection title={m.users.title} icon={<ShieldCheck aria-hidden />} count={users.length}>
                {users.length ? (
                  <PresenceList
                    items={users}
                    keyOf={(v) => v.spec.id}
                    className="grid grid-cols-1 gap-1.5"
                    label={m.users.label}
                  >
                    {(v) => (
                      <div className="grid grid-cols-1 gap-0.5">
                        <div className="flex min-h-7 flex-wrap items-center gap-x-2 gap-y-1">
                          <Link
                            to={`/instances/${v.spec.id}`}
                            className={cn(TEXT_LINK, "min-w-0 text-data [overflow-wrap:anywhere]")}
                          >
                            {v.spec.name}
                          </Link>
                          <StatusPill look={instanceLook(v)} />
                          {pending.includes(v) ? <Tag tone="warning">{m.users.afterRestart}</Tag> : null}
                        </div>
                        <ConnectionState v={v} />
                      </div>
                    )}
                  </PresenceList>
                ) : (
                  <p className="text-data text-fg-tertiary">{m.users.none}</p>
                )}
              </PropertySection>
            ) : null}
          </InspectorTab>

          <InspectorTab value="destinations" lead={lead}>
            <PropertySection
              title={m.allow.title}
              icon={<Network aria-hidden />}
              count={allowParsed.nets.length}
              {...section("allow")}
            >
              <Field label={m.allow.label} hint={m.allow.hint} error={show(errors.allow)}>
                {({ id, describedBy, invalid }) => (
                  <Textarea
                    id={id}
                    mono
                    rows={4}
                    spellCheck={false}
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    placeholder={"10.99.0.0/24\nfd99::/64"}
                    value={allow}
                    onChange={(e) => {
                      setAllow(e.target.value);
                    }}
                  />
                )}
              </Field>
            </PropertySection>

            <PropertySection
              title={m.firewall.title}
              icon={<Route aria-hidden />}
              count={destParsed.nets.length + allowedPortsParsed.ranges.length}
              {...section("firewall")}
            >
              <div className="grid grid-cols-1 gap-4">
                <p className="text-data text-fg-tertiary">{m.firewall.note}</p>
                <Field
                  label={m.firewall.destinations}
                  hint={m.firewall.destinationsHint}
                  warning={destPrivate.length ? m.firewall.privateWarning(destPrivate) : null}
                  error={show(errors.dests)}
                >
                  {({ id, describedBy, invalid }) => (
                    <Textarea
                      id={id}
                      mono
                      rows={3}
                      spellCheck={false}
                      aria-describedby={describedBy}
                      aria-invalid={invalid}
                      placeholder={m.firewall.destinationsPlaceholder}
                      value={dests}
                      onChange={(e) => {
                        setDests(e.target.value);
                      }}
                    />
                  )}
                </Field>
                <Field label={m.firewall.ports} hint={m.firewall.portsHint} error={show(errors.allowedPorts)}>
                  {({ id, describedBy, invalid }) => (
                    <Input
                      id={id}
                      mono
                      aria-describedby={describedBy}
                      aria-invalid={invalid}
                      placeholder={m.firewall.portsPlaceholder}
                      value={allowedPorts}
                      onChange={(e) => {
                        setAllowedPorts(e.target.value);
                      }}
                    />
                  )}
                </Field>
              </div>
            </PropertySection>

            <PropertySection
              title={m.ports.title}
              icon={<Ban aria-hidden />}
              count={parsed.ports.length}
              {...section("ports")}
            >
              <div className="grid grid-cols-1 gap-3">
                <Field label={m.ports.field} hint={m.ports.hint} error={show(errors.ports)}>
                  {({ id, describedBy, invalid }) => (
                    <Input
                      id={id}
                      mono
                      aria-describedby={describedBy}
                      aria-invalid={invalid}
                      placeholder="25, 465, 587"
                      value={ports}
                      onChange={(e) => {
                        setPorts(e.target.value);
                      }}
                    />
                  )}
                </Field>
                <div className="flex flex-wrap gap-2">
                  {PORT_PRESETS.map((p) => (
                    <ActionButton
                      key={p.label}
                      size="sm"
                      variant="quiet"
                      icon={Plus}
                      disabledReason={p.ports.every((n) => parsed.ports.includes(n)) ? m.ports.allListed : null}
                      onClick={() => {
                        setPorts(parsePorts(`${ports} ${p.ports.join(" ")}`).ports.join(", "));
                      }}
                    >
                      {p.label}
                    </ActionButton>
                  ))}
                </div>
              </div>
            </PropertySection>
          </InspectorTab>

          <InspectorTab value="blocking" lead={lead}>
            <PropertySection
              title={shell.nav.blocklists.label}
              icon={<ListX aria-hidden />}
              count={selectedLists.length}
              actions={
                <SectionLink to="/security/blocklists" icon={ListX}>
                  {m.manageLists}
                </SectionLink>
              }
              {...section("lists")}
            >
              <BlocklistPicker
                lists={lists}
                selected={selectedLists}
                onChange={setSelectedLists}
                error={show(errors.lists) ?? (listBytes > OVERLAY_LIMIT ? errors.lists : null)}
              />
            </PropertySection>

            <PropertySection
              title={m.autoBan.title}
              icon={<ShieldBan aria-hidden />}
              actions={
                <SectionLink to="/security/bans" icon={ShieldBan}>
                  {m.autoBan.log}
                </SectionLink>
              }
              {...section("ban")}
            >
              <div className="grid grid-cols-1 gap-3">
                <Switch
                  checked={banOn}
                  onCheckedChange={setBanOn}
                  label={m.autoBan.switchLabel}
                  description={m.autoBan.switchHint}
                />
                {banOn ? (
                  forwards === null ? (
                    inbound.isError ? (
                      <Callout tone="warning" title={m.autoBan.forwardsUnknown} />
                    ) : null
                  ) : !users.length ? (
                    <Callout tone="info" title={m.autoBan.unused}>
                      {m.autoBan.unusedBody}
                    </Callout>
                  ) : forwards.total === 0 ? (
                    <Callout tone="warning" title={m.autoBan.noForwards}>
                      {m.autoBan.noForwardsBody(
                        <Link to="/forwards" className={TEXT_LINK}>
                          {m.autoBan.createForward}
                        </Link>,
                      )}
                    </Callout>
                  ) : (
                    <p className="text-data text-fg-tertiary">{m.autoBan.forwards(forwards.total, forwards.enabled)}</p>
                  )
                ) : null}
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  {(Object.keys(AUTO_BAN_BOUNDS) as (keyof typeof AUTO_BAN_BOUNDS)[]).map((k) => {
                    const b = AUTO_BAN_BOUNDS[k];
                    return (
                      <Field key={k} label={m.autoBan.field(b.label, b.unit)} error={show(banErrors[k])}>
                        {({ id, describedBy, invalid }) => (
                          <Input
                            id={id}
                            mono
                            inputMode="numeric"
                            aria-describedby={describedBy}
                            aria-invalid={invalid}
                            value={ban[k]}
                            onChange={(e) => {
                              setBan((cur) => ({ ...cur, [k]: e.target.value }));
                            }}
                          />
                        )}
                      </Field>
                    );
                  })}
                </div>
                <p className="text-caption text-fg-tertiary">
                  {m.autoBan.summary(
                    banOn,
                    formatCount(ban.window_secs),
                    formatCount(ban.threshold),
                    formatCount(ban.ban_secs),
                    formatCount(ban.max_bans),
                  )}
                </p>
              </div>
            </PropertySection>
          </InspectorTab>
        </InspectorTabs>
      </InspectorFrame>
      <UnsavedGuard dirty={unsaved} />
    </form>
  );
}

/** A list row: the profile, a summary of its rules and users, and the same ⋯ menu as its editor. */
function SecurityRow({ p, users, selected }: { p: SecurityProfile; users: number; selected: boolean }) {
  const actions = useSecurityActions(p, users);
  return (
    <ListItem
      to={`/security/${p.id}`}
      selected={selected}
      title={p.name}
      meta={<FactLine items={users ? [...summaryFacts(p), m.connections(users)] : summaryFacts(p)} />}
      actions={
        <ActionMenu
          actions={actions}
          label={ui.action.menuOf(p.name)}
          triggerLabel={ui.action.moreOf(p.name)}
          size="sm"
        />
      }
    />
  );
}

export function SecurityPage() {
  const { id } = useParams();
  const security = useSecurityProfiles();
  const instances = useInstances();
  const lists = useBlocklists();
  const all = useMemo(() => security.data ?? [], [security.data]);
  const selected = id && id !== "new" ? all.find((p) => p.id === id) : undefined;
  useCrumb(id === "new" ? m.newProfile : selected?.name);
  const users = useMemo(() => {
    const m = new Map<string, InstanceView[]>();
    for (const v of instances.data ?? []) {
      const s = v.spec.security_profile_id;
      if (s) m.set(s, [...(m.get(s) ?? []), v]);
    }
    return m;
  }, [instances.data]);

  const create = (
    <ButtonLink to="/security/new" variant="primary" icon={Plus}>
      {m.add}
    </ButtonLink>
  );

  let detail: ReactNode;
  // A new profile starts with the built-in lists selected: wait for the lists (a failure to load
  // them starts it without, as the picker then says).
  if (id === "new")
    detail = lists.isPending ? (
      <LoadingRows rows={4} label={m.loadingLists} />
    ) : (
      <SecurityEditor key="new" profile={null} users={[]} defaults={defaultLists(lists.data ?? [])} />
    );
  else if (selected)
    detail = <SecurityEditor key={selected.id} profile={selected} users={users.get(selected.id) ?? []} />;
  else if (security.isPending) detail = <LoadingRows rows={3} label={m.loading} />;
  else if (security.isError && !security.data)
    detail = (
      <ErrorState error={security.error} onRetry={() => void security.refetch()} retrying={security.isFetching} />
    );
  else if (id)
    detail = (
      <EmptyState icon={Shield} title={m.notFound}>
        {ui.common.mayHaveBeenDeleted}
      </EmptyState>
    );
  // The only one opens by itself; with several the user picks one.
  else if (all.length === 1 && all[0]) detail = <Navigate replace to={`/security/${all[0].id}`} />;
  else if (all.length)
    detail = (
      <EmptyState icon={Shield} title={m.pick}>
        {m.pickBody}
      </EmptyState>
    );
  else
    detail = (
      <EmptyState brand icon={Shield} title={m.none} actions={create}>
        {m.noneBody}
      </EmptyState>
    );

  let list: ReactNode;
  if (security.isPending) list = <LoadingRows rows={3} label={m.loading} />;
  else if (security.isError && !security.data)
    list = (
      <ErrorState
        compact
        error={security.error}
        onRetry={() => void security.refetch()}
        retrying={security.isFetching}
      />
    );
  else
    list = (
      <>
        {security.isError ? (
          // Stale: the last list stays, marked, with a retry.
          <div className="shrink-0 border-b border-line-subtle p-2">
            <ErrorCallout
              error={security.error}
              title={m.stale(new Date(security.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void security.refetch()}
              retrying={security.isFetching}
            />
          </div>
        ) : null}
        {all.length ? (
          <MasterList label={shell.nav.security.label}>
            <PresenceList
              items={all}
              keyOf={(p) => p.id}
              className="grid grid-cols-1 gap-0.5"
              label={shell.nav.security.label}
            >
              {(p) => <SecurityRow p={p} users={users.get(p.id)?.length ?? 0} selected={p.id === id} />}
            </PresenceList>
          </MasterList>
        ) : (
          <EmptyState compact icon={Shield} title={m.none}>
            {m.noneShort}
          </EmptyState>
        )}
      </>
    );

  return (
    <Page>
      <SecurityActionHost profiles={all}>
        <PageHeader
          title={shell.nav.security.label}
          description={m.description}
          help={m.help}
          helpText={m.helpText}
          actions={create}
        />
        <MasterDetail
          listLabel={m.listLabel}
          detailLabel={selected ? m.settingsOf(selected.name) : m.detail}
          backLabel={m.all}
          list={list}
          detail={detail}
        />
      </SecurityActionHost>
    </Page>
  );
}
