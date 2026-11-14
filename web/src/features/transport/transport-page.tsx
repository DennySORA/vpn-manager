// 傳輸設定 (/transport, /transport/:id, /transport/new[?from=…]): the profiles a connection's flows and health probes
// follow — the ones that are part of the program (read only; a copy is the way to change one) and the saved ones —
// beside the detail of one (MasterDetail), following the page recipe of docs/frontend-design.md §8.1. A saved
// profile's editor is an inspector: the EntityHeader (name, usage, ID, the ⋯ menu — the same menu as the list row),
// collapsible sections, and the fixed footer with the one primary action, 儲存. Nothing here waits for a restart: a
// running connection applies a saved profile to the flows it opens from then on.
import { HeartPulse, Layers, Network, Plus, Route, SlidersHorizontal, Workflow, X } from "lucide-react";
import { type ReactNode, useId, useMemo, useState } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router";
import { apiGet } from "@/api/client";
import { useBuiltinTransports, useInstances, useSaveTransportProfile, useTransportProfiles } from "@/api/queries";
import type {
  CongestionControl,
  FlowSettings,
  HealthSettings,
  InstanceView,
  TransportProfile,
  TransportProfileInput,
} from "@/api/types";
import { useCrumb } from "@/components/shell/nav";
import { ListItem, MasterDetail, MasterList, MasterListHeading, Page, PageHeader } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ButtonLink } from "@/components/ui/button";
import { ActionMenu, FooterActions, TitleActions } from "@/components/ui/entity-actions";
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
import { CARD, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Segmented } from "@/components/ui/segmented";
import { EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { toast } from "@/components/ui/toast";
import { ToolButton } from "@/components/ui/tool-strip";
import { instanceLook } from "@/features/instances/model";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { parseIntField, serverFieldErrors } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { allowNextNavigation, UnsavedGuard } from "@/components/unsaved";
import { useQueryParam } from "@/lib/url";
import { TransportActionHost, useTransportActions } from "./action-host";
import { m } from "./messages";
import {
  AUTO_KEY,
  BALANCED_FLOW,
  BOUNDS,
  brief,
  bufferText,
  ceilingMbps,
  type Choice,
  CONGESTION_LABEL,
  choices,
  DEFAULT_HEALTH,
  findChoice,
  rangeBrief,
  refName,
  refValue,
  sizeText,
} from "./model";

/** The round trip the speed a buffer allows is quoted for. */
const QUOTE_RTT_MS = 100;

/** A grid of number fields: as many columns as the inspector's width holds (each at least 11rem). */
const NUMBER_GRID = "grid grid-cols-[repeat(auto-fit,minmax(11rem,1fr))] gap-x-4 gap-y-3";

function UsersSection({ users }: { users: InstanceView[] }) {
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
              {v.status?.running?.transport?.automatic ? (
                <Tag tone="neutral">{m.users.range(localized(v.status.running.transport.band))}</Tag>
              ) : null}
            </div>
          )}
        </PresenceList>
      ) : (
        <p className="text-data text-fg-tertiary">{m.users.none}</p>
      )}
    </PropertySection>
  );
}

/** What a buffer of this size allows one connection at the quoted round trip. */
function ceilingNote(f: Pick<FlowSettings, "tcp_send_kib" | "tcp_recv_kib">): string {
  return m.values.ceiling(
    QUOTE_RTT_MS,
    ceilingMbps(f.tcp_send_kib, QUOTE_RTT_MS),
    ceilingMbps(f.tcp_recv_kib, QUOTE_RTT_MS),
  );
}

function healthRows(h: HealthSettings): ReactNode {
  return (
    <PropertyGrid>
      <PropertyRow label={m.values.probeInterval} mono>
        {m.values.secs(h.probe_interval_secs)}
      </PropertyRow>
      <PropertyRow label={m.values.failures} mono hint={m.values.failuresMeaning}>
        {m.values.failureCount(h.probe_failures)}
      </PropertyRow>
      <PropertyRow label={m.values.handshakeTimeout} mono hint={m.values.handshakeMeaning}>
        {m.values.secs(h.handshake_timeout_secs)}
      </PropertyRow>
    </PropertyGrid>
  );
}

/** A built-in profile: its values, read only, and the one action — a copy to change. */
function BuiltinDetail({ c, all, users }: { c: Choice; all: Choice[]; users: InstanceView[] }) {
  const actions = useTransportActions(c, { users: users.length, namedBy: [] });
  const flow = c.settings.mode === "fixed" ? c.settings.flow : null;
  return (
    <InspectorFrame
      header={
        <EntityHeader
          icon={SlidersHorizontal}
          tone="entity"
          title={c.name}
          status={
            <span className="flex flex-wrap items-center justify-end gap-1.5">
              <Tag tone="neutral">{ui.common.builtIn}</Tag>
              <Tag tone={users.length ? "brand" : "neutral"}>{m.usedBy(users.length)}</Tag>
            </span>
          }
          description={c.summary}
        />
      }
      footer={
        <InspectorFooter note={m.builtIn.note}>
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      {c.settings.mode === "auto" ? (
        <PropertySection title={m.values.byRoundTrip} icon={<Route aria-hidden />} count={c.settings.bands.length}>
          <div className="grid grid-cols-1 gap-3">
            <p className="text-data text-fg-tertiary">{m.values.measuring}</p>
            <PropertyGrid>
              {c.settings.bands.map((b) => {
                const used = findChoice(all, b.profile);
                return (
                  <PropertyRow
                    key={b.from_rtt_ms}
                    label={m.values.fromRoundTrip(b.from_rtt_ms)}
                    hint={used ? rangeBrief(used, all) : undefined}
                  >
                    {used ? (
                      <Link to={`/transport/${used.value}`} className={TEXT_LINK}>
                        {used.name}
                      </Link>
                    ) : (
                      refName(all, b.profile)
                    )}
                  </PropertyRow>
                );
              })}
            </PropertyGrid>
          </div>
        </PropertySection>
      ) : null}
      {flow ? (
        <>
          <PropertySection title={m.values.tcpBuffers} icon={<Layers aria-hidden />}>
            <div className="grid grid-cols-1 gap-2">
              <PropertyGrid>
                <PropertyRow label={m.values.send} mono>
                  {bufferText(flow.tcp_send_start_kib, flow.tcp_send_kib)}
                </PropertyRow>
                <PropertyRow label={m.values.receive} mono>
                  {bufferText(flow.tcp_recv_start_kib, flow.tcp_recv_kib)}
                </PropertyRow>
              </PropertyGrid>
              <p className="text-caption text-fg-tertiary">{ceilingNote(flow)}</p>
            </div>
          </PropertySection>
          <PropertySection title={m.values.tcpBehavior} icon={<Workflow aria-hidden />}>
            <PropertyGrid>
              <PropertyRow label={m.values.congestion}>{CONGESTION_LABEL[flow.congestion]}</PropertyRow>
              <PropertyRow label="Nagle">{flow.nagle ? m.values.on : m.values.off}</PropertyRow>
              <PropertyRow label={m.values.delayedAck} mono>
                {flow.ack_delay_ms ? m.values.ms(flow.ack_delay_ms) : m.values.off}
              </PropertyRow>
              <PropertyRow label={m.values.connectTimeout} mono>
                {m.values.secs(flow.connect_timeout_secs)}
              </PropertyRow>
              <PropertyRow label={m.values.keepalive} mono>
                {m.values.every(flow.keepalive_secs)}
              </PropertyRow>
              <PropertyRow label={m.values.deadPeer} mono>
                {m.values.secs(flow.dead_peer_secs)}
              </PropertyRow>
              <PropertyRow label={m.values.udpBuffer} mono hint={m.values.perDirection}>
                {sizeText(flow.udp_buffer_kib)}
              </PropertyRow>
            </PropertyGrid>
          </PropertySection>
        </>
      ) : null}
      <PropertySection title={m.values.health} icon={<HeartPulse aria-hidden />}>
        {healthRows(c.health)}
      </PropertySection>
      <UsersSection users={users} />
    </InspectorFrame>
  );
}

type Mode = "fixed" | "auto";

/** The numbers of a fixed profile as typed (a number that does not parse is an edit with a problem). */
interface FlowDraft {
  sendStart: string;
  send: string;
  recvStart: string;
  recv: string;
  congestion: CongestionControl;
  nagle: boolean;
  ackDelay: string;
  connect: string;
  keepalive: string;
  deadPeer: string;
  udp: string;
}

interface BandDraft {
  key: string;
  from: string;
  /** The `Choice.value` of the fixed profile the range uses; empty until one is chosen. */
  value: string;
}

interface HealthDraft {
  interval: string;
  failures: string;
  handshake: string;
}

function flowDraft(f: FlowSettings): FlowDraft {
  return {
    sendStart: String(f.tcp_send_start_kib),
    send: String(f.tcp_send_kib),
    recvStart: String(f.tcp_recv_start_kib),
    recv: String(f.tcp_recv_kib),
    congestion: f.congestion,
    nagle: f.nagle,
    ackDelay: String(f.ack_delay_ms),
    connect: String(f.connect_timeout_secs),
    keepalive: String(f.keepalive_secs),
    deadPeer: String(f.dead_peer_secs),
    udp: String(f.udp_buffer_kib),
  };
}

function healthDraft(h: HealthSettings): HealthDraft {
  return {
    interval: String(h.probe_interval_secs),
    failures: String(h.probe_failures),
    handshake: String(h.handshake_timeout_secs),
  };
}

let bandSeq = 0;
function bandDraft(from: number, value: string): BandDraft {
  bandSeq += 1;
  return { key: `b${bandSeq}`, from: String(from), value };
}

/** "16–16384" when `v` is not a whole number within `[min, max]`. */
function outOf(v: string, [min, max]: readonly [number, number]): string | null {
  const n = parseIntField(v);
  return n === null || n < min || n > max ? m.editor.errors.wholeNumber(min, max) : null;
}

function NumberField({
  label,
  units,
  hint,
  value,
  onChange,
  error,
}: {
  label: string;
  units: string;
  hint?: string | undefined;
  value: string;
  onChange: (v: string) => void;
  error: string | null;
}) {
  return (
    <Field label={label} units={units} hint={hint} error={error}>
      {({ id, describedBy, invalid }) => (
        <Input
          id={id}
          mono
          inputMode="numeric"
          aria-describedby={describedBy}
          aria-invalid={invalid}
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
          }}
        />
      )}
    </Field>
  );
}

/** What a new profile starts from: a copy of `seed`, or the values every connection had before profiles existed. */
function startingPoint(seed: Choice | null): Pick<Choice, "name" | "health" | "settings"> {
  if (!seed) return { name: "", health: DEFAULT_HEALTH, settings: { mode: "fixed", flow: BALANCED_FLOW } };
  return { name: m.editor.copyName(seed.name), health: seed.health, settings: seed.settings };
}

function TransportEditor({
  profile,
  seed,
  all,
  users,
  namedBy,
}: {
  profile: TransportProfile | null;
  /** A new profile starts as a copy of this one. */
  seed: Choice | null;
  all: Choice[];
  users: InstanceView[];
  namedBy: string[];
}) {
  const save = useSaveTransportProfile();
  const intent = useIntentKey(`transport.save:${profile?.id ?? "new"}`);
  const blocked = useMutationBlocked();
  const navigate = useNavigate();
  const formId = useId();
  const base = profile ?? startingPoint(seed);
  const [name, setName] = useState(base.name);
  const [mode, setMode] = useState<Mode>(base.settings.mode);
  const [flow, setFlow] = useState<FlowDraft>(() =>
    flowDraft(base.settings.mode === "fixed" ? base.settings.flow : BALANCED_FLOW),
  );
  const [bands, setBands] = useState<BandDraft[]>(() =>
    base.settings.mode === "auto"
      ? base.settings.bands.map((b) => bandDraft(b.from_rtt_ms, refValue(b.profile)))
      : [bandDraft(0, "balanced"), bandDraft(40, "long_haul"), bandDraft(150, "ultra_long")],
  );
  const [health, setHealth] = useState<HealthDraft>(() => healthDraft(base.health));
  const [revision, setRevision] = useState(profile?.revision);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [baseline, setBaseline] = useState<string | null>(null);

  // What a range may use: every fixed profile but this one.
  const fixedChoices = all.filter((c) => c.settings.mode === "fixed" && c.value !== profile?.id);
  const num = (v: string, fallback: number) => parseIntField(v) ?? fallback;
  const input = (): TransportProfileInput => ({
    name: name.trim(),
    health: {
      probe_interval_secs: num(health.interval, DEFAULT_HEALTH.probe_interval_secs),
      probe_failures: num(health.failures, DEFAULT_HEALTH.probe_failures),
      handshake_timeout_secs: num(health.handshake, DEFAULT_HEALTH.handshake_timeout_secs),
    },
    settings:
      mode === "fixed"
        ? {
            mode: "fixed",
            flow: {
              tcp_recv_kib: num(flow.recv, BALANCED_FLOW.tcp_recv_kib),
              tcp_recv_start_kib: num(flow.recvStart, BALANCED_FLOW.tcp_recv_start_kib),
              tcp_send_kib: num(flow.send, BALANCED_FLOW.tcp_send_kib),
              tcp_send_start_kib: num(flow.sendStart, BALANCED_FLOW.tcp_send_start_kib),
              congestion: flow.congestion,
              nagle: flow.nagle,
              ack_delay_ms: num(flow.ackDelay, BALANCED_FLOW.ack_delay_ms),
              connect_timeout_secs: num(flow.connect, BALANCED_FLOW.connect_timeout_secs),
              keepalive_secs: num(flow.keepalive, BALANCED_FLOW.keepalive_secs),
              dead_peer_secs: num(flow.deadPeer, BALANCED_FLOW.dead_peer_secs),
              udp_buffer_kib: num(flow.udp, BALANCED_FLOW.udp_buffer_kib),
            },
          }
        : {
            mode: "auto",
            bands: bands.flatMap((b) => {
              const used = fixedChoices.find((c) => c.value === b.value);
              return used ? [{ from_rtt_ms: num(b.from, 0), profile: used.ref }] : [];
            }),
          },
  });
  // Changed compares against what was last loaded or saved (a fresh editor starts from its first render).
  const current = JSON.stringify(input());
  const [initial] = useState(current);
  const changed = current !== (baseline ?? initial);

  const server = serverFieldErrors(error);
  const at = (path: string, client: string | null) => client ?? server.get(path) ?? null;
  const flowErrors = {
    sendStart:
      outOf(flow.sendStart, BOUNDS.tcpKib) ??
      (num(flow.sendStart, 0) > num(flow.send, 0) ? m.editor.errors.startAboveLimit : null),
    send: outOf(flow.send, BOUNDS.tcpKib),
    recvStart:
      outOf(flow.recvStart, BOUNDS.tcpKib) ??
      (num(flow.recvStart, 0) > num(flow.recv, 0) ? m.editor.errors.startAboveLimit : null),
    recv: outOf(flow.recv, BOUNDS.tcpKib),
    ackDelay: outOf(flow.ackDelay, BOUNDS.ackDelayMs),
    connect: outOf(flow.connect, BOUNDS.connectSecs),
    keepalive: outOf(flow.keepalive, BOUNDS.keepaliveSecs),
    deadPeer:
      outOf(flow.deadPeer, BOUNDS.deadPeerSecs) ??
      (num(flow.deadPeer, 0) < num(flow.keepalive, 0) * 2 ? m.editor.errors.deadPeerTooShort : null),
    udp: outOf(flow.udp, BOUNDS.udpKib),
  };
  const healthErrors = {
    interval: outOf(health.interval, BOUNDS.probeIntervalSecs),
    failures: outOf(health.failures, BOUNDS.probeFailures),
    handshake: outOf(health.handshake, BOUNDS.handshakeSecs),
  };
  const bandError = (b: BandDraft, i: number): string | null => {
    const from = parseIntField(b.from);
    if (from === null || from < BOUNDS.rttMs[0] || from > BOUNDS.rttMs[1])
      return m.editor.errors.rangeStart(BOUNDS.rttMs[0], BOUNDS.rttMs[1]);
    if (i === 0 && from !== 0) return m.editor.errors.firstRange;
    const previous = bands[i - 1];
    if (previous && from <= num(previous.from, -1)) return m.editor.errors.rangeOrder;
    if (!fixedChoices.some((c) => c.value === b.value)) return m.editor.errors.rangeProfile;
    return null;
  };
  const nameError = !name.trim() ? ui.common.enterName : (server.get("/name") ?? null);
  const flowValid = mode !== "fixed" || Object.values(flowErrors).every((e) => e === null);
  const bandsValid = mode !== "auto" || (bands.length >= 1 && bands.every((b, i) => bandError(b, i) === null));
  const healthValid = Object.values(healthErrors).every((e) => e === null);
  const valid = Boolean(name.trim()) && flowValid && bandsValid && healthValid;
  // A number that does not parse is never replaced by the saved value silently: it is an edit with a problem.
  const unsaved = changed || !(flowValid && bandsValid && healthValid);
  const show = (message: string | null) => (submitted || error ? message : null);
  const [mainOpen, setMainOpen] = useState(true);
  const [behaviourOpen, setBehaviourOpen] = useState(true);
  const [healthOpen, setHealthOpen] = useState(true);

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (!flowValid || !bandsValid) {
      setMainOpen(true);
      setBehaviourOpen(true);
    }
    if (!healthValid) setHealthOpen(true);
    if (!valid) return;
    const body = input();
    setError(null);
    save.mutate(
      { id: profile?.id, revision: rev, input: body, key: intent.next({ id: profile?.id, rev, body }) },
      {
        onSuccess: (r) => {
          intent.settle();
          setRevision(r.data.revision);
          setBaseline(JSON.stringify(body));
          if (profile) {
            toast.success(users.length ? m.editor.savedInUse(body.name) : m.editor.saved(body.name));
          } else {
            toast.success(m.editor.created(body.name));
            allowNextNavigation();
            void navigate(`/transport/${r.data.id}`, { replace: true });
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
      const p = await apiGet<TransportProfile>(`/v1/transport-profiles/${profile.id}`);
      setRevision(p.revision);
      if (!apply) {
        submit(p.revision);
        return;
      }
      setName(p.name);
      setMode(p.settings.mode);
      if (p.settings.mode === "fixed") setFlow(flowDraft(p.settings.flow));
      else setBands(p.settings.bands.map((b) => bandDraft(b.from_rtt_ms, refValue(b.profile))));
      setHealth(healthDraft(p.health));
      // The same shape and order as `input()` builds.
      const loaded: TransportProfileInput = { name: p.name, health: p.health, settings: p.settings };
      setBaseline(JSON.stringify(loaded));
      setError(null);
    } catch (e) {
      setError(e);
    }
  };

  const choice = profile ? (all.find((c) => c.value === profile.id && !c.builtin) ?? null) : null;
  const actions = useTransportActions(
    choice,
    { users: users.length, namedBy },
    {
      dirty: unsaved,
      own: {
        save: {
          run: () => {
            submit();
          },
          pending: save.isPending,
        },
      },
    },
  );
  const setFlowField = (patch: Partial<FlowDraft>) => {
    setFlow((f) => ({ ...f, ...patch }));
  };
  const full = bands.length >= BOUNDS.bands[1];
  const quoted = { tcp_send_kib: num(flow.send, 0), tcp_recv_kib: num(flow.recv, 0) };

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
            icon={SlidersHorizontal}
            tone="entity"
            title={profile ? profile.name : seed ? m.editor.duplicating(seed.name) : m.newProfile}
            status={
              profile ? (
                <TitleActions actions={actions} menuLabel={m.actionsOf(profile.name)}>
                  <Tag tone={users.length ? "brand" : "neutral"}>{m.usedBy(users.length)}</Tag>
                </TitleActions>
              ) : null
            }
            description={choice ? brief(choice, all) : m.editor.description}
            id={profile?.id}
            idLabel={m.editor.idLabel}
          />
        }
        footer={
          <InspectorFooter
            note={
              <span aria-live="polite">
                {profile && unsaved ? (
                  <span className="text-warning">{ui.common.unsavedChanges}</span>
                ) : profile ? (
                  users.length ? (
                    m.editor.appliesAtOnce
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
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <Segmented
              label={m.editor.kind}
              value={mode}
              onChange={setMode}
              options={[
                { value: "fixed", label: m.editor.fixed, title: m.editor.fixedTitle },
                { value: "auto", label: m.editor.automatic, title: m.editor.automaticTitle },
              ]}
            />
            <p className="min-w-0 flex-1 basis-48 text-caption text-fg-tertiary">
              {mode === "fixed" ? m.editor.fixedNote : m.editor.automaticNote}
            </p>
          </div>
          {mode === "auto" && namedBy.length ? (
            <p role="alert" className="text-caption text-danger">
              {m.editor.mustStayFixed(namedBy)}
            </p>
          ) : null}
        </div>

        {mode === "fixed" ? (
          <>
            <PropertySection
              title={m.values.tcpBuffers}
              icon={<Layers aria-hidden />}
              open={mainOpen}
              onOpenChange={setMainOpen}
            >
              <div className="grid grid-cols-1 gap-3">
                <p className="text-data text-fg-tertiary">{m.editor.buffers}</p>
                <div className={NUMBER_GRID}>
                  <NumberField
                    label={m.editor.sendStart}
                    units="KiB"
                    value={flow.sendStart}
                    onChange={(v) => {
                      setFlowField({ sendStart: v });
                    }}
                    error={show(at("/settings/flow/tcp_send_start_kib", flowErrors.sendStart))}
                  />
                  <NumberField
                    label={m.editor.sendLimit}
                    units="KiB"
                    hint={m.editor.uploadDirection}
                    value={flow.send}
                    onChange={(v) => {
                      setFlowField({ send: v });
                    }}
                    error={show(at("/settings/flow/tcp_send_kib", flowErrors.send))}
                  />
                  <NumberField
                    label={m.editor.receiveStart}
                    units="KiB"
                    value={flow.recvStart}
                    onChange={(v) => {
                      setFlowField({ recvStart: v });
                    }}
                    error={show(at("/settings/flow/tcp_recv_start_kib", flowErrors.recvStart))}
                  />
                  <NumberField
                    label={m.editor.receiveLimit}
                    units="KiB"
                    hint={m.editor.downloadDirection}
                    value={flow.recv}
                    onChange={(v) => {
                      setFlowField({ recv: v });
                    }}
                    error={show(at("/settings/flow/tcp_recv_kib", flowErrors.recv))}
                  />
                </div>
                {flowErrors.send === null && flowErrors.recv === null ? (
                  <p className="text-caption text-fg-secondary">{ceilingNote(quoted)}</p>
                ) : null}
                <p className="text-caption text-fg-tertiary">{m.editor.strictIsolation}</p>
              </div>
            </PropertySection>

            <PropertySection
              title={m.editor.behavior}
              icon={<Workflow aria-hidden />}
              open={behaviourOpen}
              onOpenChange={setBehaviourOpen}
            >
              <div className="grid grid-cols-1 gap-3.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                  <span className="text-data font-medium text-fg-secondary">{m.values.congestion}</span>
                  <Segmented
                    size="sm"
                    label={m.values.congestion}
                    value={flow.congestion}
                    onChange={(congestion) => {
                      setFlowField({ congestion });
                    }}
                    options={[
                      { value: "cubic", label: "Cubic", title: m.editor.cubic },
                      { value: "reno", label: "Reno", title: m.editor.reno },
                      { value: "bbr", label: "BBR", title: m.editor.bbr },
                    ]}
                  />
                </div>
                <Switch
                  checked={flow.nagle}
                  onCheckedChange={(nagle) => {
                    setFlowField({ nagle });
                  }}
                  label={m.editor.nagle}
                  description={m.editor.nagleMeaning}
                />
                <div className={NUMBER_GRID}>
                  <NumberField
                    label={m.values.delayedAck}
                    units={m.editor.milliseconds}
                    hint={m.editor.delayedAckHint}
                    value={flow.ackDelay}
                    onChange={(v) => {
                      setFlowField({ ackDelay: v });
                    }}
                    error={show(at("/settings/flow/ack_delay_ms", flowErrors.ackDelay))}
                  />
                  <NumberField
                    label={m.values.connectTimeout}
                    units={ui.common.seconds}
                    hint={m.editor.connectTimeoutHint}
                    value={flow.connect}
                    onChange={(v) => {
                      setFlowField({ connect: v });
                    }}
                    error={show(at("/settings/flow/connect_timeout_secs", flowErrors.connect))}
                  />
                  <NumberField
                    label={m.editor.keepaliveInterval}
                    units={ui.common.seconds}
                    hint={m.editor.keepaliveHint}
                    value={flow.keepalive}
                    onChange={(v) => {
                      setFlowField({ keepalive: v });
                    }}
                    error={show(at("/settings/flow/keepalive_secs", flowErrors.keepalive))}
                  />
                  <NumberField
                    label={m.values.deadPeer}
                    units={ui.common.seconds}
                    hint={m.editor.deadPeerHint}
                    value={flow.deadPeer}
                    onChange={(v) => {
                      setFlowField({ deadPeer: v });
                    }}
                    error={show(at("/settings/flow/dead_peer_secs", flowErrors.deadPeer))}
                  />
                  <NumberField
                    label={m.values.udpBuffer}
                    units="KiB"
                    hint={m.editor.udpBufferHint}
                    value={flow.udp}
                    onChange={(v) => {
                      setFlowField({ udp: v });
                    }}
                    error={show(at("/settings/flow/udp_buffer_kib", flowErrors.udp))}
                  />
                </div>
              </div>
            </PropertySection>
          </>
        ) : (
          <PropertySection
            title={m.editor.ranges.title}
            icon={<Route aria-hidden />}
            count={bands.length}
            open={mainOpen}
            onOpenChange={setMainOpen}
          >
            <div className="grid grid-cols-1 gap-3">
              <p className="text-data text-fg-tertiary">{m.values.measuring}</p>
              <PresenceList
                as="ol"
                items={bands}
                keyOf={(b) => b.key}
                className="grid grid-cols-1 gap-2"
                label={m.editor.ranges.label}
              >
                {(b) => {
                  const i = bands.findIndex((x) => x.key === b.key);
                  const n = i + 1;
                  const err =
                    i < 0
                      ? null
                      : show(
                          bandError(b, i) ??
                            server.get(`/settings/bands/${i}/from_rtt_ms`) ??
                            server.get(`/settings/bands/${i}/profile`) ??
                            null,
                        );
                  return (
                    <div className={cn(CARD, "grid grid-cols-1 gap-2 p-3")}>
                      <div className="flex flex-wrap items-center gap-2">
                        <Input
                          mono
                          size="sm"
                          inputMode="numeric"
                          aria-label={m.editor.ranges.start(n)}
                          aria-invalid={Boolean(err)}
                          readOnly={i === 0}
                          value={b.from}
                          onChange={(e) => {
                            setBands((bs) => bs.map((x) => (x.key === b.key ? { ...x, from: e.target.value } : x)));
                          }}
                          className="w-20"
                        />
                        <span className="text-data text-fg-tertiary">{m.editor.ranges.thenUse}</span>
                        <Select
                          compact
                          aria-label={m.editor.ranges.profile(n)}
                          aria-invalid={Boolean(err)}
                          value={fixedChoices.some((c) => c.value === b.value) ? b.value : ""}
                          onChange={(e) => {
                            setBands((bs) => bs.map((x) => (x.key === b.key ? { ...x, value: e.target.value } : x)));
                          }}
                          className="min-w-40 flex-1"
                        >
                          <option value="">{m.editor.ranges.choose}</option>
                          <optgroup label={ui.common.builtIn}>
                            {fixedChoices
                              .filter((c) => c.builtin)
                              .map((c) => (
                                <option key={c.value} value={c.value}>
                                  {c.name}
                                </option>
                              ))}
                          </optgroup>
                          {fixedChoices.some((c) => !c.builtin) ? (
                            <optgroup label={m.list.mine}>
                              {fixedChoices
                                .filter((c) => !c.builtin)
                                .map((c) => (
                                  <option key={c.value} value={c.value}>
                                    {c.name}
                                  </option>
                                ))}
                            </optgroup>
                          ) : null}
                        </Select>
                        <ToolButton
                          label={m.editor.ranges.remove(n)}
                          icon={<X aria-hidden />}
                          disabledReason={
                            bands.length === 1 ? m.editor.ranges.lastOne : i === 0 ? m.editor.ranges.firstStays : null
                          }
                          onClick={() => {
                            setBands((bs) => bs.filter((x) => x.key !== b.key));
                          }}
                        />
                      </div>
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
                  disabledReason={full ? m.editor.ranges.atMost(BOUNDS.bands[1]) : null}
                  onClick={() => {
                    setBands((bs) => {
                      const last = bs[bs.length - 1];
                      const from = last ? num(last.from, 0) : 0;
                      return [...bs, bandDraft(from ? from * 2 : 50, "")];
                    });
                  }}
                >
                  {m.editor.ranges.add}
                </ActionButton>
              </div>
            </div>
          </PropertySection>
        )}

        <PropertySection
          title={m.values.health}
          icon={<HeartPulse aria-hidden />}
          open={healthOpen}
          onOpenChange={setHealthOpen}
        >
          <div className="grid grid-cols-1 gap-3">
            {mode === "auto" ? <p className="text-data text-fg-tertiary">{m.editor.healthOfAutomatic}</p> : null}
            <div className={NUMBER_GRID}>
              <NumberField
                label={m.values.probeInterval}
                units={ui.common.seconds}
                value={health.interval}
                onChange={(interval) => {
                  setHealth((h) => ({ ...h, interval }));
                }}
                error={show(at("/health/probe_interval_secs", healthErrors.interval))}
              />
              <NumberField
                label={m.values.failures}
                units={m.editor.failuresUnit}
                hint={m.editor.failuresHint}
                value={health.failures}
                onChange={(failures) => {
                  setHealth((h) => ({ ...h, failures }));
                }}
                error={show(at("/health/probe_failures", healthErrors.failures))}
              />
              <NumberField
                label={m.values.handshakeTimeout}
                units={ui.common.seconds}
                hint={m.editor.handshakeHint}
                value={health.handshake}
                onChange={(handshake) => {
                  setHealth((h) => ({ ...h, handshake }));
                }}
                error={show(at("/health/handshake_timeout_secs", healthErrors.handshake))}
              />
            </div>
          </div>
        </PropertySection>

        {profile ? <UsersSection users={users} /> : null}
      </InspectorFrame>
      <UnsavedGuard dirty={unsaved} />
    </form>
  );
}

/** A list row: the profile, what it holds and who uses it; a saved one has the same ⋯ menu as its editor. */
function TransportRow({
  c,
  all,
  users,
  namedBy,
  selected,
}: {
  c: Choice;
  all: Choice[];
  users: number;
  namedBy: string[];
  selected: boolean;
}) {
  const actions = useTransportActions(c, { users, namedBy });
  return (
    <ListItem
      to={`/transport/${c.value}`}
      selected={selected}
      title={c.name}
      meta={m.list.meta(brief(c, all), users)}
      actions={
        c.builtin ? undefined : (
          <ActionMenu actions={actions} label={m.actionsOf(c.name)} triggerLabel={m.moreActionsOf(c.name)} size="sm" />
        )
      }
    />
  );
}

export function TransportPage() {
  const { id } = useParams();
  const [from] = useQueryParam("from");
  const builtin = useBuiltinTransports();
  const saved = useTransportProfiles();
  const instances = useInstances();
  const profiles = useMemo(() => saved.data ?? [], [saved.data]);
  const all = useMemo(() => choices(builtin.data ?? [], profiles), [builtin.data, profiles]);
  const views = useMemo(() => instances.data ?? [], [instances.data]);
  const selected = id && id !== "new" ? all.find((c) => c.value === id) : undefined;
  useCrumb(id === "new" ? m.newProfile : selected?.name);
  // Who uses each profile: the connections, and the automatic profiles a range of which names it.
  const users = useMemo(() => {
    const byProfile = new Map<string, InstanceView[]>();
    for (const v of views) {
      const key = refValue(v.spec.transport);
      byProfile.set(key, [...(byProfile.get(key) ?? []), v]);
    }
    return byProfile;
  }, [views]);
  const namedBy = useMemo(() => {
    const byProfile = new Map<string, string[]>();
    for (const p of profiles) {
      if (p.settings.mode !== "auto") continue;
      for (const b of p.settings.bands) {
        if (b.profile.kind !== "profile") continue;
        byProfile.set(b.profile.id, [...new Set([...(byProfile.get(b.profile.id) ?? []), p.name])]);
      }
    }
    return byProfile;
  }, [profiles]);

  const create = (
    <ButtonLink to="/transport/new" variant="primary" icon={Plus}>
      {m.add}
    </ButtonLink>
  );
  const pending = builtin.isPending || saved.isPending;
  const failed = builtin.isError && !builtin.data ? builtin : saved.isError && !saved.data ? saved : null;

  let detail: ReactNode;
  if (pending) detail = <LoadingRows rows={3} label={m.loading} />;
  else if (failed)
    detail = <ErrorState error={failed.error} onRetry={() => void failed.refetch()} retrying={failed.isFetching} />;
  else if (id === "new") {
    const seed = from ? (all.find((c) => c.value === from) ?? null) : null;
    detail = <TransportEditor key={`new:${from ?? ""}`} profile={null} seed={seed} all={all} users={[]} namedBy={[]} />;
  } else if (selected?.saved)
    detail = (
      <TransportEditor
        key={selected.value}
        profile={selected.saved}
        seed={null}
        all={all}
        users={users.get(selected.value) ?? []}
        namedBy={namedBy.get(selected.value) ?? []}
      />
    );
  else if (selected)
    detail = <BuiltinDetail key={selected.value} c={selected} all={all} users={users.get(selected.value) ?? []} />;
  else if (id)
    detail = (
      <EmptyState icon={SlidersHorizontal} title={m.notFound}>
        {ui.common.mayHaveBeenDeleted}
      </EmptyState>
    );
  // What every connection uses until another is chosen opens by itself.
  else detail = <Navigate replace to={`/transport/${AUTO_KEY}`} />;

  let list: ReactNode;
  if (pending) list = <LoadingRows rows={5} label={m.loading} />;
  else if (failed)
    list = (
      <ErrorState compact error={failed.error} onRetry={() => void failed.refetch()} retrying={failed.isFetching} />
    );
  else {
    const row = (c: Choice) => (
      <TransportRow
        c={c}
        all={all}
        users={users.get(c.value)?.length ?? 0}
        namedBy={namedBy.get(c.value) ?? []}
        selected={c.value === id}
      />
    );
    const own = all.filter((c) => !c.builtin);
    list = (
      <>
        {saved.isError ? (
          // Stale: the last list stays, marked, with a retry.
          <div className="shrink-0 border-b border-line-subtle p-2">
            <ErrorCallout
              error={saved.error}
              title={m.stale(new Date(saved.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void saved.refetch()}
              retrying={saved.isFetching}
            />
          </div>
        ) : null}
        <MasterList label={m.title}>
          <MasterListHeading>{ui.common.builtIn}</MasterListHeading>
          <PresenceList
            items={all.filter((c) => c.builtin)}
            keyOf={(c) => c.value}
            className="grid grid-cols-1 gap-0.5"
            label={m.list.builtIn}
          >
            {row}
          </PresenceList>
          <MasterListHeading>{m.list.mine}</MasterListHeading>
          {own.length ? (
            <PresenceList
              items={own}
              keyOf={(c) => c.value}
              className="grid grid-cols-1 gap-0.5"
              label={m.list.mineLabel}
            >
              {row}
            </PresenceList>
          ) : (
            <p className="px-3 pb-2 text-caption text-fg-tertiary">{m.list.noneOfMine}</p>
          )}
        </MasterList>
      </>
    );
  }

  return (
    <Page>
      <TransportActionHost profiles={profiles}>
        <PageHeader title={m.title} description={m.description} help={m.help} helpText={m.helpText} actions={create} />
        <MasterDetail
          listLabel={m.list.label}
          detailLabel={selected ? m.list.settingsOf(selected.name) : m.list.detail}
          backLabel={m.list.all}
          list={list}
          detail={detail}
        />
      </TransportActionHost>
    </Page>
  );
}
