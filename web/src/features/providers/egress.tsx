// The Provider egress: where every provider request leaves, and the one fix for each state (actions.ts egressActions:
// at most one primary, everything else secondary; nothing unavailable is hidden). The direct bootstrap is offered only
// before any egress has worked, and only with its limits said; a manual rebootstrap only while the selected egress
// cannot come back by itself, with its exposure said and acknowledged.

import type { LucideIcon } from "lucide-react";
import {
  CircleCheck,
  CircleDashed,
  CircleX,
  Globe,
  LoaderCircle,
  Route,
  ShieldAlert,
  TriangleAlert,
  Unplug,
} from "lucide-react";
import { RadioGroup } from "radix-ui";
import { type ReactNode, useEffect, useState } from "react";
import {
  useCancelRebootstrap,
  useCheckEgress,
  useEndBootstrap,
  useInstances,
  useOpenBootstrap,
  usePutProviderEgress,
  useRebootstrap,
} from "@/api/queries";
import type { ProviderEgressStatus, ProviderIpCheck, ProviderGate, ProviderKind } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusPill, Tag, toneText } from "@/components/ui/badge";
import { Button, ButtonLink } from "@/components/ui/button";
import { ChangeFade } from "@/components/ui/change-value";
import { Dialog } from "@/components/ui/dialog";
import { FormFailure } from "@/components/ui/form-failure";
import { OPTION_CARD, OPTION_IDLE, OPTION_SELECTED, STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { Callout } from "@/components/ui/states";
import { reportFailure, toast } from "@/components/ui/toast";
import { TILE_TONE } from "@/components/ui/tones";
import { instanceLook } from "@/features/instances/model";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { relativeTime } from "@/lib/format";
import { useIntentKey } from "@/lib/intent";
import { cityName } from "@/lib/places";
import { serverNow, useServerNow } from "@/lib/server-clock";
import { type EgressActionId, egressActions } from "./actions";
import { m as connectText } from "./connect/messages";
import { m } from "./egress/messages";
import { checkLook, countdown, EGRESS_LOOK, GATE_LOOK, gateName, gatesOf, rebootstrapOpen } from "./model";

/** Whose functions a row of gates is about. */
export const GATE_OWNER: Record<ProviderKind, string> = {
  airvpn: "AirVPN",
  mullvad: "Mullvad",
  generic: m.gate.genericOwner,
};

/** One exit observation, on one line: address, place, what it proves. */
export function CheckLine({ c }: { c: ProviderIpCheck }) {
  const look = checkLook(c);
  const place = connectText.cityAndCountry(c.city ? cityName(c.city) : null, c.country);
  return (
    <span className="inline-flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
      {c.status === "ok" ? (
        <>
          <span className="machine text-fg">{c.observed_ip}</span>
          <span className="text-fg-secondary">{place || m.check.placeUnknown}</span>
        </>
      ) : (
        <span className="text-danger">{c.reason ? localized(c.reason) : (c.reason_code ?? m.check.notCompleted)}</span>
      )}
      {c.exit_server ? <span className="machine text-fg-secondary">{m.check.exitServer(c.exit_server)}</span> : null}
      <Tag
        tone={look.tone}
        icon={look.tone === "success" ? CircleCheck : look.tone === "warning" ? TriangleAlert : undefined}
      >
        {look.label}
      </Tag>
      {c.route_mode === "bootstrap_direct" ? (
        <Tag tone="warning">{m.check.direct}</Tag>
      ) : c.tunnel_verified ? (
        <Tag>{m.check.viaTunnel}</Tag>
      ) : null}
    </span>
  );
}

const GATE_ICON: Partial<Record<ProviderGate["status"], LucideIcon>> = {
  passed: CircleCheck,
  failed: CircleX,
  blocked: TriangleAlert,
};

/**
 * One provider's function gates, each on its own (whatismyip, membership, IPv6, settings, port reservation): a pass of
 * one never stands for another. Compact: one line of tags, the reason on hover; otherwise a list with each reason and
 * how long ago it was observed (the time keeps counting, a state that changes fades in).
 */
export function GateList({
  gates,
  provider,
  compact,
}: {
  gates: ProviderGate[] | undefined;
  provider: ProviderKind;
  compact?: boolean;
}) {
  const mine = gatesOf(gates, provider);
  if (!mine.length) return null;
  if (compact) {
    return (
      <span className="inline-flex min-w-0 flex-wrap items-center gap-1.5">
        {mine.map((g) => {
          const look = GATE_LOOK[g.status];
          return (
            <span key={g.gate} title={g.reason ? localized(g.reason) : undefined}>
              <Tag tone={look.tone} icon={GATE_ICON[g.status]}>
                {m.gate.state(gateName(provider, g.gate), look.label)}
              </Tag>
            </span>
          );
        })}
      </span>
    );
  }
  return <GateRows gates={mine} provider={provider} />;
}

function GateRows({ gates, provider }: { gates: ProviderGate[]; provider: ProviderKind }) {
  const now = useServerNow();
  return (
    <ul className="grid grid-cols-1 divide-y divide-line-subtle" aria-label={m.gate.checksOf(GATE_OWNER[provider])}>
      {gates.map((g) => {
        const look = GATE_LOOK[g.status];
        return (
          <li key={g.gate} className="flex items-start justify-between gap-3 py-2">
            <div className="grid min-w-0 gap-0.5">
              <p className="text-data text-fg">{gateName(provider, g.gate)}</p>
              {g.reason ? (
                <p className="text-caption text-fg-tertiary [overflow-wrap:anywhere]">{localized(g.reason)}</p>
              ) : null}
            </div>
            <div className="flex shrink-0 flex-col items-end gap-1">
              <StatusPill look={{ label: look.label, tone: look.tone, icon: GATE_ICON[g.status] ?? CircleDashed }} />
              <span className="text-micro text-fg-tertiary">
                {g.observed_at ? relativeTime(g.observed_at, now) : m.gate.notObserved}
              </span>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** The server's clock, ticking once a second while `active` (the countdown of a direct grant the server set). */
function useNowTick(active = true) {
  const [now, setNow] = useState(() => serverNow());
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(() => {
      setNow(serverNow());
    }, 1000);
    return () => {
      window.clearInterval(t);
    };
  }, [active]);
  return now;
}

/** The phase's tile icon. */
function PhaseIcon({ tone, busy }: { tone: string; busy: boolean | undefined }) {
  if (busy) return <LoaderCircle className="animate-spin" />;
  if (tone === "success") return <Route />;
  if (tone === "danger") return <ShieldAlert />;
  if (tone === "neutral") return <Unplug />;
  return <TriangleAlert />;
}

export function EgressStrip({
  status,
  hasInstances,
  index,
}: {
  status: ProviderEgressStatus;
  hasInstances: boolean;
  index?: number;
}) {
  const rebootstrap = rebootstrapOpen(status);
  const look = rebootstrap
    ? { tone: "warning" as const, title: m.phase.rebootstrap, busy: false }
    : EGRESS_LOOK[status.phase];
  const blocked = useMutationBlocked();
  const open = useOpenBootstrap();
  const end = useEndBootstrap();
  const cancel = useCancelRebootstrap();
  const check = useCheckEgress();
  const enable = usePutProviderEgress();
  const intent = useIntentKey("provider_egress.bootstrap");
  const enableIntent = useIntentKey("provider_egress.update");
  const [choosing, setChoosing] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const now = useNowTick(Boolean(status.bootstrap_expires_at));
  const left = countdown(status.bootstrap_expires_at, now);

  const run: Record<EgressActionId, () => void> = {
    check: () => {
      check.mutate(undefined, {
        onError: (e) => {
          reportFailure(m.failed.check, e);
        },
      });
    },
    choose: () => {
      setChoosing(true);
    },
    open_bootstrap: () => {
      const body = { bootstrap: true };
      open.mutate(
        { key: intent.next(body) },
        {
          onSuccess: () => {
            intent.settle();
            toast.success(m.firstSetupOpened, m.firstSetupOpenedDetail);
          },
          onError: (e) => {
            intent.settle(e);
            reportFailure(m.failed.openFirstSetup, e);
          },
        },
      );
    },
    end_bootstrap: () => {
      end.mutate(undefined, {
        onError: (e) => {
          reportFailure(m.failed.endDirect, e);
        },
      });
    },
    rebootstrap: () => {
      setRecovering(true);
    },
    cancel_rebootstrap: () => {
      cancel.mutate(undefined, {
        onSuccess: () => toast.success(m.rebootstrapCancelled, m.rebootstrapCancelledDetail),
        onError: (e) => {
          reportFailure(m.failed.cancelRebootstrap, e);
        },
      });
    },
    enable: () => {
      const input = { desired_mode: "via_instance" as const, selected_instance_id: null };
      enable.mutate(
        { key: enableIntent.next(input), revision: status.revision, input },
        {
          onSuccess: () => {
            enableIntent.settle();
          },
          onError: (e) => {
            enableIntent.settle(e);
            reportFailure(m.failed.enable, e);
          },
        },
      );
    },
    open_instance: () => undefined,
    import: () => undefined,
  };
  const pending: Partial<Record<EgressActionId, boolean>> = {
    check: check.isPending,
    open_bootstrap: open.isPending,
    end_bootstrap: end.isPending,
    cancel_rebootstrap: cancel.isPending,
    enable: enable.isPending,
  };

  const reason = status.reason ? localized(status.reason) : null;
  let body: ReactNode;
  switch (status.phase) {
    case "vpn_ready":
      body = m.body.vpnReady;
      break;
    case "starting_instance":
      body = m.body.starting;
      break;
    case "switching":
      body = reason ?? m.body.switching;
      break;
    case "bootstrap_direct": {
      const text = rebootstrap ? m.body.rebootstrap : m.body.firstSetup;
      body = reason ? m.body.lastTime(text, reason) : text;
      break;
    }
    case "recovery_required":
      body = reason ?? m.body.recovery;
      break;
    case "unconfigured": {
      const text = status.bootstrap_consumed
        ? hasInstances
          ? m.body.chooseEgress
          : m.body.importFirst
        : hasInstances
          ? m.body.chooseOrDirect
          : m.body.directOnce;
      body = reason ? m.body.lastSetting(text, reason) : text;
      break;
    }
    case "blocked":
      body = reason ?? m.body.blocked;
      break;
    case "disabled":
      body = hasInstances ? m.body.disabled : m.body.disabledNoConnections;
      break;
  }
  // How long the direct grant stays open, said for the grant it is.
  const leftOf =
    status.phase === "bootstrap_direct"
      ? m.left.direct
      : status.bootstrap?.kind === "rebootstrap"
        ? m.left.rebootstrap
        : m.left.firstSetup;

  // At most one primary (the fix this state calls for), then the other controls.
  const actions = egressActions(status, { hasInstances, blocked });
  const ordered = [...actions.filter((a) => a.slot === "footer"), ...actions.filter((a) => a.slot !== "footer")];
  const named =
    status.phase === "vpn_ready" ||
    status.phase === "starting_instance" ||
    status.phase === "blocked" ||
    status.phase === "recovery_required";

  return (
    <section
      aria-label={m.title}
      style={index === undefined ? undefined : staggerStyle(index)}
      className={cn("panel shrink-0 px-4 py-3", index === undefined ? undefined : STAGGER_IN)}
    >
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="flex min-w-0 flex-1 basis-96 gap-3">
          <span
            aria-hidden
            className={cn(
              "grid size-9 shrink-0 place-items-center rounded-lg border transition-[color,background-color,border-color] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) [&_svg]:size-[18px]",
              TILE_TONE[look.tone],
            )}
          >
            <PhaseIcon tone={look.tone} busy={look.busy} />
          </span>
          <div className="grid min-w-0 flex-1 gap-1">
            {/* The title fades in when the phase changes (never on the first render); the countdown updates in place. */}
            <ChangeFade
              as="p"
              value={look.title}
              className="flex flex-wrap items-center gap-x-2 gap-y-1 text-data font-medium"
            >
              <span>
                <span className={toneText[look.tone]}>{look.title}</span>
                {named ? (
                  <span className="text-fg">{m.instanceName(status.selected_instance_name ?? m.nameUnknown)}</span>
                ) : null}
              </span>
              {left ? <span className="text-fg">{leftOf(<span className="machine">{left}</span>)}</span> : null}
            </ChangeFade>
            <p className="text-caption text-fg-secondary">{body}</p>
            {status.last_check ? (
              <>
                <p className="flex min-w-0 flex-wrap items-center gap-2 text-caption">
                  <span className="text-fg-tertiary">{m.lastCheck}</span>
                  <CheckLine c={status.last_check} />
                </p>
                <p className="flex min-w-0 flex-wrap items-center gap-2 text-caption">
                  <span className="text-fg-tertiary">{m.checksIn(GATE_OWNER[status.last_check.provider])}</span>
                  <GateList gates={status.gates} provider={status.last_check.provider} compact />
                </p>
              </>
            ) : null}
          </div>
        </div>
        {/* On a narrow card the controls wrap within the card instead of pushing past its edge. */}
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {status.phase === "recovery_required" && !status.recovery?.rebootstrap_eligible ? (
            <Tag tone="neutral">{m.noRebootstrap}</Tag>
          ) : null}
          {ordered.map((a) => {
            const primary = a.slot === "footer";
            if (a.id === "open_instance" && status.selected_instance_id)
              return (
                <ButtonLink
                  key={a.id}
                  size="sm"
                  variant="quiet"
                  to={`/instances/${status.selected_instance_id}`}
                  icon={a.icon}
                >
                  {a.label}
                </ButtonLink>
              );
            if (a.id === "import")
              return (
                <ButtonLink key={a.id} size="sm" variant="primary" to="/profiles?import=1" icon={a.icon}>
                  {a.label}
                </ButtonLink>
              );
            return (
              <ActionButton
                key={a.id}
                size="sm"
                variant={primary ? "primary" : a.danger ? "danger" : "secondary"}
                icon={a.icon}
                pending={pending[a.id] ?? false}
                pendingLabel={a.pendingLabel}
                disabledReason={pending[a.id] ? null : a.disabledReason}
                onClick={run[a.id]}
              >
                {a.label}
              </ActionButton>
            );
          })}
        </div>
      </div>
      <ChooseEgress open={choosing} onOpenChange={setChoosing} status={status} />
      <RebootstrapDialog open={recovering} onOpenChange={setRecovering} status={status} />
    </section>
  );
}

/**
 * The manual rebootstrap: what leaves without a VPN, for how long and for what, acknowledged
 * before it opens. Sent with the egress revision shown, so a change since refuses it.
 */
function RebootstrapDialog({
  open,
  onOpenChange,
  status,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: ProviderEgressStatus;
}) {
  const start = useRebootstrap();
  const intent = useIntentKey("provider_egress.rebootstrap");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<unknown>(null);
  // Each opening starts unacknowledged and without the last failure (reset while rendering, not in an effect).
  const [wasOpen, setWasOpen] = useState(open);
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) {
      setUnderstood(false);
      setError(null);
    }
  }

  const confirm = () => {
    const input = { confirm_direct: true };
    start.mutate(
      { key: intent.next(input), revision: status.revision, input },
      {
        onSuccess: () => {
          intent.settle();
          onOpenChange(false);
          toast.success(m.rebootstrap.opened, m.rebootstrap.openedDetail);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.rebootstrap.title}
      description={m.rebootstrap.description}
      width={600}
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
            variant="danger-confirm"
            icon={Globe}
            disabled={!understood}
            title={understood ? undefined : m.rebootstrap.tickFirst}
            pending={start.isPending}
            pendingLabel={m.actions.opening}
            onClick={confirm}
          >
            {m.rebootstrap.open}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <FormFailure error={error} />
        {status.recovery ? <p className="text-data text-fg-secondary">{localized(status.recovery.reason)}</p> : null}
        <Callout tone="warning" title={m.rebootstrap.exposure}>
          {m.rebootstrap.exposureDetail}
        </Callout>
        <ol className="list-decimal space-y-1.5 pl-5 text-data text-fg-secondary">
          <li>{m.rebootstrap.terms.time}</li>
          <li>{m.rebootstrap.terms.scope}</li>
          <li>{m.rebootstrap.terms.takeover}</li>
          <li>{m.rebootstrap.terms.once}</li>
        </ol>
        <label className="flex cursor-pointer items-start gap-2 text-data text-fg">
          <input
            type="checkbox"
            data-autofocus
            className="mt-1 size-4 shrink-0 accent-action"
            checked={understood}
            onChange={(e) => {
              setUnderstood(e.target.checked);
            }}
          />
          {m.rebootstrap.understood}
        </label>
      </div>
    </Dialog>
  );
}

/** One choice of the egress dialog: a radio card (soft brand fill and hairline when chosen; a form option, no lift). */
function EgressOption({ value, chosen, children }: { value: string; chosen: boolean; children: ReactNode }) {
  return (
    <RadioGroup.Item
      value={value}
      className={cn(
        OPTION_CARD,
        chosen ? OPTION_SELECTED : OPTION_IDLE,
        "group flex w-full items-center gap-3 px-3 py-2.5 text-left outline-none focus-visible:ring-2 focus-visible:ring-focus",
      )}
    >
      <span
        aria-hidden
        className="grid size-4 shrink-0 place-items-center rounded-full border border-line-control group-data-[state=checked]:border-action group-data-[state=checked]:bg-action"
      >
        <span className="size-1.5 rounded-full bg-on-accent opacity-0 group-data-[state=checked]:opacity-100" />
      </span>
      {children}
    </RadioGroup.Item>
  );
}

function ChooseEgress({
  open,
  onOpenChange,
  status,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: ProviderEgressStatus;
}) {
  const instances = useInstances();
  const put = usePutProviderEgress();
  const check = useCheckEgress();
  const intent = useIntentKey("provider_egress.update");
  const current = status.desired_mode === "disabled" ? "off" : (status.selected_instance_id ?? "");
  const all = instances.data ?? [];
  // Nothing chosen yet and exactly one connection is ready: that is the obvious candidate.
  const ready = all.filter((v) => v.status?.phase === "ready");
  const suggested = current || (ready.length === 1 ? (ready[0]?.spec.id ?? "") : "");
  const [choice, setChoice] = useState(suggested);
  const [error, setError] = useState<unknown>(null);
  // Each opening, and a new suggestion while open, starts from the suggestion (reset while rendering, not in an effect).
  const [seen, setSeen] = useState({ open, suggested });
  if (seen.open !== open || seen.suggested !== suggested) {
    setSeen({ open, suggested });
    if (open) {
      setChoice(suggested);
      setError(null);
    }
  }

  const save = () => {
    const input =
      choice === "off"
        ? { desired_mode: "disabled" as const, selected_instance_id: null }
        : { desired_mode: "via_instance" as const, selected_instance_id: choice || null };
    put.mutate(
      { key: intent.next(input), revision: status.revision, input },
      {
        onSuccess: () => {
          intent.settle();
          toast.success(choice === "off" ? m.choose.disabled : m.choose.changed);
          onOpenChange(false);
          // Show where the new route leaves right away (a failure shows in the strip).
          if (choice !== "off") check.mutate(undefined);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const reason = !choice ? m.choose.chooseFirst : choice === current ? m.choose.isCurrent : null;
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.title}
      description={m.choose.description}
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
            disabledReason={reason}
            pending={put.isPending}
            pendingLabel={m.choose.applying}
            onClick={save}
          >
            {m.choose.apply}
          </ActionButton>
        </>
      }
    >
      <div className="space-y-3">
        <FormFailure error={error} />
        <RadioGroup.Root
          value={choice}
          onValueChange={setChoice}
          aria-label={m.choose.label}
          className="grid grid-cols-1 gap-1.5"
        >
          {[...ready, ...all.filter((v) => v.status?.phase !== "ready")].map((v) => {
            const look = instanceLook(v);
            return (
              <EgressOption key={v.spec.id} value={v.spec.id} chosen={choice === v.spec.id}>
                <span className="min-w-0 flex-1 text-data text-fg [overflow-wrap:anywhere]">{v.spec.name}</span>
                <span className={cn("shrink-0 text-caption", toneText[look.tone])}>{look.label}</span>
              </EgressOption>
            );
          })}
          <EgressOption value="off" chosen={choice === "off"}>
            <span className="flex-1 text-data text-fg">{m.choose.disable}</span>
            <span className="text-caption text-fg-tertiary">{m.choose.disableHint}</span>
          </EgressOption>
        </RadioGroup.Root>
      </div>
    </Dialog>
  );
}
