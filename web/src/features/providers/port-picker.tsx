import { Check, Plus } from "lucide-react";
import { ApiFailure, describeFailure } from "@/api/client";
import { useForwardedPorts, useReserveForwardedPort } from "@/api/queries";
import type { ForwardedPort, ProviderAccount } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { Button } from "@/components/ui/button";
import { CARD, CHOICE_BASE, CHOICE_IDLE, CHOICE_SELECTED } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { Callout, LoadingRows } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";
import { useIntentKey } from "@/lib/intent";
import { PORT_PROTOCOL, WEBSITE_STEPS, portUsage, websiteFallback } from "./ports";
import { m } from "./ports/messages";

/** Doing it on AirVPN's website by hand, after VPN Manager could not. */
export function WebsiteSteps() {
  return (
    <ol className="list-decimal space-y-1 pl-4">
      {WEBSITE_STEPS.map((s) => (
        <li key={s}>{s}</li>
      ))}
    </ol>
  );
}

/**
 * The AirVPN account's forwarded ports (連入埠) to build a forward from: picking one fills the
 * tunnel port, the public port and the App's port; one more can be reserved here (AirVPN picks
 * it). Replaces the steps on AirVPN's website when the account is in VPN Manager.
 */
export function ForwardedPortPicker({
  account,
  selected,
  onPick,
}: {
  account: ProviderAccount;
  /** The public port the form holds now. */
  selected: number | null;
  onPick: (port: ForwardedPort) => void;
}) {
  const ports = useForwardedPorts(account.id);
  const reserve = useReserveForwardedPort();
  const blocked = useMutationBlocked();
  const intent = useIntentKey(`provider.reserve_port:${account.id}`);

  const reserveOne = () => {
    reserve.mutate(
      { account: account.id, port: null, key: intent.next({ port: null }) },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(m.reserve.reserved(r.data.port), m.reserve.reservedFilled);
          onPick(r.data);
        },
        onError: (e) => {
          intent.settle(e);
        },
      },
    );
  };

  let body;
  if (ports.isError) {
    const code = ports.error instanceof ApiFailure ? ports.error.code : "";
    body = (
      <Callout
        tone="warning"
        title={m.list.unreadable}
        actions={
          <Button size="sm" onClick={() => void ports.refetch()}>
            {m.retry}
          </Button>
        }
      >
        <p>{describeFailure(ports.error)}</p>
        {websiteFallback(code) ? (
          <div className="pt-1">
            <p>{m.list.reserveOnWebsite}</p>
            <WebsiteSteps />
          </div>
        ) : null}
      </Callout>
    );
  } else if (!ports.data) {
    body = <LoadingRows rows={1} label={m.list.loading} />;
  } else {
    const usage = portUsage(ports.data);
    body = (
      <>
        <div className="flex flex-wrap gap-2" role="group" aria-label={m.picker.choose}>
          {ports.data.ports.map((p) => {
            const on = selected === p.port;
            return (
              <button
                key={`${p.pool}-${p.port}`}
                type="button"
                aria-pressed={on}
                onClick={() => {
                  onPick(p);
                }}
                className={cn(
                  CHOICE_BASE,
                  "inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 text-data",
                  on ? cn(CHOICE_SELECTED, "text-fg") : cn(CHOICE_IDLE, "text-fg-secondary hover:text-fg"),
                )}
                title={p.enabled ? undefined : m.picker.disabledOnWebsite}
              >
                {on ? <Check aria-hidden className="size-3.5 text-brand-cyan" /> : null}
                <span className="machine">{p.port}</span>
                <span className="text-caption text-fg-tertiary">{PORT_PROTOCOL[p.protocol]}</span>
                {!p.enabled ? <span className="text-caption text-warning">{ui.common.disabled}</span> : null}
              </button>
            );
          })}
          {!ports.data.ports.length ? (
            <span className="self-center text-caption text-fg-tertiary">{m.list.noneYet}</span>
          ) : null}
          <ActionButton
            size="sm"
            icon={Plus}
            pending={reserve.isPending}
            pendingLabel={m.reserve.reserving}
            disabledReason={blocked ?? (usage.full ? m.reserve.limitReachedElsewhere(usage.limit) : null)}
            onClick={reserveOne}
          >
            {m.reserve.submit}
          </ActionButton>
        </div>
        {reserve.error ? (
          <p className="text-caption text-danger animate-reveal">{describeFailure(reserve.error)}</p>
        ) : null}
        <p className="text-caption text-fg-tertiary">{m.picker.hint(usage.text)}</p>
      </>
    );
  }

  return (
    <div className={cn(CARD, "space-y-2 px-3.5 py-3")}>
      <p className="text-data font-medium text-fg-secondary">{m.picker.title(account.label)}</p>
      {body}
    </div>
  );
}
