// The AirVPN account's forwarded ports (連入埠), managed here: VPN Manager signs in to AirVPN's website with the
// account (its API has no port service), through the Provider egress. Everything the website's Ports page does: list,
// reserve, delete, each port's settings and AirVPN's test of it, the DDNS check and the search for consecutive free
// ports. Operation aggregation (docs/frontend-design.md §8.1): each port row has one quick action (測試) and one ⋯ menu
// (建立轉發, 設定 | 刪除), from one action model (actions.ts portActions); the section header holds the list-wide
// 重新讀取; the reservation form's 保留一個埠 is the area's primary action. Every website operation also records the
// 「轉發 port 保留」 function check on the server, so the egress status (which carries the checks) is read again when one
// settles — the check on this page never lags behind the list.
import { useQueryClient } from "@tanstack/react-query";
import { DoorOpen, Globe, Plus, RefreshCw, Search } from "lucide-react";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { ApiFailure, describeFailure, newIdempotencyKey } from "@/api/client";
import {
  keys,
  useDdnsCheck,
  useDeleteForwardedPort,
  useForwardedPorts,
  useForwards,
  useFreePortSearch,
  useInstances,
  useProfiles,
  useReserveForwardedPort,
  useTestForwardedPort,
} from "@/api/queries";
import type { ForwardedPort, ForwardedPorts, ProviderAccount } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ActionButton } from "@/components/ui/action-button";
import { Tag } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChangeValue } from "@/components/ui/change-value";
import { ConfirmDialog } from "@/components/ui/dialog";
import { RowActions } from "@/components/ui/entity-actions";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { PropertySection } from "@/components/ui/inspector";
import { CARD, STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { PresenceList } from "@/components/ui/presence-list";
import { Segmented } from "@/components/ui/segmented";
import { Callout, EmptyState, ErrorCallout, LoadingRows } from "@/components/ui/states";
import { reportFailure, toast } from "@/components/ui/toast";
import { ToolButton } from "@/components/ui/tool-strip";
import { ForwardDialog } from "@/features/forwards/forward-dialog";
import { intlLocale } from "@/i18n";
import { cn } from "@/lib/cn";
import { useIntentKey } from "@/lib/intent";
import { type PortActionId, portActions } from "./actions";
import { m as providerText } from "./messages";
import { WebsiteSteps } from "./port-picker";
import { PortSettingsDialog } from "./port-settings";
import { PortTestDialog } from "./port-test";
import {
  checkPortDraft,
  checkSearchCount,
  connectionsOf,
  ddnsHost,
  ddnsLook,
  deviceLabel,
  type ForwardPrefill,
  forwardPrefill,
  forwardsOnPort,
  ipLayerLabel,
  PORT_PROTOCOL,
  portUsage,
  type ReserveMode,
  remapWarning,
  SEARCH_MAX,
  SEARCH_MIN,
  websiteFallback,
} from "./ports";
import { m } from "./ports/messages";

/**
 * Every AirVPN website operation (reading the list, reserving, deleting, a port's settings, its test, the DDNS check,
 * the free-port search) records the 「轉發 port 保留」 check on the server: read the egress status, which carries the
 * checks, when one settles.
 */
export function useGateRefresh(): () => void {
  const qc = useQueryClient();
  return useCallback(() => void qc.invalidateQueries({ queryKey: keys.providerEgress }), [qc]);
}

function ReserveForm({
  account,
  list,
  onSettled,
}: {
  account: ProviderAccount;
  list: ForwardedPorts;
  onSettled: () => void;
}) {
  const reserve = useReserveForwardedPort();
  const blocked = useMutationBlocked();
  const intent = useIntentKey(`provider.reserve_port:${account.id}`);
  const formId = useId();
  const [mode, setMode] = useState<ReserveMode>("random");
  const [text, setText] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const usage = portUsage(list);
  const check = checkPortDraft(mode, text, list);
  const fieldError =
    (submitted || text.trim() ? check.error : null) ??
    (error instanceof ApiFailure ? (error.fieldErrors().get("/port") ?? null) : null);
  const reason = blocked ?? (usage.full ? m.reserve.limitReached(usage.limit) : null);

  const submit = () => {
    setSubmitted(true);
    if (check.error || reason || reserve.isPending) return;
    setError(null);
    reserve.mutate(
      { account: account.id, port: check.port, key: intent.next({ port: check.port }) },
      {
        onSuccess: (r) => {
          intent.settle();
          setText("");
          setSubmitted(false);
          toast.success(m.reserve.reserved(r.data.port), m.reserve.reservedDetail);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
        onSettled,
      },
    );
  };

  return (
    <form
      id={formId}
      noValidate
      aria-label={m.reserve.label}
      className="space-y-3 px-3.5 py-3"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <FormFailure error={error instanceof ApiFailure && error.fieldErrors().size ? null : error} />
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1.5">
          <span className="text-data font-medium text-fg-secondary">{m.reserve.port}</span>
          <Segmented
            label={m.reserve.port}
            value={mode}
            onChange={setMode}
            options={[
              { value: "random", label: m.reserve.byAirvpn },
              { value: "chosen", label: m.reserve.chosen },
            ]}
          />
        </div>
        {mode === "chosen" ? (
          <Field label={m.reserve.portField} error={fieldError} className="w-40 animate-reveal">
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                autoComplete="off"
                placeholder={`${list.min_port}–65535`}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={text}
                onChange={(e) => {
                  setText(e.target.value);
                }}
              />
            )}
          </Field>
        ) : null}
        <ActionButton
          type="submit"
          icon={Plus}
          pending={reserve.isPending}
          pendingLabel={m.reserve.reserving}
          disabledReason={reason}
        >
          {m.reserve.submit}
        </ActionButton>
      </div>
      <p className="text-caption text-fg-tertiary">
        {usage.full ? m.reserve.allUsed(usage.limit) : m.reserve.hint(usage.limit, list.min_port)}
      </p>
    </form>
  );
}

/** AirVPN's search for consecutive ports nobody holds; it reserves nothing. */
function FreePortSearch({ account, onSettled }: { account: ProviderAccount; onSettled: () => void }) {
  const search = useFreePortSearch();
  const [text, setText] = useState(String(SEARCH_MIN));
  const [submitted, setSubmitted] = useState(false);
  const check = checkSearchCount(text);
  return (
    <form
      noValidate
      aria-label={m.search.label}
      className="space-y-2 px-3.5 py-3"
      onSubmit={(e) => {
        e.preventDefault();
        setSubmitted(true);
        // Enter in the field while searching does not ask again.
        if (check.count !== null && !search.isPending)
          search.mutate({ account: account.id, count: check.count }, { onSettled });
      }}
    >
      <div className="flex flex-wrap items-end gap-3">
        <Field label={m.search.count} error={submitted ? check.error : null} className="w-40">
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              mono
              inputMode="numeric"
              autoComplete="off"
              placeholder={`${SEARCH_MIN}–${SEARCH_MAX}`}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={text}
              onChange={(e) => {
                setText(e.target.value);
              }}
            />
          )}
        </Field>
        <Button type="submit" icon={Search} pending={search.isPending} pendingLabel={m.search.searching}>
          {m.search.label}
        </Button>
      </div>
      <div aria-live="polite">
        {search.isError ? (
          <div className="animate-reveal">
            <Callout tone="danger" title={m.search.failed}>
              {describeFailure(search.error)}
            </Callout>
          </div>
        ) : search.data ? (
          <div className="animate-reveal">
            <Callout tone="info" title={m.search.result(search.data.count)}>
              <p>{search.data.message}</p>
            </Callout>
          </div>
        ) : null}
      </div>
      <p className="text-caption text-fg-tertiary">{m.search.hint}</p>
    </form>
  );
}

/** AirVPN's DDNS check: where each DDNS name of the account's ports leads now. */
function DdnsCheck({ account, onSettled }: { account: ProviderAccount; onSettled: () => void }) {
  const check = useDdnsCheck();
  const report = check.data;
  return (
    <div className={cn(CARD, "space-y-2 px-3.5 py-3")}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="min-w-0 flex-1 basis-60 text-caption text-fg-tertiary">{m.ddns.intro}</p>
        <Button
          size="sm"
          icon={Globe}
          pending={check.isPending}
          pendingLabel={ui.common.checking}
          onClick={() => {
            check.mutate(account.id, { onSettled });
          }}
        >
          {m.ddns.check}
        </Button>
      </div>
      <div aria-live="polite">
        {check.isError ? (
          <div className="animate-reveal">
            <Callout tone="danger" title={m.ddns.failed}>
              {describeFailure(check.error)}
            </Callout>
          </div>
        ) : report && !report.names.length ? (
          <p className="text-caption text-fg-tertiary animate-reveal">{m.ddns.none}</p>
        ) : report ? (
          <ul className="space-y-1.5" aria-label={m.ddns.names}>
            {report.names.map((n, i) => {
              const look = ddnsLook(n.sessions);
              return (
                <li
                  key={n.name}
                  style={staggerStyle(i)}
                  className={cn("flex flex-wrap items-baseline gap-x-2 gap-y-0.5", STAGGER_IN)}
                >
                  <span className="machine text-data text-fg">{ddnsHost(n.name)}</span>
                  <Tag tone={look.tone}>{look.text}</Tag>
                  {n.ipv4 || n.ipv6 ? (
                    <span className="machine text-caption text-fg-tertiary">
                      {m.ddns.resolvesTo([n.ipv4, n.ipv6].filter((a): a is string => Boolean(a)))}
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : null}
      </div>
    </div>
  );
}

/** One reserved port: what AirVPN holds for it, what uses it, and its actions (測試 + the ⋯ menu). */
function PortRow({
  p,
  forwards,
  actions,
}: {
  p: ForwardedPort;
  forwards: string[];
  actions: EntityAction<PortActionId>[];
}) {
  const remap = remapWarning(p);
  const notes = [
    p.dns_name ? `DDNS ${ddnsHost(p.dns_name)}` : null,
    p.notes ? m.list.notes(p.notes) : null,
    forwards.length ? m.list.forwards(forwards) : null,
  ].filter(Boolean);
  return (
    <div className="grid grid-cols-1 gap-1.5 py-2.5">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="machine text-body font-medium text-fg">{p.port}</span>
        <span className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          <Tag>{PORT_PROTOCOL[p.protocol]}</Tag>
          <Tag>{ipLayerLabel(p.ip_layer)}</Tag>
          <Tag>{deviceLabel(p)}</Tag>
          {p.enabled ? <Tag tone="success">{m.enabled}</Tag> : <Tag tone="warning">{ui.common.disabled}</Tag>}
        </span>
        <RowActions actions={actions} name={m.named(p.port)} />
      </div>
      {remap ? <p className="text-caption text-warning">{remap}</p> : null}
      {notes.length ? (
        <p className="text-caption text-fg-tertiary [overflow-wrap:anywhere]">{notes.join(" · ")}</p>
      ) : null}
    </div>
  );
}

/**
 * The 連入埠 section of an AirVPN account page. Read when the section shows (through the Provider egress), never
 * polled; a failure is not retried by itself.
 */
export function ForwardedPortsSection({ account, egressUsable }: { account: ProviderAccount; egressUsable: boolean }) {
  const ports = useForwardedPorts(account.id, egressUsable);
  const profiles = useProfiles();
  const instances = useInstances();
  const forwards = useForwards();
  const remove = useDeleteForwardedPort();
  const tester = useTestForwardedPort();
  const blocked = useMutationBlocked();
  const refreshGates = useGateRefresh();
  const connections = useMemo(
    () => connectionsOf(account, profiles.data ?? [], instances.data ?? []),
    [account, profiles.data, instances.data],
  );
  // The forward dialog's prefill, kept while it animates closed.
  const [prefill, setPrefill] = useState<ForwardPrefill | null>(null);
  const [forwardOpen, setForwardOpen] = useState(false);
  const [target, setTarget] = useState<ForwardedPort | null>(null);
  const [shown, setShown] = useState<ForwardedPort | null>(null);
  const deleted = useRef(false);
  // The port of the test and settings dialogs, kept while they animate closed.
  const [testOpen, setTestOpen] = useState(false);
  const [testPort, setTestPort] = useState<number | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsPort, setSettingsPort] = useState<number | null>(null);

  // The list was read (or failed to be): the server recorded the check meanwhile.
  const settledAt = Math.max(ports.dataUpdatedAt, ports.errorUpdatedAt);
  const seen = useRef(settledAt);
  useEffect(() => {
    if (settledAt === seen.current) return;
    seen.current = settledAt;
    refreshGates();
  }, [settledAt, refreshGates]);

  const usedBy = (port: number) => forwardsOnPort(port, forwards.data ?? [], connections);
  const test = (port: number) => {
    setTestPort(port);
    setTestOpen(true);
    tester.mutate({ account: account.id, port }, { onSettled: refreshGates });
  };
  const testing = tester.isPending ? testPort : null;
  const noConnection = connections.length ? null : m.list.noConnection;
  const actionsOf = (p: ForwardedPort): EntityAction<PortActionId>[] =>
    portActions(p, { noConnection, blocked, testing }).map((spec) => ({
      ...spec,
      pending:
        (spec.id === "test" && testing === p.port) ||
        (spec.id === "delete" && remove.isPending && remove.variables.port === p.port),
      run: () => {
        switch (spec.id) {
          case "test":
            test(p.port);
            return;
          case "forward":
            setPrefill(forwardPrefill(p, connections[0]?.spec.id));
            setForwardOpen(true);
            return;
          case "settings":
            setSettingsPort(p.port);
            setSettingsOpen(true);
            return;
          case "delete":
            setShown(p);
            setTarget(p);
            return;
        }
      },
    }));

  const list = ports.data;
  let body;
  if (!egressUsable) body = <p className="text-caption text-fg-tertiary">{m.list.needEgress}</p>;
  else if (ports.isError && !list) {
    const code = ports.error instanceof ApiFailure ? ports.error.code : "";
    body = (
      <ErrorCallout
        error={ports.error}
        title={m.list.unreadable}
        onRetry={() => void ports.refetch()}
        retrying={ports.isFetching}
      >
        {websiteFallback(code) ? (
          <div className="pt-1">
            <p>{m.list.manageOnWebsite}</p>
            <WebsiteSteps />
          </div>
        ) : null}
      </ErrorCallout>
    );
  } else if (!list) body = <LoadingRows rows={2} label={m.list.loading} />;
  else {
    const usage = portUsage(list);
    body = (
      <div className="grid grid-cols-1 gap-3">
        <p className="text-caption text-fg-tertiary">
          <ChangeValue value={usage.text} className="text-fg-secondary" /> ·{" "}
          {m.list.readAt(new Date(list.observed_at).toLocaleTimeString(intlLocale, { hour12: false }))}
        </p>
        {ports.isError ? (
          // Stale: the last list stays, marked, with a retry.
          <ErrorCallout
            error={ports.error}
            title={providerText.staleSince(
              new Date(ports.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }),
            )}
            onRetry={() => void ports.refetch()}
            retrying={ports.isFetching}
          />
        ) : null}
        {list.ports.length ? (
          <PresenceList
            items={list.ports}
            keyOf={(p) => `${p.pool}-${p.port}`}
            className="grid grid-cols-1 divide-y divide-line-subtle"
            label={m.title}
          >
            {(p) => <PortRow p={p} forwards={usedBy(p.port).map((f) => f.binding.name)} actions={actionsOf(p)} />}
          </PresenceList>
        ) : (
          <EmptyState compact icon={DoorOpen} title={m.list.none}>
            {m.list.noneHint}
          </EmptyState>
        )}
        <div className={cn(CARD, "divide-y divide-line-subtle")}>
          <ReserveForm account={account} list={list} onSettled={refreshGates} />
          <FreePortSearch account={account} onSettled={refreshGates} />
        </div>
        <DdnsCheck account={account} onSettled={refreshGates} />
      </div>
    );
  }

  return (
    <PropertySection
      title={m.title}
      icon={<DoorOpen aria-hidden />}
      count={list ? list.ports.length : null}
      actions={
        egressUsable ? (
          <ToolButton
            label={m.list.refresh}
            icon={<RefreshCw aria-hidden />}
            pending={ports.isFetching}
            disabledReason={null}
            onClick={() => void ports.refetch()}
          />
        ) : null
      }
    >
      {body}
      <ForwardDialog open={forwardOpen} onOpenChange={setForwardOpen} prefill={prefill ?? undefined} />
      <PortTestDialog
        open={testOpen}
        onOpenChange={setTestOpen}
        port={list?.ports.find((p) => p.port === testPort)}
        run={tester}
        onRetry={() => {
          if (testPort !== null) tester.mutate({ account: account.id, port: testPort }, { onSettled: refreshGates });
        }}
      />
      <PortSettingsDialog
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        account={account}
        port={list?.ports.find((p) => p.port === settingsPort)}
        devices={list?.devices ?? []}
        onSettled={refreshGates}
      />
      <ConfirmDialog
        open={Boolean(target)}
        onOpenChange={(o) => {
          if (!o) setTarget(null);
        }}
        title={m.remove.title(shown?.port ?? "")}
        confirmLabel={m.remove.confirm}
        pending={remove.isPending}
        onConfirm={() => {
          if (!target) return;
          remove.mutate(
            { account: account.id, port: target.port, key: newIdempotencyKey() },
            {
              onSuccess: () => {
                toast.success(m.remove.deleted(target.port), m.remove.deletedDetail);
                deleted.current = true;
                setTarget(null);
              },
              onError: (e) => {
                reportFailure(m.remove.intent(target.port), e);
              },
              onSettled: refreshGates,
            },
          );
        }}
        // The row that opened it leaves: focus goes to the page title, not to the page.
        onCloseAutoFocus={(e) => {
          if (!deleted.current) return;
          deleted.current = false;
          e.preventDefault();
          document.getElementById("page-title")?.focus({ preventScroll: true });
        }}
      >
        <p>{m.remove.body}</p>
        {shown && usedBy(shown.port).length ? (
          <p className="text-warning">{m.remove.usedBy(usedBy(shown.port).map((f) => f.binding.name))}</p>
        ) : null}
      </ConfirmDialog>
    </PropertySection>
  );
}
