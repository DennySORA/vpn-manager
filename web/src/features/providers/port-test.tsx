import type { UseMutationResult } from "@tanstack/react-query";
import type { LucideIcon } from "lucide-react";
import {
  ArrowRight,
  CircleCheck,
  CircleDashed,
  CircleQuestionMark,
  CircleX,
  LoaderCircle,
  RefreshCw,
  TriangleAlert,
} from "lucide-react";
import { describeFailure } from "@/api/client";
import type { ForwardedPort, ForwardedPortTest, PortTestState } from "@/api/types";
import { StatusPill } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { STAGGER_IN } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { staggerStyle } from "@/components/ui/motion";
import { Callout } from "@/components/ui/states";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { deviceLabel, endpoint, PORT_PROTOCOL, serverText, testLook } from "./ports";
import { m } from "./ports/messages";

const TEST_ICON: Record<PortTestState, LucideIcon> = {
  open: CircleCheck,
  closed: CircleX,
  warning: TriangleAlert,
  unknown: CircleQuestionMark,
  not_tested: CircleDashed,
};

type TestRun = UseMutationResult<ForwardedPortTest, Error, { account: string; port: number }>;

/** No AirVPN session uses the port: what makes one, then test again. */
function NoSession({ port }: { port: ForwardedPort }) {
  return (
    <Callout tone="info" title={m.test.noSession}>
      <ol className="list-decimal space-y-1 pl-4">
        <li>{m.test.steps.connect(port.device_id ? deviceLabel(port) : null)}</li>
        <li>{m.test.steps.listen(port.port)}</li>
        <li>{m.test.steps.again}</li>
      </ol>
    </Callout>
  );
}

/**
 * AirVPN's own test of one forwarded port (連入埠), run from the server of every connected session
 * that uses it — TCP only, as on AirVPN's website. Each session says what AirVPN found, in words
 * and with a symbol; only AirVPN's own "open" is shown as success.
 */
export function PortTestDialog({
  open,
  onOpenChange,
  port,
  run,
  onRetry,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The port as listed now (it may have gone meanwhile). */
  port: ForwardedPort | undefined;
  run: TestRun;
  onRetry: () => void;
}) {
  const result = run.data && run.data.port === port?.port ? run.data : undefined;
  let body;
  if (!port) {
    body = <Callout tone="warning" title={m.settings.gone} />;
  } else if (run.isPending) {
    body = (
      <p className="flex items-center gap-2 text-data text-fg-secondary">
        <LoaderCircle aria-hidden className="size-4 animate-spin" />
        {m.test.running(port.port)}
      </p>
    );
  } else if (run.isError) {
    body = (
      <Callout tone="danger" title={m.test.failed}>
        {describeFailure(run.error)}
      </Callout>
    );
  } else if (result && !result.sessions.length) {
    body = <NoSession port={port} />;
  } else if (result) {
    body = (
      <>
        <ul
          className="divide-y divide-line-subtle rounded-lg border border-line-subtle bg-sunken/40"
          aria-label={m.test.results}
        >
          {result.sessions.map((s, i) => {
            const look = testLook(s);
            return (
              <li
                key={`${s.server_ip}-${s.protocol}-${s.ip_layer}-${i}`}
                style={staggerStyle(i)}
                className={cn("space-y-1 px-3 py-2.5", STAGGER_IN)}
              >
                <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                  <StatusPill look={{ ...look, icon: TEST_ICON[s.state] }} />
                  <span className="text-data text-fg-secondary">
                    {PORT_PROTOCOL[s.protocol]} · {s.ip_layer === "ipv6" ? "IPv6" : "IPv4"}
                  </span>
                  <span className="min-w-0 text-data text-fg [overflow-wrap:anywhere]">{serverText(s)}</span>
                </div>
                <p className="machine flex flex-wrap items-center gap-1.5 text-caption text-fg-secondary">
                  <span title={m.test.outside}>{endpoint(s.server_ip, s.port)}</span>
                  <ArrowRight aria-hidden className="size-3.5 text-fg-tertiary" />
                  <span className="sr-only">{m.test.deliveredTo}</span>
                  <span title={m.test.delivered}>
                    {s.client_ip ? endpoint(s.client_ip, s.local_port) : `port ${s.local_port}`}
                  </span>
                  {s.device_name ? (
                    <span className="font-sans text-fg-tertiary">{m.test.device(s.device_name)}</span>
                  ) : null}
                </p>
                {s.message ? (
                  <p className="text-caption text-fg-tertiary [overflow-wrap:anywhere]">
                    {s.state === "not_tested" ? localized(s.message) : m.test.said(localized(s.message))}
                  </p>
                ) : null}
              </li>
            );
          })}
        </ul>
        <p className="text-caption text-fg-tertiary">
          {m.test.testedAt(new Date(result.observed_at).toLocaleTimeString(intlLocale))}
        </p>
      </>
    );
  }
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.test.title(port?.port ?? "")}
      description={m.test.description}
      footer={
        <>
          <Button
            variant="quiet"
            onClick={() => {
              onOpenChange(false);
            }}
          >
            {ui.common.close}
          </Button>
          <Button
            variant="primary"
            icon={RefreshCw}
            pending={run.isPending}
            pendingLabel={m.actions.testing}
            disabled={!port}
            onClick={onRetry}
          >
            {m.test.again}
          </Button>
        </>
      }
    >
      {/* Focus lands on the result, which is announced when it changes. */}
      <div
        data-autofocus
        tabIndex={-1}
        aria-live="polite"
        aria-busy={run.isPending || undefined}
        className="space-y-3 focus:outline-none"
      >
        {port && !port.enabled ? (
          <Callout tone="warning" title={m.test.portDisabled}>
            {m.test.portDisabledHint}
          </Callout>
        ) : null}
        {body}
      </div>
    </Dialog>
  );
}
