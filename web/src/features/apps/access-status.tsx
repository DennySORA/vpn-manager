// The App inspector's 「本機存取埠」: each published port, where to open it, and what the manager
// sees — listening or not, whether the App listens inside its sandbox, refusals and errors. A
// collapsible property section (docs/frontend-design.md §8.1); the ports come and go with presence.

import { Plug } from "lucide-react";
import type { AppView } from "@/api/types";
import { StatusPill, Tag } from "@/components/ui/badge";
import { ChangeValue } from "@/components/ui/change-value";
import { PropertySection } from "@/components/ui/inspector";
import { PresenceList } from "@/components/ui/presence-list";
import { localized } from "@/i18n";
import { relativeTime } from "@/lib/format";
import { UNKNOWN_STATE } from "@/lib/status";
import { ACCESS_STATE, accessUrls, BIND_LABEL } from "./access";
import { AccessUrls } from "./access-editor";
import { m as access } from "./access/messages";

export function AccessPortsSection({
  app,
  hostAddresses,
  now,
}: {
  app: AppView;
  hostAddresses: string[];
  now: number;
}) {
  const statuses = app.status?.access ?? [];
  return (
    <PropertySection title={access.title} icon={<Plug aria-hidden />} count={app.spec.access_ports.length}>
      <PresenceList
        items={app.spec.access_ports}
        keyOf={(p) => String(p.host_port)}
        className="grid grid-cols-1 gap-2"
        label={access.title}
      >
        {(p) => {
          const s = statuses.find((x) => x.host_port === p.host_port) ?? null;
          return (
            <div className="grid grid-cols-1 gap-1.5 rounded-lg border border-line-subtle bg-sunken/50 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="machine text-data text-fg">
                  App :{p.app_port} → {p.bind === "lan" ? "0.0.0.0" : "127.0.0.1"}:{p.host_port}
                </span>
                <Tag tone={p.bind === "lan" ? "warning" : "neutral"}>{BIND_LABEL[p.bind].title}</Tag>
                <span className="ml-auto">
                  <StatusPill look={s ? ACCESS_STATE[s.state] : UNKNOWN_STATE} />
                </span>
              </div>
              <AccessUrls urls={accessUrls(p.bind, p.host_port, hostAddresses)} />
              {p.bind === "lan" ? (
                <p className="text-caption text-fg-tertiary">{access.status.allowed(p.allow)}</p>
              ) : null}
              {s?.app_listening === false ? (
                <p className="text-caption text-warning">{access.status.notListening(p.app_port)}</p>
              ) : s?.app_listening ? (
                <p className="text-caption text-fg-tertiary">{access.status.listening(p.app_port)}</p>
              ) : null}
              {s ? (
                <p className="text-caption text-fg-tertiary">
                  {access.status.counts(
                    <ChangeValue value={s.accepted} className="machine" />,
                    <ChangeValue value={s.refused} className="machine" />,
                  )}
                </p>
              ) : (
                <p className="text-caption text-fg-tertiary">{access.status.notReported}</p>
              )}
              {s?.last_error ? (
                <p className="text-caption text-danger" role="alert">
                  {access.status.errorAt(localized(s.last_error.message), relativeTime(s.last_error.at, now))}
                </p>
              ) : null}
              {s?.last_refused ? (
                <p className="text-caption text-fg-tertiary [overflow-wrap:anywhere]">
                  {access.status.lastRefused(localized(s.last_refused.message), relativeTime(s.last_refused.at, now))}
                </p>
              ) : null}
            </div>
          );
        }}
      </PresenceList>
    </PropertySection>
  );
}
