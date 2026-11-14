// How the OS confines a worker or an App run: the limits in force as the kernel accepted them,
// the ones that are not with the host's reason, and the cgroup's memory in use.
// Rows for an evidence list (`Facts`, the default) or an inspector property grid (`PropertyGrid`,
// variant="properties"): the same facts, labels and sources either way.

import type { ReactNode } from "react";
import type { ResourceStatus } from "@/api/types";
import { Fact } from "@/components/ui/facts";
import { PropertyRow } from "@/components/ui/inspector";
import { m as ui } from "@/components/ui/messages";
import { localized } from "@/i18n";
import { formatBytes, relativeTime } from "@/lib/format";
import { m } from "./messages";
import { LIMIT_LABEL, resourceLines } from "./model";

type Variant = "facts" | "properties";

function Row({
  variant,
  label,
  source,
  mono,
  children,
}: {
  variant: Variant;
  label: string;
  source?: ReactNode;
  mono?: boolean;
  children: ReactNode;
}) {
  return variant === "properties" ? (
    <PropertyRow label={label} hint={source} mono={mono}>
      {children}
    </PropertyRow>
  ) : (
    <Fact label={label} source={source} mono={mono}>
      {children}
    </Fact>
  );
}

export function ResourceFacts({ r, now, variant = "facts" }: { r: ResourceStatus; now: number; variant?: Variant }) {
  const { inForce, notInForce } = resourceLines(r);
  const notes = r.enforced.filter((e) => e.note);
  return (
    <>
      <Row
        variant={variant}
        label={m.inForce}
        mono={inForce.length > 0}
        source={r.cgroup ? <span className="font-mono">{r.cgroup}</span> : undefined}
      >
        {inForce.length ? (
          inForce.map((l) => <div key={l}>{l}</div>)
        ) : (
          <span className="font-sans text-fg-secondary">{ui.common.none}</span>
        )}
        {notes.map((e) => (
          <div key={e.kind} className="font-sans text-caption text-warning">
            {m.note(LIMIT_LABEL[e.kind], e.note ? localized(e.note) : "")}
          </div>
        ))}
      </Row>
      {notInForce.length ? (
        <Row variant={variant} label={m.notInForce}>
          {notInForce.map((u) => (
            <div key={u.reason}>
              <span className="text-warning">{m.unenforced(u.kinds)}</span>
              <span className="text-fg-secondary">{m.unenforcedReason(u.reason)}</span>
            </div>
          ))}
        </Row>
      ) : null}
      {r.memory_bytes !== null ? (
        <Row
          variant={variant}
          label={m.cgroupUsage}
          mono
          source={`memory.current · ${relativeTime(r.observed_at, now)}`}
        >
          {formatBytes(r.memory_bytes)}
          {r.oom_kills ? <span className="ml-2 font-sans text-danger">{m.oomKills(r.oom_kills)}</span> : null}
        </Row>
      ) : null}
    </>
  );
}
