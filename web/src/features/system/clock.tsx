// 執行環境's 時間 panel: the host's clock as the server tells it, how far it stands from this device's, and whether
// something keeps it synchronized. Live figures are judged in the host's time (lib/server-clock), so a gap between the
// two clocks no longer blanks them; a gap of a few seconds or more is said here, with what to do about it.
import { Clock } from "lucide-react";
import type { CSSProperties } from "react";
import { useSystemStatus } from "@/api/queries";
import { StatusPill } from "@/components/ui/badge";
import { PropertyGrid, PropertyRow } from "@/components/ui/inspector";
import { STAGGER_IN } from "@/components/ui/look";
import { Panel } from "@/components/ui/panel";
import { Callout } from "@/components/ui/states";
import { absoluteTime } from "@/lib/format";
import { CLOCK_SKEW_NOTICE_MS, useServerNow, useServerOffset } from "@/lib/server-clock";
import { m } from "./diagnostics/messages";
import { clockSkewText, clockSyncLook } from "./model";

function syncText(synchronized: boolean | null | undefined): string {
  if (synchronized === true) return m.clock.synced;
  if (synchronized === false) return m.clock.notSynced;
  return m.clock.unknown;
}

export function HostClock({ style }: { style?: CSSProperties }) {
  const sys = useSystemStatus();
  const offset = useServerOffset();
  const now = useServerNow();
  const synchronized = sys.data?.clock_synchronized;
  const skewed = offset !== null && Math.abs(offset) >= CLOCK_SKEW_NOTICE_MS;
  return (
    <Panel
      icon={Clock}
      title={m.clock.title}
      action={typeof synchronized === "boolean" ? <StatusPill look={clockSyncLook(synchronized)} /> : undefined}
      style={style}
      className={STAGGER_IN}
    >
      {skewed ? (
        <Callout tone="warning" title={m.clock.skewed(clockSkewText(offset))} className="mb-3">
          {m.clock.skewedBody(synchronized)}
        </Callout>
      ) : null}
      <PropertyGrid>
        <PropertyRow label={m.clock.hostTime} mono>
          {absoluteTime(new Date(now).toISOString())}
        </PropertyRow>
        <PropertyRow label={m.clock.versus} hint={m.clock.versusHint}>
          {offset === null ? m.clock.notYet : clockSkewText(offset)}
        </PropertyRow>
        <PropertyRow label={m.clock.sync}>{syncText(synchronized)}</PropertyRow>
      </PropertyGrid>
    </Panel>
  );
}
