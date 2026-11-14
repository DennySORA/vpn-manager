// 最近操作 (系統 › 操作紀錄): what this installation was asked to do and how each request ended, newest first. A
// result that is unknown (the reply was lost) is said plainly, with what to do about it.

import { useQueryClient } from "@tanstack/react-query";
import { History } from "lucide-react";
import { keys, useOperations } from "@/api/queries";
import type {
  AppView,
  BlocklistView,
  ForwardView,
  GatewaySpec,
  InstanceView,
  Operation,
  OperationStatus,
  ProviderAccount,
  RuntimeProfile,
} from "@/api/types";
import { Tag } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { localized } from "@/i18n";
import { absoluteTime, relativeTime } from "@/lib/format";
import type { Tone } from "@/lib/status";
import { useServerNow } from "@/lib/server-clock";
import { m } from "./operations/messages";

/** Operation kinds in words. A kind not listed here shows as itself. */
export const OPERATION_LABEL: Record<string, string> = m.kind;

const STATUS: Record<OperationStatus, { label: string; tone: Tone }> = {
  accepted: { label: m.status.accepted, tone: "info" },
  running: { label: m.status.running, tone: "info" },
  succeeded: { label: m.status.succeeded, tone: "success" },
  failed: { label: m.status.failed, tone: "danger" },
  unknown: { label: m.status.unknown, tone: "warning" },
  cancelled: { label: m.status.cancelled, tone: "neutral" },
};

/** Names of the objects operations point at, from what the page already loaded (no extra requests). */
function useNames(): Map<string, string> {
  const qc = useQueryClient();
  const names = new Map<string, string>();
  for (const v of qc.getQueryData<InstanceView[]>(keys.instances) ?? []) {
    names.set(v.spec.id, v.spec.name);
    for (const g of v.gateways) names.set(g.id, m.gateway(g.name, g.port));
  }
  for (const p of qc.getQueryData<RuntimeProfile[]>(keys.profiles) ?? []) names.set(p.id, p.name);
  for (const g of qc.getQueryData<GatewaySpec[]>(keys.gateways) ?? []) names.set(g.id, m.gateway(g.name, g.port));
  for (const a of qc.getQueryData<ProviderAccount[]>(keys.providerAccounts) ?? []) names.set(a.id, a.label);
  for (const a of qc.getQueryData<AppView[]>(keys.apps) ?? []) names.set(a.spec.id, a.spec.name);
  for (const f of qc.getQueryData<ForwardView[]>(keys.forwards) ?? []) names.set(f.binding.id, f.binding.name);
  for (const v of qc.getQueryData<BlocklistView[]>(keys.blocklists) ?? []) names.set(v.blocklist.id, v.blocklist.name);
  for (const [key, field] of [
    [keys.dns, "name"],
    [keys.security, "name"],
    [keys.sshHosts, "alias"],
  ] as const) {
    for (const e of qc.getQueryData<Record<string, unknown>[]>(key) ?? []) {
      if (typeof e.id === "string" && typeof e[field] === "string") names.set(e.id, e[field]);
    }
  }
  return names;
}

function Row({ op, names, now }: { op: Operation; names: Map<string, string>; now: number }) {
  const look = STATUS[op.status];
  const label = OPERATION_LABEL[op.kind];
  // A creation names what it made in its results.
  const ref = op.target_id ?? op.result_refs[0];
  const target = ref ? names.get(ref) : undefined;
  return (
    <li className="space-y-1 px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <p className="min-w-0 text-data text-fg">
          {label ?? <span className="font-mono">{op.kind}</span>}
          {target ? <span className="text-fg-secondary"> · {target}</span> : null}
        </p>
        <Tag tone={look.tone}>{look.label}</Tag>
      </div>
      <p className="text-caption text-fg-tertiary" title={absoluteTime(op.created_at)}>
        {relativeTime(op.created_at, now)}
        {op.durable ? "" : m.notDurable}
      </p>
      {op.error ? <p className="text-caption text-danger">{localized(op.error.message)}</p> : null}
      {op.status === "unknown" ? <p className="text-caption text-warning">{m.unknownAdvice}</p> : null}
    </li>
  );
}

/** The newest operations, polled while shown; names come from what the page already loaded (no extra requests). */
export function OperationsList({ enabled }: { enabled: boolean }) {
  const ops = useOperations(enabled);
  const names = useNames();
  const now = useServerNow();
  if (ops.isError) return <ErrorState compact error={ops.error} onRetry={() => void ops.refetch()} title={m.failed} />;
  if (!ops.data) return <LoadingRows rows={5} label={m.loading} />;
  if (!ops.data.length)
    return (
      <EmptyState icon={History} title={m.empty}>
        {m.emptyBody}
      </EmptyState>
    );
  return (
    <div>
      <ul className="divide-y divide-line">
        {ops.data.map((op) => (
          <Row key={op.id} op={op} names={names} now={now} />
        ))}
      </ul>
      <p className="px-4 py-3 text-caption text-fg-tertiary">{m.limit}</p>
    </div>
  );
}
