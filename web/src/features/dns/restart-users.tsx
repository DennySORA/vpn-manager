// A saved DNS or security profile applies to a running connection only after it restarts. The editor says so first —
// its conclusion, from what the manager reports (`running.pending_changes`), never guessed — and offers the very action
// the notification after saving offers, "重新啟動使用中的 N 條連線" (docs/frontend-design.md §8 rule 5), confirmed with
// its exact scope because a restart interrupts those connections.
import { RotateCw } from "lucide-react";
import { useState } from "react";
import type { InstanceView } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { restartPending } from "@/features/instances/actions";
import { isRunning, usesConfig } from "@/features/instances/model";
import { m } from "./messages";

/**
 * Running connections built on this DNS or security profile whose worker still runs an earlier version of it, as the
 * manager reports it. Stopped or emergency-stopped ones are left alone (a restart would start them).
 */
export function pendingUsers(views: readonly InstanceView[], kind: "dns" | "security", id: string): InstanceView[] {
  return views.filter(
    (v) =>
      usesConfig(v, kind, id) &&
      isRunning(v) &&
      !v.status?.intent.emergency_latched &&
      (v.status?.running?.pending_changes ?? []).includes(kind),
  );
}

export function RestartUsers({
  views,
  kind,
  id,
}: {
  views: readonly InstanceView[];
  kind: "dns" | "security";
  id: string;
}) {
  const blocked = useMutationBlocked();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const targets = pendingUsers(views, kind, id);
  const n = targets.length;
  const names = targets.map((v) => v.spec.name);
  const label = m.restart.offer(n);
  return (
    <>
      {n ? (
        <Callout
          tone="warning"
          title={m.restart.stillEarlier(n)}
          actions={
            <ActionButton
              size="sm"
              icon={RotateCw}
              pending={pending}
              pendingLabel={ui.common.restarting}
              disabledReason={pending ? null : blocked}
              onClick={() => {
                setOpen(true);
              }}
            >
              {label}
            </ActionButton>
          }
        >
          {m.restart.waiting(names)}
        </Callout>
      ) : null}
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        tone="primary"
        title={m.restart.confirmTitle(n)}
        confirmLabel={m.restart.confirm(n)}
        pending={pending}
        onConfirm={() => {
          setPending(true);
          // Who to restart is decided again now, from the latest facts.
          void restartPending(pendingUsers(views, kind, id)).finally(() => {
            setPending(false);
            setOpen(false);
          });
        }}
      >
        <p>{m.restart.rebuilt(names, kind)}</p>
        <p>{m.restart.interrupts(n)}</p>
      </ConfirmDialog>
    </>
  );
}
