// The connection actions bound to their effects, and the dialogs behind them — once per page, so a row's menu, the
// inspector and a link (`?do=<action>` on the connection's page) open the very same dialog
// (docs/frontend-design.md §8.1). Lifecycle intents are sent in place (actions.ts); editing, a new proxy port, the
// emergency stop and deleting open their dialog here. A closing dialog keeps showing the connection it was opened for
// until its exit has played.
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import { useDeleteInstance } from "@/api/queries";
import type { InstanceView } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { GatewayDialog } from "@/features/gateways/gateway-dialog";
import { useQueryParam } from "@/lib/url";
import {
  type InstanceActionId,
  instanceActions,
  sendEmergencyStop,
  sendLifecycle,
  sendsOf,
  useSending,
} from "./actions";
import { m } from "./dialogs/messages";
import { InstanceDialog } from "./instance-dialog";

type DialogKind = "edit" | "add_gateway" | "emergency_stop" | "delete";

const DIALOGS: ReadonlySet<InstanceActionId> = new Set<InstanceActionId>([
  "edit",
  "add_gateway",
  "emergency_stop",
  "delete",
]);

interface Host {
  open: (kind: DialogKind, view: InstanceView) => void;
}

const HostContext = createContext<Host | null>(null);

/** What pressing an action of `v` does: send its intent, or open its dialog on the page's host. */
function runAction(v: InstanceView, id: InstanceActionId, host: Host | null) {
  if (DIALOGS.has(id)) {
    host?.open(id as DialogKind, v);
    return;
  }
  const sends = sendsOf(id);
  if (sends === "emergency_stop") void sendEmergencyStop(v);
  else if (sends) void sendLifecycle(v, sends);
}

/**
 * The actions of `v`, bound: what each one does and whether its intent is on its way. `own` binds the actions a view
 * runs itself (the inspector's 檢查出口 IP shows its own result).
 */
export function useInstanceActions(
  v: InstanceView,
  own: Partial<Record<InstanceActionId, { run: () => void; pending: boolean }>> = {},
): EntityAction<InstanceActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const sending = useSending(v.spec.id);
  return instanceActions(v, { blocked, sending }).map((spec) => {
    const bound = own[spec.id];
    const sends = sendsOf(spec.id);
    return {
      ...spec,
      pending: bound?.pending ?? (sends !== null && sends === sending),
      run:
        bound?.run ??
        (() => {
          runAction(v, spec.id, host);
        }),
    };
  });
}

function EmergencyConfirm({
  view,
  open,
  onOpenChange,
}: {
  view: InstanceView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const sending = useSending(view.spec.id);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.emergency.title(view.spec.name)}
      confirmLabel={m.emergency.confirm}
      pending={sending === "emergency_stop"}
      onConfirm={() =>
        void sendEmergencyStop(view, () => {
          onOpenChange(false);
        })
      }
    >
      <p>
        {m.emergency.body(view.gateways.length, (text) => (
          <strong className="font-medium text-fg">{text}</strong>
        ))}
      </p>
      <p>{m.emergency.latches}</p>
    </ConfirmDialog>
  );
}

function DeleteConfirm({
  view,
  open,
  onOpenChange,
}: {
  view: InstanceView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const deleteInstance = useDeleteInstance();
  const navigate = useNavigate();
  const { search } = useLocation();
  const { id: selected } = useParams();
  const [deleted, setDeleted] = useState(false);
  // One request: the Instance and exactly these Gateways go together, or nothing changes.
  const run = () => {
    deleteInstance.mutate(
      {
        id: view.spec.id,
        revision: view.spec.revision,
        gateways: view.gateways.map((g) => g.id),
        key: newIdempotencyKey(),
      },
      {
        onSuccess: () => {
          setDeleted(true);
          onOpenChange(false);
          toast.success(m.delete.done(view.spec.name));
          if (selected === view.spec.id) void navigate(`/instances${search}`);
        },
        onError: (e) => {
          reportFailure(m.delete.intent(view.spec.name), e);
        },
      },
    );
  };
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setDeleted(false);
        onOpenChange(o);
      }}
      title={m.delete.title(view.spec.name)}
      confirmLabel={ui.common.delete}
      pending={deleteInstance.isPending}
      onConfirm={run}
      // The row or inspector that opened it is gone: focus goes to the page title, not to the page.
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{m.delete.body(view.gateways.map((g) => g.port))}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the connection dialogs for one page. `views` are the page's connections (live): a dialog shows the latest
 * facts of the connection it was opened for, and the facts it was opened with once the connection is gone (deleted),
 * so its exit still plays.
 */
export function InstanceActionHost({ views, children }: { views: readonly InstanceView[]; children: ReactNode }) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: InstanceView; open: boolean } | null>(
    null,
  );
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.spec.id, opened, open: true });
      },
    }),
    [],
  );
  const view = state ? (views.find((v) => v.spec.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=<action>` (from a link): open that dialog for the selected connection once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = views.find((v) => v.spec.id === id);
    if (!target) return;
    setRequest(null);
    if (DIALOGS.has(request as InstanceActionId)) host.open(request as DialogKind, target);
  }, [request, id, views, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {view ? (
        <>
          <InstanceDialog open={shown("edit")} onOpenChange={change("edit")} instance={view} />
          <EmergencyConfirm view={view} open={shown("emergency_stop")} onOpenChange={change("emergency_stop")} />
          <DeleteConfirm view={view} open={shown("delete")} onOpenChange={change("delete")} />
        </>
      ) : null}
      <GatewayDialog
        open={shown("add_gateway")}
        onOpenChange={change("add_gateway")}
        instanceId={state?.kind === "add_gateway" ? state.id : undefined}
      />
    </HostContext.Provider>
  );
}
