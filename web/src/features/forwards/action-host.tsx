// The forward actions bound to their effects, and the dialogs behind them — once per page, so a row's menu, the
// inspector and a link (`?do=edit|delete` on the forward's page) open the very same dialog
// (docs/frontend-design.md §8.1). The switch is sent in place (actions.ts); editing and deleting open their dialog here.
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import { useApps, useInstances, useProfiles, useProviderAccounts } from "@/api/queries";
import type { ForwardView } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { airvpnAccountOf } from "@/features/providers/ports";
import { useQueryParam } from "@/lib/url";
import {
  type ForwardActionId,
  forwardActions,
  sendForwardDelete,
  sendForwardEnabled,
  testProblemOf,
  useForwardSending,
} from "./actions";
import { ForwardDialog } from "./forward-dialog";
import { m } from "./messages";
import { PROTOCOL_LABEL, providerGuide } from "./model";

type DialogKind = "edit" | "delete";

const DIALOGS: ReadonlySet<string> = new Set<DialogKind>(["edit", "delete"]);

interface Host {
  open: (kind: DialogKind, f: ForwardView) => void;
}

const HostContext = createContext<Host | null>(null);

/**
 * The actions of forward `f`, bound: what each one does and whether its intent is on its way. `own` binds the actions a
 * view runs itself (the inspector's 測試連入 shows its own result).
 */
export function useForwardActions(
  f: ForwardView,
  own: Partial<Record<ForwardActionId, { run: () => void; pending: boolean }>> = {},
): EntityAction<ForwardActionId>[] {
  const host = useContext(HostContext);
  const navigate = useNavigate();
  const sending = useForwardSending(f.binding.id);
  const blocked = useMutationBlocked();
  const instances = useInstances();
  const apps = useApps();
  const profiles = useProfiles();
  const accounts = useProviderAccounts();
  const b = f.binding;
  const owner = instances.data?.find((v) => v.spec.id === b.instance_id);
  const account = airvpnAccountOf(owner, profiles.data ?? [], accounts.data ?? []);
  const ctx = {
    sending,
    unsupported: providerGuide(owner).unsupported,
    testProblem: testProblemOf(b.protocol, Boolean(account), blocked),
    appKnown: Boolean(apps.data?.some((a) => a.spec.id === b.target_app_id)),
    ownerKnown: Boolean(owner),
  };
  const run = (id: ForwardActionId) => {
    switch (id) {
      case "enable":
      case "disable":
        void sendForwardEnabled(f, id === "enable");
        return;
      case "edit":
      case "delete":
        host?.open(id, f);
        return;
      case "open_app":
        void navigate(`/apps/${b.target_app_id}`);
        return;
      case "open_instance":
        void navigate(`/instances/${b.instance_id}`);
        return;
      case "test":
        return;
    }
  };
  return forwardActions(f, ctx).map((spec) => {
    const bound = own[spec.id];
    return {
      ...spec,
      pending:
        bound?.pending ??
        ((spec.id === "enable" || spec.id === "disable" || spec.id === "delete") && spec.id === sending),
      run:
        bound?.run ??
        (() => {
          run(spec.id);
        }),
    };
  });
}

function DeleteConfirm({
  f,
  open,
  onOpenChange,
}: {
  f: ForwardView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const navigate = useNavigate();
  const { search } = useLocation();
  const { id: selected } = useParams();
  const sending = useForwardSending(f.binding.id);
  const [deleted, setDeleted] = useState(false);
  const b = f.binding;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setDeleted(false);
        onOpenChange(o);
      }}
      title={m.deleteConfirm.title(b.name)}
      confirmLabel={ui.common.delete}
      pending={sending === "delete"}
      onConfirm={() =>
        void sendForwardDelete(f, () => {
          setDeleted(true);
          onOpenChange(false);
          if (selected === b.id) void navigate(`/forwards${search}`);
        })
      }
      // The row or inspector that opened it is gone: focus goes to the page title, not to the page.
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{m.deleteConfirm.stops(b.tunnel_port, PROTOCOL_LABEL[b.protocol])}</p>
      <p>{m.deleteConfirm.unaffected}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the forward dialogs for one page. `forwards` are the page's forwards (live): a dialog shows the latest facts of
 * the forward it was opened for, and the facts it was opened with once it is gone, so its exit still plays.
 */
export function ForwardActionHost({ forwards, children }: { forwards: readonly ForwardView[]; children: ReactNode }) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: ForwardView; open: boolean } | null>(null);
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.binding.id, opened, open: true });
      },
    }),
    [],
  );
  const f = state ? (forwards.find((x) => x.binding.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=<action>` (from a link): open that dialog for the selected forward once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = forwards.find((x) => x.binding.id === id);
    if (!target) return;
    setRequest(null);
    if (DIALOGS.has(request)) host.open(request as DialogKind, target);
  }, [request, id, forwards, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {f ? (
        <>
          <ForwardDialog open={shown("edit")} onOpenChange={change("edit")} forward={f} />
          <DeleteConfirm f={f} open={shown("delete")} onOpenChange={change("delete")} />
        </>
      ) : null}
    </HostContext.Provider>
  );
}
