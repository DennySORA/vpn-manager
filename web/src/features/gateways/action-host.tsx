// The proxy-port actions bound to their effects, and the dialogs behind them — once per page, so a row's menu, the
// inspector and a link (`?do=edit|delete` on the port's page) open the very same dialog
// (docs/frontend-design.md §8.1). The switch is sent in place (actions.ts); editing and deleting open their dialog here.
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import type { GatewaySpec, InstanceView } from "@/api/types";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { useQueryParam } from "@/lib/url";
import {
  copyAddress,
  type GatewayActionId,
  gatewayActions,
  proxyAddress,
  sendDelete,
  sendEnabled,
  useGatewaySending,
} from "./actions";
import { GatewayDialog } from "./gateway-dialog";
import { m } from "./messages";

type DialogKind = "edit" | "delete";

const DIALOGS: ReadonlySet<string> = new Set<DialogKind>(["edit", "delete"]);

interface Host {
  open: (kind: DialogKind, g: GatewaySpec) => void;
}

const HostContext = createContext<Host | null>(null);

/** The actions of port `g`, bound: what each one does and whether its intent is on its way. */
export function useGatewayActions(g: GatewaySpec, owner: InstanceView | undefined): EntityAction<GatewayActionId>[] {
  const host = useContext(HostContext);
  const navigate = useNavigate();
  const sending = useGatewaySending(g.id);
  const run = (id: GatewayActionId) => {
    switch (id) {
      case "enable":
      case "disable":
        void sendEnabled(g, id === "enable");
        return;
      case "edit":
      case "delete":
        host?.open(id, g);
        return;
      case "copy_address":
        void copyAddress(g);
        return;
      case "open_instance":
        void navigate(`/instances/${g.instance_id}`);
        return;
    }
  };
  return gatewayActions(g, { sending, ownerKnown: Boolean(owner) }).map((spec) => ({
    ...spec,
    pending: (spec.id === "enable" || spec.id === "disable" || spec.id === "delete") && spec.id === sending,
    run: () => {
      run(spec.id);
    },
  }));
}

function DeleteConfirm({
  g,
  open,
  onOpenChange,
}: {
  g: GatewaySpec;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const navigate = useNavigate();
  const { search } = useLocation();
  const { id: selected } = useParams();
  const sending = useGatewaySending(g.id);
  const [deleted, setDeleted] = useState(false);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setDeleted(false);
        onOpenChange(o);
      }}
      title={m.deleteConfirm.title(g.name)}
      confirmLabel={ui.common.delete}
      pending={sending === "delete"}
      onConfirm={() =>
        void sendDelete(g, () => {
          setDeleted(true);
          onOpenChange(false);
          if (selected === g.id) void navigate(`/gateways${search}`);
        })
      }
      // The row or inspector that opened it is gone: focus goes to the page title, not to the page.
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{m.deleteConfirm.body(proxyAddress(g))}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the proxy-port dialogs for one page. `gateways` are the page's ports (live): a dialog shows the latest facts of
 * the port it was opened for, and the facts it was opened with once the port is gone, so its exit still plays.
 */
export function GatewayActionHost({ gateways, children }: { gateways: readonly GatewaySpec[]; children: ReactNode }) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: GatewaySpec; open: boolean } | null>(null);
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.id, opened, open: true });
      },
    }),
    [],
  );
  const g = state ? (gateways.find((x) => x.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=<action>` (from a link): open that dialog for the selected port once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = gateways.find((x) => x.id === id);
    if (!target) return;
    setRequest(null);
    if (DIALOGS.has(request)) host.open(request as DialogKind, target);
  }, [request, id, gateways, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {g ? (
        <>
          <GatewayDialog open={shown("edit")} onOpenChange={change("edit")} gateway={g} />
          <DeleteConfirm g={g} open={shown("delete")} onOpenChange={change("delete")} />
        </>
      ) : null}
    </HostContext.Provider>
  );
}
