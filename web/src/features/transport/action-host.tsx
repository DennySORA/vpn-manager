// The transport profile actions bound to their effects, and the confirmation behind 刪除 — once per page, so a row's ⋯
// menu, the editor's ⋯ menu and a link (`?do=delete` on the profile's page) open the very same dialog
// (docs/frontend-design.md §8.1). The editor binds 儲存 itself (it owns the draft); 複製 opens a new profile that starts
// from this one.
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import type { TransportProfile } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { allowNextNavigation } from "@/components/unsaved";
import { useQueryParam } from "@/lib/url";
import { sendTransportDelete, type TransportActionId, transportActions, useTransportSending } from "./actions";
import { m } from "./messages";
import type { Choice } from "./model";

interface Host {
  confirmDelete: (p: TransportProfile) => void;
}

const HostContext = createContext<Host | null>(null);

type Own = Partial<Record<TransportActionId, { run: () => void; pending: boolean }>>;

/**
 * The actions of profile `c`, bound: what each one does and whether it is on its way. `own` binds what the editor runs
 * itself (儲存), `dirty` is its draft's state; `users` and `namedBy` are what still uses the profile.
 */
export function useTransportActions(
  c: Choice | null,
  uses: { users: number; namedBy: readonly string[] },
  opts: { dirty?: boolean; own?: Own } = {},
): EntityAction<TransportActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const navigate = useNavigate();
  const sending = useTransportSending(c?.saved?.id ?? "");
  if (!c) return [];
  return transportActions(c, { blocked, ...uses, dirty: opts.dirty, sending }).map((spec) => {
    const bound = opts.own?.[spec.id];
    const run = () => {
      if (spec.id === "copy") void navigate(`/transport/new?from=${encodeURIComponent(c.value)}`);
      else if (spec.id === "delete" && c.saved) host?.confirmDelete(c.saved);
    };
    return {
      ...spec,
      pending: bound?.pending ?? (spec.id === "delete" && sending === "delete"),
      run: bound?.run ?? run,
    };
  });
}

function DeleteConfirm({
  p,
  open,
  onOpenChange,
}: {
  p: TransportProfile;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const navigate = useNavigate();
  const { id: selected } = useParams();
  const sending = useTransportSending(p.id);
  const [deleted, setDeleted] = useState(false);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setDeleted(false);
        onOpenChange(o);
      }}
      title={m.deleteConfirm.title(p.name)}
      confirmLabel={ui.common.delete}
      pending={sending === "delete"}
      onConfirm={() =>
        void sendTransportDelete(p, () => {
          setDeleted(true);
          onOpenChange(false);
          if (selected === p.id) {
            // The editor of a deleted profile has nothing left to save.
            allowNextNavigation();
            void navigate("/transport");
          }
        })
      }
      // The row or editor that opened it is gone: focus goes to the page title.
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{m.deleteConfirm.unused}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the transport profile dialogs for one page. `profiles` are the page's saved profiles (live): the dialog shows
 * the latest facts of the profile it was opened for, and the ones it was opened with once the profile is gone, so its
 * exit still plays.
 */
export function TransportActionHost({
  profiles,
  children,
}: {
  profiles: readonly TransportProfile[];
  children: ReactNode;
}) {
  const [state, setState] = useState<{ id: string; opened: TransportProfile; open: boolean } | null>(null);
  const host = useMemo<Host>(
    () => ({
      confirmDelete: (opened) => {
        setState({ id: opened.id, opened, open: true });
      },
    }),
    [],
  );
  const p = state ? (profiles.find((x) => x.id === state.id) ?? state.opened) : undefined;

  // `?do=delete` (from a link): open the confirmation for the selected profile once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = profiles.find((x) => x.id === id);
    if (!target) return;
    setRequest(null);
    if (request === "delete") host.confirmDelete(target);
  }, [request, id, profiles, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {p ? (
        <DeleteConfirm
          p={p}
          open={Boolean(state?.open)}
          onOpenChange={(open) => {
            setState((s) => (s ? { ...s, open } : s));
          }}
        />
      ) : null}
    </HostContext.Provider>
  );
}
