// The SSH host entry actions bound to their effects, and the confirmation behind 移除 — once per page, so a row's ⋯ menu,
// the editor's ⋯ menu and a link (`?do=remove` on the entry's page) open the very same dialog
// (docs/frontend-design.md §8.1). The editor binds 測試連線 and 儲存 itself (it owns the draft and shows the result).
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import type { SshHost } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { allowNextNavigation } from "@/components/unsaved";
import { useQueryParam } from "@/lib/url";
import { type SshActionId, sendSshRemove, sshActions, useSshSending } from "./actions";
import { m } from "./messages";

interface Host {
  confirmRemove: (h: SshHost) => void;
}

const HostContext = createContext<Host | null>(null);

type Own = Partial<Record<SshActionId, { run: () => void; pending: boolean }>>;

/** The actions of entry `h` (none for a new one), bound. `own` binds what the editor runs itself (測試連線, 儲存). */
export function useSshActions(
  h: SshHost | null,
  opts: { dirty?: boolean; own?: Own } = {},
): EntityAction<SshActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const sending = useSshSending(h?.id ?? "");
  if (!h) return [];
  return sshActions(h, { blocked, dirty: opts.dirty, sending }).map((spec) => {
    const bound = opts.own?.[spec.id];
    return {
      ...spec,
      pending: bound?.pending ?? (spec.id === "remove" && sending === "remove"),
      run: bound?.run ?? (() => (spec.id === "remove" ? host?.confirmRemove(h) : undefined)),
    };
  });
}

function RemoveConfirm({
  h,
  last,
  open,
  onOpenChange,
}: {
  h: SshHost;
  last: boolean;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const navigate = useNavigate();
  const { id: selected } = useParams();
  const sending = useSshSending(h.id);
  const [removed, setRemoved] = useState(false);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setRemoved(false);
        onOpenChange(o);
      }}
      title={m.remove.title(h.alias)}
      confirmLabel={m.actions.remove}
      pending={sending === "remove"}
      onConfirm={() =>
        void sendSshRemove(h, () => {
          setRemoved(true);
          onOpenChange(false);
          if (selected === h.id) {
            allowNextNavigation();
            void navigate("/ssh");
          }
        })
      }
      // The row or editor that opened it is gone: focus goes to the page title.
      onCloseAutoFocus={(e) => {
        if (!removed) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{h.kind === "overlay" ? m.remove.overlay(h.alias) : m.remove.host(h.alias)}</p>
      {last ? <p className="text-fg-tertiary">{m.remove.last}</p> : null}
    </ConfirmDialog>
  );
}

/**
 * Hosts the SSH entry dialogs for one page. `hosts` are the page's entries (live): the dialog shows the latest facts of
 * the entry it was opened for, and the ones it was opened with once the entry is gone, so its exit still plays.
 */
export function SshActionHost({ hosts, children }: { hosts: readonly SshHost[]; children: ReactNode }) {
  const [state, setState] = useState<{ id: string; opened: SshHost; open: boolean } | null>(null);
  const host = useMemo<Host>(
    () => ({
      confirmRemove: (opened) => {
        setState({ id: opened.id, opened, open: true });
      },
    }),
    [],
  );
  const h = state ? (hosts.find((x) => x.id === state.id) ?? state.opened) : undefined;

  // `?do=remove` (from a link): open the confirmation for the selected entry once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = hosts.find((x) => x.id === id);
    if (!target) return;
    setRequest(null);
    if (request === "remove") host.confirmRemove(target);
  }, [request, id, hosts, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {h ? (
        <RemoveConfirm
          h={h}
          last={hosts.length === 1 && hosts[0]?.id === h.id}
          open={Boolean(state?.open)}
          onOpenChange={(open) => {
            setState((s) => (s ? { ...s, open } : s));
          }}
        />
      ) : null}
    </HostContext.Provider>
  );
}
