// The DNS profile actions bound to their effects, and the confirmation behind 刪除 — once per page, so a row's ⋯ menu,
// the editor's ⋯ menu and a link (`?do=delete` on the profile's page) open the very same dialog
// (docs/frontend-design.md §8.1). The editor binds 儲存 itself (it owns the draft).
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import type { DnsProfile } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { allowNextNavigation } from "@/components/unsaved";
import { useQueryParam } from "@/lib/url";
import { type DnsActionId, dnsActions, sendDnsDelete, useDnsSending } from "./actions";
import { m } from "./messages";

interface Host {
  confirmDelete: (p: DnsProfile) => void;
}

const HostContext = createContext<Host | null>(null);

type Own = Partial<Record<DnsActionId, { run: () => void; pending: boolean }>>;

/**
 * The actions of profile `p` (none for a new, unsaved one), bound: what each one does and whether it is on its way. `own`
 * binds what the editor runs itself (儲存), `dirty` is its draft's state.
 */
export function useDnsActions(
  p: DnsProfile | null,
  users: number,
  opts: { dirty?: boolean; own?: Own } = {},
): EntityAction<DnsActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const sending = useDnsSending(p?.id ?? "");
  if (!p) return [];
  return dnsActions(p, { blocked, users, dirty: opts.dirty, sending }).map((spec) => {
    const bound = opts.own?.[spec.id];
    return {
      ...spec,
      pending: bound?.pending ?? (spec.id === "delete" && sending === "delete"),
      run: bound?.run ?? (() => (spec.id === "delete" ? host?.confirmDelete(p) : undefined)),
    };
  });
}

function DeleteConfirm({
  p,
  open,
  onOpenChange,
}: {
  p: DnsProfile;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const navigate = useNavigate();
  const { id: selected } = useParams();
  const sending = useDnsSending(p.id);
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
        void sendDnsDelete(p, () => {
          setDeleted(true);
          onOpenChange(false);
          if (selected === p.id) {
            // The editor of a deleted profile has nothing left to save.
            allowNextNavigation();
            void navigate("/dns");
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
      <p>{m.deleteConfirm.body(p.servers.length)}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the DNS profile dialogs for one page. `profiles` are the page's profiles (live): the dialog shows the latest facts
 * of the profile it was opened for, and the ones it was opened with once the profile is gone, so its exit still plays.
 */
export function DnsActionHost({ profiles, children }: { profiles: readonly DnsProfile[]; children: ReactNode }) {
  const [state, setState] = useState<{ id: string; opened: DnsProfile; open: boolean } | null>(null);
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
