// The provider-account actions bound to their effects, and the dialogs behind them — once per page, so the account's
// list row, its page and `?do=connect|remove` open the very same dialog (docs/frontend-design.md §8.1). 重新讀取帳號 is
// sent in place (actions.ts); 建立連線 and 移除帳號 open their dialog here. A closing dialog keeps showing the account
// it was opened for until its exit has played.
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import { useDeleteProviderAccount } from "@/api/queries";
import type { ProviderAccount } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { reportFailure, toast } from "@/components/ui/toast";
import { useQueryParam } from "@/lib/url";
import { type AccountActionId, accountActions, sendRefresh, useAccountSending } from "./actions";
import { ConnectDialog } from "./connect-dialog";
import { m } from "./messages";
import { PROVIDER_NAME } from "./model";

type DialogKind = "connect" | "remove";

const DIALOGS: ReadonlySet<AccountActionId> = new Set<AccountActionId>(["connect", "remove"]);

interface Host {
  open: (kind: DialogKind, a: ProviderAccount) => void;
  /** Provider requests can leave now. */
  egressUsable: boolean;
  /** Profiles built by each account (an account is kept while one exists). */
  profilesOf: (id: string) => number;
}

const HostContext = createContext<Host | null>(null);

/** The actions of account `a`, bound: what each one does and whether its read is on its way. */
export function useAccountActions(a: ProviderAccount): EntityAction<AccountActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const sending = useAccountSending(a.id);
  return accountActions(a, {
    egressUsable: host?.egressUsable ?? false,
    blocked,
    profiles: host?.profilesOf(a.id) ?? 0,
  }).map((spec) => ({
    ...spec,
    pending: spec.id === "refresh" && sending === "refresh",
    run: () => {
      if (spec.id === "refresh") void sendRefresh(a);
      else host?.open(spec.id, a);
    },
  }));
}

function RemoveConfirm({
  account,
  open,
  onOpenChange,
}: {
  account: ProviderAccount;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const remove = useDeleteProviderAccount();
  const navigate = useNavigate();
  const [removed, setRemoved] = useState(false);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setRemoved(false);
        onOpenChange(o);
      }}
      title={m.remove.title(account.label)}
      confirmLabel={m.account.remove}
      pending={remove.isPending}
      onConfirm={() => {
        remove.mutate(
          { id: account.id, revision: account.revision, key: newIdempotencyKey() },
          {
            onSuccess: () => {
              setRemoved(true);
              onOpenChange(false);
              toast.success(m.remove.removed(account.label), m.remove.removedDetail);
              void navigate("/providers");
            },
            onError: (e) => {
              reportFailure(m.remove.intent(account.label), e);
            },
          },
        );
      }}
      // The row or page that opened it is gone: focus goes to the page title, not to the page.
      onCloseAutoFocus={(e) => {
        if (!removed) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{m.remove.whatIsDeleted(PROVIDER_NAME[account.provider])}</p>
      <p>{m.remove.afterwards}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the account dialogs for one page. `accounts` are the page's accounts (live): a dialog shows the latest facts of
 * the account it was opened for, and the facts it was opened with once the account is gone (removed), so its exit still
 * plays.
 */
export function AccountActionHost({
  accounts,
  egressUsable,
  direct,
  profilesOf,
  children,
}: {
  accounts: readonly ProviderAccount[];
  egressUsable: boolean;
  /** A direct grant is open: the connection built now becomes the egress. */
  direct: boolean;
  profilesOf: (id: string) => number;
  children: ReactNode;
}) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: ProviderAccount; open: boolean } | null>(
    null,
  );
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.id, opened, open: true });
      },
      egressUsable,
      profilesOf,
    }),
    [egressUsable, profilesOf],
  );
  const account = state ? (accounts.find((a) => a.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=connect|remove`: open that dialog for the selected account once it is loaded, when the action can run now.
  const { id } = useParams();
  const blocked = useMutationBlocked();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = accounts.find((a) => a.id === id);
    if (!target) return;
    setRequest(null);
    const action = accountActions(target, { egressUsable, blocked, profiles: profilesOf(target.id) }).find(
      (a) => a.id === request,
    );
    if (action?.disabledReason === null && DIALOGS.has(action.id)) host.open(action.id as DialogKind, target);
  }, [request, id, accounts, host, setRequest, egressUsable, blocked, profilesOf]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {account ? (
        <>
          <ConnectDialog
            account={account}
            open={shown("connect")}
            onOpenChange={change("connect")}
            egressUsable={egressUsable}
            direct={direct}
          />
          <RemoveConfirm account={account} open={shown("remove")} onOpenChange={change("remove")} />
        </>
      ) : null}
    </HostContext.Provider>
  );
}
