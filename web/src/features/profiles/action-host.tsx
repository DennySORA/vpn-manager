// The WireGuard profile actions bound to their effects, and the dialogs behind them — once per page, so a row's menu,
// the inspector and a link (`?do=edit|change_server|delete` on the profile's page) open the very same
// dialog (docs/frontend-design.md §8.1). 建立連線 opens the connections page's new-connection dialog with this profile;
// 檢查設定 is the inspector's own (it shows the answer). A closing dialog keeps showing the profile it was opened for
// until its exit has played.
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import { useDeleteProfile } from "@/api/queries";
import type { RuntimeProfile } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { useQueryParam } from "@/lib/url";
import { createInstancePath, PROFILE_DIALOGS, type ProfileActionId, profileActions } from "./actions";
import { ChangeServerDialog } from "./change-server-dialog";
import { EditProfileDialog } from "./edit-dialog";
import { m } from "./messages";
import { keepsDeviceKey } from "./model";

type DialogKind = "edit" | "change_server" | "delete";

interface Host {
  open: (kind: DialogKind, p: RuntimeProfile) => void;
}

const HostContext = createContext<Host | null>(null);

/**
 * The actions of profile `p` (used by `users` connections), bound: what each one does. `own` binds the actions a view
 * runs itself (the inspector's 檢查設定 shows its own answer).
 */
export function useProfileActions(
  p: RuntimeProfile,
  users: number,
  own: Partial<Record<ProfileActionId, { run: () => void; pending: boolean }>> = {},
): EntityAction<ProfileActionId>[] {
  const host = useContext(HostContext);
  const navigate = useNavigate();
  const blocked = useMutationBlocked();
  const run = (id: ProfileActionId) => {
    if (PROFILE_DIALOGS.has(id)) host?.open(id as DialogKind, p);
    else if (id === "create_instance") void navigate(createInstancePath(p));
    else void navigate(`/profiles/${p.id}`);
  };
  return profileActions(p, { users, blocked }).map((spec) => {
    const bound = own[spec.id];
    return {
      ...spec,
      pending: bound?.pending ?? false,
      run:
        bound?.run ??
        (() => {
          run(spec.id);
        }),
    };
  });
}

function DeleteConfirm({
  profile,
  open,
  onOpenChange,
}: {
  profile: RuntimeProfile;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const remove = useDeleteProfile();
  const navigate = useNavigate();
  const { search } = useLocation();
  const { id: selected } = useParams();
  const [deleted, setDeleted] = useState(false);
  const run = () => {
    remove.mutate(
      { id: profile.id, revision: profile.revision, key: newIdempotencyKey() },
      {
        onSuccess: () => {
          setDeleted(true);
          onOpenChange(false);
          toast.success(
            m.toast.deleted(profile.name),
            keepsDeviceKey(profile) ? m.toast.deviceKeyKept : m.toast.privateKeyRemoved,
          );
          if (selected === profile.id) void navigate(`/profiles${search}`);
        },
        onError: (e) => {
          reportFailure(m.toast.deleteIntent(profile.name), e);
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
      title={m.deleteConfirm.title(profile.name)}
      confirmLabel={ui.common.delete}
      pending={remove.isPending}
      onConfirm={run}
      // The row or inspector that opened it is gone: focus goes to the page title, not to the page.
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      {keepsDeviceKey(profile) ? (
        <p>{m.deleteConfirm.keepsDeviceKey}</p>
      ) : profile.source.kind === "provider" ? (
        <p>{m.deleteConfirm.provider}</p>
      ) : (
        <p>{m.deleteConfirm.imported}</p>
      )}
      <p>{m.deleteConfirm.unaffected}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the profile dialogs for one page. `profiles` are the page's profiles (live): a dialog shows the latest facts of
 * the profile it was opened for, and the facts it was opened with once the profile is gone (deleted), so its exit
 * still plays.
 */
export function ProfileActionHost({
  profiles,
  usersOf,
  children,
}: {
  profiles: readonly RuntimeProfile[];
  /** How many connections use a profile (a dialog asked for by `?do=` opens only when its action can run). */
  usersOf: (id: string) => number;
  children: ReactNode;
}) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: RuntimeProfile; open: boolean } | null>(
    null,
  );
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.id, opened, open: true });
      },
    }),
    [],
  );
  const profile = state ? (profiles.find((p) => p.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=<action>` (from a link): open that dialog for the selected profile once it is loaded, when the
  // action can run now (an old link to deleting a profile that is in use opens nothing).
  const { id } = useParams();
  const blocked = useMutationBlocked();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = profiles.find((p) => p.id === id);
    if (!target) return;
    setRequest(null);
    const action = profileActions(target, { users: usersOf(target.id), blocked }).find((a) => a.id === request);
    if (action?.disabledReason === null && PROFILE_DIALOGS.has(action.id)) host.open(action.id as DialogKind, target);
  }, [request, id, profiles, host, setRequest, usersOf, blocked]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {profile ? (
        <>
          <EditProfileDialog profile={profile} open={shown("edit")} onOpenChange={change("edit")} />
          <ChangeServerDialog profile={profile} open={shown("change_server")} onOpenChange={change("change_server")} />
          <DeleteConfirm profile={profile} open={shown("delete")} onOpenChange={change("delete")} />
        </>
      ) : null}
    </HostContext.Provider>
  );
}
