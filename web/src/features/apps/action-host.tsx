// The managed-App actions bound to their effects, and the dialogs behind them — once per page, so a row's menu, the
// inspector and a link (`?do=<action>` on the App's page) open the very same dialog
// (docs/frontend-design.md §8.1). Start, stop and restart are sent in place (actions.ts); editing, checking and approving
// the executable, a new forward and deleting open their dialog here. A closing dialog keeps showing the App it was
// opened for until its exit has played.
import { FileCheck2 } from "lucide-react";
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import { useCapabilities, useDeleteApp, useExecutableCheck, useForwards, useInstances } from "@/api/queries";
import type { AppView } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import type { EntityAction } from "@/components/ui/action-model";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { PropertyGrid, PropertyRow } from "@/components/ui/inspector";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { reportFailure, toast } from "@/components/ui/toast";
import { ForwardDialog } from "@/features/forwards/forward-dialog";
import { absoluteTime, formatBytes } from "@/lib/format";
import { useQueryParam } from "@/lib/url";
import { type AppActionId, appActions, appSendsOf, markDeleting, sendAppAction, useAppSending, VERB } from "./actions";
import { AppDialog, ExecutableReport } from "./app-dialog";
import { m } from "./messages";
import { shortDigest } from "./model";

type DialogKind = "edit" | "approve" | "add_forward" | "delete";

const DIALOGS: ReadonlySet<string> = new Set<DialogKind>(["edit", "approve", "add_forward", "delete"]);

interface Host {
  open: (kind: DialogKind, view: AppView) => void;
}

const HostContext = createContext<Host | null>(null);

/**
 * The actions of App `v`, bound: what each one does and whether its intent is on its way. Outside a host (a page that
 * shows an App without its dialogs) the dialog actions do nothing.
 */
export function useAppActions(v: AppView): EntityAction<AppActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const sending = useAppSending(v.spec.id);
  const caps = useCapabilities();
  const instances = useInstances();
  const forwards = useForwards();
  const owner = instances.data?.find((i) => i.spec.id === v.spec.instance_id);
  const delivering = (forwards.data ?? [])
    .filter((f) => f.binding.target_app_id === v.spec.id)
    .map((f) => f.binding.name);
  return appActions(v, { blocked, sending, caps: caps.data, owner, forwards: delivering }).map((spec) => {
    const sends = appSendsOf(spec.id);
    return {
      ...spec,
      pending: spec.id === "approve" ? sending === "approve" : sends !== null && sends === sending,
      run: () => {
        if (sends) void sendAppAction(v, sends);
        else if (DIALOGS.has(spec.id)) host?.open(spec.id as DialogKind, v);
      },
    };
  });
}

/** Compare the approved file with what is on disk now, and approve the current one. */
function ApproveDialog({
  app,
  open,
  onOpenChange,
}: {
  app: AppView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const check = useExecutableCheck(open ? app.spec.executable : null);
  const sending = useAppSending(app.spec.id);
  const blocked = useMutationBlocked();
  const approved = app.spec.approval;
  const c = check.data?.path === app.spec.executable ? check.data : null;
  const same = Boolean(approved && c?.ok && c.sha256 === approved.sha256 && c.resolved === approved.path);
  const reason =
    blocked ??
    (sending && sending !== "approve"
      ? m.actions.waitingFor(VERB[sending])
      : !c
        ? m.approve.waitForCheck
        : same
          ? m.sameAsApproved
          : c.ok && c.sha256
            ? null
            : m.approve.cannotApprove);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={600}
      title={m.approve.title}
      description={m.approve.description}
      footer={
        <>
          <Button
            variant="quiet"
            onClick={() => {
              onOpenChange(false);
            }}
          >
            {ui.common.cancel}
          </Button>
          <ActionButton
            variant="primary"
            icon={FileCheck2}
            disabledReason={sending === "approve" ? null : reason}
            pending={sending === "approve"}
            pendingLabel={m.actions.approving}
            onClick={() =>
              c?.sha256 &&
              void sendAppAction(app, "approve", {
                sha256: c.sha256,
                onDone: () => {
                  onOpenChange(false);
                },
              })
            }
          >
            {m.approve.confirm}
          </ActionButton>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4">
        <PropertyGrid>
          <PropertyRow label={m.approve.configuredPath} mono>
            {app.spec.executable}
          </PropertyRow>
          <PropertyRow
            label={m.approve.approved}
            mono
            hint={approved ? m.approvedAt(absoluteTime(approved.approved_at), formatBytes(approved.size)) : undefined}
          >
            {approved ? (
              <>
                <span>{approved.path}</span>
                <span className="inline-flex items-center gap-1 text-fg-secondary">
                  {shortDigest(approved.sha256)}
                  <CopyButton value={approved.sha256} label={m.approve.approvedDigest} />
                </span>
              </>
            ) : (
              <span className="font-sans text-warning">{m.notApproved}</span>
            )}
          </PropertyRow>
        </PropertyGrid>
        <div className="grid grid-cols-1 gap-1.5">
          <p className="text-data font-medium text-fg-secondary">{m.approve.currentFile}</p>
          <ExecutableReport
            check={c}
            checking={check.isFetching}
            failure={check.error}
            approval={approved}
            onRetry={() => void check.refetch()}
          />
          {c?.ok && c.sha256 ? <p className="machine text-micro text-fg-tertiary">SHA-256 {c.sha256}</p> : null}
        </div>
        {same ? <Callout tone="info">{m.approve.unchanged}</Callout> : null}
        {c?.ok && c.sha256 && !same ? (
          <Callout tone="warning" title={m.approve.expectedOnly}>
            {m.approve.expectedOnlyDetail}
          </Callout>
        ) : null}
      </div>
    </Dialog>
  );
}

function DeleteConfirm({
  view,
  open,
  onOpenChange,
}: {
  view: AppView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const remove = useDeleteApp();
  const navigate = useNavigate();
  const { search } = useLocation();
  const { id: selected } = useParams();
  const [deleted, setDeleted] = useState(false);
  const run = () => {
    markDeleting(view.spec.id, true);
    remove.mutate(
      { id: view.spec.id, revision: view.spec.revision, key: newIdempotencyKey() },
      {
        onSuccess: () => {
          setDeleted(true);
          onOpenChange(false);
          toast.success(m.actions.done.deleted(view.spec.name), m.actions.done.deletedDetail);
          if (selected === view.spec.id) void navigate(`/apps${search}`);
        },
        onError: (e) => {
          markDeleting(view.spec.id, false);
          reportFailure(m.actions.intent.remove(view.spec.name), e);
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
      title={m.remove.title(view.spec.name)}
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
      <p>{m.remove.body}</p>
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/**
 * Hosts the App dialogs for one page. `views` are the page's Apps (live): a dialog shows the latest facts of the App it
 * was opened for, and the facts it was opened with once the App is gone (deleted), so its exit still plays.
 */
export function AppActionHost({ views, children }: { views: readonly AppView[]; children: ReactNode }) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: AppView; open: boolean } | null>(null);
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

  // `?do=<action>` (from a link): open that dialog for the selected App once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = views.find((v) => v.spec.id === id);
    if (!target) return;
    setRequest(null);
    if (DIALOGS.has(request)) host.open(request as DialogKind, target);
  }, [request, id, views, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {view ? (
        <>
          <AppDialog
            open={shown("edit")}
            onOpenChange={change("edit")}
            app={view.spec}
            running={view.status?.state === "running"}
          />
          <ApproveDialog app={view} open={shown("approve")} onOpenChange={change("approve")} />
          <DeleteConfirm view={view} open={shown("delete")} onOpenChange={change("delete")} />
        </>
      ) : null}
      <ForwardDialog
        open={shown("add_forward")}
        onOpenChange={change("add_forward")}
        appId={state?.kind === "add_forward" ? state.id : undefined}
      />
    </HostContext.Provider>
  );
}
