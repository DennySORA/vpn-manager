// The SSH download actions bound to their effects, and the dialogs behind them — once per page, so a row's menu, the
// inspector and a link (`?do=edit|delete|trust_host_key|clear_log|clear_history` on the job's page) open the very same
// dialog (docs/frontend-design.md §8.1). Pause, resume and a listing are sent in place (actions.ts).
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import type { EntityAction } from "@/components/ui/action-model";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m as ui } from "@/components/ui/messages";
import { useMutationBlocked } from "@/components/shell/service";
import { useQueryParam } from "@/lib/url";
import {
  type ClearWhat,
  type JobActionId,
  jobActions,
  jobSendsOf,
  sendClear,
  sendDelete,
  sendJobAction,
  useJobSending,
} from "./actions";
import { JobDialog } from "./job-dialog";
import { m } from "./messages";

type DialogKind = "edit" | "delete" | "trust_host_key" | "clear_log" | "clear_history";

const DIALOGS: ReadonlySet<string> = new Set<DialogKind>([
  "edit",
  "delete",
  "trust_host_key",
  "clear_log",
  "clear_history",
]);

interface Host {
  open: (kind: DialogKind, v: SshDownloadView) => void;
}

const HostContext = createContext<Host | null>(null);

/** The actions of job `v`, bound: what each one does and whether its intent is on its way. */
export function useJobActions(v: SshDownloadView, gatewayKnown: boolean): EntityAction<JobActionId>[] {
  const host = useContext(HostContext);
  const navigate = useNavigate();
  const blocked = useMutationBlocked();
  const sending = useJobSending(v.job.id);
  const run = (id: JobActionId) => {
    const sends = jobSendsOf(id);
    if (sends) {
      void sendJobAction(v, sends);
      return;
    }
    switch (id) {
      case "edit":
      case "delete":
      case "trust_host_key":
      case "clear_log":
      case "clear_history":
        host?.open(id, v);
        return;
      case "open_gateway":
        void navigate(`/gateways/${v.job.gateway_id}`);
        return;
      case "pause":
      case "resume":
      case "retry":
      case "scan":
        // Sent above (`jobSendsOf`).
        return;
    }
  };
  return jobActions(v, { blocked, sending, gatewayKnown }).map((spec) => {
    const sends = jobSendsOf(spec.id);
    return {
      ...spec,
      pending: sending !== null && (sends === sending || spec.id === sending),
      run: () => {
        run(spec.id);
      },
    };
  });
}

function DeleteConfirm({
  v,
  open,
  onOpenChange,
}: {
  v: SshDownloadView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const navigate = useNavigate();
  const { search } = useLocation();
  const { id: selected } = useParams();
  const sending = useJobSending(v.job.id);
  const [deleted, setDeleted] = useState(false);
  const unfinished = v.status?.unfinished ?? 0;
  const active = v.status?.active.length ?? 0;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setDeleted(false);
        onOpenChange(o);
      }}
      title={m.deleteConfirm.title(v.job.name)}
      confirmLabel={ui.common.delete}
      pending={sending === "delete"}
      onConfirm={() =>
        void sendDelete(v, () => {
          setDeleted(true);
          onOpenChange(false);
          if (selected === v.job.id) void navigate(`/ssh-downloads${search}`);
        })
      }
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      <p>{m.deleteConfirm.body(v.job.local_dir)}</p>
      {unfinished + active > 0 ? (
        <p className="text-warning">{m.deleteConfirm.unfinished(unfinished + active, v.job.work_dir)}</p>
      ) : null}
      <p className="text-fg-tertiary">{ui.common.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

/** Clearing a job's log or its finished records: the exact scope, before anything is deleted. */
function ClearConfirm({
  v,
  what,
  open,
  onOpenChange,
}: {
  v: SshDownloadView;
  what: ClearWhat;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const sending = useJobSending(v.job.id);
  const unfinished = (v.status?.unfinished ?? 0) + (v.status?.active.length ?? 0);
  const log = what === "log";
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={log ? m.clearConfirm.logTitle(v.job.name) : m.clearConfirm.historyTitle(v.job.name)}
      confirmLabel={log ? m.verb.clear_log : m.verb.clear_history}
      pending={sending === (log ? "clear_log" : "clear_history")}
      onConfirm={() =>
        void sendClear(v, what, () => {
          onOpenChange(false);
        })
      }
    >
      <p>{log ? m.clearConfirm.logBody : m.clearConfirm.historyBody}</p>
      {!log && unfinished > 0 ? <p>{m.clearConfirm.keepsUnfinished(unfinished)}</p> : null}
      <p>{log ? m.clearConfirm.untouchedLog(v.job.local_dir) : m.clearConfirm.untouchedHistory(v.job.local_dir)}</p>
      <p className="text-fg-tertiary">{m.clearConfirm.cannotBeUndone}</p>
    </ConfirmDialog>
  );
}

function TrustConfirm({
  v,
  open,
  onOpenChange,
}: {
  v: SshDownloadView;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const sending = useJobSending(v.job.id);
  const [checked, setChecked] = useState(false);
  const offered = v.status?.offered_host_key;
  const known = v.status?.host_key;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setChecked(false);
        onOpenChange(o);
      }}
      title={m.trustConfirm.title}
      confirmLabel={m.trustConfirm.confirm}
      tone="danger"
      pending={sending === "trust_host_key"}
      onConfirm={() => {
        if (!offered || !checked) return;
        void sendJobAction(v, "trust_host_key", {
          fingerprint: offered.fingerprint,
          onDone: () => {
            onOpenChange(false);
          },
        });
      }}
    >
      <p>{m.trustConfirm.body(v.job.host, v.job.port)}</p>
      <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-data">
        <dt className="text-fg-tertiary">{m.trustConfirm.recorded}</dt>
        <dd className="machine [overflow-wrap:anywhere]">
          {known ? m.trustConfirm.key(known.fingerprint, known.algorithm) : "—"}
        </dd>
        <dt className="text-fg-tertiary">{m.trustConfirm.offered}</dt>
        <dd className="machine text-warning [overflow-wrap:anywhere]">
          {offered ? m.trustConfirm.key(offered.fingerprint, offered.algorithm) : "—"}
        </dd>
      </dl>
      <label className="flex items-start gap-2 text-data text-fg">
        <input
          type="checkbox"
          className="mt-1"
          checked={checked}
          onChange={(e) => {
            setChecked(e.target.checked);
          }}
        />
        {m.trustConfirm.checked}
      </label>
      {!checked ? <p className="text-caption text-fg-tertiary">{m.trustConfirm.checkFirst}</p> : null}
    </ConfirmDialog>
  );
}

/**
 * Hosts the job dialogs for one page. `jobs` are the page's jobs (live): a dialog shows the latest facts of the job it
 * was opened for, and the facts it was opened with once the job is gone, so its exit still plays.
 */
export function JobActionHost({ jobs, children }: { jobs: readonly SshDownloadView[]; children: ReactNode }) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: SshDownloadView; open: boolean } | null>(
    null,
  );
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.job.id, opened, open: true });
      },
    }),
    [],
  );
  const v = state ? (jobs.find((x) => x.job.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=<action>` (from a link): open that dialog for the selected job once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = jobs.find((x) => x.job.id === id);
    if (!target) return;
    setRequest(null);
    if (DIALOGS.has(request)) host.open(request as DialogKind, target);
  }, [request, id, jobs, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {v ? (
        <>
          <JobDialog open={shown("edit")} onOpenChange={change("edit")} job={v} />
          <DeleteConfirm v={v} open={shown("delete")} onOpenChange={change("delete")} />
          <TrustConfirm v={v} open={shown("trust_host_key")} onOpenChange={change("trust_host_key")} />
          <ClearConfirm v={v} what="log" open={shown("clear_log")} onOpenChange={change("clear_log")} />
          <ClearConfirm v={v} what="transfers" open={shown("clear_history")} onOpenChange={change("clear_history")} />
        </>
      ) : null}
    </HostContext.Provider>
  );
}
