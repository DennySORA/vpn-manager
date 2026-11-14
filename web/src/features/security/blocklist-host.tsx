// The IP blocklist actions bound to their effects, and the dialogs behind them — once per page, so a row's quick action
// and ⋯ menu, the detail and a link (`?do=edit|replace|delete` on the list's page) open the very same
// dialog (docs/frontend-design.md §8.1). The switch and the download are sent in place (blocklist-actions.ts); 編輯
// (name, URL, refresh interval), 更新內容 (a new upload, previewed first) and 刪除 open their dialog here. A closing
// dialog keeps showing the list it was opened for until its exit has played.
import { createContext, type ReactNode, useContext, useEffect, useId, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { useUpdateBlocklist } from "@/api/queries";
import type { BlocklistSource, BlocklistView } from "@/api/types";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import type { EntityAction } from "@/components/ui/action-model";
import { Button } from "@/components/ui/button";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { allowNextNavigation } from "@/components/unsaved";
import { useQueryParam } from "@/lib/url";
import {
  type BlocklistActionId,
  blocklistActions,
  sendBlocklistDelete,
  sendBlocklistEnabled,
  sendBlocklistRefresh,
  sendsOf,
  useBlocklistSending,
} from "./blocklist-actions";
import {
  type Draft,
  DraftInput,
  type DraftMode,
  emptyDraft,
  PreviewPanel,
  useBlocklistPreview,
} from "./blocklist-preview";
import { m } from "./blocklists/messages";
import { listName, listSize, REFRESH_CHOICES, refreshLabel } from "./model";

type DialogKind = "edit" | "replace" | "delete";

const DIALOGS: ReadonlySet<string> = new Set<DialogKind>(["edit", "replace", "delete"]);

interface Host {
  open: (kind: DialogKind, v: BlocklistView) => void;
}

const HostContext = createContext<Host | null>(null);

/** The actions of list `v`, bound: what each one does and whether its intent is on its way. */
export function useBlocklistActions(v: BlocklistView): EntityAction<BlocklistActionId>[] {
  const host = useContext(HostContext);
  const blocked = useMutationBlocked();
  const sending = useBlocklistSending(v.blocklist.id);
  const run = (id: BlocklistActionId) => {
    switch (id) {
      case "enable":
      case "disable":
        void sendBlocklistEnabled(v, id === "enable");
        return;
      case "refresh":
        void sendBlocklistRefresh(v);
        return;
      case "delete":
      case "edit":
      case "replace":
        host?.open(id, v);
    }
  };
  return blocklistActions(v, { blocked, sending }).map((spec) => {
    const sends = sendsOf(spec.id);
    return {
      ...spec,
      pending: sends !== null && sends === sending,
      run: () => {
        run(spec.id);
      },
    };
  });
}

/** The list's text content for a commit: what the preview of an upload or paste was made from. */
export async function draftText(d: Draft): Promise<string | null> {
  if (d.mode === "paste") return d.text;
  if (d.mode === "upload" && d.file) return d.file.text();
  return null;
}

// -------------------------------------------------------------------------------------------------
// 編輯: name, and for a URL source its address and refresh interval (a new URL is previewed first)
// -------------------------------------------------------------------------------------------------

interface Settings {
  name: string;
  url: string;
  refresh: number | null;
}

function settingsOf(v: BlocklistView): Settings {
  const s = v.blocklist.source;
  return {
    name: listName(v),
    url: s.kind === "url" ? s.url : "",
    refresh: s.kind === "url" ? s.refresh_hours : null,
  };
}

interface DialogProps {
  view: BlocklistView;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function EditBlocklistDialog(props: DialogProps) {
  const session = useOpenSession(props.open);
  return <EditBody key={session} {...props} />;
}

/**
 * While the form holds no edits it follows the stored list (a refresh may land while it is open); edits are kept when
 * the list changes elsewhere and are saved against the revision they started from (a conflict is reported).
 */
function EditBody({ view, open, onOpenChange }: DialogProps) {
  const b = view.blocklist;
  const update = useUpdateBlocklist();
  const intent = useIntentKey(`blocklist.update:${b.id}`);
  const blocked = useMutationBlocked();
  const previews = useBlocklistPreview();
  const formId = useId();
  const [base, setBase] = useState<Settings>(() => settingsOf(view));
  const [baseRevision, setBaseRevision] = useState(b.revision);
  const [seenRevision, setSeenRevision] = useState(b.revision);
  const [name, setName] = useState(base.name);
  const [url, setUrl] = useState(base.url);
  const [urlVersion, setUrlVersion] = useState(0);
  const [refresh, setRefresh] = useState<number | null>(base.refresh);
  const [error, setError] = useState<unknown>(null);

  const isUrl = b.source.kind === "url";
  const urlChanged = isUrl && url.trim() !== base.url;
  const dirty = name.trim() !== base.name || (isUrl && (urlChanged || refresh !== base.refresh));
  if (b.revision !== seenRevision) {
    // A newer revision arrived (a refresh, an edit elsewhere): follow it unless the user is editing.
    setSeenRevision(b.revision);
    if (!dirty) {
      const next = settingsOf(view);
      setBase(next);
      setBaseRevision(b.revision);
      setName(next.name);
      setUrl(next.url);
      setRefresh(next.refresh);
    }
  }

  const load = (overwrite: boolean) => {
    const next = settingsOf(view);
    setBase(next);
    setBaseRevision(b.revision);
    setError(null);
    if (!overwrite) {
      setName(next.name);
      setUrl(next.url);
      setRefresh(next.refresh);
    }
  };

  const draft: Draft = { mode: "url", url, refreshHours: refresh, version: urlVersion };
  const preview = urlChanged ? previews.current(draft) : null;
  const source: BlocklistSource = isUrl ? { kind: "url", url: url.trim(), refresh_hours: refresh } : { kind: "upload" };
  const nameError = !name.trim() ? ui.common.enterName : null;
  const server = serverFieldErrors(error);
  const needsPreview = urlChanged && (!preview || preview.problems.length > 0);
  const reason = blocked ?? (!dirty ? m.edit.noChanges : (nameError ?? (needsPreview ? m.edit.previewFirst : null)));

  const save = (revision = baseRevision) => {
    if (!dirty || nameError || needsPreview) return;
    // A built-in list's name shown in the reader's language and left as it is keeps the name it is stored under.
    const typed = name.trim();
    const kept = typed === listName(view) ? b.name : typed;
    const input = { name: kept, source, text: null, expected_import_hash: preview?.import_hash ?? null };
    setError(null);
    update.mutate(
      { id: b.id, revision, input, key: intent.next({ ...input, revision }) },
      {
        onSuccess: () => {
          intent.settle();
          toast.success(m.edit.saved(typed));
          onOpenChange(false);
        },
        onError: (err) => {
          intent.settle(err);
          setError(err);
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={640}
      title={m.edit.title(listName(view))}
      description={isUrl ? m.edit.urlDescription : m.edit.uploadDescription}
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
            type="submit"
            form={formId}
            variant="primary"
            pending={update.isPending}
            pendingLabel={ui.common.saving}
            disabledReason={update.isPending ? null : reason}
          >
            {ui.common.save}
          </ActionButton>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
        className="grid grid-cols-1 gap-4"
      >
        <FormFailure
          error={error}
          pending={update.isPending}
          onReload={() => {
            load(false);
          }}
          onOverwrite={() => {
            load(true);
            save(b.revision);
          }}
        />
        <Field label={ui.common.name} required error={nameError ?? server.get("/name") ?? null}>
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              maxLength={64}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={name}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          )}
        </Field>
        {isUrl ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_200px]">
            <Field
              label={m.url}
              hint={view.builtin ? m.edit.builtinUrlHint : urlChanged ? m.edit.changedUrlHint : m.edit.urlHint}
              error={server.get("/source/url") ?? null}
            >
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  mono
                  spellCheck={false}
                  readOnly={view.builtin !== null}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    setUrlVersion((v) => v + 1);
                  }}
                />
              )}
            </Field>
            <Field label={m.refresh} error={server.get("/source/refresh_hours") ?? null}>
              {({ id }) => (
                <Select
                  id={id}
                  value={refresh === null ? "" : String(refresh)}
                  onChange={(e) => {
                    setRefresh(e.target.value ? Number(e.target.value) : null);
                  }}
                >
                  {REFRESH_CHOICES.map((h) => (
                    <option key={h ?? "manual"} value={h === null ? "" : String(h)}>
                      {refreshLabel(h)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
        ) : null}
        {urlChanged ? (
          <div className="grid grid-cols-1 gap-3">
            <div>
              <ActionButton
                size="sm"
                pending={previews.pending}
                pendingLabel={m.downloading}
                onClick={() => void previews.run(draft)}
              >
                {m.edit.previewUrl}
              </ActionButton>
            </div>
            {previews.error(draft) ? <FormFailure error={previews.error(draft)} /> : null}
            {preview ? <PreviewPanel preview={preview} title={m.edit.newUrlContent} /> : null}
          </div>
        ) : null}
      </form>
    </Dialog>
  );
}

// -------------------------------------------------------------------------------------------------
// 更新內容: replace an uploaded list's content (upload or paste → preview → replace)
// -------------------------------------------------------------------------------------------------

export function ReplaceContentDialog(props: DialogProps) {
  const session = useOpenSession(props.open);
  return <ReplaceBody key={session} {...props} />;
}

function ReplaceBody({ view, open, onOpenChange }: DialogProps) {
  const b = view.blocklist;
  const update = useUpdateBlocklist();
  const intent = useIntentKey(`blocklist.content:${b.id}`);
  const blocked = useMutationBlocked();
  const previews = useBlocklistPreview();
  const [draft, setDraft] = useState<Draft>(emptyDraft("upload"));
  const [error, setError] = useState<unknown>(null);
  const preview = previews.current(draft);
  const same = preview?.import_hash === b.content_sha256;
  const reason =
    blocked ??
    (!preview
      ? m.replace.previewFirst
      : preview.problems.length
        ? m.previewProblems
        : same
          ? m.replace.sameReason
          : null);

  const replace = async () => {
    if (!preview || preview.problems.length || same) return;
    setError(null);
    let text: string | null;
    try {
      text = await draftText(draft);
    } catch (err) {
      setError(err);
      return;
    }
    const input = {
      name: b.name,
      source: { kind: "upload" } as BlocklistSource,
      text,
      expected_import_hash: preview.import_hash,
    };
    update.mutate(
      { id: b.id, revision: b.revision, input, key: intent.next({ hash: preview.import_hash, revision: b.revision }) },
      {
        onSuccess: (r) => {
          intent.settle();
          previews.reset();
          toast.success(m.replace.done(listName(view)), m.replace.doneNote(listSize(r.data.blocklist.stats)));
          onOpenChange(false);
        },
        onError: (err) => {
          intent.settle(err);
          setError(err);
        },
      },
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={640}
      title={m.replace.title(listName(view))}
      description={m.replace.description}
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
            pending={update.isPending}
            pendingLabel={m.replace.updating}
            disabledReason={update.isPending ? null : reason}
            onClick={() => void replace()}
          >
            {m.replace.confirm}
          </ActionButton>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4">
        <FormFailure error={error} />
        <DraftInput
          draft={draft}
          onChange={(d) => {
            setDraft(d);
            setError(null);
          }}
          modes={["upload", "paste"] satisfies DraftMode[]}
          pending={previews.pending}
          disabled={update.isPending}
          onPreview={() => void previews.run(draft)}
        />
        {previews.error(draft) ? <FormFailure error={previews.error(draft)} /> : null}
        {preview ? <PreviewPanel preview={preview} title={m.replace.newContent} /> : null}
        {same ? (
          <Callout tone="info" title={m.replace.same}>
            {m.replace.sameBody}
          </Callout>
        ) : null}
      </div>
    </Dialog>
  );
}

// -------------------------------------------------------------------------------------------------
// 刪除
// -------------------------------------------------------------------------------------------------

function DeleteConfirm({ view, open, onOpenChange }: DialogProps) {
  const b = view.blocklist;
  const navigate = useNavigate();
  const { id: selected } = useParams();
  const sending = useBlocklistSending(b.id);
  const [deleted, setDeleted] = useState(false);
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (o) setDeleted(false);
        onOpenChange(o);
      }}
      title={m.deleteConfirm.title(listName(view))}
      confirmLabel={ui.common.delete}
      pending={sending === "delete"}
      onConfirm={() =>
        void sendBlocklistDelete(view, () => {
          setDeleted(true);
          onOpenChange(false);
          if (selected === b.id) {
            allowNextNavigation();
            void navigate("/security/blocklists");
          }
        })
      }
      // The row or detail that opened it is gone: focus goes to the page title.
      onCloseAutoFocus={(e) => {
        if (!deleted) return;
        e.preventDefault();
        document.getElementById("page-title")?.focus({ preventScroll: true });
      }}
    >
      {view.builtin ? <p>{m.deleteConfirm.builtin}</p> : <p>{m.deleteConfirm.own}</p>}
    </ConfirmDialog>
  );
}

/**
 * Hosts the IP blocklist dialogs for one page. `lists` are the page's lists (live): a dialog shows the latest facts of the
 * list it was opened for, and the ones it was opened with once the list is gone, so its exit still plays.
 */
export function BlocklistActionHost({ lists, children }: { lists: readonly BlocklistView[]; children: ReactNode }) {
  const [state, setState] = useState<{ kind: DialogKind; id: string; opened: BlocklistView; open: boolean } | null>(
    null,
  );
  const host = useMemo<Host>(
    () => ({
      open: (kind, opened) => {
        setState({ kind, id: opened.blocklist.id, opened, open: true });
      },
    }),
    [],
  );
  const view = state ? (lists.find((v) => v.blocklist.id === state.id) ?? state.opened) : undefined;
  const shown = (kind: DialogKind) => Boolean(state?.open && state.kind === kind);
  const change = (kind: DialogKind) => (open: boolean) => {
    setState((s) => (s?.kind === kind ? { ...s, open } : s));
  };

  // `?do=<action>` (from a link): open that dialog for the selected list once it is loaded.
  const { id } = useParams();
  const [request, setRequest] = useQueryParam("do");
  useEffect(() => {
    if (!request || !id) return;
    const target = lists.find((v) => v.blocklist.id === id);
    if (!target) return;
    setRequest(null);
    if (DIALOGS.has(request)) host.open(request as DialogKind, target);
  }, [request, id, lists, host, setRequest]);

  return (
    <HostContext.Provider value={host}>
      {children}
      {view ? (
        <>
          <EditBlocklistDialog view={view} open={shown("edit")} onOpenChange={change("edit")} />
          <ReplaceContentDialog view={view} open={shown("replace")} onOpenChange={change("replace")} />
          <DeleteConfirm view={view} open={shown("delete")} onOpenChange={change("delete")} />
        </>
      ) : null}
    </HostContext.Provider>
  );
}
