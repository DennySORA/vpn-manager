// IP 封鎖清單 (/security/blocklists, /:id, /new): the short list of IP blocklists beside the detail of one (MasterDetail),
// following the page recipe of docs/frontend-design.md §8.1. Each row has its quick action (停用／啟用) and the same ⋯
// menu as the detail; the detail is an inspector — the EntityHeader (state, kind, size, ID, 停用／啟用, 編輯, ⋯), the
// conclusion first (why nothing is enforced yet, a failed refresh), the overview, content and usage sections, and the
// fixed footer with the view's primary action: 立即更新 (a URL list) or 更新內容 (an uploaded one). 編輯, 更新內容 and
// 刪除 open their dialogs (blocklist-host.tsx). A new list is previewed before it can be created.
import { ExternalLink, FileText, Info, ListX, Plus, RotateCcw, ScanSearch, ShieldCheck } from "lucide-react";
import { type SubmitEvent, type ReactNode, useId, useMemo, useState } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import {
  useBlocklists,
  useBuiltinBlocklists,
  useCreateBlocklist,
  useInstances,
  useRestoreBuiltinBlocklist,
} from "@/api/queries";
import type { BlocklistInput, BlocklistSource, BlocklistView, BuiltinBlocklistInfo, InstanceView } from "@/api/types";
import { m as shell } from "@/components/shell/messages";
import { useCrumb } from "@/components/shell/nav";
import { ListItem, MasterDetail, MasterList, MasterListHeading, Page, PageHeader } from "@/components/shell/page";
import { useMutationBlocked } from "@/components/shell/service";
import { ActionButton } from "@/components/ui/action-button";
import { StatusChip, Tag } from "@/components/ui/badge";
import { ButtonLink } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { FooterActions, HeaderActions, RowActions } from "@/components/ui/entity-actions";
import { FactLine } from "@/components/ui/fact-line";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import {
  EntityHeader,
  InspectorFooter,
  InspectorFrame,
  PropertyGrid,
  PropertyRow,
  PropertySection,
} from "@/components/ui/inspector";
import { CARD, TEXT_LINK } from "@/components/ui/look";
import { m as ui } from "@/components/ui/messages";
import { PresenceList } from "@/components/ui/presence-list";
import { Callout, EmptyState, ErrorCallout, ErrorState, LoadingRows } from "@/components/ui/states";
import { reportFailure, toast } from "@/components/ui/toast";
import { TEXT_TONE } from "@/components/ui/tones";
import { intlLocale, localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { absoluteTime, relativeTime } from "@/lib/format";
import { useIntentKey } from "@/lib/intent";
import type { Tone } from "@/lib/status";
import { allowNextNavigation, UnsavedGuard } from "@/components/unsaved";
import { useServerNow } from "@/lib/server-clock";
import { BlocklistActionHost, draftText, useBlocklistActions } from "./blocklist-host";
import {
  type Draft,
  DraftInput,
  emptyDraft,
  InvalidLines,
  PreviewPanel,
  SpecialFiltered,
  StatsGrid,
  useBlocklistPreview,
} from "./blocklist-preview";
import { m } from "./blocklists/messages";
import {
  connectionsUsing,
  defaultPolicyUsers,
  entriesLabel,
  familyLabel,
  formatLabel,
  listName,
  listSize,
  listState,
  overlayState,
  refreshLabel,
  sortLists,
  sourceLabel,
} from "./model";

function draftSource(d: Draft): BlocklistSource {
  return d.mode === "url" ? { kind: "url", url: d.url.trim(), refresh_hours: d.refreshHours } : { kind: "upload" };
}

/** A name from a file name or URL (`firehol_level1.netset` → `firehol_level1`). */
function suggestedName(d: Draft): string {
  if (d.mode === "upload" && d.file) return d.file.name.replace(/\.[^.]+$/, "").slice(0, 64);
  if (d.mode === "url") {
    const last =
      d.url
        .trim()
        .replace(/[?#].*$/, "")
        .split("/")
        .filter(Boolean)
        .pop() ?? "";
    return last.replace(/\.[^.]+$/, "").slice(0, 64);
  }
  return "";
}

// -------------------------------------------------------------------------------------------------
// Create
// -------------------------------------------------------------------------------------------------

function CreateBlocklist() {
  const navigate = useNavigate();
  const create = useCreateBlocklist();
  const intent = useIntentKey("blocklist.create");
  const blocked = useMutationBlocked();
  const previews = useBlocklistPreview();
  const formId = useId();
  const [draft, setDraft] = useState<Draft>(emptyDraft("upload"));
  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const preview = previews.current(draft);
  const nameError = !name.trim() ? ui.common.enterName : name.trim().length > 64 ? ui.common.nameTooLong : null;
  const ready = preview !== null && preview.problems.length === 0 && !nameError;
  const dirty = draft.version > 0 || name.trim() !== "";
  const reason =
    blocked ?? (!preview ? m.create.previewFirst : preview.problems.length ? m.previewProblems : nameError);

  const change = (d: Draft) => {
    setDraft(d);
    setError(null);
    if (!nameTouched) setName(suggestedName(d));
  };

  const submit = async (e: SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!preview || !ready || blocked) return;
    setError(null);
    let text: string | null;
    try {
      text = await draftText(draft);
    } catch (err) {
      setError(err);
      return;
    }
    const input: BlocklistInput = {
      name: name.trim(),
      source: draftSource(draft),
      text,
      expected_import_hash: preview.import_hash,
    };
    // The key follows the previewed content (its hash), never the text itself (up to 8 MiB).
    const key = intent.next({ name: input.name, source: input.source, hash: preview.import_hash });
    create.mutate(
      { input, key },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(m.create.created(input.name), m.create.createdNote);
          allowNextNavigation();
          void navigate(`/security/blocklists/${r.data.blocklist.id}`, { replace: true });
        },
        onError: (err) => {
          intent.settle(err);
          setError(err);
        },
      },
    );
  };

  return (
    <form id={formId} noValidate onSubmit={(e) => void submit(e)} className="flex h-full min-h-0 flex-col">
      <InspectorFrame
        header={<EntityHeader icon={ListX} tone="file" title={m.newList} description={m.create.description} />}
        footer={
          <InspectorFooter
            note={
              <span aria-live="polite">
                {!preview ? m.create.notePreview : preview.problems.length ? m.create.noteProblems : m.create.noteReady}
              </span>
            }
          >
            <ActionButton
              type="submit"
              size="sm"
              variant="primary"
              icon={Plus}
              pending={create.isPending}
              pendingLabel={ui.common.creating}
              disabledReason={create.isPending ? null : reason}
            >
              {ui.common.create}
            </ActionButton>
          </InspectorFooter>
        }
      >
        <div className="grid grid-cols-1 gap-3 border-b border-line-subtle px-4 py-3.5">
          <FormFailure error={error} />
          <Field label={ui.common.name} required error={nameTouched || preview ? nameError : null}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                maxLength={64}
                placeholder={m.create.namePlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={name}
                onChange={(e) => {
                  setNameTouched(true);
                  setName(e.target.value);
                }}
              />
            )}
          </Field>
        </div>
        <PropertySection title={m.content} icon={<FileText aria-hidden />}>
          <div className="grid grid-cols-1 gap-3">
            <DraftInput
              draft={draft}
              onChange={change}
              modes={["upload", "paste", "url"]}
              pending={previews.pending}
              disabled={create.isPending}
              onPreview={() => void previews.run(draft)}
            />
            {previews.error(draft) ? <FormFailure error={previews.error(draft)} /> : null}
          </div>
        </PropertySection>
        <PropertySection title={m.create.previewTitle} icon={<ScanSearch aria-hidden />}>
          {preview ? (
            <PreviewPanel preview={preview} />
          ) : previews.outdated(draft) ? (
            <Callout tone="warning" title={m.preview.changed}>
              {m.create.previewAgain}
            </Callout>
          ) : (
            <p className="text-data text-fg-tertiary">{m.create.previewNote}</p>
          )}
        </PropertySection>
        <PropertySection title={m.create.format} icon={<Info aria-hidden />}>
          <p className="text-data text-fg-secondary">
            {m.create.formatBody(
              <span className="font-mono">#</span>,
              <span className="font-mono">;</span>,
              <span className="font-mono">{'{"cidr": …}'}</span>,
            )}
          </p>
        </PropertySection>
      </InspectorFrame>
      <UnsavedGuard dirty={dirty && !create.isSuccess} />
    </form>
  );
}

// -------------------------------------------------------------------------------------------------
// One list
// -------------------------------------------------------------------------------------------------

/** How one connection stands with this list, from what its worker reported. */
function connectionState(v: InstanceView, listId: string): { tone: Tone; text: string } {
  const s = overlayState(v);
  switch (s.kind) {
    case "not_running":
      return { tone: "neutral", text: m.connections.notRunning };
    case "error":
      return { tone: "danger", text: s.message };
    case "pending":
      return { tone: "info", text: m.connections.applying(s.revision, s.applied) };
    case "applied":
      return s.lists.includes(listId)
        ? { tone: "success", text: m.connections.applied(s.revision) }
        : { tone: "warning", text: m.connections.missing(s.revision) };
  }
}

function ConnectionList({ conns, listId, empty }: { conns: InstanceView[]; listId: string; empty: string }) {
  if (!conns.length) return <p className="text-caption text-fg-tertiary">{empty}</p>;
  return (
    <ul className="grid grid-cols-1 gap-1">
      {conns.map((v) => {
        const st = connectionState(v, listId);
        return (
          <li key={v.spec.id} className="flex flex-wrap items-baseline gap-x-2 text-data">
            <Link to={`/instances/${v.spec.id}`} className={TEXT_LINK}>
              {v.spec.name}
            </Link>
            <span className={TEXT_TONE[st.tone]}>{st.text}</span>
          </li>
        );
      })}
    </ul>
  );
}

function Usage({ view, instances }: { view: BlocklistView; instances: InstanceView[] }) {
  const id = view.blocklist.id;
  if (!view.blocklist.enabled) {
    return <p className="text-data text-fg-tertiary">{m.usage.disabled(view.used_by.length)}</p>;
  }
  if (!view.used_by.length && !view.default_policy) {
    return <p className="text-data text-fg-tertiary">{m.usage.none}</p>;
  }
  return (
    <ul className="grid grid-cols-1 gap-2">
      {view.default_policy ? (
        <li className={cn(CARD, "grid grid-cols-1 gap-1.5 px-3 py-2.5")}>
          <span className="text-data font-medium text-fg">{m.usage.defaultPolicy}</span>
          <p className="text-caption text-fg-tertiary">{m.usage.defaultPolicyNote}</p>
          <ConnectionList conns={defaultPolicyUsers(instances)} listId={id} empty={m.usage.allCustom} />
        </li>
      ) : null}
      {view.used_by.map((p) => (
        <li key={p.id} className={cn(CARD, "grid grid-cols-1 gap-1.5 px-3 py-2.5")}>
          <Link to={`/security/${p.id}`} className={cn(TEXT_LINK, "text-data font-medium")}>
            {m.usage.profile(p.name)}
          </Link>
          <ConnectionList conns={connectionsUsing(instances, [p.id])} listId={id} empty={m.usage.profileUnused} />
        </li>
      ))}
    </ul>
  );
}

/** What the catalogue says about a built-in list: what it holds, where it comes from, its terms. */
function BuiltinFacts({ info }: { info: BuiltinBlocklistInfo }) {
  return (
    <>
      <PropertyRow label={m.facts.builtin}>{localized(info.description)}</PropertyRow>
      <PropertyRow label={m.facts.source} hint={`${formatLabel(info.format)} · ${familyLabel(info.family)}`}>
        <a
          href={info.homepage}
          target="_blank"
          rel="noreferrer"
          className={cn(TEXT_LINK, "inline-flex items-center gap-1")}
        >
          {new URL(info.homepage).host}
          <ExternalLink aria-hidden className="size-3.5" />
        </a>
      </PropertyRow>
      <PropertyRow label={m.facts.terms}>
        <span>
          {localized(info.terms)}{" "}
          <a
            href={info.terms_url}
            target="_blank"
            rel="noreferrer"
            className={cn(TEXT_LINK, "inline-flex items-center gap-1")}
          >
            {m.facts.fullTerms}
            <ExternalLink aria-hidden className="size-3.5" />
          </a>
        </span>
      </PropertyRow>
    </>
  );
}

/** Why a list enforces nothing yet, or is not refreshed: waiting for the egress, failed, disabled. */
function StateCallout({ view }: { view: BlocklistView }) {
  const r = view.refresh;
  if (!view.blocklist.enabled) {
    return (
      <Callout tone="info" title={ui.common.disabled}>
        {m.state.disabled(!view.awaiting_content)}
      </Callout>
    );
  }
  if (!view.awaiting_content) return null;
  if (view.waiting) {
    return (
      <Callout tone="warning" title={m.state.waitingTitle}>
        {m.state.waiting(localized(view.waiting))}
      </Callout>
    );
  }
  if (r && !r.ok) {
    return (
      <Callout tone="danger" title={m.state.firstFailedTitle}>
        {m.state.firstFailed(r.message ? localized(r.message) : ui.common.unknownReason)}
      </Callout>
    );
  }
  return (
    <Callout tone="info" title={m.state.awaitingTitle}>
      {m.state.awaiting}
    </Callout>
  );
}

/** A next refresh still ahead (one already due waits for the egress or the scheduler, it is not "17 分鐘前"). */
function upcoming(view: BlocklistView, now: number): string | null {
  const t = view.next_refresh_at ? Date.parse(view.next_refresh_at) : Number.NaN;
  return Number.isFinite(t) && t > now ? (view.next_refresh_at ?? null) : null;
}

/** The footer's line: when the content changes next, or why it cannot now (beside the action that would). */
function NextUpdate({ view, now }: { view: BlocklistView; now: number }) {
  const s = view.blocklist.source;
  if (s.kind === "upload") return <>{m.next.upload}</>;
  if (!view.blocklist.enabled) return <>{m.next.disabled}</>;
  if (view.waiting) return <>{m.next.waiting(localized(view.waiting))}</>;
  const next = upcoming(view, now);
  if (next) return <>{m.next.at(relativeTime(next, now), refreshLabel(s.refresh_hours))}</>;
  return <>{m.next.interval(refreshLabel(s.refresh_hours))}</>;
}

function BlocklistDetail({ view, instances }: { view: BlocklistView; instances: InstanceView[] }) {
  const b = view.blocklist;
  const now = useServerNow();
  const actions = useBlocklistActions(view);
  const r = view.refresh;
  const url = b.source.kind === "url" ? b.source.url : null;
  const state = listState(view);
  const conclusion = (view.stale && r !== null && !view.awaiting_content) || !b.enabled || view.awaiting_content;

  return (
    <InspectorFrame
      header={
        <EntityHeader
          icon={ListX}
          tone="file"
          title={listName(view)}
          status={<StatusChip tone={state?.tone ?? "neutral"} label={state?.label ?? m.enabled} />}
          description={
            <span className="flex flex-wrap items-center gap-1.5">
              {view.builtin ? <Tag tone="brand">{ui.common.builtIn}</Tag> : null}
              <Tag tone={url ? "info" : "neutral"}>{sourceLabel(b.source)}</Tag>
              <span className="machine">{view.awaiting_content ? m.notDownloaded : listSize(b.stats)}</span>
            </span>
          }
          id={b.id}
          idLabel={m.idLabel}
          actions={<HeaderActions actions={actions} menuLabel={ui.action.menuOf(listName(view))} />}
        />
      }
      footer={
        <InspectorFooter note={<NextUpdate view={view} now={now} />}>
          <FooterActions actions={actions} />
        </InspectorFooter>
      }
    >
      {conclusion ? (
        <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">
          <StateCallout view={view} />
          {view.stale && r && !view.awaiting_content ? (
            <Callout tone="warning" title={m.refreshFailed.title}>
              {m.refreshFailed.body(
                r.message ? localized(r.message) : ui.common.unknownReason,
                relativeTime(r.attempted_at, now),
                r.stale_since && r.stale_since !== r.attempted_at ? absoluteTime(r.stale_since) : null,
                r.succeeded_at ? absoluteTime(r.succeeded_at) : null,
              )}
            </Callout>
          ) : null}
        </div>
      ) : null}

      <PropertySection title={ui.common.overview} icon={<Info aria-hidden />}>
        <PropertyGrid>
          {view.builtin ? <BuiltinFacts info={view.builtin} /> : null}
          <PropertyRow label={view.builtin ? m.facts.downloadUrl : m.facts.source} mono={Boolean(url)}>
            {url ? (
              <span className="inline-flex items-center gap-1">
                {url}
                <CopyButton value={url} label={m.url} />
              </span>
            ) : (
              m.facts.uploaded
            )}
          </PropertyRow>
          {url ? (
            <PropertyRow
              label={m.refresh}
              hint={view.next_refresh_at ? m.facts.nextAt(absoluteTime(view.next_refresh_at)) : undefined}
            >
              <span>
                {!b.enabled ? ui.common.disabled : b.source.kind === "url" ? refreshLabel(b.source.refresh_hours) : "—"}
                {upcoming(view, now) ? m.facts.relative(relativeTime(upcoming(view, now), now)) : ""}
                {view.waiting && !view.awaiting_content ? (
                  <span className="text-warning">{m.facts.waiting(localized(view.waiting))}</span>
                ) : null}
              </span>
            </PropertyRow>
          ) : null}
          {url ? (
            <PropertyRow label={m.facts.lastRefresh} hint={r ? absoluteTime(r.attempted_at) : undefined}>
              {r ? (
                <span className={r.ok ? "text-success" : "text-warning"}>
                  {r.ok ? m.facts.succeeded : m.facts.failed} · {relativeTime(r.attempted_at, now)}
                  {r.message ? ` · ${localized(r.message)}` : ""}
                </span>
              ) : (
                m.facts.neverRefreshed
              )}
            </PropertyRow>
          ) : null}
          {view.awaiting_content ? null : (
            <PropertyRow label={m.facts.contentUpdated} hint={absoluteTime(b.content_updated_at)}>
              {relativeTime(b.content_updated_at, now)}
            </PropertyRow>
          )}
          {view.awaiting_content ? null : (
            <PropertyRow label={m.facts.sha} mono>
              <span className="inline-flex items-center gap-1">
                {b.content_sha256.slice(0, 16)}…
                <CopyButton value={b.content_sha256} label="SHA-256" />
              </span>
            </PropertyRow>
          )}
        </PropertyGrid>
      </PropertySection>

      <PropertySection
        title={m.content}
        icon={<FileText aria-hidden />}
        count={view.awaiting_content ? null : b.stats.entries}
      >
        <div className="grid grid-cols-1 gap-3">
          <StatsGrid stats={b.stats} />
          {b.stats.special_filtered ? <SpecialFiltered count={b.stats.special_filtered} /> : null}
          <InvalidLines lines={b.invalid_lines} total={b.stats.invalid} />
        </div>
      </PropertySection>

      <PropertySection
        title={m.usage.title}
        icon={<ShieldCheck aria-hidden />}
        count={view.used_by.length + (view.default_policy ? 1 : 0)}
      >
        <Usage view={view} instances={instances} />
      </PropertySection>
    </InspectorFrame>
  );
}

/** A list row: its kind, size and state, its quick action (停用／啟用) and the same ⋯ menu as its detail. */
function BlocklistRow({ v, selected }: { v: BlocklistView; selected: boolean }) {
  const actions = useBlocklistActions(v);
  const state = listState(v);
  const facts = [
    v.builtin ? ui.common.builtIn : null,
    sourceLabel(v.blocklist.source),
    v.awaiting_content ? m.notDownloaded : entriesLabel(v.blocklist.stats),
    state?.label ?? null,
    v.default_policy ? m.row.byDefault : null,
    v.used_by.length ? m.row.usedBy(v.used_by.length) : null,
  ].filter((fact) => fact !== null);
  return (
    <ListItem
      to={`/security/blocklists/${v.blocklist.id}`}
      selected={selected}
      title={listName(v)}
      meta={
        <span className={cn(state && TEXT_TONE[state.tone])}>
          <FactLine items={facts} />
        </span>
      }
      actions={<RowActions actions={actions} name={listName(v)} />}
    />
  );
}

/** Built-in lists the user deleted: they stay deleted until restored here. */
function DeletedBuiltin() {
  const catalogue = useBuiltinBlocklists();
  const restore = useRestoreBuiltinBlocklist();
  const blocked = useMutationBlocked();
  const navigate = useNavigate();
  const headingId = useId();
  const deleted = (catalogue.data ?? []).filter((s) => s.blocklist_id === null);
  if (!deleted.length) return null;
  const restoring = restore.isPending ? restore.variables.builtin : undefined;
  return (
    <section aria-labelledby={headingId} className="shrink-0 border-t border-line-subtle p-2">
      <MasterListHeading id={headingId}>{m.deleted.heading}</MasterListHeading>
      <PresenceList items={deleted} keyOf={(s) => s.info.key} className="grid grid-cols-1 gap-0.5">
        {(s) => (
          <div className="flex min-h-9 items-center justify-between gap-2 rounded-lg pl-3">
            <span className="min-w-0 truncate text-data text-fg-secondary" title={localized(s.info.description)}>
              {localized(s.info.name)}
            </span>
            <ActionButton
              size="sm"
              variant="quiet"
              icon={RotateCcw}
              aria-label={m.deleted.restoreOf(localized(s.info.name))}
              pending={restoring === s.info.key}
              pendingLabel={m.deleted.restoring}
              disabledReason={restoring === s.info.key ? null : (blocked ?? (restoring ? m.deleted.busy : null))}
              onClick={() => {
                restore.mutate(
                  { builtin: s.info.key, key: newIdempotencyKey() },
                  {
                    onSuccess: (r) => {
                      toast.success(m.deleted.restored(localized(s.info.name)), m.deleted.restoredNote);
                      void navigate(`/security/blocklists/${r.data.blocklist.id}`);
                    },
                    onError: (e) => {
                      reportFailure(m.deleted.restoreIntent(localized(s.info.name)), e);
                    },
                  },
                );
              }}
            >
              {m.deleted.restore}
            </ActionButton>
          </div>
        )}
      </PresenceList>
    </section>
  );
}

// -------------------------------------------------------------------------------------------------
// Page
// -------------------------------------------------------------------------------------------------

export function BlocklistsPage() {
  const { id } = useParams();
  const lists = useBlocklists();
  const instances = useInstances();
  const all = useMemo(() => sortLists(lists.data ?? []), [lists.data]);
  const selected = id && id !== "new" ? all.find((v) => v.blocklist.id === id) : undefined;
  useCrumb(id === "new" ? m.newList : selected ? listName(selected) : undefined);

  const create = (
    <ButtonLink to="/security/blocklists/new" variant="primary" icon={Plus}>
      {m.add}
    </ButtonLink>
  );

  let detail: ReactNode;
  if (id === "new") detail = <CreateBlocklist />;
  else if (selected)
    detail = <BlocklistDetail key={selected.blocklist.id} view={selected} instances={instances.data ?? []} />;
  else if (lists.isPending) detail = <LoadingRows rows={3} label={m.loading} />;
  else if (lists.isError && !lists.data)
    detail = <ErrorState error={lists.error} onRetry={() => void lists.refetch()} retrying={lists.isFetching} />;
  else if (id)
    detail = (
      <EmptyState icon={ListX} title={m.notFound}>
        {ui.common.mayHaveBeenDeleted}
      </EmptyState>
    );
  // The only one opens by itself; with several the user picks one.
  else if (all.length === 1 && all[0]) detail = <Navigate replace to={`/security/blocklists/${all[0].blocklist.id}`} />;
  else if (all.length)
    detail = (
      <EmptyState icon={ListX} title={m.pick}>
        {m.pickBody}
      </EmptyState>
    );
  else
    detail = (
      <EmptyState brand icon={ListX} title={m.none} actions={create}>
        {m.noneBody}
      </EmptyState>
    );

  let list: ReactNode;
  if (lists.isPending) list = <LoadingRows rows={3} label={m.loading} />;
  else if (lists.isError && !lists.data)
    list = <ErrorState compact error={lists.error} onRetry={() => void lists.refetch()} retrying={lists.isFetching} />;
  else
    list = (
      <>
        {lists.isError ? (
          // Stale: the last list stays, marked, with a retry.
          <div className="shrink-0 border-b border-line-subtle p-2">
            <ErrorCallout
              error={lists.error}
              title={m.stale(new Date(lists.dataUpdatedAt).toLocaleTimeString(intlLocale, { hour12: false }))}
              onRetry={() => void lists.refetch()}
              retrying={lists.isFetching}
            />
          </div>
        ) : null}
        {all.length ? (
          <MasterList label={shell.nav.blocklists.label}>
            <PresenceList
              items={all}
              keyOf={(v) => v.blocklist.id}
              className="grid grid-cols-1 gap-0.5"
              label={m.listLabel}
            >
              {(v) => <BlocklistRow v={v} selected={v.blocklist.id === id} />}
            </PresenceList>
          </MasterList>
        ) : (
          <EmptyState compact icon={ListX} title={m.noneShort}>
            {m.noneShortBody}
          </EmptyState>
        )}
        <DeletedBuiltin />
      </>
    );

  return (
    <Page>
      <BlocklistActionHost lists={all}>
        <PageHeader
          title={shell.nav.blocklists.label}
          description={m.description}
          help={m.help}
          helpText={m.helpText}
          actions={create}
        />
        <MasterDetail
          listLabel={shell.nav.blocklists.label}
          detailLabel={selected ? m.detailsOf(listName(selected)) : id === "new" ? m.newList : m.details}
          backLabel={m.all}
          list={list}
          detail={detail}
        />
      </BlocklistActionHost>
    </Page>
  );
}
