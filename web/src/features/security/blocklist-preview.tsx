// Preparing new content for an IP blocklist: where it comes from (a file, pasted text or a URL), the preview the server
// makes of it (nothing is stored), and what parsing found. Used by the create editor and the 編輯／更新內容 dialogs.
import { ScanSearch, Upload } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { apiPreview } from "@/api/client";
import type { BlocklistPreview, BlocklistStats, InvalidLine } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { Segmented } from "@/components/ui/segmented";
import { Callout } from "@/components/ui/states";
import { intlLocale, localized } from "@/i18n";
import { formatBytes, shortId } from "@/lib/format";
import { m } from "./blocklists/messages";
import { formatCount, LIMITS, REFRESH_CHOICES, refreshLabel } from "./model";

const nf = new Intl.NumberFormat(intlLocale);

/** Where new content comes from. `version` changes with every edit, so a preview knows it is outdated. */
export type Draft =
  | { mode: "upload"; file: File | null; version: number }
  | { mode: "paste"; text: string; version: number }
  | { mode: "url"; url: string; refreshHours: number | null; version: number };

export type DraftMode = Draft["mode"];

export function emptyDraft(mode: DraftMode): Draft {
  switch (mode) {
    case "upload":
      return { mode, file: null, version: 0 };
    case "paste":
      return { mode, text: "", version: 0 };
    case "url":
      return { mode, url: "", refreshHours: null, version: 0 };
  }
}

function draftKey(d: Draft): string {
  return `${d.mode}:${d.version}`;
}

/** Nothing to preview yet, or why this input cannot be previewed (checked before sending). */
export function draftProblem(d: Draft): string | null {
  switch (d.mode) {
    case "upload":
      if (!d.file) return m.draft.chooseFile;
      if (d.file.size > LIMITS.rawBytes) return m.draft.fileTooLarge(LIMITS.rawBytes / 1024 / 1024);
      return null;
    case "paste":
      if (!d.text.trim()) return m.draft.pasteList;
      // A UTF-8 character takes at most 3 bytes per UTF-16 unit: only long text needs encoding.
      if (d.text.length * 3 > LIMITS.rawBytes && new TextEncoder().encode(d.text).length > LIMITS.rawBytes) {
        return m.draft.textTooLarge(LIMITS.rawBytes / 1024 / 1024);
      }
      return null;
    case "url":
      if (!d.url.trim()) return m.draft.enterUrl;
      if (!/^https:\/\//i.test(d.url.trim())) return m.draft.httpsOnly;
      return null;
  }
}

/**
 * Previews of the current draft. Only the latest request may set the result (an earlier one that
 * answers late is dropped), and a result belongs to the draft version it was made from.
 */
export function useBlocklistPreview() {
  const [result, setResult] = useState<{ key: string; preview: BlocklistPreview } | null>(null);
  const [error, setError] = useState<{ key: string; error: unknown } | null>(null);
  const [pending, setPending] = useState(false);
  const seq = useRef(0);
  const inflight = useRef<AbortController | null>(null);
  useEffect(() => () => inflight.current?.abort(), []);

  const run = useCallback(async (d: Draft) => {
    inflight.current?.abort();
    const controller = new AbortController();
    inflight.current = controller;
    seq.current += 1;
    const id = seq.current;
    const key = draftKey(d);
    setPending(true);
    setError(null);
    try {
      let preview: BlocklistPreview;
      if (d.mode === "upload" && d.file) {
        // The file's own bytes: a compressed file is recognised and refused by the server.
        preview = await apiPreview<BlocklistPreview>(
          "/v1/blocklists/preview",
          d.file,
          "application/octet-stream",
          controller.signal,
        );
      } else if (d.mode === "paste") {
        preview = await apiPreview<BlocklistPreview>(
          "/v1/blocklists/preview",
          d.text,
          "text/plain; charset=utf-8",
          controller.signal,
        );
      } else if (d.mode === "url") {
        preview = await apiPreview<BlocklistPreview>(
          "/v1/blocklists/preview",
          JSON.stringify({ url: d.url.trim() }),
          "application/json",
          controller.signal,
        );
      } else {
        return;
      }
      if (id === seq.current) setResult({ key, preview });
    } catch (e) {
      if (id === seq.current && !controller.signal.aborted) setError({ key, error: e });
    } finally {
      if (id === seq.current) setPending(false);
    }
  }, []);

  const reset = useCallback(() => {
    inflight.current?.abort();
    seq.current += 1;
    setResult(null);
    setError(null);
    setPending(false);
  }, []);

  return {
    run,
    reset,
    pending,
    /** The preview of exactly this draft, if any. */
    current: (d: Draft) => (result?.key === draftKey(d) ? result.preview : null),
    /** A preview exists, but of an earlier version of the input. */
    outdated: (d: Draft) => result !== null && result.key !== draftKey(d),
    error: (d: Draft) => (error?.key === draftKey(d) ? error.error : null),
  };
}

const MODE_LABEL: Record<DraftMode, string> = {
  upload: m.draft.mode.upload,
  paste: m.draft.mode.paste,
  url: m.draft.mode.url,
};

/** The content input of a draft: a file, pasted text, or a URL with its refresh interval. */
export function DraftInput({
  draft,
  onChange,
  modes,
  onPreview,
  pending,
  disabled,
}: {
  draft: Draft;
  onChange: (d: Draft) => void;
  modes: DraftMode[];
  onPreview: () => void;
  pending: boolean;
  disabled?: boolean;
}) {
  const fileInput = useRef<HTMLInputElement>(null);
  const problem = draftProblem(draft);
  return (
    <div className="space-y-3">
      {modes.length > 1 ? (
        <Segmented
          label={m.draft.source}
          value={draft.mode}
          onChange={(m) => {
            onChange({ ...emptyDraft(m), version: draft.version + 1 });
          }}
          options={modes.map((m) => ({ value: m, label: MODE_LABEL[m] }))}
        />
      ) : null}
      {draft.mode === "upload" ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-dashed border-line-strong bg-sunken/50 px-4 py-3">
          <input
            ref={fileInput}
            type="file"
            name="blocklist-file"
            className="sr-only"
            aria-label={m.draft.fileLabel}
            accept=".txt,.list,.netset,.ipset,.cidr,.conf,text/plain"
            onChange={(e) => {
              const file = e.target.files?.[0] ?? null;
              onChange({ ...draft, file, version: draft.version + 1 });
              e.target.value = "";
            }}
          />
          <ActionButton
            icon={Upload}
            size="sm"
            disabledReason={disabled ? m.draft.savingFile : null}
            onClick={() => fileInput.current?.click()}
          >
            {draft.file ? m.draft.changeFile : m.draft.pickFile}
          </ActionButton>
          {draft.file ? (
            <span className="min-w-0 truncate text-data text-fg">
              <span className="font-mono">{draft.file.name}</span>
              <span className="ml-2 text-fg-tertiary">{formatBytes(draft.file.size)}</span>
            </span>
          ) : (
            <span className="text-data text-fg-tertiary">{m.draft.fileHint}</span>
          )}
        </div>
      ) : null}
      {draft.mode === "paste" ? (
        <Field label={m.draft.contentLabel} hint={m.draft.contentHint}>
          {({ id, describedBy }) => (
            <Textarea
              id={id}
              mono
              rows={9}
              spellCheck={false}
              aria-describedby={describedBy}
              disabled={disabled}
              placeholder={m.draft.placeholder}
              value={draft.text}
              onChange={(e) => {
                onChange({ ...draft, text: e.target.value, version: draft.version + 1 });
              }}
            />
          )}
        </Field>
      ) : null}
      {draft.mode === "url" ? (
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_200px]">
          <Field label={m.url} hint={m.draft.urlHint}>
            {({ id, describedBy }) => (
              <Input
                id={id}
                mono
                inputMode="url"
                spellCheck={false}
                autoComplete="off"
                disabled={disabled}
                aria-describedby={describedBy}
                placeholder="https://example.org/drop.txt"
                value={draft.url}
                onChange={(e) => {
                  onChange({ ...draft, url: e.target.value, version: draft.version + 1 });
                }}
              />
            )}
          </Field>
          <Field label={m.refresh}>
            {({ id }) => (
              <Select
                id={id}
                disabled={disabled}
                value={draft.refreshHours === null ? "" : String(draft.refreshHours)}
                // The interval does not change the content: the preview stays valid.
                onChange={(e) => {
                  onChange({ ...draft, refreshHours: e.target.value ? Number(e.target.value) : null });
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
      <div className="flex flex-wrap items-center gap-3">
        <ActionButton
          icon={ScanSearch}
          disabledReason={pending ? null : (problem ?? (disabled ? m.draft.savingPreview : null))}
          pending={pending}
          pendingLabel={draft.mode === "url" ? m.downloading : m.draft.parsing}
          onClick={onPreview}
        >
          {draft.mode === "url" ? m.draft.downloadAndPreview : m.draft.preview}
        </ActionButton>
        {problem && draft.version > 0 ? (
          <span aria-hidden className="text-caption text-fg-tertiary">
            {problem}
          </span>
        ) : null}
      </div>
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div title={hint} className="rounded-md border border-line-subtle bg-sunken/60 px-2.5 py-1.5">
      <dt className="text-caption text-fg-tertiary">{label}</dt>
      <dd className="truncate font-mono text-data tabular-nums text-fg">{value}</dd>
    </div>
  );
}

/** What parsing found: entries, merged ranges, covered addresses, what was skipped and why. */
export function StatsGrid({ stats }: { stats: BlocklistStats }) {
  return (
    <dl className="grid grid-cols-2 gap-2 lg:grid-cols-3">
      <Stat label={m.stats.entries} value={nf.format(stats.entries)} hint={m.stats.entriesHint} />
      <Stat label={m.stats.special} value={nf.format(stats.special_filtered)} hint={m.stats.specialHint} />
      <Stat label={m.stats.invalid} value={nf.format(stats.invalid)} />
      <Stat label={m.stats.ranges("IPv4")} value={nf.format(stats.v4_ranges)} hint={m.stats.rangesHint} />
      <Stat label={m.stats.ranges("IPv6")} value={nf.format(stats.v6_ranges)} hint={m.stats.rangesHint} />
      <Stat label={m.stats.comments} value={`${nf.format(stats.comments)} / ${nf.format(stats.blank)}`} />
      <Stat label={m.stats.addresses("IPv4")} value={formatCount(stats.v4_addresses)} />
      <Stat label={m.stats.addresses("IPv6")} value={formatCount(stats.v6_addresses)} />
      <Stat
        label={m.stats.size}
        value={`${formatBytes(stats.raw_bytes)} → ${formatBytes(stats.parsed_bytes)}`}
        hint={m.stats.sizeHint}
      />
    </dl>
  );
}

/** Why private and special-use entries of a list are not blocked. */
export function SpecialFiltered({ count }: { count: number }) {
  return <p className="text-data text-fg-tertiary">{m.special(nf.format(count), count)}</p>;
}

export function InvalidLines({ lines, total }: { lines: InvalidLine[]; total: number }) {
  if (!total) return null;
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      {/* Fixed layout: the line keeps half the width however long the reasons are. */}
      <table className="w-full table-fixed border-separate border-spacing-0 text-data">
        <caption className="border-b border-line bg-surface px-3 py-2 text-left text-caption text-fg-tertiary">
          {total > lines.length ? m.invalid.first(lines.length, nf.format(total)) : m.invalid.all(total)}
        </caption>
        <thead>
          <tr>
            <th
              scope="col"
              className="w-16 border-b border-line-subtle px-3 py-1.5 text-right text-caption font-medium text-fg-tertiary"
            >
              {m.invalid.line}
            </th>
            <th
              scope="col"
              className="w-1/2 border-b border-line-subtle px-3 py-1.5 text-left text-caption font-medium text-fg-tertiary"
            >
              {m.invalid.content}
            </th>
            <th
              scope="col"
              className="border-b border-line-subtle px-3 py-1.5 text-left text-caption font-medium text-fg-tertiary"
            >
              {m.invalid.reason}
            </th>
          </tr>
        </thead>
        <tbody>
          {lines.map((l) => (
            <tr key={l.line}>
              <td className="border-b border-line-subtle px-3 py-1.5 text-right font-mono tabular-nums text-fg-tertiary">
                {l.line}
              </td>
              <td className="truncate border-b border-line-subtle px-3 py-1.5 font-mono text-fg" title={l.content}>
                {l.content || <span className="text-fg-tertiary">{m.invalid.blank}</span>}
              </td>
              <td className="border-b border-line-subtle px-3 py-1.5 text-fg-secondary">{localized(l.reason)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A preview: what would be saved, and why it cannot be when it cannot. `title` adds its heading (inside a dialog). */
export function PreviewPanel({
  preview,
  outdated,
  title,
}: {
  preview: BlocklistPreview;
  outdated?: boolean;
  title?: string;
}) {
  const s = preview.stats;
  return (
    <section aria-label={title ?? m.preview.label} className="grid grid-cols-1 gap-3 animate-reveal">
      {title ? <h3 className="text-data font-semibold text-fg">{title}</h3> : null}
      {outdated ? (
        <Callout tone="warning" title={m.preview.changed}>
          {m.preview.changedBody}
        </Callout>
      ) : null}
      {preview.problems
        .map((p) => localized(p))
        .map((problem) => (
          <Callout key={problem} tone="danger" title={m.preview.cannotSave}>
            {problem}
          </Callout>
        ))}
      {preview.fetched ? (
        <p className="text-data text-fg-tertiary">
          {m.preview.fetched(
            <span className="font-mono">{shortId(preview.fetched.via_instance_id)}</span>,
            preview.fetched.via_generation,
            <span className="font-mono">{preview.fetched.url}</span>,
            formatBytes(preview.fetched.bytes),
            preview.fetched.content_type,
          )}
        </p>
      ) : null}
      <StatsGrid stats={s} />
      {s.special_filtered ? <SpecialFiltered count={s.special_filtered} /> : null}
      {s.host_bits_normalized || s.mapped_ipv4 ? (
        <p className="text-data text-fg-tertiary">
          {m.preview.sentences([
            s.host_bits_normalized ? m.preview.hostBits(nf.format(s.host_bits_normalized), s.host_bits_normalized) : "",
            s.mapped_ipv4 ? m.preview.mapped(nf.format(s.mapped_ipv4), s.mapped_ipv4) : "",
          ])}
        </p>
      ) : null}
      {preview.sample.length ? (
        <div>
          <p className="mb-1.5 text-caption text-fg-tertiary">
            {preview.sample.length < s.v4_ranges + s.v6_ranges
              ? m.preview.sampleFirst(preview.sample.length, nf.format(s.v4_ranges + s.v6_ranges))
              : m.preview.sampleAll(preview.sample.length)}
          </p>
          <ul className="flex flex-wrap gap-1.5">
            {preview.sample.map((r) => (
              <li
                key={r}
                className="rounded-sm border border-line bg-sunken px-1.5 py-0.5 font-mono text-micro text-fg-secondary"
              >
                {r}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <InvalidLines lines={preview.invalid_lines} total={s.invalid} />
    </section>
  );
}
