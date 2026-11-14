// The 「本機存取埠」 section of the App dialog (strict isolation): which of the App's ports in its
// sandbox are published on this host, where, and for whom — with the address to open. Rows rise in
// when added, fade out when removed while the others slide up (PresenceList); a new row takes focus,
// and after a removal the add button does.

import { Plus, TriangleAlert, X } from "lucide-react";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useFreePort } from "@/api/queries";
import type { AccessBind } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { IconButton } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy";
import { Input } from "@/components/ui/field";
import { CARD, TEXT_LINK } from "@/components/ui/look";
import { PresenceList } from "@/components/ui/presence-list";
import { Segmented } from "@/components/ui/segmented";
import { cn } from "@/lib/cn";
import { type AccessRow, accessUrls, BIND_LABEL, MAX_ACCESS_PORTS } from "./access";
import { m as access } from "./access/messages";
import { m } from "./messages";

/** Where a suggestion starts when the App's port is not typed yet. */
const SUGGEST_FROM = 18000;

const BINDS: AccessBind[] = ["loopback", "lan"];

function parsed(text: string): number | null {
  const n = Number(text.trim());
  return /^\d{1,5}$/.test(text.trim()) && n >= 1024 && n <= 65535 ? n : null;
}

/** The addresses to open, each copyable. */
export function AccessUrls({ urls }: { urls: string[] }) {
  return (
    <ul className="grid grid-cols-1 gap-0.5">
      {urls.map((u) => (
        <li key={u} className="flex min-w-0 items-center gap-1 font-mono text-caption text-fg-secondary">
          <a href={u} target="_blank" rel="noreferrer" className={cn(TEXT_LINK, "min-w-0 [overflow-wrap:anywhere]")}>
            {u}
          </a>
          <CopyButton value={u} label={u} />
        </li>
      ))}
    </ul>
  );
}

function AccessRowEditor({
  row,
  index,
  onChange,
  onRemove,
  errorAt,
  hostAddresses,
  focusFirst,
}: {
  row: AccessRow;
  /** Its position among the rows (-1: it was removed and is leaving). */
  index: number;
  onChange: (row: AccessRow) => void;
  onRemove: () => void;
  errorAt: (field: "app_port" | "host_port" | "allow") => string | null;
  hostAddresses: string[];
  focusFirst: boolean;
}) {
  const id = useId();
  const n = index >= 0 ? String(index + 1) : m.removedRow;
  const app = parsed(row.appPort);
  // The host port follows the App's port (the same number when it is free here) until the user
  // types one.
  const wantsSuggestion = index >= 0 && (row.hostAuto || row.hostPort === "");
  const free = useFreePort(app ?? SUGGEST_FROM, wantsSuggestion && app !== null);
  const suggestion = free.isSuccess ? free.data.port : free.isError ? app : null;
  useEffect(() => {
    if (wantsSuggestion && suggestion !== null && String(suggestion) !== row.hostPort)
      onChange({ ...row, hostPort: String(suggestion), hostAuto: true });
  }, [wantsSuggestion, suggestion, row, onChange]);
  const host = parsed(row.hostPort);
  const errors = index >= 0 ? [errorAt("app_port"), errorAt("host_port"), errorAt("allow")] : [];
  const [appError, hostError, allowError] = errors;
  return (
    <div className={cn(CARD, "grid grid-cols-1 gap-2.5 px-3 py-2.5")}>
      <div className="flex flex-wrap items-end gap-2">
        <label htmlFor={`${id}-app`} className="flex min-w-0 flex-col gap-1 text-caption text-fg-tertiary">
          {access.editor.appPort}
          <Input
            mono
            compact
            className="w-28"
            inputMode="numeric"
            autoComplete="off"
            // eslint-disable-next-line jsx-a11y/no-autofocus -- only the row the user just added takes focus
            autoFocus={focusFirst}
            id={`${id}-app`}
            aria-label={access.editor.appPortOf(n)}
            aria-invalid={Boolean(appError)}
            placeholder="17890"
            value={row.appPort}
            onChange={(e) => {
              onChange({ ...row, appPort: e.target.value });
            }}
          />
        </label>
        <span aria-hidden className="pb-1.5 text-fg-tertiary">
          →
        </span>
        <label htmlFor={`${id}-host`} className="flex min-w-0 flex-col gap-1 text-caption text-fg-tertiary">
          {access.editor.hostPort}
          <Input
            mono
            compact
            className="w-28"
            inputMode="numeric"
            autoComplete="off"
            id={`${id}-host`}
            aria-label={access.editor.hostPortOf(n)}
            aria-invalid={Boolean(hostError)}
            placeholder={app ? String(app) : access.editor.suggested}
            value={row.hostPort}
            onChange={(e) => {
              onChange({ ...row, hostPort: e.target.value, hostAuto: false });
            }}
          />
        </label>
        <div className="flex min-w-0 flex-col gap-1 text-caption text-fg-tertiary">
          <span aria-hidden>{access.editor.whoCanConnect}</span>
          <Segmented
            size="sm"
            label={access.editor.bindOf(n)}
            value={row.bind}
            onChange={(bind) => {
              onChange({ ...row, bind });
            }}
            options={BINDS.map((b) => ({ value: b, label: BIND_LABEL[b].title, title: BIND_LABEL[b].text }))}
          />
        </div>
        <IconButton className="mb-0.5 ml-auto" label={access.editor.remove(n)} icon={X} onClick={onRemove} />
      </div>
      <p className="text-caption text-fg-tertiary">{BIND_LABEL[row.bind].text}</p>
      {row.bind === "lan" ? (
        <label htmlFor={`${id}-allow`} className="flex flex-col gap-1 text-caption text-fg-tertiary">
          {access.editor.allow}
          <Input
            mono
            compact
            autoComplete="off"
            spellCheck={false}
            id={`${id}-allow`}
            aria-label={access.editor.allowOf(n)}
            aria-invalid={Boolean(allowError)}
            placeholder="192.168.10.0/24, 192.168.20.0/24"
            value={row.allow}
            onChange={(e) => {
              onChange({ ...row, allow: e.target.value });
            }}
          />
        </label>
      ) : null}
      {errors
        .filter((e): e is string => Boolean(e))
        .map((e) => (
          <p key={e} className="text-caption text-danger animate-reveal" role="alert">
            {e}
          </p>
        ))}
      {host !== null ? (
        <div className="grid grid-cols-1 gap-1">
          <p className="text-caption text-fg-tertiary">{access.editor.urls}</p>
          <AccessUrls urls={accessUrls(row.bind, host, hostAddresses)} />
          {row.bind === "loopback" ? (
            <p className="text-caption text-fg-tertiary">
              {access.editor.fromOtherComputers(
                <code className="font-mono text-fg-secondary">{access.editor.sshForward(host)}</code>,
                <code className="font-mono text-fg-secondary">{`http://127.0.0.1:${host}`}</code>,
              )}
            </p>
          ) : (
            <p className="flex gap-1.5 text-caption text-warning">
              <TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0" />
              {access.editor.lanWarning}
            </p>
          )}
        </div>
      ) : null}
    </div>
  );
}

/** The editor of an App's local access ports. */
export function AccessPortsEditor({
  rows,
  onChange,
  errorAt,
  hostAddresses,
  newKey,
}: {
  rows: AccessRow[];
  onChange: (rows: AccessRow[]) => void;
  /** The problem at a JSON pointer below `/access_ports/<i>/` (the field, or an entry of it). */
  errorAt: (path: string) => string | null;
  hostAddresses: string[];
  newKey: () => string;
}) {
  const [added, setAdded] = useState<string | null>(null);
  const addRef = useRef<HTMLButtonElement>(null);
  const [removals, setRemovals] = useState(0);
  useEffect(() => {
    if (removals) addRef.current?.focus();
  }, [removals]);
  // Rows change one at a time; the latest list is what a row's change applies to.
  const latest = useRef(rows);
  useLayoutEffect(() => {
    latest.current = rows;
  });
  const full = rows.length >= MAX_ACCESS_PORTS;
  return (
    <section className="grid grid-cols-1 gap-2" aria-label={access.title}>
      <div className="grid grid-cols-1 gap-0.5">
        <h3 className="text-data font-medium text-fg-secondary">{access.title}</h3>
        <p className="text-caption text-fg-tertiary">{access.editor.intro}</p>
      </div>
      {errorAt("/access_ports") ? (
        <p className="text-caption text-danger animate-reveal" role="alert">
          {errorAt("/access_ports")}
        </p>
      ) : null}
      {rows.length ? (
        <PresenceList items={rows} keyOf={(r) => r.key} className="grid grid-cols-1 gap-2">
          {(r) => {
            const i = rows.findIndex((x) => x.key === r.key);
            return (
              <AccessRowEditor
                row={r}
                index={i}
                focusFirst={r.key === added}
                hostAddresses={hostAddresses}
                errorAt={(field) => errorAt(`/access_ports/${i}/${field}`)}
                onChange={(next) => {
                  onChange(latest.current.map((x) => (x.key === next.key ? next : x)));
                }}
                onRemove={() => {
                  onChange(latest.current.filter((x) => x.key !== r.key));
                  setRemovals((k) => k + 1);
                }}
              />
            );
          }}
        </PresenceList>
      ) : null}
      <div>
        <ActionButton
          ref={addRef}
          size="sm"
          variant="quiet"
          icon={Plus}
          disabledReason={full ? access.editor.full(MAX_ACCESS_PORTS) : null}
          onClick={() => {
            const key = newKey();
            setAdded(key);
            onChange([...rows, { key, appPort: "", hostPort: "", hostAuto: true, bind: "loopback", allow: "" }]);
          }}
        >
          {access.editor.add}
        </ActionButton>
      </div>
    </section>
  );
}
