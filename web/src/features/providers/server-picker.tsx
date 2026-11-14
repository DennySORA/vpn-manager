// A provider's servers grouped by country and city, searchable; inactive ones cannot be picked. Each country is a
// disclosure (the chevron turns on the snappy spring; where supported the height opens on the smooth spring); a server
// is a radio row (native radios: arrow keys move within the open countries) that shows as the current row when picked.
import { ChevronRight, Search } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { ProviderServer } from "@/api/types";
import { Tag } from "@/components/ui/badge";
import { Input } from "@/components/ui/field";
import { LIST_ROW, LIST_ROW_IDLE, LIST_ROW_SELECTED } from "@/components/ui/look";
import { cn } from "@/lib/cn";
import { m } from "./connect/messages";
import { groupServers } from "./model";

/**
 * A provider's servers grouped by country and city, searchable; inactive ones cannot be picked.
 * `current` (the server in use) is marked, and its country starts open and scrolled into view.
 */
export function ServerPicker({
  servers,
  value,
  current = null,
  onChange,
  label = m.servers.label,
  takesFocus = true,
  unusable,
}: {
  servers: ProviderServer[];
  value: string | null;
  current?: string | null;
  onChange: (s: ProviderServer) => void;
  /** The list's name (two pickers in one dialog: 出口, 入口). */
  label?: string;
  /** Its search field takes the dialog's first focus. */
  takesFocus?: boolean;
  /** Why a server cannot be picked here, beyond being inactive (e.g. no multihop port); null: it can. */
  unusable?: (s: ProviderServer) => string | null;
}) {
  const [query, setQuery] = useState("");
  const name = useId();
  const groups = useMemo(() => groupServers(servers, query), [servers, query]);
  const total = groups.reduce((n, g) => n + g.count, 0);
  const list = useRef<HTMLDivElement>(null);
  const currentRow = useRef<HTMLLabelElement>(null);
  // Once, when the list first shows: the current server in the middle of the list (only the list
  // scrolls, not the dialog around it).
  useEffect(() => {
    const box = list.current;
    const row = currentRow.current;
    if (box && row) box.scrollTop = Math.max(0, row.offsetTop - box.clientHeight / 2 + row.offsetHeight / 2);
  }, []);
  return (
    <div className="space-y-2">
      <div className="group/search relative">
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-fg-tertiary transition-colors duration-(--duration-fast) group-focus-within/search:text-brand-cyan"
        />
        {/* A dialog that opens with the list already loaded starts here (`Dialog` focuses [data-autofocus]). */}
        <Input
          data-autofocus={takesFocus || undefined}
          aria-label={m.servers.search(label)}
          placeholder={m.servers.searchPlaceholder}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
          }}
          className="pl-8"
        />
      </div>
      <div
        ref={list}
        role="radiogroup"
        aria-label={label}
        className="relative max-h-80 overflow-y-auto rounded-lg border border-line-subtle bg-sunken/60"
      >
        {groups.length ? (
          groups.map((g) => (
            <details
              key={g.code}
              open={
                Boolean(query) ||
                groups.length <= 3 ||
                g.cities.some((c) => c.servers.some((s) => s.id === value || s.id === current))
              }
              className="disclosure border-b border-line-subtle last:border-b-0"
            >
              <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2 text-data text-fg transition-colors duration-(--duration-fast) select-none hover:bg-raised/60 active:bg-sunken [&::-webkit-details-marker]:hidden">
                <span className="flex items-center gap-2">
                  <ChevronRight
                    aria-hidden
                    className="size-3.5 shrink-0 text-fg-tertiary transition-[rotate] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) [[open]>summary>&]:rotate-90"
                  />
                  <span className="machine text-caption text-fg-tertiary">{g.code.toUpperCase()}</span>
                  {g.name}
                </span>
                <span className="text-caption text-fg-tertiary">{m.servers.count(g.count)}</span>
              </summary>
              {g.cities.map((c) => (
                <div key={c.code} className="pb-1.5">
                  <p className="px-3 pt-1.5 pb-1 text-micro font-medium text-fg-tertiary">{c.name}</p>
                  {c.servers.map((s) => {
                    const v6 = s.endpoints.some((e) => e.startsWith("["));
                    const chosen = value === s.id;
                    const why = s.active ? (unusable?.(s) ?? null) : null;
                    const pickable = s.active && why === null;
                    return (
                      <label
                        key={s.id}
                        ref={s.id === current ? currentRow : undefined}
                        className={cn(
                          LIST_ROW,
                          "mx-1.5 flex items-center gap-3 rounded-md px-2.5 py-1.5",
                          chosen ? LIST_ROW_SELECTED : pickable ? LIST_ROW_IDLE : undefined,
                          pickable ? "cursor-pointer" : "cursor-not-allowed opacity-55",
                        )}
                        title={why ?? undefined}
                      >
                        <input
                          type="radio"
                          name={name}
                          className="size-4 shrink-0 accent-action"
                          disabled={!pickable}
                          checked={chosen}
                          onChange={() => {
                            onChange(s);
                          }}
                        />
                        <span className="machine min-w-0 flex-1 truncate text-data text-fg">{s.id}</span>
                        {s.id === current ? <Tag tone="info">{m.route.current}</Tag> : null}
                        {s.hosting ? (
                          <span className="max-w-[40%] shrink truncate text-caption text-fg-tertiary max-sm:hidden">
                            {s.hosting}
                          </span>
                        ) : null}
                        {s.load_percent !== null ? (
                          <span className="machine text-caption text-fg-tertiary">{s.load_percent}%</span>
                        ) : null}
                        {v6 ? <Tag>IPv6</Tag> : null}
                        {s.owned ? <Tag tone="info">{m.servers.providerOwned}</Tag> : null}
                        {!s.active ? <Tag tone="warning">{m.servers.inactive}</Tag> : null}
                        {why ? <Tag tone="neutral">{m.servers.cannotPick}</Tag> : null}
                        {s.warning ? <Tag tone="warning">{s.warning}</Tag> : null}
                      </label>
                    );
                  })}
                </div>
              ))}
            </details>
          ))
        ) : (
          <p className="px-3 py-6 text-center text-caption text-fg-tertiary [overflow-wrap:anywhere]">
            {m.servers.noMatch(query)}
          </p>
        )}
      </div>
      <p className="text-caption text-fg-tertiary" aria-live="polite">
        {query ? m.servers.matching(total) : m.servers.total(servers.length)}
      </p>
    </div>
  );
}
