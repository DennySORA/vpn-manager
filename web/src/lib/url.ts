import { useCallback } from "react";
import { useSearchParams } from "react-router";

/** The query string after `changes` (null or "" removes a name, any other value sets it); other names are kept. */
export function withQueryChanges(
  prev: URLSearchParams,
  changes: Readonly<Record<string, string | null>>,
): URLSearchParams {
  const next = new URLSearchParams(prev);
  for (const [name, v] of Object.entries(changes)) {
    if (v === null || v === "") next.delete(name);
    else next.set(name, v);
  }
  return next;
}

/** One query-string value as state (filters, open dialogs): restorable and shareable, replace by default. */
export function useQueryParam(
  name: string,
): [string | null, (value: string | null, opts?: { push?: boolean }) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(name);
  const set = useCallback(
    (v: string | null, opts?: { push?: boolean }) => {
      setParams((prev) => withQueryChanges(prev, { [name]: v }), { replace: !opts?.push });
    },
    [name, setParams],
  );
  return [value, set];
}

/**
 * The current tab of a view as a query-string value: `view` for a page's tabs, `tab` for an inspector's or editor's.
 * `tabs` lists the tabs the view has now, the first being the default, which keeps the URL clean. A value that is not
 * one of them (another object has fewer tabs, an old link) shows the default and leaves the URL as it is. Choosing a
 * tab pushes a history entry: Back returns to the previous tab.
 */
export function useTabParam<V extends string>(name: string, tabs: readonly V[]): [V, (next: V) => void] {
  const [value, set] = useQueryParam(name);
  const first = tabs[0];
  const current = tabs.find((t) => t === value) ?? first;
  const choose = useCallback(
    (next: V) => {
      set(next === first ? null : next, { push: true });
    },
    [set, first],
  );
  if (current === undefined) throw new Error(`useTabParam("${name}") needs at least one tab`);
  return [current, choose];
}

/**
 * Changes several query-string values in ONE navigation (「清除篩選」 clears the search and the state filter together).
 * Calling two useQueryParam setters in the same event does not work: react-router does not queue functional
 * setSearchParams updates, so both start from the same URL and only the last one applies.
 */
export function useSetQueryParams(): (
  changes: Readonly<Record<string, string | null>>,
  opts?: { push?: boolean },
) => void {
  const [, setParams] = useSearchParams();
  return useCallback(
    (changes: Readonly<Record<string, string | null>>, opts?: { push?: boolean }) => {
      setParams((prev) => withQueryChanges(prev, changes), { replace: !opts?.push });
    },
    [setParams],
  );
}
