// Adapted from Phasyn Studio (Apache-2.0).
// Data tables are workbench surfaces: crisp and solid — no glow, blur or lift. A sticky sunken header, hover tints the
// row and pressing darkens it, the selected row is the selection ground with a 3 px action line, a row whose work is in
// flight carries a thin shimmering band along its bottom. Rows are Motion rows: they rise in one after another on
// first appearance only (opacity and an 8 px rise, no scale; polling never replays it: the keys keep the same rows
// mounted). With TBody (AnimatePresence), rows that leave (filtered out, deleted) fade out in place, inert from the
// start of the exit, and the others then glide to their new places (layout="position"); with TableFrame's
// selectionMarker the action line slides from the old selected row to the new one.
import { AnimatePresence, motion, useIsPresent } from "motion/react";
import {
  createContext,
  type KeyboardEvent,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
} from "react";
import { cn } from "@/lib/cn";
import { ActiveIndicator } from "./active-indicator";
import { layoutTransition, riseVariants } from "./motion-tokens";

/** The selected row's line is drawn by the frame's sliding marker instead of by the row itself. */
const MarkerContext = createContext(false);

/**
 * A TBody row's presentation: its entrance stagger (its place when it appeared; 0 for a row that joined a body already
 * on screen) and the body's layout version (the rows glide only when it changes).
 */
const RowContext = createContext<{ stagger: number; layoutDependency: string } | null>(null);

/** The current row (the marker follows it): selected and not leaving. */
const SELECTED_ROW = 'tr[aria-selected="true"]';

/**
 * The list's scroll owner; the header row stays pinned. Wide tables fade the edge that has more columns behind it.
 * `selectionMarker`: the selected row's 3 px action line is one marker that slides between rows on the snappy spring
 * (placed without motion the first time; hidden while nothing is selected).
 */
export function TableFrame({
  label,
  children,
  onKeyDown,
  selectionMarker = false,
  tableClassName,
}: {
  label: string;
  children: ReactNode;
  onKeyDown?: ((e: KeyboardEvent<HTMLDivElement>) => void) | undefined;
  selectionMarker?: boolean | undefined;
  /** Classes of the table itself, e.g. `max-sm:min-w-0` when the columns left on a narrow screen fit without scrolling. */
  tableClassName?: string | undefined;
}) {
  const frame = useRef<HTMLDivElement>(null);
  return (
    // eslint-disable-next-line jsx-a11y/no-static-element-interactions -- arrow keys bubble up from the focused row; the frame itself takes no focus
    <div ref={frame} className="scroll-x-fade relative min-h-0 flex-1 overflow-auto" onKeyDown={onKeyDown}>
      <table
        aria-label={label}
        className={cn("w-full min-w-[520px] border-separate border-spacing-0 text-left text-data", tableClassName)}
      >
        <MarkerContext.Provider value={selectionMarker}>{children}</MarkerContext.Provider>
      </table>
      {/* Under the sticky header (z-2), over the rows. */}
      {selectionMarker ? (
        <ActiveIndicator
          container={frame}
          edge="left"
          selector={SELECTED_ROW}
          className="w-[3px] rounded-none bg-none bg-action"
        />
      ) : null}
    </div>
  );
}

/**
 * Header cell. The ground is sunken/80 composited onto the panel surface, written opaque, because the header is sticky
 * and rows scroll under it.
 */
export function Th({
  children,
  className,
  align = "left",
  sort,
}: {
  children?: ReactNode | undefined;
  className?: string | undefined;
  align?: "left" | "right" | undefined;
  /** A sortable column: its aria-sort (the header holds the button that sorts by it). */
  sort?: "ascending" | "descending" | "none" | undefined;
}) {
  return (
    <th
      scope="col"
      aria-sort={sort}
      className={cn(
        "sticky top-0 z-[2] h-9 whitespace-nowrap border-b border-line bg-surface bg-[linear-gradient(rgb(4_6_12_/_0.8),rgb(4_6_12_/_0.8))] px-3 text-caption font-medium text-fg-tertiary first:pl-4 last:pr-4",
        align === "right" ? "text-right" : "text-left",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  className,
  align = "left",
}: {
  children?: ReactNode | undefined;
  className?: string | undefined;
  align?: "left" | "right" | undefined;
}) {
  return (
    <td
      className={cn(
        "h-12 border-b border-line-subtle px-3 py-1.5 align-middle first:pl-4 last:pr-4",
        align === "right" && "text-right",
        className,
      )}
    >
      {children}
    </td>
  );
}

/**
 * A selectable row: the whole row is a pointer target; keyboard users reach its primary link. `running` draws the
 * indeterminate in-flight band (a word in the row still says what is happening). `exiting` (from TBody; a Tr also knows it
 * from its presence): the row has left the data and fades out in place — inert, hidden from assistive technology, never
 * selected.
 */
export function Tr({
  selected,
  onSelect,
  children,
  index = 0,
  running = false,
  exiting = false,
  className,
}: {
  selected?: boolean | undefined;
  onSelect?: (() => void) | undefined;
  children: ReactNode;
  index?: number | undefined;
  running?: boolean | undefined;
  exiting?: boolean | undefined;
  className?: string | undefined;
}) {
  const marker = useContext(MarkerContext);
  const row = useContext(RowContext);
  const present = useIsPresent();
  const leaving = exiting || !present;
  const current = Boolean(selected) && !leaving;
  // The stagger delay is the row's place when it appeared; it is read on mount only, so it never shifts mid-entrance.
  const stagger = row ? row.stagger : index;
  return (
    <motion.tr
      aria-selected={current || undefined}
      data-selected={current || undefined}
      data-running={running || undefined}
      data-exiting={leaving || undefined}
      inert={leaving || undefined}
      aria-hidden={leaving || undefined}
      onClick={(e) => {
        // Let inner controls (buttons, links, menus) handle their own clicks.
        if ((e.target as HTMLElement).closest("button, a, [role=menuitem], input, label")) return;
        onSelect?.();
      }}
      layout={row ? "position" : false}
      layoutDependency={row?.layoutDependency}
      transition={layoutTransition()}
      variants={riseVariants()}
      custom={stagger}
      initial="hidden"
      animate="shown"
      exit="gone"
      className={cn(
        "group relative transition-[background-color] duration-(--duration-fast) ease-standard",
        leaving && "pointer-events-none",
        onSelect && "cursor-pointer",
        current
          ? cn("bg-selection", !marker && "[&>td:first-child]:shadow-[inset_3px_0_0_var(--color-action)]")
          : cn("hover:bg-raised/60", onSelect && "active:bg-sunken/60"),
        running &&
          "after:pointer-events-none after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 after:bg-brand-gradient-soft after:animate-shimmer",
        className,
      )}
    >
      {children}
    </motion.tr>
  );
}

/** One entry of a TBody: its row's presentation, and `exiting` for the row while it plays its exit. */
function RowPresence({
  stagger,
  layoutDependency,
  children,
}: {
  stagger: number;
  layoutDependency: string;
  children: (exiting: boolean) => ReactNode;
}) {
  const exiting = !useIsPresent();
  const value = useMemo(() => ({ stagger, layoutDependency }), [stagger, layoutDependency]);
  return <RowContext.Provider value={value}>{children(exiting)}</RowContext.Provider>;
}

/**
 * The rows of a changing collection (filter, sort, add, remove), in AnimatePresence keyed by `keyOf`: a row that leaves
 * stays in place while it fades out (--duration-exit; inert, hidden from assistive technology), the others then glide
 * to their new places (Motion layout, snappy, transform only), and a row that comes back before it is gone simply stays
 * (the latest data wins). Rows of the first render rise in as a staggered group, a row that arrives later on its own.
 * The data is never delayed: `items` is what the page shows, the exiting rows are presentation only.
 */
export function TBody<T>({
  items,
  keyOf,
  children,
}: {
  items: readonly T[];
  keyOf: (item: T) => string;
  children: (item: T, row: { index: number; exiting: boolean }) => ReactNode;
}) {
  const keys = items.map(keyOf);
  const [firstKeys] = useState(() => new Set(keys));
  // Bumped when exits complete, so the remaining rows measure and glide into the freed place.
  const [settled, setSettled] = useState(0);
  const layoutDependency = `${keys.join("\u0000")}#${String(settled)}`;
  return (
    <tbody>
      <AnimatePresence
        onExitComplete={() => {
          setSettled((n) => n + 1);
        }}
      >
        {items.map((item, index) => {
          const key = keys[index] ?? keyOf(item);
          return (
            <RowPresence key={key} stagger={firstKeys.has(key) ? index : 0} layoutDependency={layoutDependency}>
              {(exiting) => children(item, { index, exiting })}
            </RowPresence>
          );
        })}
      </AnimatePresence>
    </tbody>
  );
}

/**
 * Up/Down/Home/End move the selection between rows and focus the row's primary link (`data-row-link={id}`); the URL
 * stays the selection owner. The latest intent wins: keys pressed faster than the URL updates move on from the row
 * last asked for, not from the one the URL still shows; a selection made elsewhere (a click) starts afresh.
 */
export function useRowNavigation(ids: string[], selected: string | undefined, select: (id: string) => void) {
  const pending = useRef<string | null>(null);
  /** The row last asked for, and every row asked for on the way to it (the URL may show any of them meanwhile). */
  const intent = useRef<{ id: string; chain: Set<string> } | null>(null);
  const focusLater = useCallback((root: HTMLElement, id: string) => {
    pending.current = id;
    requestAnimationFrame(() => {
      if (pending.current !== id) return;
      root.querySelector<HTMLElement>(`[data-row-link="${CSS.escape(id)}"]`)?.focus();
    });
  }, []);
  return (e: KeyboardEvent<HTMLDivElement>) => {
    if (!ids.length || (e.target as HTMLElement).closest("input, textarea, select, [role=menu]")) return;
    const asked = intent.current;
    const catchingUp =
      asked !== null &&
      asked.id !== selected &&
      ids.includes(asked.id) &&
      (selected === undefined || asked.chain.has(selected));
    if (!catchingUp) intent.current = null;
    const from = catchingUp ? asked.id : selected;
    const i = from ? ids.indexOf(from) : -1;
    let next: string | undefined;
    if (e.key === "ArrowDown") next = ids[Math.min(ids.length - 1, i + 1)];
    else if (e.key === "ArrowUp") next = ids[Math.max(0, i - 1)];
    else if (e.key === "Home") next = ids[0];
    else if (e.key === "End") next = ids[ids.length - 1];
    if (!next) return;
    e.preventDefault();
    const chain = intent.current?.chain ?? new Set(selected ? [selected] : []);
    chain.add(next);
    intent.current = { id: next, chain };
    if (next !== from) select(next);
    focusLater(e.currentTarget, next);
  };
}
