// Adapted from Phasyn Studio (Apache-2.0).
import type { LucideIcon } from "lucide-react";
import { motion } from "motion/react";
import { Tabs as T } from "radix-ui";
import { createContext, type ReactNode, useContext, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import { ActiveIndicator } from "./active-indicator";
import { COUNT_PILL } from "./look";
import { swapVariants } from "./motion-tokens";
import { StableLabel } from "./stable-label";

export interface TabItem<V extends string> {
  value: V;
  label: string;
  icon?: LucideIcon | undefined;
  /** A small trailing marker (e.g. how many items need attention). */
  badge?: ReactNode | undefined;
}

/**
 * page: a page's views (the system page): 40 px tabs with icons, the list as wide as the page.
 * compact: the views of one object in an inspector or editor (340–420 px wide): 36 px tabs, labels only, the first
 * label in line with the header's text; up to six two-character labels fit in the narrowest inspector.
 */
type TabsSize = "page" | "compact";

/** The tab shown when the Tabs mounted, until the first change: its panel appears at once (nothing replays on load). */
const FirstTabContext = createContext<string | null>(null);

// A phone-wide page drops the icons and tightens the tabs, so six of them still fit at 390 px; a narrower screen
// scrolls the list itself (its overflowing edge fades), never the page.
const LIST: Record<TabsSize, string> = {
  page: "gap-1 px-4 max-sm:gap-0 max-sm:px-2 md:px-6",
  compact: "px-1",
};

const TRIGGER: Record<TabsSize, string> = {
  page: "h-10 gap-2 rounded-t-md px-3 max-sm:px-2 max-sm:[&>svg]:hidden [&_svg]:size-4",
  compact: "h-9 gap-1.5 rounded-t-md px-[7px] [&_svg]:size-3.5",
};

/**
 * Views of one object as real tabs (Radix: tablist/tab/tabpanel, arrow keys, Home/End). The caller keeps the value
 * (usually in the URL) and renders each panel with `TabPanel`. The brand-gradient underline slides to the new tab on
 * the snappy spring and the new panel cross-fades in (Motion, swapVariants; the first panel shows at once). Only the
 * active panel is rendered, so the old one is gone at once and never stays a second interactive copy; the selected label turns bold
 * without shifting its neighbours.
 */
export function Tabs<V extends string>({
  value,
  onChange,
  items,
  label,
  children,
  className,
  size = "page",
}: {
  value: V;
  onChange: (value: V) => void;
  items: TabItem<V>[];
  label: string;
  children: ReactNode;
  className?: string | undefined;
  size?: TabsSize | undefined;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const [first, setFirst] = useState<string | null>(value);
  if (first !== null && first !== value) setFirst(null);
  return (
    <T.Root
      value={value}
      onValueChange={(v) => {
        onChange(v as V);
      }}
      className={cn("flex min-h-0 flex-1 flex-col", className)}
    >
      <T.List
        ref={listRef}
        aria-label={label}
        className={cn(
          "scroll-x-fade relative flex shrink-0 overflow-x-auto border-b border-line-subtle [scrollbar-width:none]",
          LIST[size],
        )}
      >
        {items.map((it) => {
          const Icon = it.icon;
          const selected = it.value === value;
          return (
            <T.Trigger
              key={it.value}
              value={it.value}
              className={cn(
                "relative inline-flex shrink-0 items-center text-data whitespace-nowrap outline-none",
                TRIGGER[size],
                "focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-inset",
                "[&_svg]:shrink-0 [&_svg]:transition-colors [&_svg]:duration-(--duration-fast)",
                selected
                  ? "text-fg [&_svg]:text-action-fg"
                  : "text-fg-secondary hover:bg-raised/60 hover:text-fg [&_svg]:text-fg-tertiary",
              )}
            >
              {Icon ? <Icon aria-hidden /> : null}
              <StableLabel className={selected ? "font-semibold" : undefined}>{it.label}</StableLabel>
              {/* The space keeps the badge a word of the tab's name ("連入埠 3"); a flex container does not render it. */}
              {it.badge ? <> {it.badge}</> : null}
            </T.Trigger>
          );
        })}
        <ActiveIndicator container={listRef} edge="bottom" />
      </T.List>
      <FirstTabContext.Provider value={first}>{children}</FirstTabContext.Provider>
    </T.Root>
  );
}

/**
 * One tab's panel: the scroll owner of its view. Inactive panels are not rendered, so whatever a panel edits keeps its
 * state outside it. Keyboard users reach the panel itself with Tab (Radix makes it focusable, so it scrolls with the
 * arrow keys); its focus is an inset outline, which forced colours keep.
 */
export function TabPanel({
  value,
  children,
  className,
}: {
  value: string;
  children: ReactNode;
  className?: string | undefined;
}) {
  const first = useContext(FirstTabContext);
  return (
    <T.Content value={value} asChild>
      <motion.div
        variants={swapVariants()}
        initial={value === first ? false : "hidden"}
        animate="shown"
        className={cn(
          "min-h-0 flex-1 overflow-y-auto focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus",
          className,
        )}
      >
        {children}
      </motion.div>
    </T.Content>
  );
}

/**
 * A tab's badge: a count (records, ports, hints; the same pill as a segment's count) or, with tone "danger" or
 * "warning", a problem in that view (a field that will not save). `label` is read after the value ("2 個問題").
 */
export function TabCount({
  value,
  tone = "neutral",
  label,
}: {
  value: number | string;
  tone?: "neutral" | "warning" | "danger" | undefined;
  label?: string | undefined;
}) {
  return (
    <span
      className={cn(
        COUNT_PILL,
        tone === "danger" && "bg-danger/15 text-danger",
        tone === "warning" && "bg-warning/15 text-warning",
      )}
    >
      {value}
      {label ? <span className="sr-only"> {label}</span> : null}
    </span>
  );
}
