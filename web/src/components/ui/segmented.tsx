// Adapted from Phasyn Studio (Apache-2.0).
// A macOS-style segmented control for a few parallel choices (filters, modes): radio semantics (Radix RadioGroup —
// one Tab stop, arrow keys move the choice). The chosen block slides to the new option on the snappy spring
// (useThumb), options press with `pressable`, and the bold label never shifts its neighbours (StableLabel); a count that
// changes fades briefly. The choice itself is aria-checked and never waits for the block.
import { RadioGroup as R } from "radix-ui";
import { useId, useRef } from "react";
import { cn } from "@/lib/cn";
import { ChangeValue } from "./change-value";
import { COUNT_PILL } from "./look";
import { useThumb } from "./motion";
import { StableLabel } from "./stable-label";

export interface SegmentOption<V extends string> {
  value: V;
  label: string;
  count?: number | undefined;
  /** Tooltip (what the option contains). */
  title?: string | undefined;
}

/** Single-choice segmented control (radio semantics, arrow keys move the choice). */
export function Segmented<V extends string>({
  value,
  onChange,
  options,
  label,
  size = "md",
  className,
}: {
  /** `null`: none of the options holds now (nothing is shown chosen). */
  value: V | null;
  onChange: (value: V) => void;
  options: SegmentOption<V>[];
  label: string;
  size?: "sm" | "md" | undefined;
  className?: string | undefined;
}) {
  // Inside a form Radix adds hidden radio inputs; give them a name.
  const name = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const thumbRef = useRef<HTMLSpanElement>(null);
  useThumb(rootRef, thumbRef, '[role="radio"][data-state="checked"]');
  return (
    <R.Root
      ref={rootRef}
      name={name}
      value={value ?? ""}
      onValueChange={(v) => {
        onChange(v as V);
      }}
      aria-label={label}
      orientation="horizontal"
      className={cn(
        "relative inline-flex min-w-0 shrink-0 items-center rounded-lg border border-line-control/70 bg-sunken p-0.5",
        className,
      )}
    >
      <span
        ref={thumbRef}
        aria-hidden
        className="pointer-events-none absolute top-0 left-0 rounded-md border border-white/[0.07] bg-overlay opacity-0 shadow-[0_1px_2px_rgb(0_0_0_/_0.4),inset_0_1px_0_rgb(255_255_255_/_0.06)] transition-[transform,width,height,opacity] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) forced-colors:hidden"
      />
      {options.map((o) => {
        const chosen = o.value === value;
        return (
          <R.Item
            key={o.value}
            value={o.value}
            title={o.title}
            className={cn(
              "pressable relative z-[1] inline-flex min-w-0 items-center justify-center gap-1.5 rounded-md whitespace-nowrap outline-none focus-visible:ring-2 focus-visible:ring-focus",
              size === "sm" ? "h-6 px-2.5 text-caption" : "h-7 px-3 text-data",
              chosen ? "text-fg" : "text-fg-tertiary hover:text-fg-secondary",
              "disabled:cursor-not-allowed disabled:text-fg-disabled",
            )}
          >
            <StableLabel weight="medium" className={chosen ? "font-medium" : undefined}>
              {o.label}
            </StableLabel>
            {o.count !== undefined ? <ChangeValue value={o.count} className={COUNT_PILL} /> : null}
          </R.Item>
        );
      })}
    </R.Root>
  );
}
