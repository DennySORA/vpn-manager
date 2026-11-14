// Adapted from Phasyn Studio (Apache-2.0).
// Status chips, tags and dots. State is always a symbol plus a word; colour is only the second cue. A chip's tone
// moves on the snappy spring and its icon and word fade in when the state changes (never on the first render).
import type { LucideIcon } from "lucide-react";
import { LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { StateLook, Tone } from "@/lib/status";
import { ChangeFade } from "./change-value";
import { CHIP_TONE, DOT_TONE, TEXT_TONE, type ToneKey } from "./tones";

export const toneText: Record<Tone, string> = {
  success: TEXT_TONE.success,
  info: TEXT_TONE.info,
  warning: TEXT_TONE.warning,
  danger: TEXT_TONE.danger,
  neutral: TEXT_TONE.neutral,
  brand: TEXT_TONE.brand,
};

/** Ground and border of a tone (no text colour). */
export const toneFill: Record<Tone, string> = {
  success: "border-success/30 bg-success/12",
  info: "border-info/30 bg-info/12",
  warning: "border-warning/30 bg-warning/12",
  danger: "border-danger/30 bg-danger/12",
  neutral: "border-line bg-raised",
  brand: "border-action/30 bg-action/12",
};

const CHIP =
  "inline-flex max-w-full shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-px text-caption font-medium transition-[color,background-color,border-color] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)";

/** A runtime state (from lib/status): its icon (spinning while busy) and word. */
export function StatusPill({
  look,
  className,
  title,
}: {
  look: StateLook;
  className?: string | undefined;
  title?: string | undefined;
}) {
  const Icon = look.icon;
  return (
    <span title={title} className={cn(CHIP, "min-h-6", CHIP_TONE[look.tone], className)}>
      <ChangeFade
        value={`${look.tone}:${look.label}:${look.busy ? 1 : 0}`}
        className="inline-flex min-w-0 items-center gap-1.5"
      >
        <Icon aria-hidden className={cn("size-3.5 shrink-0", look.busy && "animate-spin")} strokeWidth={2} />
        <span className="truncate">{look.label}</span>
      </ChangeFade>
    </span>
  );
}

/** A state as a dot and a word (a spinning icon while in progress). */
export function StatusChip({
  tone,
  label,
  spinning = false,
  title,
  className,
}: {
  tone: ToneKey;
  label: string;
  spinning?: boolean | undefined;
  title?: string | undefined;
  className?: string | undefined;
}) {
  return (
    <span title={title} className={cn(CHIP, "px-1.5", CHIP_TONE[tone], className)}>
      <ChangeFade value={`${tone}:${label}:${spinning ? 1 : 0}`} className="inline-flex min-w-0 items-center gap-1.5">
        {spinning ? (
          <LoaderCircle aria-hidden className="size-3 shrink-0 animate-spin" />
        ) : (
          <span aria-hidden className="size-1.5 shrink-0 rounded-full bg-current" />
        )}
        <span className="truncate">{label}</span>
      </ChangeFade>
    </span>
  );
}

/** A small fact label (a kind, a mode, "內建"). */
export function Tag({
  children,
  tone = "neutral",
  icon: Icon,
  className,
}: {
  children: ReactNode;
  tone?: ToneKey | undefined;
  icon?: LucideIcon | undefined;
  className?: string | undefined;
}) {
  return (
    <span
      className={cn(
        "inline-flex max-w-full items-center gap-1 whitespace-nowrap rounded-full border px-2 py-px text-caption font-medium [&_svg]:size-3 [&_svg]:shrink-0",
        CHIP_TONE[tone],
        className,
      )}
    >
      {Icon ? <Icon aria-hidden strokeWidth={2} /> : null}
      {children}
    </span>
  );
}

/** A small live dot (paired with text by the caller); `pulse` breathes while the state is being established. */
export function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean | undefined }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block size-2 shrink-0 rounded-full forced-colors:bg-[CanvasText]",
        DOT_TONE[tone],
        pulse && "brand-breathe",
      )}
    />
  );
}
