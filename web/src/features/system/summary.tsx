// The raised conclusion of a 系統 view (its one primary summary, docs/frontend-design.md §8.1): a verdict in symbol and
// words, where it came from, the view's actions, and the facts behind it underneath. A verdict or a fact that changes
// moves its tone on the snappy spring and fades its words in (never on the first render); counts fade when they change.

import type { LucideIcon } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import { toneFill, toneText } from "@/components/ui/badge";
import { ChangeFade, ChangeValue } from "@/components/ui/change-value";
import { STAGGER_IN } from "@/components/ui/look";
import { Skeleton } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import type { StateLook, Tone } from "@/lib/status";

const TONE_SHIFT =
  "transition-[color,background-color,border-color] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)";

export function SummaryBand({
  label,
  tone,
  icon: Icon,
  busy,
  title,
  detail,
  aside,
  children,
  style,
}: {
  label: string;
  tone: Tone;
  icon: LucideIcon;
  busy?: boolean;
  title: string;
  detail: ReactNode;
  /** The view's actions (and where the facts came from). */
  aside?: ReactNode;
  children?: ReactNode;
  style?: CSSProperties | undefined;
}) {
  return (
    <section aria-label={label} style={style} className={cn("panel-raised", STAGGER_IN)}>
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
        <ChangeFade as="div" value={`${tone}:${title}`} className="flex min-w-0 flex-1 basis-72 items-center gap-3.5">
          <span
            aria-hidden
            className={cn(
              "grid size-10 shrink-0 place-items-center rounded-full border",
              TONE_SHIFT,
              toneFill[tone],
              toneText[tone],
            )}
          >
            <Icon className={cn("size-5", busy && "animate-spin")} />
          </span>
          <div className="min-w-0">
            <h2 className="text-section font-semibold text-fg [overflow-wrap:anywhere]">{title}</h2>
            <p className="text-data text-fg-secondary">{detail}</p>
          </div>
        </ChangeFade>
        {aside ? <div className="flex shrink-0 flex-wrap items-center gap-2">{aside}</div> : null}
      </div>
      {children ? <div className="border-t border-line-subtle">{children}</div> : null}
    </section>
  );
}

/** One fact of a summary band: a label, its state in symbol and words, and a short source line. */
export function SummaryCell({ label, look, detail }: { label: string; look: StateLook | null; detail?: ReactNode }) {
  const Icon = look?.icon;
  return (
    <div className="min-w-0 px-5 py-3">
      <dt className="text-caption text-fg-tertiary">{label}</dt>
      <dd className="mt-0.5 min-w-0">
        {look && Icon ? (
          <ChangeFade
            value={`${look.tone}:${look.label}`}
            className={cn("inline-flex items-center gap-1.5 text-data font-medium", TONE_SHIFT, toneText[look.tone])}
          >
            <Icon aria-hidden className={cn("size-4 shrink-0", look.busy && "animate-spin")} />
            {look.label}
          </ChangeFade>
        ) : (
          <Skeleton className="mt-1 w-16" />
        )}
        {detail ? <span className="block truncate text-caption text-fg-tertiary">{detail}</span> : null}
      </dd>
    </div>
  );
}

/** A count of a summary band (checks by status, leftovers by kind): zero stays quiet, a change fades in. */
export function SummaryCount({
  label,
  icon: Icon,
  count,
  tone,
  detail,
}: {
  label: string;
  icon: LucideIcon;
  count: number;
  /** The colour a non-zero count takes. */
  tone: Tone;
  detail?: ReactNode;
}) {
  return (
    <div className="min-w-0 px-5 py-3">
      <dt className="flex items-center gap-1.5 text-caption text-fg-tertiary">
        <Icon aria-hidden className={cn("size-3.5", TONE_SHIFT, count ? toneText[tone] : undefined)} />
        {label}
      </dt>
      <dd className="flex items-baseline gap-1.5">
        <ChangeValue
          value={count}
          className={cn(
            "machine text-title",
            TONE_SHIFT,
            count ? (tone === "success" || tone === "neutral" ? "text-fg" : toneText[tone]) : "text-fg-tertiary",
          )}
        />
        {detail ? <span className="truncate text-caption text-fg-tertiary">{detail}</span> : null}
      </dd>
    </div>
  );
}
