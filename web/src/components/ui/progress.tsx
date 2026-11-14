// Adapted from Phasyn Studio (Apache-2.0).
// Progress only from real ratios (bytes, completed steps, observed counts). Without evidence there is no ratio: use an
// indeterminate track or a spinning icon and a word. Progress moves linearly, never on a spring.
import { useId } from "react";
import { cn } from "@/lib/cn";
import { m } from "./messages";

/**
 * A macOS-style circular progress: a thin line-strong track and an arc in the four-stop brand gradient (its own
 * gradient, no external defs) that advances linearly. role="progressbar" with aria-valuenow (0–100).
 */
export function CircularProgress({
  value,
  size = 20,
  strokeWidth = 2.5,
  label = m.progress.label,
  showValue = false,
  className,
}: {
  /** 0–1. */
  value: number;
  /** Diameter (px). */
  size?: number | undefined;
  /** Arc width in the 24-unit box. */
  strokeWidth?: number | undefined;
  label?: string | undefined;
  /** The percentage in the centre (legible from 36 px). */
  showValue?: boolean | undefined;
  className?: string | undefined;
}) {
  const id = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const fraction = Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 0;
  const percent = Math.round(fraction * 100);
  const radius = 12 - strokeWidth / 2 - 0.5;
  const circumference = 2 * Math.PI * radius;
  return (
    <span
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
      aria-valuetext={`${percent}%`}
      className={cn("relative inline-grid shrink-0 place-items-center", className)}
      style={{ width: size, height: size }}
    >
      <svg viewBox="0 0 24 24" width={size} height={size} aria-hidden focusable="false" className="-rotate-90">
        <defs>
          <linearGradient id={`cp-${id}`} x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
            <stop offset="0" style={{ stopColor: "var(--color-brand-cyan)" }} />
            <stop offset="0.36" style={{ stopColor: "var(--color-brand-blue)" }} />
            <stop offset="0.68" style={{ stopColor: "var(--color-brand-iris)" }} />
            <stop offset="1" style={{ stopColor: "var(--color-brand-violet)" }} />
          </linearGradient>
        </defs>
        <circle cx="12" cy="12" r={radius} fill="none" strokeWidth={strokeWidth} className="stroke-line-strong" />
        <circle
          cx="12"
          cy="12"
          r={radius}
          fill="none"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          stroke={`url(#cp-${id})`}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - fraction)}
          className="transition-[stroke-dashoffset] duration-200 ease-linear forced-colors:stroke-[Highlight]"
        />
      </svg>
      {showValue ? (
        <span className="machine absolute text-[10px] leading-none text-fg-secondary">{percent}</span>
      ) : null}
    </span>
  );
}

export type ProgressTone = "running" | "done" | "failed" | "idle";

const FILL: Record<ProgressTone, string> = {
  running: "bg-brand-gradient animate-shimmer",
  done: "bg-success",
  failed: "bg-danger",
  idle: "bg-line-strong",
};

/**
 * A linear track: running = brand gradient with a sweeping highlight; done = success; failed = danger; idle = neutral.
 * `value === null` = indeterminate: the whole track shimmers softly and there is no aria-valuenow (no invented number).
 * The width moves with --duration-base; the state never waits for it.
 */
export function ProgressTrack({
  value,
  max = 1,
  tone,
  label,
  valueText,
  size = "md",
  className,
}: {
  value: number | null;
  max?: number | undefined;
  tone: ProgressTone;
  /** Accessible name (e.g. "下載進度"). */
  label: string;
  /** What assistive technology reads (e.g. "12／30 MB"). */
  valueText?: string | undefined;
  size?: "sm" | "md" | undefined;
  className?: string | undefined;
}) {
  const fraction = value === null || max <= 0 ? null : Math.min(1, Math.max(0, value / max));
  const track = cn(
    "relative block overflow-hidden rounded-full bg-sunken shadow-[inset_0_0_0_1px_var(--color-line-subtle)] forced-colors:border forced-colors:border-[CanvasText]",
    size === "sm" ? "h-1" : "h-1.5",
    className,
  );
  if (fraction === null) {
    return (
      <span
        role="progressbar"
        aria-label={label}
        aria-valuetext={valueText ?? (tone === "running" ? m.progress.running : undefined)}
        className={track}
      >
        <span
          aria-hidden
          className={cn(
            "absolute inset-0 rounded-full",
            tone === "running" ? "bg-brand-gradient-soft animate-shimmer" : FILL[tone],
          )}
        />
      </span>
    );
  }
  return (
    <span
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value ?? undefined}
      aria-valuetext={valueText}
      className={track}
    >
      <span
        aria-hidden
        className={cn(
          "absolute inset-y-0 left-0 rounded-full transition-[width] duration-(--duration-base) ease-linear forced-colors:bg-[Highlight]",
          FILL[tone],
        )}
        style={{ width: `${fraction * 100}%` }}
      />
    </span>
  );
}
