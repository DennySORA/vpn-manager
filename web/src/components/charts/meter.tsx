// A usage meter (space used of a quota, of a disk): role="meter" with its value in words. The fill is the brand gradient
// while usage is normal and the status colour once it is a warning or a problem (with the words beside it); its width
// moves linearly (a measured quantity never springs). `mark` draws where a threshold begins. Forced colours: the fill
// is Highlight, the border and mark CanvasText (app.css).
import { cn } from "@/lib/cn";

export type MeterTone = "normal" | "warning" | "danger";

const FILL: Record<MeterTone, string> = {
  normal: "bg-brand-gradient",
  warning: "bg-warning",
  danger: "bg-danger",
};

/** The share of the track a value fills (0–1); something used never shows as nothing. */
export function meterShare(value: number, max: number): number {
  if (!(max > 0) || !(value > 0)) return 0;
  return Math.min(1, Math.max(value / max, 0.01));
}

export function UsageMeter({
  label,
  value,
  max,
  valueText,
  tone = "normal",
  mark = null,
  className,
}: {
  /** Accessible name (e.g. "指標空間使用量"). */
  label: string;
  value: number;
  max: number;
  /** What assistive technology reads (e.g. "12 MiB／64 MiB"). */
  valueText: string;
  tone?: MeterTone | undefined;
  /** Where a threshold begins, 0–1 of the track. */
  mark?: number | null | undefined;
  className?: string | undefined;
}) {
  return (
    <div
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={Math.min(Math.max(value, 0), max)}
      aria-valuetext={valueText}
      className={cn("relative h-2 overflow-hidden rounded-full bg-sunken ring-1 ring-line-subtle", className)}
    >
      <div
        className={cn(
          "meter-fill absolute inset-y-0 left-0 rounded-full transition-[width] duration-(--duration-base) ease-linear",
          FILL[tone],
        )}
        style={{ width: `${meterShare(value, max) * 100}%` }}
      />
      {mark !== null ? (
        <div
          aria-hidden
          className="meter-mark absolute inset-y-0 w-0.5 bg-warning"
          style={{ left: `calc(${Math.min(1, Math.max(0, mark)) * 100}% - 1px)` }}
        />
      ) : null}
    </div>
  );
}
