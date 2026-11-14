// Adapted from Phasyn Studio (Apache-2.0).
// Fields: a sunken ground with a required control boundary (line-control ≥ 3:1); hover brightens the border one step;
// keyboard focus = the cyan ring in place of the border plus a faint brand-blue halo. md = 40 px, compact = 32 px
// (toolbars, property grids). Errors keep what the user typed.
import { ChevronDown, TriangleAlert } from "lucide-react";
import {
  forwardRef,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
  useId,
} from "react";
import { cn } from "@/lib/cn";
import { m } from "./messages";

const control = cn(
  "w-full min-w-0 rounded-md border border-line-control bg-sunken text-body text-fg transition-[border-color,box-shadow,color] duration-(--duration-fast) placeholder:text-fg-tertiary",
  "hover:border-fg-tertiary focus-visible:outline-offset-0 focus-visible:shadow-[0_0_0_4px_rgb(79_123_255_/_0.18)]",
  "aria-[invalid=true]:border-danger aria-[invalid=true]:focus-visible:shadow-[0_0_0_4px_rgb(244_135_146_/_0.18)]",
  "disabled:cursor-not-allowed disabled:border-line-strong disabled:text-fg-disabled",
);
const textEntry = "read-only:border-line read-only:text-fg-secondary";

/** Label + control + hint/warning/error, wired with ids for assistive technology. */
export function Field({
  label,
  hint,
  warning,
  error,
  required,
  units,
  children,
  className,
}: {
  label: string;
  hint?: ReactNode | undefined;
  /** Allowed but worth knowing (shown instead of the hint; an error wins). */
  warning?: string | null | undefined;
  error?: string | null | undefined;
  required?: boolean | undefined;
  /** Unit of the value, shown after the label (e.g. "秒"). */
  units?: string | undefined;
  children: (ids: { id: string; describedBy: string | undefined; invalid: boolean }) => ReactNode;
  className?: string | undefined;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = [hint || warning ? hintId : null, error ? errId : null].filter(Boolean).join(" ") || undefined;
  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
      <label htmlFor={id} className="flex flex-wrap items-baseline gap-x-1.5 text-data font-medium text-fg-secondary">
        <span>
          {label}
          {required ? (
            <span className="ml-1 text-danger" aria-hidden>
              *
            </span>
          ) : null}
        </span>
        {units ? <span className="text-caption font-normal text-fg-tertiary">{m.field.units(units)}</span> : null}
      </label>
      {children({ id, describedBy, invalid: Boolean(error) })}
      {error ? (
        <p id={errId} className="text-caption text-danger animate-reveal" role="alert">
          {error}
        </p>
      ) : warning ? (
        <p id={hintId} className="flex gap-1.5 text-caption text-warning animate-reveal">
          <TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0" />
          <span>{warning}</span>
        </p>
      ) : hint ? (
        <p id={hintId} className="text-caption text-fg-tertiary">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

type ControlSize = "sm" | "md";

/** `size="sm"` / `compact`: the 32 px control of toolbars and property grids. */
function isCompact(size: ControlSize | undefined, compact: boolean | undefined): boolean {
  return Boolean(compact) || size === "sm";
}

export const Input = forwardRef<
  HTMLInputElement,
  Omit<InputHTMLAttributes<HTMLInputElement>, "size"> & {
    mono?: boolean | undefined;
    size?: ControlSize | undefined;
    compact?: boolean | undefined;
  }
>(function Input({ className, mono, size, compact, ...rest }, ref) {
  return (
    <input
      ref={ref}
      {...rest}
      className={cn(
        control,
        textEntry,
        isCompact(size, compact) ? "min-h-8 px-2.5 py-1 text-data" : "min-h-10 px-3 py-2",
        mono && "machine text-data",
        className,
      )}
    />
  );
});

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean | undefined; compact?: boolean | undefined }
>(function Textarea({ className, mono, compact, ...rest }, ref) {
  return (
    <textarea
      ref={ref}
      {...rest}
      className={cn(
        control,
        textEntry,
        compact ? "px-2.5 py-1.5 text-data" : "px-3 py-2 leading-relaxed",
        mono && "machine text-data",
        className,
      )}
    />
  );
});

export const Select = forwardRef<
  HTMLSelectElement,
  SelectHTMLAttributes<HTMLSelectElement> & { compact?: boolean | undefined }
>(function Select({ className, children, compact, ...rest }, ref) {
  return (
    <div className="relative min-w-0">
      <select
        ref={ref}
        {...rest}
        className={cn(
          control,
          "appearance-none",
          compact ? "min-h-8 py-1 pr-8 pl-2.5 text-data" : "min-h-10 py-2 pr-9 pl-3",
          className,
        )}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden
        className={cn(
          "pointer-events-none absolute top-1/2 -translate-y-1/2 text-fg-tertiary",
          compact ? "right-2.5 size-3.5" : "right-3 size-4",
        )}
      />
    </div>
  );
});

/** A keycap (shortcut hints). */
export function Kbd({ children, className }: { children: ReactNode; className?: string | undefined }) {
  return (
    <kbd
      className={cn(
        "machine inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-sm border border-line bg-raised px-1.5 text-micro leading-none text-fg-secondary",
        className,
      )}
    >
      {children}
    </kbd>
  );
}
