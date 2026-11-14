// Adapted from Phasyn Studio (Apache-2.0).
import { Switch as S } from "radix-ui";
import { type ReactNode, useId } from "react";
import { cn } from "@/lib/cn";

/**
 * On/off control with its own label. On = the deep action gradient with a white thumb that springs across (snappy);
 * the focus ring is drawn on the track. Every state keeps a visible thumb, including checked + disabled.
 */
export function Switch({
  checked,
  onCheckedChange,
  label,
  description,
  disabled,
  autofocus,
  className,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: ReactNode;
  description?: ReactNode | undefined;
  disabled?: boolean | undefined;
  /** The control a dialog focuses when it opens (`Dialog`), not the hidden checkbox Radix adds. */
  autofocus?: boolean | undefined;
  className?: string | undefined;
}) {
  const id = useId();
  return (
    // Positioned: inside a form Radix adds an absolutely positioned hidden checkbox, which must stay in this box
    // (and in the panel that scrolls it).
    <div className={cn("relative flex items-start gap-3", className)}>
      <S.Root
        id={id}
        data-autofocus={autofocus ? true : undefined}
        // Inside a form Radix adds a hidden checkbox; give it a name.
        name={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-describedby={description ? `${id}-d` : undefined}
        className={cn(
          "relative mt-px inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-[background-color,border-color,box-shadow] duration-(--duration-fast)",
          "border-line-control bg-sunken hover:border-fg-tertiary",
          "data-[state=checked]:border-transparent data-[state=checked]:bg-action-gradient data-[state=checked]:hover:brightness-110",
          "disabled:cursor-not-allowed disabled:border-line-subtle disabled:bg-raised disabled:hover:border-line-subtle",
          "data-[state=checked]:disabled:bg-none data-[state=checked]:disabled:bg-[rgb(58_120_242_/_0.35)] data-[state=checked]:disabled:hover:brightness-100",
        )}
      >
        <S.Thumb
          className={cn(
            "block size-3.5 translate-x-0.5 rounded-full bg-fg-secondary shadow-[0_1px_2px_rgb(0_0_0_/_0.4)]",
            "transition-[translate,background-color] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)",
            "data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-[#fff]",
            disabled && "bg-fg-disabled data-[state=checked]:bg-fg-secondary",
          )}
        />
      </S.Root>
      <div className="min-w-0">
        <label htmlFor={id} className={cn("text-body", disabled ? "text-fg-tertiary" : "cursor-pointer text-fg")}>
          {label}
        </label>
        {description ? (
          <p id={`${id}-d`} className="text-caption text-fg-tertiary">
            {description}
          </p>
        ) : null}
      </div>
    </div>
  );
}
