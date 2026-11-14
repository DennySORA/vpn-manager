// Adapted from Phasyn Studio (Apache-2.0).
import { CircleHelp } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { m } from "./messages";

/**
 * The (?) toggle of a help text: click or Enter shows the paragraph below; the pointer's title shows the same text.
 * Details go here instead of into long page paragraphs.
 */
export function HelpButton({
  open,
  onToggle,
  controls,
  label,
  text,
  className,
}: {
  open: boolean;
  onToggle: () => void;
  /** The HelpText's id. */
  controls: string;
  /** What the help is about (e.g. a field name), read as "{label}：說明". */
  label: string;
  /** Pointer tooltip (plain text). */
  text?: string | undefined;
  className?: string | undefined;
}) {
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-controls={controls}
      aria-label={m.help.about(label)}
      title={text}
      onClick={onToggle}
      className={cn(
        "pressable inline-flex size-6 shrink-0 items-center justify-center rounded-md text-fg-tertiary hover:bg-raised hover:text-fg active:bg-sunken aria-expanded:text-action-fg [&_svg]:size-3.5",
        className,
      )}
    >
      <CircleHelp aria-hidden />
    </button>
  );
}

/** The help paragraph: always in the DOM (hidden when closed, so aria-describedby still reads it), fading in when shown. */
export function HelpText({
  id,
  open,
  children,
  className,
}: {
  id: string;
  open: boolean;
  children: ReactNode;
  className?: string | undefined;
}) {
  return (
    <p id={id} hidden={!open} className={cn("text-caption text-fg-tertiary animate-reveal", className)}>
      {children}
    </p>
  );
}
