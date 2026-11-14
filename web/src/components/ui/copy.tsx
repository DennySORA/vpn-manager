// Adapted from Phasyn Studio (Apache-2.0): pressable feedback and the change fade of the copied state.
import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/cn";
import { ChangeFade } from "./change-value";
import { m } from "./messages";

/**
 * Puts `text` on the clipboard. Plain HTTP to a LAN address is not a secure context, so the
 * asynchronous clipboard API is missing there; a selected, hidden textarea and the copy command
 * still work for a click. Focus goes back to where it was.
 */
export async function writeClipboard(text: string): Promise<void> {
  // lib.dom types `clipboard` as always present; outside a secure context it is undefined.
  const { clipboard } = navigator as { clipboard?: Clipboard | undefined };
  if (clipboard) return clipboard.writeText(text);
  const back = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.setAttribute("aria-hidden", "true");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.focus();
  area.select();
  // eslint-disable-next-line @typescript-eslint/no-deprecated -- the only copy path without a secure context (no replacement API there)
  const copied = document.execCommand("copy");
  area.remove();
  back?.focus();
  if (!copied) throw new Error("copy command refused");
}

/** Copies a public value (address, port, key fingerprint). Secrets are never readable, so never copyable. */
export function CopyButton({
  value,
  label,
  className,
}: {
  value: string;
  label: string;
  className?: string | undefined;
}) {
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  const copy = async () => {
    try {
      await writeClipboard(value);
      setState("done");
    } catch {
      setState("failed");
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setState("idle");
    }, 1600);
  };

  const Icon = state === "done" ? Check : Copy;
  // 「複製 DNS 設定 ID」, 「複製位址」: each language places and spaces the label its own way (messages.ts).
  const name = m.copy.name(label);
  // The icon swaps with a short fade (a check after copying), never on the first render.
  return (
    <button
      type="button"
      onClick={() => void copy()}
      aria-label={name}
      title={state === "failed" ? m.copy.refused : name}
      className={cn(
        "pressable relative inline-flex size-6 shrink-0 items-center justify-center rounded-md text-fg-tertiary hover:bg-raised hover:text-fg active:bg-sunken",
        state === "done" && "text-success hover:text-success",
        state === "failed" && "text-danger hover:text-danger",
        className,
      )}
    >
      <ChangeFade value={state} className="inline-flex">
        <Icon aria-hidden className="size-3.5" />
      </ChangeFade>
      <span className="sr-only" aria-live="polite">
        {state === "done" ? m.copy.done : state === "failed" ? m.copy.failed : ""}
      </span>
    </button>
  );
}
