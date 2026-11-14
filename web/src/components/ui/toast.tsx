// Adapted from Phasyn Studio (Apache-2.0).
// The one feedback channel: notifications stacked at the top right under the top bar, newest on top, at most four
// (the oldest goes first), on Motion: AnimatePresence keyed by the notification's id. A new one slides in on the
// bouncy spring (toastVariants); a closed or expired one pops out of the layout and leaves on the exit transition while
// the others glide into place (layout, snappy). A leaving notification is inert and hidden from assistive technology
// from the start of its exit. The data always updates at once — the list only presents it.
// Timing: success closes after 5 s, or 15 s when it offers a follow-up action (every such action is also reachable
// where it belongs); hovering or focusing pauses it and leaving resumes with the time left (at least 2 s). Information
// that is not yet confirmed, failures and unknown outcomes stay until dismissed. An unknown outcome offers a read-only
// lookup of the operation — never an automatic re-send; an offered action runs only when clicked.

import { CircleAlert, CircleCheck, CircleHelp, Info, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type Ref, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { ApiFailure, lookupOperation } from "@/api/client";
import { queryClient } from "@/api/query-client";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { forgetUnknownKey } from "@/lib/intent";
import { Button } from "./button";
import { m } from "./messages";
import { usePresenceInert } from "./motion";
import { layoutTransition, toastVariants } from "./motion-tokens";

type Tone = "success" | "error" | "unknown" | "info";

/** A follow-up the user may take (e.g. "建立連線"); it reports its own outcome. */
export interface ToastAction {
  label: string;
  run: () => unknown;
  pendingLabel?: string | undefined;
}

interface ToastItem {
  id: number;
  tone: Tone;
  title: string;
  description?: string | undefined;
  /** Idempotency key of a mutation whose outcome is unknown. */
  lookupKey?: string | undefined;
  lookupState?: "idle" | "pending" | undefined;
  action?: ToastAction | undefined;
  actionPending?: boolean | undefined;
}

const MAX = 4;
let items: ToastItem[] = [];
let seq = 0;
const listeners = new Set<() => void>();

function emit(next: ToastItem[]) {
  items = next;
  for (const l of listeners) l();
}

function push(t: Omit<ToastItem, "id">): number {
  seq += 1;
  const id = seq;
  const next = [...items, { ...t, id }];
  emit(next.length > MAX ? next.slice(next.length - MAX) : next);
  return id;
}

function patch(id: number, p: Partial<ToastItem>) {
  emit(items.map((t) => (t.id === id ? { ...t, ...p } : t)));
}

export const toast = {
  success: (title: string, description?: string, action?: ToastAction) =>
    push({ tone: "success", title, description, action }),
  info: (title: string, description?: string, action?: ToastAction) =>
    push({ tone: "info", title, description, action }),
  error: (title: string, description?: string) => push({ tone: "error", title, description }),
  dismiss: (id: number) => {
    emit(items.filter((t) => t.id !== id));
  },
};

/** Report a failed mutation for `intent` (e.g. "啟動 tokyo-1"). */
export function reportFailure(intent: string, e: unknown) {
  if (e instanceof ApiFailure && e.kind === "unknown_outcome" && e.idempotencyKey) {
    push({
      tone: "unknown",
      title: m.toast.outcomeUnknown(intent),
      description: m.toast.outcomeUnknownDetail,
      lookupKey: e.idempotencyKey,
      lookupState: "idle",
    });
    return;
  }
  const message = e instanceof Error ? e.message : m.unexpectedError;
  // "刪除 Mullvad · Tokyo jp-tyo-wg-001 失敗": each language joins the intent and the outcome its own way (messages.ts).
  push({ tone: "error", title: m.toast.failed(intent), description: message });
}

async function lookup(t: ToastItem) {
  if (!t.lookupKey) return;
  patch(t.id, { lookupState: "pending" });
  try {
    const op = await lookupOperation(t.lookupKey);
    if (!op) {
      // No record proves nothing: it may not have arrived, may still run, or (a stop under a busy store) may have run
      // without a record. The key stays, so redoing reuses it.
      patch(t.id, { description: m.toast.noRecord, lookupState: "idle" });
      return;
    }
    if (op.status !== "accepted" && op.status !== "running") forgetUnknownKey(t.lookupKey);
    if (op.status === "succeeded") {
      patch(t.id, { tone: "success", description: m.toast.confirmed, lookupKey: undefined });
      void queryClient.invalidateQueries();
    } else if (op.status === "failed" || op.status === "cancelled") {
      patch(t.id, {
        tone: "error",
        description: op.error ? localized(op.error.message) : m.toast.notCompleted,
        lookupKey: undefined,
      });
    } else if (op.status === "unknown") {
      patch(t.id, { description: m.toast.undetermined, lookupKey: undefined });
      void queryClient.invalidateQueries();
    } else {
      patch(t.id, { description: m.toast.stillRunning, lookupState: "idle" });
    }
  } catch (err) {
    patch(t.id, {
      description: m.toast.lookupFailed(err instanceof Error ? err.message : m.toast.unknownError),
      lookupState: "idle",
    });
  }
}

/** Run an offered action once; the notification goes when it is done. */
async function runAction(t: ToastItem) {
  if (!t.action) return;
  patch(t.id, { actionPending: true });
  try {
    await t.action.run();
    toast.dismiss(t.id);
  } catch {
    patch(t.id, { actionPending: false });
  }
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}
const snapshot = () => items;

function useToasts(): ToastItem[] {
  return useSyncExternalStore(subscribe, snapshot);
}

const LOOK: Record<Tone, { icon: typeof Info; tile: string; label: string }> = {
  success: { icon: CircleCheck, tile: "bg-success/15 text-success", label: m.toast.tone.success },
  error: { icon: CircleAlert, tile: "bg-danger/15 text-danger", label: m.toast.tone.error },
  unknown: { icon: CircleHelp, tile: "bg-warning/15 text-warning", label: m.toast.tone.unknown },
  info: { icon: Info, tile: "bg-info/15 text-info", label: m.toast.tone.info },
};

/** How long a notification stays on its own (ms), or null when it stays until dismissed. */
function lifetime(t: ToastItem): number | null {
  if (t.tone !== "success") return null;
  return t.action ? 15_000 : 5000;
}

const RESUME_AT_LEAST = 2000;

function ToastCard({ t, ref }: { t: ToastItem; ref?: Ref<HTMLDivElement> | undefined }) {
  const { exiting, props } = usePresenceInert();
  const L = LOOK[t.tone];
  const Icon = L.icon;
  const [paused, setPaused] = useState(false);
  const life = lifetime(t);
  const remaining = useRef<number | null>(life);
  const lifeShown = useRef(life);

  // The timer only decides when to dismiss; the exit is AnimatePresence's job.
  useEffect(() => {
    // A notification that turns into a success (a looked-up unknown outcome) starts its own clock then.
    if (lifeShown.current !== life) {
      lifeShown.current = life;
      remaining.current = life;
    }
    if (remaining.current === null || paused || exiting) return;
    const started = performance.now();
    const timer = window.setTimeout(() => {
      toast.dismiss(t.id);
    }, remaining.current);
    return () => {
      window.clearTimeout(timer);
      if (remaining.current !== null)
        remaining.current = Math.max(RESUME_AT_LEAST, remaining.current - (performance.now() - started));
    };
  }, [paused, exiting, t.id, life]);

  return (
    // Pointer and focus only pause the dismiss timer (a status or alert card, not a control).
    <motion.div
      ref={ref}
      id={`toast-${t.id}`}
      role={exiting ? undefined : t.tone === "error" || t.tone === "unknown" ? "alert" : "status"}
      // A leaving card is neither interactive nor announced twice.
      {...props}
      layout
      variants={toastVariants()}
      initial="hidden"
      animate="shown"
      exit="gone"
      transition={layoutTransition()}
      onPointerEnter={() => {
        setPaused(true);
      }}
      onPointerLeave={() => {
        setPaused(false);
      }}
      onFocus={() => {
        setPaused(true);
      }}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setPaused(false);
      }}
      className={cn(
        "material-popover flex items-start gap-2.5 rounded-xl px-3 py-2.5 text-fg forced-colors:border forced-colors:border-[CanvasText]",
        exiting ? "pointer-events-none" : "pointer-events-auto",
      )}
    >
      <span aria-hidden className={cn("grid size-7 shrink-0 place-items-center rounded-full", L.tile)}>
        <Icon className="size-4" />
      </span>
      <div className="grid min-w-0 flex-1 gap-0.5 pt-0.5">
        <p className="text-data font-medium text-fg [overflow-wrap:anywhere]">
          <span className="sr-only">{m.toast.toneLead(L.label)}</span>
          {t.title}
        </p>
        {t.description ? (
          <p className="text-caption text-fg-secondary [overflow-wrap:anywhere]">{t.description}</p>
        ) : null}
        {t.lookupKey ? (
          <div className="mt-1.5">
            <Button
              size="sm"
              pending={t.lookupState === "pending"}
              pendingLabel={m.toast.lookingUp}
              onClick={() => void lookup(t)}
            >
              {m.toast.lookup}
            </Button>
          </div>
        ) : t.action ? (
          <div className="mt-1.5">
            <Button
              size="sm"
              pending={t.actionPending}
              pendingLabel={t.action.pendingLabel ?? m.working}
              onClick={() => void runAction(t)}
            >
              {t.action.label}
            </Button>
          </div>
        ) : null}
      </div>
      <button
        type="button"
        aria-label={m.toast.close}
        title={life !== null ? (paused ? m.toast.closePaused : m.toast.closePausesOnHover) : m.toast.close}
        onClick={() => {
          toast.dismiss(t.id);
        }}
        className="pressable inline-flex size-6 shrink-0 items-center justify-center rounded-md text-fg-tertiary hover:bg-white/10 hover:text-fg active:bg-sunken"
      >
        <X aria-hidden className="size-3.5" />
      </button>
    </motion.div>
  );
}

export function Toaster() {
  const list = useToasts();
  // Each card carries its own live role, so the region itself is not live (some screen readers would read it twice).
  return (
    <section
      aria-label={m.toast.region}
      className="pointer-events-none fixed top-14 right-4 z-[60] w-[min(24rem,calc(100vw-2rem))]"
    >
      <div className="relative grid gap-2">
        <AnimatePresence mode="popLayout">
          {[...list].reverse().map((item) => (
            <ToastCard key={item.id} t={item} />
          ))}
        </AnimatePresence>
      </div>
    </section>
  );
}
