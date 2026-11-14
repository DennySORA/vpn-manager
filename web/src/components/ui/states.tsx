// Adapted from Phasyn Studio (Apache-2.0).
// The four panel states besides "content": loading (Skeleton, LoadingRows), empty (EmptyState), error (ErrorState,
// ErrorCallout) — and the in-place explanations (Callout). Each enters with a short rise or fade; none waits for it.
import type { LucideIcon } from "lucide-react";
import { CircleAlert, CircleCheck, Info, RefreshCw, TriangleAlert, Unplug } from "lucide-react";
import type { ReactNode } from "react";
import { ApiFailure, describeFailure } from "@/api/client";
import { BrandBackdrop } from "@/components/scene/brand-backdrop";
import { LogoMark } from "@/components/shell/logo";
import { cn } from "@/lib/cn";
import { Button } from "./button";
import { m } from "./messages";
import { staggerStyle } from "./motion";

/**
 * First-run, nothing selected, or filtered-empty: what is missing and the one action that fixes it. `icon` = a neutral
 * lucide tile (inside panels); `mark` = VPN Manager's mark with a soft halo (whole-page brand moments). `brand` = a
 * page-level empty state (first run: the page has nothing yet), shown over the brand scene; in-panel empties
 * (filtered, nothing selected, not found) stay plain.
 */
export function EmptyState({
  icon: Icon,
  mark = false,
  title,
  children,
  actions,
  className,
  compact,
  brand = false,
}: {
  icon?: LucideIcon | undefined;
  mark?: boolean | undefined;
  brand?: boolean | undefined;
  title: string;
  children?: ReactNode | undefined;
  actions?: ReactNode | undefined;
  className?: string | undefined;
  compact?: boolean | undefined;
}) {
  return (
    <div
      className={cn(
        "grid justify-items-center text-center animate-rise-in",
        compact ? "gap-2 px-4 py-6" : "gap-3 px-6 py-12",
        brand && "relative isolate h-full min-h-72 content-center overflow-hidden",
        className,
      )}
    >
      {brand ? <BrandBackdrop variant="empty" className="-z-10" /> : null}
      {mark ? (
        <span
          aria-hidden
          className="relative grid place-items-center"
          style={{ width: compact ? 56 : 80, height: compact ? 56 : 80 }}
        >
          <span className="absolute inset-0 rounded-full bg-[radial-gradient(closest-side,rgb(62_137_255_/_0.28),transparent)]" />
          <span className="relative drop-shadow-[0_0_16px_rgb(62_137_255_/_0.45)]">
            <LogoMark size={compact ? 36 : 52} />
          </span>
        </span>
      ) : Icon ? (
        <span
          aria-hidden
          className={cn(
            "grid place-items-center rounded-2xl border border-line bg-sunken text-fg-tertiary shadow-edge",
            compact ? "size-10 [&_svg]:size-5" : "size-12 [&_svg]:size-6",
          )}
        >
          <Icon />
        </span>
      ) : null}
      <p className={cn("font-semibold text-fg", compact ? "text-body" : "text-section")}>{title}</p>
      {children ? <div className="max-w-[46ch] text-data leading-6 text-fg-secondary">{children}</div> : null}
      {actions ? <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** Code and HTTP status of a failure, when the server or the connection gave them. */
function failureCode(error: unknown): string | null {
  if (!(error instanceof ApiFailure)) return null;
  return error.status ? `${error.code} · HTTP ${error.status}` : error.code;
}

/** The controller did not answer: calm (never red), it says so and offers to try again. */
function isOffline(error: unknown): boolean {
  return error instanceof ApiFailure && error.kind === "network";
}

/**
 * A failed load in place of a panel's content, with the reason and a retry. Content already on screen stays (the
 * caller decides). Never retries on its own.
 */
export function ErrorState({
  error,
  onRetry,
  retrying,
  title = m.states.loadFailed,
  compact,
}: {
  error: unknown;
  onRetry?: (() => void) | undefined;
  retrying?: boolean | undefined;
  title?: string | undefined;
  compact?: boolean | undefined;
}) {
  const offline = isOffline(error);
  const code = failureCode(error);
  const Icon = offline ? Unplug : TriangleAlert;
  return (
    <div
      role="alert"
      className={cn(
        "grid justify-items-center gap-3 text-center animate-rise-in",
        compact ? "px-4 py-6" : "px-6 py-12",
      )}
    >
      <span
        aria-hidden
        className={cn(
          "grid size-11 place-items-center rounded-2xl border shadow-edge [&_svg]:size-5",
          offline ? "border-line bg-sunken text-fg-tertiary" : "border-danger/30 bg-danger/10 text-danger",
        )}
      >
        <Icon />
      </span>
      <div className="grid max-w-[46ch] gap-1">
        <p className="text-section font-semibold text-fg">{title}</p>
        <p className="text-data text-fg-secondary [overflow-wrap:anywhere]">{describeFailure(error)}</p>
        {code ? <p className="machine text-caption text-fg-tertiary">{code}</p> : null}
      </div>
      {onRetry ? (
        <Button size="sm" icon={RefreshCw} pending={retrying} pendingLabel={m.states.retrying} onClick={onRetry}>
          {m.states.retry}
        </Button>
      ) : null}
    </div>
  );
}

/**
 * A failure inside a panel or form, next to what it concerns: the server's message, its code and HTTP status, and a
 * retry. Appears with a fade (no movement, the alert is never delayed).
 */
export function ErrorCallout({
  error,
  title,
  onRetry,
  retrying,
  retryLabel = m.states.retry,
  children,
  className,
}: {
  error: unknown;
  title?: string | undefined;
  onRetry?: (() => void) | undefined;
  retrying?: boolean | undefined;
  retryLabel?: string | undefined;
  children?: ReactNode | undefined;
  className?: string | undefined;
}) {
  const message = describeFailure(error);
  const code = failureCode(error);
  return (
    <div role="alert" className={cn("animate-fade-in", className)}>
      <Callout
        tone={isOffline(error) ? "warning" : "danger"}
        title={title ?? message}
        actions={
          onRetry ? (
            <Button size="sm" icon={RefreshCw} pending={retrying} pendingLabel={m.states.retrying} onClick={onRetry}>
              {retryLabel}
            </Button>
          ) : undefined
        }
      >
        {title && title !== message ? <p className="[overflow-wrap:anywhere]">{message}</p> : null}
        {code ? <p className="machine text-caption text-fg-tertiary">{code}</p> : null}
        {children}
      </Callout>
    </div>
  );
}

/** A loading placeholder shaped like the coming content (decorative; the caller gives the role="status" text). */
export function Skeleton({ className }: { className?: string | undefined }) {
  return <span aria-hidden className={cn("skeleton block h-4 animate-shimmer", className)} />;
}

/** Row placeholders shaped like the real rows so nothing jumps when data lands. */
export function LoadingRows({
  rows = 4,
  label = m.states.loading,
}: {
  rows?: number | undefined;
  label?: string | undefined;
}) {
  return (
    <div role="status" aria-label={label} className="divide-y divide-line-subtle">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} style={staggerStyle(i)} className="flex h-12 items-center gap-4 px-4 animate-fade-in stagger">
          <Skeleton className="w-40" />
          <Skeleton className="w-20" />
          <Skeleton className="ml-auto w-28" />
        </div>
      ))}
    </div>
  );
}

type CalloutTone = "info" | "success" | "warning" | "danger";

const calloutStyle: Record<CalloutTone, { border: string; icon: LucideIcon; text: string }> = {
  info: { border: "border-line-strong", icon: Info, text: "text-info" },
  success: { border: "border-success/40", icon: CircleCheck, text: "text-success" },
  warning: { border: "border-warning/40", icon: TriangleAlert, text: "text-warning" },
  danger: { border: "border-danger/40", icon: CircleAlert, text: "text-danger" },
};

/** Inline, in-place explanation of a state; a symbol in the tone and words, never colour alone. */
export function Callout({
  tone,
  title,
  children,
  actions,
  className,
  icon,
}: {
  tone: CalloutTone;
  title?: ReactNode | undefined;
  children?: ReactNode | undefined;
  actions?: ReactNode | undefined;
  className?: string | undefined;
  icon?: LucideIcon | undefined;
}) {
  const s = calloutStyle[tone];
  const Icon = icon ?? s.icon;
  return (
    <div
      className={cn(
        "flex gap-3 rounded-md border bg-sunken px-3.5 py-3 text-data text-fg-secondary",
        s.border,
        className,
      )}
    >
      <Icon aria-hidden className={cn("mt-0.5 size-4 shrink-0", s.text)} />
      <div className="min-w-0 flex-1 space-y-1">
        {title ? <p className="font-semibold text-fg [overflow-wrap:anywhere]">{title}</p> : null}
        {children ? <div className="text-data text-fg-secondary">{children}</div> : null}
        {actions ? <div className="flex flex-wrap gap-2 pt-1.5">{actions}</div> : null}
      </div>
    </div>
  );
}
