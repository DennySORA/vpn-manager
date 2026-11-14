// Adapted from Phasyn Studio (Apache-2.0): the empty/error state recipe.
import { LayoutDashboard, RefreshCw, SearchX, TriangleAlert } from "lucide-react";
import { isRouteErrorResponse, useRouteError } from "react-router";
import { Button, ButtonLink } from "@/components/ui/button";
import { m } from "./messages";

/** Last-resort boundary: a render error never leaves a blank page. */
export function RouteError() {
  const error = useRouteError();
  const notFound = isRouteErrorResponse(error) && error.status === 404;
  return (
    <div
      role="alert"
      className="grid h-full content-center justify-items-center gap-4 bg-canvas px-6 text-center animate-rise-in"
    >
      <span
        aria-hidden
        className="grid size-12 place-items-center rounded-2xl border border-danger/30 bg-danger/10 text-danger shadow-edge [&_svg]:size-6"
      >
        <TriangleAlert />
      </span>
      <div className="grid max-w-[46ch] gap-1.5">
        <h1 className="text-section font-semibold text-fg">{notFound ? m.notFound : m.renderError}</h1>
        <p className="text-data text-fg-secondary">
          {notFound ? m.notFoundHint : m.renderErrorHint}
          {!notFound && error instanceof Error ? (
            <span className="machine mt-1 block text-caption text-fg-tertiary">{error.message}</span>
          ) : null}
        </p>
      </div>
      <div className="flex gap-2">
        <Button
          variant="primary"
          icon={RefreshCw}
          onClick={() => {
            window.location.reload();
          }}
        >
          {m.reload}
        </Button>
        <a
          href="/"
          className="pressable inline-flex min-h-10 items-center rounded-md px-3.5 text-body text-fg-secondary no-underline hover:bg-raised hover:text-fg"
        >
          {m.backToOverview}
        </a>
      </div>
    </div>
  );
}

/** Unknown path inside the shell: navigation stays available. */
export function NotFound() {
  return (
    <div className="grid h-full content-center justify-items-center gap-3 px-6 text-center animate-rise-in">
      <span
        aria-hidden
        className="grid size-12 place-items-center rounded-2xl border border-line bg-sunken text-fg-tertiary shadow-edge [&_svg]:size-6"
      >
        <SearchX />
      </span>
      <h1 id="page-title" tabIndex={-1} className="text-section font-semibold text-fg outline-none">
        {m.notFound}
      </h1>
      <p className="max-w-[46ch] text-data text-fg-secondary">{m.notFoundOrDeleted}</p>
      <ButtonLink to="/" size="sm" icon={LayoutDashboard}>
        {m.backToOverview}
      </ButtonLink>
    </div>
  );
}
