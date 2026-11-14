import { useBlocker } from "react-router";
import { ConfirmDialog } from "@/components/ui/dialog";
import { m } from "./messages";

// Set by a save that navigates in the same handler: its new baseline is not rendered yet, so the
// guard would still see the draft as dirty. Consumed by the very next navigation.
let allowNext = false;

/** Lets the next in-app navigation through: call right before navigating away from a just-saved draft. */
export function allowNextNavigation() {
  allowNext = true;
}

/**
 * Keeps an edited draft from being lost to an in-app navigation: asks before leaving the current
 * object with unsaved changes. Returns the dialog element to render.
 */
export function UnsavedGuard({ dirty }: { dirty: boolean }) {
  const blocker = useBlocker(({ currentLocation, nextLocation }) => {
    if (allowNext) {
      allowNext = false;
      return false;
    }
    return dirty && currentLocation.pathname !== nextLocation.pathname;
  });
  return (
    <ConfirmDialog
      open={blocker.state === "blocked"}
      onOpenChange={(o) => {
        if (!o && blocker.state === "blocked") blocker.reset();
      }}
      title={m.discardTitle}
      confirmLabel={m.discardConfirm}
      onConfirm={() => {
        if (blocker.state === "blocked") blocker.proceed();
      }}
    >
      <p>{m.discardBody}</p>
    </ConfirmDialog>
  );
}
