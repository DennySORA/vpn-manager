// Adapted from Phasyn Studio (Apache-2.0).
// Where keyboard focus goes when a Radix dialog closes. Shared by Dialog, ConfirmDialog and Sheet (./dialog.tsx).
import { useState } from "react";

interface FocusHandlers {
  onOpenAutoFocus?: ((event: Event) => void) | undefined;
  onCloseAutoFocus?: ((event: Event) => void) | undefined;
}

/**
 * The element focus should come back to: the focused element — or, when it is an item of an open menu (the dialog was
 * chosen from a menu, which closes and leaves the page), the button that opened that menu.
 */
function focusedElement(): HTMLElement | null {
  if (typeof document === "undefined") return null;
  const active = document.activeElement;
  if (!(active instanceof HTMLElement) || active === document.body) return null;
  const menu = active.closest('[role="menu"]');
  if (menu?.id) {
    const trigger = document.querySelector(`[aria-controls="${CSS.escape(menu.id)}"]`);
    if (trigger instanceof HTMLElement) return trigger;
  }
  return active;
}

/**
 * Focus handlers for a dialog's Radix content:
 * 1. When the user or the caller already moved focus elsewhere (not to the page) while the dialog was closing, focus
 *    is not pulled back.
 * 2. Without a Dialog.Trigger (VPN Manager opens its dialogs from code: a button, a menu item, the URL) Radix has
 *    nowhere to return focus: it goes back to the element that had focus when the dialog opened, while that element
 *    is still on the page.
 * The opener is taken while the dialog renders open for the first time — before a field inside takes focus with
 * autoFocus (Radix then skips its own open focus event). The caller's handlers run first; when its onCloseAutoFocus
 * calls preventDefault, focus is left to the caller.
 */
export function useFocusReturn(open: boolean, { onOpenAutoFocus, onCloseAutoFocus }: FocusHandlers = {}) {
  const [opener, setOpener] = useState<HTMLElement | null>(() => (open ? focusedElement() : null));
  const [shownOpen, setShownOpen] = useState(open);
  if (open !== shownOpen) {
    setShownOpen(open);
    if (open) setOpener(focusedElement());
  }
  return {
    onOpenAutoFocus: (event: Event) => {
      onOpenAutoFocus?.(event);
    },
    onCloseAutoFocus: (event: Event) => {
      onCloseAutoFocus?.(event);
      if (event.defaultPrevented) return;
      const active = document.activeElement;
      if (active instanceof HTMLElement && active !== document.body && active.isConnected) {
        event.preventDefault();
        return;
      }
      const fallback = opener;
      // Radix then gives focus to the trigger; without one focus stays on the page, so return it to the opener. Without
      // an opener still on the page (opened from the URL, or the opener left), focus goes to the page's title, never to
      // the body.
      queueMicrotask(() => {
        if (document.activeElement !== document.body && document.activeElement !== null) return;
        const target = fallback?.isConnected ? fallback : document.getElementById("page-title");
        target?.focus({ preventScroll: true });
      });
    },
  };
}

/**
 * For a dialog's onCloseAutoFocus when the control that opened it can leave the page while the dialog is open (a
 * button shown only in one state): while `opener` is on the page nothing is done, so focus returns to it as usual;
 * once it is gone, focus goes to `fallback` instead of falling to the page.
 */
export function returnFocusOr(
  event: Event,
  opener: HTMLElement | null,
  fallback: HTMLElement | null | undefined,
): void {
  if (opener?.isConnected || !fallback?.isConnected) return;
  event.preventDefault();
  fallback.focus();
}
