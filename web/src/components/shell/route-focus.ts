// Adapted from Phasyn Studio (Apache-2.0).
// After a page change, focus moves to the new page's title (PageHeader's h1#page-title); the first load, a change of
// query only, or selecting another object on the same page do not move focus.
let pending = false;

export function markRouteFocusPending(): void {
  pending = true;
}

export function consumeRouteFocus(): boolean {
  const value = pending;
  pending = false;
  return value;
}

/**
 * Where focus can land on the current page when the control that had it is gone: the page title, else the main
 * content (AppShell's main#main-content).
 */
export function pageFocusTarget(): HTMLElement | null {
  return document.getElementById("page-title") ?? document.getElementById("main-content");
}
