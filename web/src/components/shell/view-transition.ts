// Adapted from Phasyn Studio (Apache-2.0).
// Which page a path belongs to. Only a page change runs the route View Transition (AppShell keys its routed
// <ViewTransition> by the page) and moves focus to the new page's title. VPN Manager keeps the selected object in the
// path (/instances/:id), so selecting another row — a different pathname on the same page — updates in place, like a
// query change, instead of making the whole main content enter again.
import { sectionFor } from "./nav";

/** The page a path belongs to: its navigation section (the longest match), else the path itself. */
export function pageOf(pathname: string): string {
  return sectionFor(pathname)?.to ?? pathname;
}
