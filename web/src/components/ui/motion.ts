// Adapted from Phasyn Studio (Apache-2.0).
// The DOM helpers of interface motion that are not Motion components: the typed View Transition for the sidebar
// collapse, the sliding active indicator and segmented thumb (a CSS transition on the snappy spring), the presence
// state of an exiting copy, the key of a same-place content swap, the focus hand-off of panel toggles and the CSS
// stagger index. Presence, reflow, stagger, panel entrances and swaps are Motion (motion.dev) in the components, with
// the transitions of motion-tokens.ts; every value comes from tokens.css. Motion is always on.
// Rules: semantic state (switches, selection, data, focus) always changes first and at once; animation only presents
// it, never waits for animationend and never moves focus by itself.
import {
  type CSSProperties,
  isValidElement,
  type ReactNode,
  type RefObject,
  useEffect,
  useLayoutEffect,
  useRef,
} from "react";
import { flushSync } from "react-dom";
import { useIsPresent } from "motion/react";
import { STAGGER_LIMIT } from "./motion-tokens";
import { type IndicatorAxis, indicatorPlacement, indicatorTransform } from "./motion-model";

/**
 * Style for an item entering in sequence with the CSS entrance (look.STAGGER_IN or animate-rise-in) where the item is
 * not a Motion component: sets --i, the index both the rise-in animation and the stagger utility read for their delay.
 * Put it on the items, not on the list.
 */
export function staggerStyle(index: number): CSSProperties {
  return { "--i": Math.min(Math.max(0, Math.trunc(index)), STAGGER_LIMIT) } as CSSProperties;
}

/**
 * Props of a copy inside AnimatePresence: while it plays its exit it is inert and hidden from assistive technology, so
 * the leaving copy never takes input or is read twice. `exiting` is the same fact for the caller's own markup.
 */
export function usePresenceInert(): {
  exiting: boolean;
  props: { inert: true | undefined; "aria-hidden": true | undefined };
} {
  const exiting = !useIsPresent();
  return { exiting, props: { inert: exiting || undefined, "aria-hidden": exiting || undefined } };
}

const typeKeys = new WeakMap<object, string>();
let typeSeq = 0;

/**
 * The identity of a same-place content (an inspector, an editor, a loading or empty state) for a keyed swap: the
 * element's own key (features key their inspectors by the object's id), else its component type. Two renders with the
 * same identity update in place; a new identity cross-fades or slides in.
 */
export function swapKey(node: ReactNode): string {
  if (!isValidElement(node)) return node === null || node === undefined || node === false ? "none" : "text";
  if (node.key !== null) return `key:${node.key}`;
  const type = node.type;
  if (typeof type === "string") return `tag:${type}`;
  let id = typeKeys.get(type);
  if (id === undefined) {
    typeSeq += 1;
    id = `type:${String(typeSeq)}`;
    typeKeys.set(type, id);
  }
  return id;
}

// ---------------------------------------------------------------------------------------------------------------
// Typed View Transition (the sidebar collapse).

type TypedViewTransitionDocument = Document & {
  startViewTransition?: ((options: { update: () => void; types: string[] }) => unknown) | undefined;
};

/** Typed View Transitions (Chrome 125+); older engines accept only a callback and throw on the object form. */
function supportsTypedViewTransition(): boolean {
  if (
    typeof document === "undefined" ||
    typeof (document as TypedViewTransitionDocument).startViewTransition !== "function"
  )
    return false;
  const ctor = (globalThis as { ViewTransition?: { prototype: object } }).ViewTransition;
  return ctor !== undefined && "types" in ctor.prototype;
}

/**
 * Wraps a synchronous state update in a typed View Transition (the sidebar collapse: styles under
 * :active-view-transition-type(sidebar) morph the shell). The state is committed at once with flushSync inside the
 * callback, never after the animation; without support or on any error it just updates.
 */
export function runViewTransition(type: string, update: () => void): void {
  if (!supportsTypedViewTransition()) {
    update();
    return;
  }
  let applied = false;
  const apply = () => {
    if (applied) return;
    applied = true;
    flushSync(update);
  };
  try {
    (document as TypedViewTransitionDocument).startViewTransition({ update: apply, types: [type] });
  } catch {
    apply();
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Panel toggles: collapsing or expanding a panel replaces the pressed toggle (the rail's and the panel's are different
// buttons). When focus was on a toggle, it moves to the surviving one after the commit, so it never falls to the body.

/** Collapse/expand controls are marked data-panel-toggle (never matched by their label text). */
export const PANEL_TOGGLE = "[data-panel-toggle]";

/**
 * Returns `note`, to call from the toggle handler before the state changes; after the commit that changes `state`,
 * focus moves to the [data-panel-toggle] inside `rootRef` when it was on a toggle. Independent of any animation.
 */
export function usePanelToggleFocus(rootRef: RefObject<HTMLElement | null>, state: unknown): () => void {
  const refocus = useRef(false);
  useLayoutEffect(() => {
    if (!refocus.current) return;
    refocus.current = false;
    // The toggle of the side that is now shown, never one of a copy that is still playing its exit (inert).
    const toggles = Array.from(rootRef.current?.querySelectorAll<HTMLElement>(PANEL_TOGGLE) ?? []);
    toggles.find((toggle) => toggle.closest("[inert]") === null)?.focus({ preventScroll: true });
  }, [rootRef, state]);
  return () => {
    const active = document.activeElement;
    refocus.current = active instanceof HTMLElement && active.matches(PANEL_TOGGLE);
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Active indicator: one line inside a tablist or navigation that follows the current item's position and length with
// transform only (the [data-tab-indicator] transition in app.css, snappy spring).

/** The current item: an ARIA tab that is selected, or a navigation link marked aria-current="page". */
export const ACTIVE_TAB_SELECTOR = '[role="tab"][aria-selected="true"], [aria-current="page"]';

/** The element's offset inside `container` along the offsetParent chain (the container must be positioned); null when off the chain. */
function offsetWithin(element: HTMLElement, container: HTMLElement, axis: IndicatorAxis): number | null {
  let offset = 0;
  let node: HTMLElement = element;
  for (;;) {
    offset += axis === "x" ? node.offsetLeft : node.offsetTop;
    const parent = node.offsetParent;
    if (parent === container) return offset;
    if (!(parent instanceof HTMLElement) || !container.contains(parent)) return null;
    node = parent;
  }
}

function rectOffset(element: HTMLElement, container: HTMLElement, axis: IndicatorAxis): number {
  const box = element.getBoundingClientRect();
  const frame = container.getBoundingClientRect();
  return axis === "x"
    ? box.left - frame.left - container.clientLeft + container.scrollLeft
    : box.top - frame.top - container.clientTop + container.scrollTop;
}

export interface IndicatorOptions {
  axis?: IndicatorAxis | undefined;
  /** Inset in px at both ends (e.g. only under the icon and the label). */
  inset?: number | undefined;
  /** Selector of the current item (default ACTIVE_TAB_SELECTOR). */
  selector?: string | undefined;
}

interface IndicatorState {
  observer: ResizeObserver | null;
  observed: WeakSet<Element>;
  transform: string;
}

/** Watches the container and its children for size changes that do not render (fonts loading, window resizes). */
function observe(
  current: IndicatorState,
  container: HTMLElement | null,
  indicator: HTMLElement | null,
  place: RefObject<() => void>,
): void {
  if (!container || typeof ResizeObserver === "undefined") return;
  current.observer ??= new ResizeObserver(() => {
    place.current();
  });
  for (const element of [container, ...Array.from(container.children)]) {
    if (current.observed.has(element) || element === indicator) continue;
    current.observed.add(element);
    current.observer.observe(element);
  }
}

/**
 * Places `indicatorRef` on the current item inside `containerRef`, measured after every render (labels, counts and the
 * selection all change geometry) and on resizes. Layout offsets ignore transforms, so an item still rising in or
 * gliding (Motion layout) never skews it. The first placement is instant (it never slides in from 0); later changes
 * slide on the snappy spring.
 */
export function useActiveIndicator(
  containerRef: RefObject<HTMLElement | null>,
  indicatorRef: RefObject<HTMLElement | null>,
  options: IndicatorOptions = {},
): void {
  const { axis = "x", inset = 0, selector = ACTIVE_TAB_SELECTOR } = options;
  const state = useRef<IndicatorState>({ observer: null, observed: new WeakSet(), transform: "" });
  const place = useRef<() => void>(() => undefined);

  useLayoutEffect(() => {
    const current = state.current;
    place.current = () => {
      const container = containerRef.current;
      const indicator = indicatorRef.current;
      if (!container || !indicator) return;
      const active = container.querySelector<HTMLElement>(selector);
      if (!active || (active.offsetWidth === 0 && active.offsetHeight === 0)) {
        indicator.dataset.state = "hidden";
        return;
      }
      const start = offsetWithin(active, container, axis) ?? rectOffset(active, container, axis);
      const size = axis === "x" ? active.offsetWidth : active.offsetHeight;
      const transform = indicatorTransform(axis, indicatorPlacement({ start, size }, inset));
      const visible = indicator.dataset.state === "visible";
      if (visible && transform === current.transform) return;
      current.transform = transform;
      if (visible) {
        indicator.style.transform = transform;
        return;
      }
      // First placement (or back from hidden): place without a transition, then enable it so later changes slide.
      indicator.style.transition = "none";
      indicator.style.transform = transform;
      indicator.getBoundingClientRect();
      indicator.style.removeProperty("transition");
      indicator.dataset.state = "visible";
    };
    place.current();
    observe(current, containerRef.current, indicatorRef.current, place);
  });

  // When the container ref belongs to a parent, a child's layout effect runs before the parent's ref is attached on the
  // first mount; every ref is ready by the passive effect, so place once more there (placing is idempotent).
  useEffect(() => {
    place.current();
    observe(state.current, containerRef.current, indicatorRef.current, place);
  });

  useEffect(() => {
    const current = state.current;
    return () => {
      current.observer?.disconnect();
      current.observer = null;
      current.observed = new WeakSet();
    };
  }, []);
}

// ---------------------------------------------------------------------------------------------------------------
// Segmented thumb: a block that sits under the chosen option, moved with transform + width / height on the snappy spring
// (the container is position: relative and the options are its children). The first placement is instant; size changes
// (fonts loading, window resizes, longer labels) are followed with a ResizeObserver. Purely presentational: the choice is
// the option's own state (aria-checked / aria-selected), never waiting for the thumb.

export function useThumb(
  containerRef: RefObject<HTMLElement | null>,
  thumbRef: RefObject<HTMLElement | null>,
  selector: string,
): void {
  const placed = useRef(false);
  const place = useRef<() => void>(() => undefined);

  useLayoutEffect(() => {
    place.current = () => {
      const container = containerRef.current;
      const thumb = thumbRef.current;
      if (!container || !thumb) return;
      const active = container.querySelector<HTMLElement>(selector);
      if (!active || active.offsetWidth === 0) {
        thumb.style.opacity = "0";
        placed.current = false;
        return;
      }
      const first = !placed.current;
      if (first) thumb.style.transition = "none";
      thumb.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`;
      thumb.style.width = `${active.offsetWidth}px`;
      thumb.style.height = `${active.offsetHeight}px`;
      thumb.style.opacity = "1";
      if (first) {
        thumb.getBoundingClientRect();
        thumb.style.removeProperty("transition");
        placed.current = true;
      }
    };
    place.current();
  });

  useEffect(() => {
    const container = containerRef.current;
    if (!container || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      place.current();
    });
    observer.observe(container);
    for (const child of Array.from(container.children)) if (child !== thumbRef.current) observer.observe(child);
    return () => {
      observer.disconnect();
    };
  }, [containerRef, thumbRef]);
}
