// The one mapping from tokens.css to Motion (motion.dev). Every duration, curve and offset comes from the stylesheet
// (`--duration-*`, `--ease-*`, `--motion-shift*`); the fallbacks equal tokens.css and are used only where computed
// styles cannot be read. The sampled `linear()` springs are evenly spaced points, so interpolating them reproduces the
// CSS curve exactly: CSS transitions and Motion move on the same spring. Components import these
// transitions; nobody writes motion numbers inline.
import type { Transition, Variants } from "motion/react";

const FALLBACK_MS = {
  fast: 120,
  base: 180,
  slow: 240,
  exit: 140,
  "spring-smooth": 620,
  "spring-snappy": 440,
  "spring-bouncy": 720,
} as const;

export type MotionDuration = keyof typeof FALLBACK_MS;
export type MotionEasing = "standard" | "enter" | "exit" | "spring-smooth" | "spring-snappy" | "spring-bouncy";

/** Per-item stagger step (tokens.css: `calc(min(var(--i), 10) * 24ms)`) and the index after which items enter together. */
export const STAGGER_STEP_MS = 24;
export const STAGGER_LIMIT = 10;

type Ease = ((t: number) => number) | [number, number, number, number];

function token(name: string): string {
  return typeof document === "undefined"
    ? ""
    : getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function parseCssDuration(raw: string): number | null {
  const match = /^\s*(-?\d*\.?\d+)(ms|s)\s*$/i.exec(raw);
  if (!match) return null;
  const value = Number(match[1]) * (match[2]?.toLowerCase() === "s" ? 1000 : 1);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

export function parseCssPixels(raw: string): number | null {
  const match = /^\s*(-?\d*\.?\d+)px\s*$/i.exec(raw);
  if (!match) return null;
  const value = Number(match[1]);
  return Number.isFinite(value) ? value : null;
}

/** A duration token in milliseconds. */
export function motionDuration(name: MotionDuration): number {
  return parseCssDuration(token(`--duration-${name}`)) ?? FALLBACK_MS[name];
}

/** A `linear(...)` or `cubic-bezier(...)` token as a Motion easing. */
export function easeFromToken(raw: string): Ease | null {
  const match = /^(linear|cubic-bezier)\(([\s\S]*)\)$/.exec(raw.trim());
  const values = match?.[2]?.split(",").map((part) => Number(part.trim())) ?? [];
  if (!match || values.length < 2 || values.some((value) => !Number.isFinite(value))) return null;
  if (match[1] === "cubic-bezier") {
    const [a, b, c, d] = values;
    return values.length === 4 && a !== undefined && b !== undefined && c !== undefined && d !== undefined
      ? [a, b, c, d]
      : null;
  }
  return (t) => {
    const position = Math.min(Math.max(t, 0), 1) * (values.length - 1);
    const index = Math.min(Math.floor(position), values.length - 2);
    const start = values[index] ?? 0;
    return start + ((values[index + 1] ?? start) - start) * (position - index);
  };
}

function transition(duration: MotionDuration, easing: MotionEasing): Transition {
  return {
    duration: motionDuration(duration) / 1000,
    ease: easeFromToken(token(`--ease-${easing}`)) ?? "easeOut",
  };
}

export interface MotionKit {
  /** Panels, dialogs, sheets, routes, sidebar collapse: no overshoot. */
  smooth: Transition;
  /** Menus, switches, indicators, press release, lift, reflow: a tiny overshoot. */
  snappy: Transition;
  /** Notification entrance, success marks, drop settle. */
  bouncy: Transition;
  /** Dialog, scrim, menu and notification exits. */
  exit: Transition;
  /** State colours and focus; same-place swaps. */
  fast: Transition;
  /** Plain fades, progress, sheet and drawer exits. */
  base: Transition;
  /** Menus and small reveals move by this many pixels. */
  shift: number;
  /** Content, panels and pages move by this many pixels. */
  shiftPanel: number;
}

let kit: MotionKit | null = null;

/** The named transitions, built once from the loaded stylesheet. */
export function motionKit(): MotionKit {
  if (kit) return kit;
  const built: MotionKit = {
    smooth: transition("spring-smooth", "spring-smooth"),
    snappy: transition("spring-snappy", "spring-snappy"),
    bouncy: transition("spring-bouncy", "spring-bouncy"),
    exit: transition("exit", "exit"),
    fast: transition("fast", "standard"),
    base: transition("base", "enter"),
    shift: parseCssPixels(token("--motion-shift")) ?? 4,
    shiftPanel: parseCssPixels(token("--motion-shift-panel")) ?? 8,
  };
  // Cache only once the stylesheet is applied (a test document without tokens.css keeps reading).
  if (token("--duration-fast") !== "") kit = built;
  return built;
}

/** The delay of the item at `index` in a staggered entrance (seconds). */
export function staggerDelay(index: number): number {
  return (Math.min(Math.max(0, Math.trunc(index)), STAGGER_LIMIT) * STAGGER_STEP_MS) / 1000;
}

/**
 * List items rising in on first mount, in sequence: pass the item index as `custom`. Data-dense lists use it too
 * (opacity and an 8 px rise only: no scale, blur or glow on rows).
 */
export function riseVariants(): Variants {
  const m = motionKit();
  return {
    hidden: { opacity: 0, y: m.shiftPanel },
    shown: (index: number) => ({ opacity: 1, y: 0, transition: { ...m.smooth, delay: staggerDelay(index) } }),
    gone: { opacity: 0, transition: m.exit },
  };
}

/** A panel's content entering from its edge (docked panels change width at once; only the content moves). */
export function panelVariants(edge: "left" | "right" | "bottom"): Variants {
  const m = motionKit();
  const from = edge === "left" ? { x: -m.shiftPanel } : edge === "right" ? { x: m.shiftPanel } : { y: m.shiftPanel };
  return {
    hidden: { opacity: 0, ...from },
    shown: { opacity: 1, x: 0, y: 0, transition: m.smooth },
    gone: { opacity: 0, ...from, transition: m.exit },
  };
}

/** A same-place replacement (tab panel, status text, changed value): a fast cross-fade, no movement. */
export function swapVariants(): Variants {
  const m = motionKit();
  return {
    hidden: { opacity: 0 },
    shown: { opacity: 1, transition: m.fast },
    gone: { opacity: 0, transition: m.exit },
  };
}

/** Reflow of the items that stay (Motion `layout`): they glide to their new place on the snappy spring. */
export function layoutTransition(): Transition {
  return { layout: motionKit().snappy };
}

/**
 * A notification: it slides in at the top right (16 px from the right, 6 px from above, from 0.96) with the visible
 * bounce, and leaves 8 px to the right, shrinking to 0.98 and fading on the exit transition.
 */
export function toastVariants(): Variants {
  const m = motionKit();
  return {
    hidden: { opacity: 0, x: 16, y: -6, scale: 0.96 },
    shown: { opacity: 1, x: 0, y: 0, scale: 1, transition: m.bouncy },
    gone: { opacity: 0, x: m.shiftPanel, scale: 0.98, transition: m.exit },
  };
}
