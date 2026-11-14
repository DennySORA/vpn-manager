// Adapted from Phasyn Studio (Apache-2.0).
// Shared look recipes: class strings (written out in full, because Tailwind only scans literals) for panels, list rows,
// choice cards, tiles, tool buttons and meters. Tokens and utilities all come from tokens.css, the single token owner
// (docs/frontend-design.md):
// - The brand gradient marks the primary action, the current position, progress and work in flight. Dense surfaces
//   (tables, properties, forms, code) stay crisp: no glow, blur or animated backgrounds. Status colours mean status.
// - Interaction: pressable shrinks to .97 and springs back (snappy); hover only changes colour, cards and tiles also
//   lift 1 px; list items enter with rise-in plus a stagger (motion.staggerStyle).
// - Only transform / opacity move (plus the translate / scale channels); state never waits for an animation. Motion is
//   always on: there is no reduced-motion branch.

/** Spring timing (static theme tokens): snappy for menus, sliders, press release, hover lift; smooth for panels. */
export const SPRING_SNAPPY = "duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)";
export const SPRING_SMOOTH = "duration-(--duration-spring-smooth) ease-(--ease-spring-smooth)";

/** Floating panel: 12 px radius, hairline border, surface fill; the border turns brand blue while keyboard focus is inside. */
export const PANEL =
  "flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-line-subtle bg-surface shadow-edge transition-[border-color] duration-(--duration-base) ease-standard has-[:focus-visible]:border-brand-blue/55";
/** Primary panel (the inspector, the main summary): adds a top light; at most two per view. */
export const PANEL_RAISED = `${PANEL} panel-raised`;
/** Panel title bar (36 px): same fill as the panel, hairline below. */
export const PANEL_HEADER = "flex h-9 shrink-0 items-center gap-2 border-b border-line-subtle px-2.5";
export const PANEL_TITLE = "text-data font-semibold text-fg-secondary";
export const PANEL_ICON = "size-3.5 shrink-0 text-fg-tertiary";
/** Group card inside a panel: one step darker, hairline border, no glow. */
export const CARD = "rounded-lg border border-line-subtle bg-canvas/60";

/**
 * Selectable list row: when selected, a 3 px brand-gradient marker on the left and a soft gradient fill; hover only
 * tints, press darkens (rows never scale). The marker is ::before, so the row is relative.
 */
export const LIST_ROW =
  "relative transition-colors duration-(--duration-fast) ease-standard before:pointer-events-none before:absolute before:inset-y-1.5 before:left-0 before:w-[3px] before:rounded-r-full before:bg-linear-to-b before:from-brand-cyan before:via-brand-blue before:to-brand-violet before:opacity-0 before:transition-opacity before:duration-(--duration-fast) forced-colors:before:bg-[Highlight]";
export const LIST_ROW_SELECTED = "bg-brand-gradient-soft before:opacity-100";
export const LIST_ROW_IDLE = "hover:bg-raised/70 active:bg-sunken";

/** Static current-item marker (2 px vertical brand gradient) for rows that are always "current"; the row is relative. */
export const ROW_MARKER =
  "before:pointer-events-none before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-full before:bg-linear-to-b before:from-brand-cyan before:via-brand-blue before:to-brand-violet";
/** Fill of the current row (separate from the keyboard focus ring). */
export const ROW_SELECTED = "bg-brand-gradient-soft";

/** Choice cards (presets, routes, modes): shared border and press feedback. */
export const CHOICE_BASE = "pressable border";
/** Unselected choice: canvas fill, hairline border; hover brightens border and fill one step (no movement). */
export const CHOICE_IDLE = "border-line-subtle bg-canvas hover:border-line-strong hover:bg-raised/60";
/** Selected choice: soft brand fill and a 1 px gradient edge that follows the radius (no status colour). */
export const CHOICE_SELECTED = "border-transparent bg-canvas bg-brand-gradient-soft border-brand-gradient";

/** Form option (radio-like cards): brand hairline and soft fill when selected; part of a form, so no glow or lift. */
export const OPTION_CARD =
  "rounded-lg border transition-[border-color,background-color] duration-(--duration-fast) ease-standard";
export const OPTION_SELECTED = "border-brand-blue/70 bg-brand-gradient-soft";
export const OPTION_IDLE = "border-line-subtle bg-canvas/60 hover:border-line-strong hover:bg-raised/60";

/** Small icon tile (section and card headers): neutral; brand moments use ICON_TILE_BRAND. */
export const ICON_TILE = "grid shrink-0 place-items-center rounded-md border border-line bg-raised text-fg-tertiary";
/** Brand icon tile (the current flow, a page header): soft gradient fill, cyan icon. */
export const ICON_TILE_SOFT =
  "grid shrink-0 place-items-center rounded-lg border border-action/25 bg-brand-gradient-soft text-brand-cyan shadow-edge";
/** Brand icon tile (primary flow): gradient fill, dark icon, soft glow. */
export const ICON_TILE_BRAND =
  "grid shrink-0 place-items-center rounded-md border border-transparent bg-brand-gradient text-on-accent shadow-glow-sm";
/** Count badge next to tabs and titles. */
export const COUNT = "machine text-caption font-normal text-fg-tertiary";
/** A count pill inside tabs and segmented controls. */
export const COUNT_PILL = "machine rounded-full bg-overlay px-1.5 text-micro text-fg-tertiary";

/** Hover lift for cards and tiles (1 px plus a deeper shadow, snappy spring). Not for table rows. */
export const LIFT =
  "transition-[translate,scale,box-shadow,border-color,background-color] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) hover:-translate-y-px hover:shadow-raised";

/** 28 px icon tool button: hover tints, press is pressable. */
export const TOOL_BUTTON =
  "pressable inline-flex size-7 shrink-0 items-center justify-center rounded-md text-fg-secondary hover:bg-raised hover:text-fg active:bg-sunken disabled:cursor-not-allowed disabled:text-fg-disabled disabled:hover:bg-transparent [&_svg]:size-3.5";
/** A tool button that is on (aria-pressed): soft brand fill, brand ring, cyan icon. */
export const TOOL_BUTTON_ON =
  "bg-brand-gradient-soft text-fg ring-1 ring-brand-blue/50 ring-inset hover:bg-brand-gradient-soft hover:text-fg [&_svg]:text-brand-cyan";

/** A link inside text or a property value: action colour, underline on hover, a light press (it never scales). */
export const TEXT_LINK =
  "text-action-fg underline-offset-2 transition-opacity duration-(--duration-fast) hover:underline active:opacity-70";

/**
 * A control wider than its strip on a narrow screen or at 200 % zoom (a segmented filter): it scrolls within the strip
 * instead of pushing the page sideways (VPN Manager).
 */
export const FIT_WIDTH = "max-w-full overflow-x-auto [scrollbar-width:none]";

/** Thin meter: track plus a brand-gradient fill whose width moves linearly (progress never springs). */
export const METER_TRACK = "relative block h-1 overflow-hidden rounded-full bg-line-subtle";
export const METER_FILL =
  "absolute inset-y-0 left-0 rounded-full bg-brand-gradient transition-[width] duration-(--duration-base) ease-linear";
/** Highlight sweeping over a gradient while work is in flight (visible on bg-brand-gradient / bg-brand-gradient-soft). */
export const SHIMMER = "animate-shimmer";

/** Entrance: fade in, rise and settle (smooth spring; CSS, for content rendered without Motion). */
export const RISE_IN = "animate-rise-in";
/** List items entering one after another: add motion.staggerStyle(index) as the item's style. */
export const STAGGER_IN = "animate-rise-in stagger";

/** The 1 px brand hairline along the top edge of a floating surface (dialogs, sheets). */
export const BRAND_HAIRLINE =
  "before:pointer-events-none before:absolute before:inset-x-8 before:top-0 before:h-px before:bg-brand-gradient before:opacity-70";
