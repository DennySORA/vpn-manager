// Adapted from Phasyn Studio (Apache-2.0).
// Pure functions of the sliding active indicator: where it goes and its transform. Data only; the DOM side is
// motion.ts (useActiveIndicator).

export type IndicatorAxis = "x" | "y";

/** The current tab's start and length along the indicator's axis, in the container's content coordinates (px). */
export interface AxisBox {
  start: number;
  size: number;
}

export interface IndicatorPlacement {
  offset: number;
  size: number;
}

/** The indicator sits on the current tab, inset by `inset` px at both ends; a tab narrower than both insets gives 0 (centred). */
export function indicatorPlacement(box: AxisBox, inset = 0): IndicatorPlacement {
  const size = Math.max(0, box.size - 2 * Math.max(0, inset));
  return { offset: box.start + (box.size - size) / 2, size };
}

const round = (value: number) => Math.round(value * 100) / 100;

/** A 1 px base indicator placed with translate + scale: only transform changes, so the compositor interpolates it. */
export function indicatorTransform(axis: IndicatorAxis, placement: IndicatorPlacement): string {
  const offset = round(placement.offset);
  const size = round(placement.size);
  return axis === "x" ? `translateX(${offset}px) scaleX(${size})` : `translateY(${offset}px) scaleY(${size})`;
}
