// Adapted from Phasyn Studio (Apache-2.0).
// Semantic tone classes shared by status chips, tags, icon tiles and dots. Written out in full (Tailwind only scans
// literals). VPN Manager's `brand` tone is the action role (the current or selected thing, never a status).
import type { Tone } from "@/lib/status";

/** Status tones plus the kind tones (entity: model internals and keys; file: files and technical tags). */
export type ToneKey = Tone | "entity" | "file";

/** Chips and tags: tone/12 ground, tone/30 border, tone text. */
export const CHIP_TONE: Record<ToneKey, string> = {
  neutral: "border-line bg-raised text-fg-secondary",
  info: "border-info/30 bg-info/12 text-info",
  success: "border-success/30 bg-success/12 text-success",
  warning: "border-warning/30 bg-warning/12 text-warning",
  danger: "border-danger/30 bg-danger/12 text-danger",
  brand: "border-action/30 bg-action/12 text-action-fg",
  entity: "border-entity/30 bg-entity/12 text-entity",
  file: "border-file/30 bg-file/12 text-file",
};

/** Icon tiles (entity headers): tone/12 ground, tone/40 border. */
export const TILE_TONE: Record<ToneKey, string> = {
  neutral: "border-line-strong bg-raised text-fg-secondary",
  info: "border-info/40 bg-info/12 text-info",
  success: "border-success/40 bg-success/12 text-success",
  warning: "border-warning/40 bg-warning/12 text-warning",
  danger: "border-danger/40 bg-danger/12 text-danger",
  brand: "border-action/40 bg-action/12 text-action-fg",
  entity: "border-entity/40 bg-entity/12 text-entity",
  file: "border-file/40 bg-file/12 text-file",
};

/** Text and icon colour. */
export const TEXT_TONE: Record<ToneKey, string> = {
  neutral: "text-fg-secondary",
  info: "text-info",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
  brand: "text-action-fg",
  entity: "text-entity",
  file: "text-file",
};

/** Solid dots (live state next to a word). */
export const DOT_TONE: Record<ToneKey, string> = {
  neutral: "bg-fg-disabled",
  info: "bg-info",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  brand: "bg-brand-blue",
  entity: "bg-entity",
  file: "bg-file",
};

/** Soft round icon grounds (notifications, empty states): tone/15. */
export const SOFT_TONE: Record<ToneKey, string> = {
  neutral: "bg-raised text-fg-secondary",
  info: "bg-info/15 text-info",
  success: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  danger: "bg-danger/15 text-danger",
  brand: "bg-action/15 text-action-fg",
  entity: "bg-entity/15 text-entity",
  file: "bg-file/15 text-file",
};
