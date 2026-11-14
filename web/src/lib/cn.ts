// Adapted from Phasyn Studio (Apache-2.0); cn() follows the shadcn/ui helper convention (MIT). See THIRD_PARTY_NOTICES.md.
import { type ClassNameValue, extendTailwindMerge } from "tailwind-merge";

/**
 * tailwind-merge has to know the names tokens.css defines, or it merges them away by mistake:
 * - type sizes (text-title…) are sizes, not colours; radii, shadows (including the brand glow and the window and
 *   popover shadows), animations and spring easings are theme values;
 * - the brand gradient fills (bg-brand-gradient, bg-brand-gradient-soft, bg-action-gradient) are background images, not
 *   colours: they live next to a fallback colour such as bg-surface;
 * - border-brand-gradient (the ::after light edge), text-brand-gradient, the materials, pressable and stagger are each
 *   their own group and never replace a border colour, a text colour or another utility.
 */
type VpnClassGroup = "border-brand-gradient" | "text-brand-gradient" | "material" | "pressable" | "stagger";

const twMerge = extendTailwindMerge<VpnClassGroup>({
  extend: {
    theme: {
      text: ["title", "page", "section", "reading", "body", "data", "caption", "metric", "micro"],
      radius: ["sm", "md", "lg", "xl", "2xl", "full"],
      shadow: ["edge", "raised", "overlay", "popover", "window", "glow", "glow-sm"],
      breakpoint: ["sm", "md", "lg", "xl", "2xl"],
      animate: [
        "fade-in",
        "fade-out",
        "pop-in",
        "dialog-in",
        "dialog-out",
        "sheet-in",
        "sheet-out",
        "drawer-in",
        "drawer-out",
        "toast-in",
        "toast-out",
        "reveal",
        "shimmer",
        "glow-pulse",
        "rise-in",
      ],
      ease: ["standard", "enter", "exit", "spring-smooth", "spring-snappy", "spring-bouncy"],
    },
    classGroups: {
      "bg-image": ["bg-brand-gradient", "bg-brand-gradient-soft", "bg-action-gradient"],
      "border-brand-gradient": ["border-brand-gradient"],
      "text-brand-gradient": ["text-brand-gradient"],
      material: ["material-sidebar", "material-popover", "material-sheet", "material-hud"],
      pressable: ["pressable"],
      stagger: ["stagger"],
    },
  },
});

/** Join class names (falsy parts skipped); a later utility replaces an earlier one of the same group. */
export function cn(...parts: ClassNameValue[]): string {
  return twMerge(...parts);
}
