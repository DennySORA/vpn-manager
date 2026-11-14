import { useId } from "react";
import { cn } from "@/lib/cn";

/**
 * VPN Manager's brand mark: the shield from the favicon, stroked with the brand gradient. `glow` adds the soft brand
 * halo of brand slots (sidebar header, empty states, loading); `breathing` its slow opacity breath (loading only).
 */
export function LogoMark({
  size = 22,
  glow = false,
  breathing = false,
  className,
}: {
  size?: number | undefined;
  glow?: boolean | undefined;
  breathing?: boolean | undefined;
  className?: string | undefined;
}) {
  const id = `lg${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  return (
    <svg
      aria-hidden
      width={size}
      height={size}
      viewBox="0 0 32 32"
      className={cn(
        "shrink-0",
        glow && "drop-shadow-[0_0_10px_rgb(62_137_255_/_0.45)]",
        breathing && "brand-breathe",
        className,
      )}
    >
      <defs>
        <linearGradient id={id} x1="4" y1="3" x2="28" y2="29" gradientUnits="userSpaceOnUse">
          <stop style={{ stopColor: "var(--color-brand-cyan)" }} />
          <stop offset=".36" style={{ stopColor: "var(--color-brand-blue)" }} />
          <stop offset=".68" style={{ stopColor: "var(--color-brand-iris)" }} />
          <stop offset="1" style={{ stopColor: "var(--color-brand-violet)" }} />
        </linearGradient>
      </defs>
      <path
        d="M16 2.5 4.5 7v8.2c0 6.9 4.7 12.3 11.5 14.3 6.8-2 11.5-7.4 11.5-14.3V7L16 2.5Z"
        style={{ fill: "var(--color-surface)" }}
        stroke={`url(#${id})`}
        strokeWidth="2"
      />
      <path
        d="m10.8 15.6 3.6 3.6 7-7.2"
        fill="none"
        stroke={`url(#${id})`}
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
