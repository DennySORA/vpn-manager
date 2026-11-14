// Adapted from Phasyn Studio (Apache-2.0).
import { BrandBackdrop } from "@/components/scene/brand-backdrop";
import { cn } from "@/lib/cn";
import { LogoMark } from "./logo";

/**
 * Loading a whole page (boot, a lazily loaded page's code): VPN Manager's mark breathing and one line of text
 * (role="status") over the brand scene. Loading is usually quick, so it fades in only after 160 ms and never flashes;
 * the scene arrives with its own lazy chunk while the breathing mark already shows.
 */
export function BrandLoading({ label, className }: { label: string; className?: string | undefined }) {
  return (
    <div
      role="status"
      className={cn("relative isolate grid h-full min-h-40 place-items-center overflow-hidden p-6", className)}
    >
      <BrandBackdrop
        variant="loading"
        className="-z-10 animate-[fade-in_var(--duration-spring-smooth)_var(--ease-enter)_160ms_both]"
      />
      <span className="grid justify-items-center gap-3 text-data text-fg-secondary animate-[fade-in_var(--duration-base)_var(--ease-enter)_160ms_both]">
        <LogoMark size={40} glow breathing />
        {label}
      </span>
    </div>
  );
}
