// Adapted from Phasyn Studio (Apache-2.0).
// The 44 px top bar: where you are (section › object), then on the right the live traffic of the running connections
// and the service state; recent operations are in 系統 › 操作紀錄. A faint brand-gradient hairline runs along its bottom
// edge. Narrower than 840 px it starts with the drawer button.
import { ChevronRight, LoaderCircle, Menu } from "lucide-react";
import { type ReactNode, useEffect } from "react";
import { Link, useLocation } from "react-router";
import { ChangeFade } from "@/components/ui/change-value";
import { CHIP_TONE } from "@/components/ui/tones";
import { Tip } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { LanguageMenu } from "./language-menu";
import { LogoMark } from "./logo";
import { m } from "./messages";
import { sectionFor, useCrumbValue } from "./nav";
import { useServiceState } from "./service";

/** Health of browser → controller → manager as a chip: a spinning icon while connecting, a dot otherwise. */
function ServicePill() {
  const s = useServiceState();
  return (
    <Tip content={s.detail} side="bottom">
      <Link
        to="/system"
        className={cn(
          "pressable relative hidden h-7 items-center overflow-hidden rounded-full border px-2.5 text-caption font-medium no-underline lg:inline-flex",
          "transition-[color,background-color,border-color] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) hover:brightness-110",
          CHIP_TONE[s.tone],
        )}
      >
        <ChangeFade value={`${s.tone}:${s.label}`} className="inline-flex items-center gap-1.5">
          {s.pulse ? (
            <LoaderCircle aria-hidden className="size-3.5 animate-spin" />
          ) : (
            <span aria-hidden className="size-1.5 rounded-full bg-current" />
          )}
          {s.label}
        </ChangeFade>
        {/* While connecting, a shimmer hairline runs along the bottom: "in progress", not a ratio. */}
        {s.pulse ? (
          <span aria-hidden className="absolute inset-x-2 bottom-0 h-px bg-brand-gradient-soft animate-shimmer" />
        ) : null}
      </Link>
    </Tip>
  );
}

export function Topbar({
  navOpen,
  onOpenNav,
  traffic,
}: {
  navOpen: boolean;
  onOpenNav: () => void;
  /** The live traffic of the connections, before the service pill. */
  traffic: ReactNode;
}) {
  const { pathname } = useLocation();
  const section = sectionFor(pathname);
  const crumb = useCrumbValue();
  const SectionIcon = section?.icon;

  useEffect(() => {
    document.title = [crumb, section?.label, "VPN Manager"].filter(Boolean).join(" · ");
  }, [crumb, section]);

  return (
    <header className="relative flex h-11 min-w-0 items-center gap-2 border-b border-line-subtle bg-canvas/70 px-3 md:px-4">
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-brand-gradient opacity-25"
      />
      <button
        type="button"
        onClick={onOpenNav}
        aria-label={m.openNavigation}
        aria-haspopup="dialog"
        aria-expanded={navOpen}
        className="pressable grid size-9 shrink-0 place-items-center rounded-lg text-fg-secondary hover:bg-raised hover:text-fg md:hidden"
      >
        <Menu aria-hidden className="size-4" />
      </button>
      <LogoMark size={22} className="md:hidden" />
      <nav aria-label={m.breadcrumb} className="min-w-0 flex-1">
        <ol className="flex min-w-0 items-center gap-1 text-data">
          {section ? (
            <li className="flex min-w-0 shrink-0 items-center">
              <Link
                to={section.to}
                aria-current={crumb ? undefined : "page"}
                className={cn(
                  "pressable flex min-w-0 items-center gap-2 rounded-md px-1.5 py-1 no-underline hover:bg-raised hover:text-fg",
                  crumb ? "text-fg-secondary" : "font-medium text-fg",
                )}
              >
                {SectionIcon ? <SectionIcon aria-hidden className="size-4 shrink-0 text-brand-cyan" /> : null}
                <span className="truncate">{section.label}</span>
              </Link>
            </li>
          ) : (
            <li aria-current="page" className="truncate px-1.5 font-medium text-fg">
              {m.pageNotFound}
            </li>
          )}
          {section && crumb ? (
            <>
              <li aria-hidden className="shrink-0 text-fg-disabled">
                <ChevronRight className="size-3.5" />
              </li>
              <li
                aria-current="page"
                className="min-w-0 truncate px-1 font-medium text-fg animate-fade-in"
                title={crumb}
              >
                {crumb}
              </li>
            </>
          ) : null}
        </ol>
      </nav>
      <div className="ml-auto flex shrink-0 items-center gap-1.5">
        {traffic}
        <LanguageMenu />
        <ServicePill />
      </div>
    </header>
  );
}
