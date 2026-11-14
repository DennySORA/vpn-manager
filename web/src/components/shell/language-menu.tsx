// The language of the interface, in the top bar: a globe button that opens the three languages, each in its own
// words, with the current one checked. Choosing another stores it and reloads the page in it (src/i18n).
import { Languages } from "lucide-react";
import { Menu, MenuRadioGroup, MenuRadioItem } from "@/components/ui/menu";
import { Tip } from "@/components/ui/tooltip";
import { LOCALE_NAMES, LOCALES, type Locale, chooseLocale, locale } from "@/i18n";
import { m } from "./messages";

export function LanguageMenu() {
  return (
    <Menu
      align="end"
      label={m.language}
      trigger={
        <button
          type="button"
          aria-label={m.languageIs(LOCALE_NAMES[locale])}
          className="pressable grid size-7 shrink-0 place-items-center rounded-full border border-line-subtle text-fg-secondary hover:bg-raised hover:text-fg"
        >
          <Tip content={m.languageIs(LOCALE_NAMES[locale])} side="bottom">
            <Languages aria-hidden className="size-3.5" />
          </Tip>
        </button>
      }
    >
      <MenuRadioGroup<Locale> value={locale} onValueChange={chooseLocale} label={m.language}>
        {LOCALES.map((l) => (
          <MenuRadioItem key={l} value={l}>
            <span lang={l}>{LOCALE_NAMES[l]}</span>
          </MenuRadioItem>
        ))}
      </MenuRadioGroup>
    </Menu>
  );
}
