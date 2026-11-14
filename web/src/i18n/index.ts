// The interface language: Traditional Chinese, English or Japanese.
//
// It is chosen once, when the page loads — the choice this browser remembers, else the first of the browser's
// languages that is one of ours, else English — and stays for the life of the page. Choosing another one stores
// the choice and reloads the page, so text held in module-level tables and `Intl` formatters is never stale and
// nothing has to subscribe to a language change.
//
// Every visible string lives in a `messages.ts` (or `messages.tsx`) file next to the code that shows it, as one
// table per language (`defineMessages`); TypeScript checks that the three tables have the same entries, and ESLint
// refuses CJK text anywhere else under `src/` (eslint.config.ts). How to write the tables: README.md here.

export const LOCALES = ["zh-TW", "en", "ja"] as const;
export type Locale = (typeof LOCALES)[number];

/** Each language in its own words, for the menu that switches between them. */
export const LOCALE_NAMES: Record<Locale, string> = {
  "zh-TW": "繁體中文",
  en: "English",
  ja: "日本語",
};

/** BCP 47 tags for `Intl` and the document language. */
const LOCALE_TAGS: Record<Locale, string> = {
  "zh-TW": "zh-Hant-TW",
  en: "en",
  ja: "ja",
};

const STORAGE_KEY = "vpnm.choice.locale";

function isLocale(value: string | null): value is Locale {
  return LOCALES.some((l) => l === value);
}

/** Our language for a browser language tag: any Chinese reads Traditional Chinese here. */
function forTag(tag: string): Locale | null {
  const primary = tag.toLowerCase().split("-")[0];
  if (primary === "zh") return "zh-TW";
  if (primary === "ja") return "ja";
  if (primary === "en") return "en";
  return null;
}

function remembered(): Locale | null {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isLocale(stored) ? stored : null;
  } catch {
    return null;
  }
}

function detect(): Locale {
  const stored = remembered();
  if (stored) return stored;
  for (const tag of navigator.languages) {
    const found = forTag(tag);
    if (found) return found;
  }
  return "en";
}

/** The language of this page. */
export const locale: Locale = detect();

/** The tag `Intl` formatters take for it. */
export const intlLocale: string = LOCALE_TAGS[locale];

document.documentElement.lang = intlLocale;

/** Remember `next` and reload the page in it. */
export function chooseLocale(next: Locale): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Not storable (private mode, blocked site data): the reload would come back in the same language.
    return;
  }
  window.location.reload();
}

/** Text the service wrote for people (`Text` in the API): every language at once. */
export type ServerText = Readonly<Record<Locale, string>>;

/**
 * Text the service wrote, in this page's language. A plain string — a value that is the same in every language, or
 * the answer of a service from before the three languages — is shown as it is.
 */
export function localized(text: ServerText | string): string {
  return typeof text === "string" ? text : text[locale];
}

/** What a translation of `T` looks like: the same entries, each of the same kind. */
export type Translation<T> = {
  [K in keyof T]: T[K] extends (...args: infer A) => infer R
    ? (...args: A) => R
    : T[K] extends string
      ? string
      : T[K] extends readonly string[]
        ? readonly string[]
        : Translation<T[K]>;
};

/**
 * The table of this page's language. English is the reference the other two must match: its entries name every
 * value a sentence can need (a count for the plural, say), and a translation may leave one unused.
 */
export function defineMessages<T>(tables: { en: T; "zh-TW": NoInfer<Translation<T>>; ja: NoInfer<Translation<T>> }): T {
  // A translation has the same shape as `T` by construction; the cast only drops the widened leaf types.
  return tables[locale] as T;
}
