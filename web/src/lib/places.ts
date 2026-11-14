// Place names for display. Providers name countries and cities in English; the UI shows them in
// its own language where the name is known, and the provider's own name otherwise.

import type { ProfileLocation } from "@/api/types";
import { intlLocale } from "@/i18n";
import { m } from "./messages";

// The short style is the everyday name (香港 rather than the long official form).
const regions = (() => {
  try {
    return new Intl.DisplayNames([intlLocale], { type: "region", style: "short" });
  } catch {
    return null;
  }
})();

/** How the runtime names a code it does not know ("unknown region"). */
const UNKNOWN_REGION = (() => {
  try {
    return regions?.of("ZZ") ?? null;
  } catch {
    return null;
  }
})();

/** null for a missing or empty string. */
function emptyToNull(s: string | null | undefined): string | null {
  return s === undefined || s === null || s === "" ? null : s;
}

/** The trimmed text, or null when nothing is left. */
function nonBlank(s: string | null | undefined): string | null {
  return emptyToNull(s?.trim());
}

/** Country name in this language from its ISO code; the provider's own name otherwise. */
export function countryName(code: string, fallback?: string): string {
  const c = code.trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(c)) {
    try {
      const name = regions?.of(c);
      if (name && name !== c && name !== UNKNOWN_REGION) return name;
    } catch {
      // Unknown region code: fall through.
    }
  }
  return nonBlank(fallback) ?? c;
}

function plain(s: string): string {
  return s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase().replace(/[.]/g, "").trim();
}

/** City name in this language when known ("New York, NY" → 紐約); the provider's name otherwise. */
export function cityName(city: string): string {
  const key = plain(city);
  return m.cities[key] ?? m.cities[key.replace(/,?\s+[a-z]{2}$/, "")] ?? city.trim();
}

/**
 * Where a profile exits, for display: 「城市，國家」, or one name when the city is the country
 * (Hong Kong, Singapore). Falls back to the server name; null when nothing is known.
 */
export function placeText(l: ProfileLocation | null | undefined): string | null {
  if (!l) return null;
  const country = l.country_code ? countryName(l.country_code, l.country ?? undefined) : nonBlank(l.country);
  const rawCity = nonBlank(l.city);
  const city = rawCity ? cityName(rawCity) : null;
  const sameAsCountry =
    city !== null && (city === country || (l.country !== null && plain(rawCity ?? "") === plain(l.country)));
  const text = city && !sameAsCountry && country ? m.cityAndCountry(city, country) : (country ?? city);
  return emptyToNull(text) ?? emptyToNull(l.server);
}
