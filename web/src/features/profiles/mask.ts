// The import field shows a pasted .conf without its keys: `PrivateKey` and `PresharedKey` values
// are drawn as bullets, so they never appear on screen, in screenshots or in the accessibility
// tree. The real text stays in the component's state only; edits made to the masked view are
// mapped back onto it.

const SECRET_LINE = /^([ \t]*(?:PrivateKey|PresharedKey)[ \t]*=[ \t]*)(\S+)([ \t]*)$/gim;
/** Only a complete key is hidden: one being typed stays visible until it is whole. */
const WHOLE_KEY = /^[A-Za-z0-9+/]{43}=$/;

/** What the field shows for each hidden value (as long as a WireGuard key). */
export const MASK = "•".repeat(44);

/** The configuration as displayed: every complete key value replaced by `MASK`. */
export function maskConfig(text: string): string {
  return text.replace(SECRET_LINE, (line, head: string, value: string, tail: string) =>
    WHOLE_KEY.test(value) ? `${head}${MASK}${tail}` : line,
  );
}

/**
 * The real configuration after the user edited the masked view `edited`. A key line that still
 * shows `MASK` takes back the value the same line (by name and order) had in `previous`; a line
 * the user retyped keeps what was typed; a deleted line stays deleted.
 */
export function unmaskConfig(edited: string, previous: string): string {
  const hidden: Record<string, string[]> = {};
  for (const m of previous.matchAll(SECRET_LINE)) {
    const name = keyName(m[1] ?? "");
    (hidden[name] ??= []).push(m[2] ?? "");
  }
  const used: Record<string, number> = {};
  return edited.replace(SECRET_LINE, (line, head: string, value: string, tail: string) => {
    const name = keyName(head);
    const index = used[name] ?? 0;
    used[name] = index + 1;
    if (value !== MASK) return line;
    const original = hidden[name]?.[index];
    return original === undefined ? line : `${head}${original}${tail}`;
  });
}

function keyName(head: string): string {
  return head.split("=")[0]?.trim().toLowerCase() ?? "";
}
