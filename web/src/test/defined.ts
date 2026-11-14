/** `v`, which a test knows is present: fails the test with what was missing instead of reading past it. */
export function defined<T>(v: T | null | undefined, what = "value"): T {
  if (v === null || v === undefined) throw new Error(`expected ${what} to be present`);
  return v;
}
