// CIDR arithmetic for the destination rule a worker applies (crates/domain validation `is_private`,
// crates/instance policy): a private destination needs an allowance from a security profile.

export interface Cidr {
  v6: boolean;
  /** The address as a 32- or 128-bit number. */
  bits: bigint;
  prefix: number;
}

function parseV4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(Number(p));
  }
  return n;
}

function parseV6(s: string): bigint | null {
  let text = s;
  let tail: bigint | null = null;
  // An embedded IPv4 tail (::ffff:10.0.0.1) stands for the last two groups.
  if (text.includes(".")) {
    const cut = text.lastIndexOf(":");
    tail = parseV4(text.slice(cut + 1));
    if (tail === null) return null;
    text = `${text.slice(0, cut + 1)}0:0`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : null;
  if (rest !== null && head.length + rest.length > 7) return null;
  const groups = rest === null ? head : [...head, ...Array<string>(8 - head.length - rest.length).fill("0"), ...rest];
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(Number.parseInt(g, 16));
  }
  return tail === null ? n : (n & ~0xffffffffn) | tail;
}

/** `10.0.0.0/8`, `fd00::/8`; a bare address is a single host. */
export function parseCidr(text: string): Cidr | null {
  const [addr = "", len, extra] = text.trim().split("/");
  if (extra !== undefined) return null;
  const v6 = addr.includes(":");
  const bits = v6 ? parseV6(addr) : parseV4(addr);
  if (bits === null) return null;
  const width = v6 ? 128 : 32;
  const prefix = len === undefined ? width : /^\d{1,3}$/.test(len) ? Number(len) : -1;
  if (prefix < 0 || prefix > width) return null;
  return { v6, bits, prefix };
}

/** Every address of `inner` lies in `outer`. */
export function covers(outer: Cidr, inner: Cidr): boolean {
  if (outer.v6 !== inner.v6 || outer.prefix > inner.prefix) return false;
  const shift = BigInt((outer.v6 ? 128 : 32) - outer.prefix);
  return outer.bits >> shift === inner.bits >> shift;
}

/** The ranges `is_private` treats as private (RFC 1918, CGNAT, documentation, ULA …). */
const PRIVATE: Cidr[] = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
  "0.0.0.0/8",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "240.0.0.0/4",
  "fc00::/7",
  "2001:db8::/32",
  "fec0::/10",
].flatMap((c) => {
  const p = parseCidr(c);
  return p ? [p] : [];
});

/** Every address of the range is private: the worker refuses it unless a security profile allows it. */
export function isPrivateRange(text: string): boolean {
  const c = parseCidr(text);
  return c !== null && PRIVATE.some((p) => covers(p, c));
}

/** The ranges of `wanted` that no range of `allowed` covers completely. */
export function notCovered(wanted: string[], allowed: string[]): string[] {
  const allow = allowed.flatMap((a) => {
    const c = parseCidr(a);
    return c ? [c] : [];
  });
  return wanted.filter((w) => {
    const c = parseCidr(w);
    return !c || !allow.some((a) => covers(a, c));
  });
}
