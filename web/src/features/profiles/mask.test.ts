import { describe, expect, it } from "vitest";
import { MASK, maskConfig, unmaskConfig } from "./mask";

const KEY = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PSK = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const CONF = `[Interface]\nPrivateKey = ${KEY}\nAddress = 10.64.0.2/32\n\n[Peer]\nPublicKey = peer\nPresharedKey=${PSK}\nEndpoint = 203.0.113.10:51820\n`;

describe("import field masking", () => {
  it("never shows key values", () => {
    const shown = maskConfig(CONF);
    expect(shown).not.toContain(KEY);
    expect(shown).not.toContain(PSK);
    expect(shown).toContain(`PrivateKey = ${MASK}`);
    expect(shown).toContain(`PresharedKey=${MASK}`);
    expect(shown).toContain("PublicKey = peer");
  });

  it("maps edits of the masked view back onto the real text", () => {
    const shown = maskConfig(CONF);
    expect(unmaskConfig(shown, CONF)).toBe(CONF);
    const renamed = shown.replace("10.64.0.2/32", "10.64.0.9/32");
    expect(unmaskConfig(renamed, CONF)).toBe(CONF.replace("10.64.0.2/32", "10.64.0.9/32"));
  });

  it("keeps a retyped key and drops a deleted one", () => {
    const shown = maskConfig(CONF);
    const retyped = shown.replace(`PrivateKey = ${MASK}`, "PrivateKey = other");
    expect(unmaskConfig(retyped, CONF)).toContain("PrivateKey = other");
    expect(unmaskConfig(retyped, CONF)).toContain(`PresharedKey=${PSK}`);
    const deleted = shown.replace(`PrivateKey = ${MASK}\n`, "");
    expect(unmaskConfig(deleted, CONF)).not.toContain(KEY);
  });

  it("leaves a key that is still being typed visible", () => {
    const typing = "[Interface]\nPrivateKey = yAnz5TF";
    expect(maskConfig(typing)).toBe(typing);
    expect(unmaskConfig(`${typing}+`, typing)).toBe(`${typing}+`);
  });

  it("handles CRLF and case like WireGuard does", () => {
    const crlf = `[Interface]\r\nprivatekey = ${KEY}\r\n`;
    expect(maskConfig(crlf)).not.toContain(KEY);
    expect(unmaskConfig(maskConfig(crlf), crlf)).toBe(crlf);
  });
});
