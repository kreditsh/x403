import { describe, expect, it } from "vitest";
import { canonicalize, hash, hashString } from "../src/jcs.js";

// One backslash, and a JSON unicode escape built from it, so the RFC text below is
// assembled at runtime and no editor or tool layer can resolve the escapes early.
const bs = String.fromCharCode(92);
const esc = (hex: string) => bs + "u" + hex;

describe("RFC 8785", () => {
  it("matches the appendix example", () => {
    // RFC 8785 section 3.2.3: the input JSON text, parsed, and its expected canonical form.
    const inputText = `{
      "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
      "string": "${esc("20ac")}$${esc("000F")}${esc("000a")}A'${esc("0042")}${esc("0022")}${esc("005c")}${bs}${bs}${bs}"${bs}/",
      "literals": [null, true, false]
    }`;
    const expected =
      `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],` +
      `"string":"${String.fromCharCode(0x20ac)}$${esc("000f")}${bs}nA'B${bs}"${bs}${bs}${bs}${bs}${bs}"/"}`;
    expect(canonicalize(JSON.parse(inputText))).toBe(expected);
  });

  it("sorts keys by UTF-16 code units and drops undefined", () => {
    const smile = String.fromCodePoint(0x1f600);
    const wide = String.fromCharCode(0xff5a);
    const out = canonicalize({ [smile]: 1, [wide]: 2, a: 3, b: undefined });
    // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5A.
    expect(out).toBe(`{"a":3,"${smile}":1,"${wide}":2}`);
  });

  it("prints integers and negative zero plainly", () => {
    expect(canonicalize({ a: 1, b: -0, c: 1e21, d: 1e-7, e: 123456789012345680000 })).toBe(
      '{"a":1,"b":0,"c":1e+21,"d":1e-7,"e":123456789012345680000}',
    );
  });

  it("refuses what JSON cannot carry", () => {
    expect(() => canonicalize({ a: Number.NaN })).toThrow();
    expect(() => canonicalize({ a: () => 1 })).toThrow();
  });

  it("hashes the canonical form", async () => {
    expect(await hash({ b: 1, a: 2 })).toBe(await hash({ a: 2, b: 1 }));
    expect(await hashString("abc")).toBe("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});
