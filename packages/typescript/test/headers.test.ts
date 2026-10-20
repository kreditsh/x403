import { describe, expect, it } from "vitest";
import { authorizationRisk, decode, encode, parseAuthorizationRisk, parseWwwAuthenticate, wwwAuthenticate } from "../src/headers.js";

describe("headers", () => {
  it("roundtrips base64url JSON without padding", () => {
    const value = { actor: { agent: { status: "asserted", id: "did:key:z6Mk" } }, note: "€ and \"quotes\"" };
    const text = encode(value);
    expect(text).not.toMatch(/[=+/]/);
    expect(decode(text)).toEqual(value);
  });

  it("writes and parses the auth-scheme challenge", () => {
    const header = wwwAuthenticate({ policy: "shop-v1", realm: "checkout", request: "abc_-", expires: "2026-10-20T10:00:00Z" });
    expect(header).toBe('Risk policy="shop-v1", realm="checkout", request="abc_-", expires="2026-10-20T10:00:00Z"');
    expect(parseWwwAuthenticate(header)).toEqual({ policy: "shop-v1", realm: "checkout", request: "abc_-", expires: "2026-10-20T10:00:00Z" });
    expect(parseWwwAuthenticate("Bearer realm=x")).toBeNull();
  });

  it("writes and parses Authorization: Risk", () => {
    const presentation = { decision_ref: "k_1" };
    const header = authorizationRisk(presentation);
    expect(parseAuthorizationRisk(header)).toEqual(presentation);
    expect(parseAuthorizationRisk("Bearer abc")).toBeNull();
    expect(parseAuthorizationRisk(undefined)).toBeNull();
  });
});
