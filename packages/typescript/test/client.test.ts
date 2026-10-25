import { describe, expect, it, vi } from "vitest";
import { X403, X403Error } from "../src/client.js";
import { generateKey, sign } from "../src/jws.js";
import { sampleDecision } from "./jws.test.js";

function fakeFetch(routes: Record<string, (init?: RequestInit) => { status?: number; body: unknown }>) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fetchFn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${String(url)}`;
    calls.push({ url: String(url), init });
    const route = routes[key];
    if (!route) return new Response(JSON.stringify({ detail: `no route ${key}` }), { status: 404 });
    const { status = 200, body } = route(init);
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  });
  return { fetchFn: fetchFn as unknown as typeof fetch, calls };
}

describe("X403 client", () => {
  it("posts a query with scheme and version filled in, under the api key", async () => {
    const decision = sampleDecision();
    const { fetchFn, calls } = fakeFetch({ "POST https://a.example/x403/decide": () => ({ body: decision }) });
    const client = new X403({ authority: "https://a.example/", apiKey: "kr_live_x", fetch: fetchFn });
    const out = await client.decide({
      direction: "inbound",
      payment: { type: "payment", amount: "10.00", currency: "USD", rail: "card", executor: { id: "shop.example" } },
    });
    expect(out).toEqual(decision);
    const sent = JSON.parse(calls[0].init!.body as string);
    expect(sent).toMatchObject({ scheme: "x403", version: "0.2", direction: "inbound" });
    expect((calls[0].init!.headers as Record<string, string>).authorization).toBe("Bearer kr_live_x");
  });

  it("preflight sets mode, get and receipts hit their paths", async () => {
    const decision = sampleDecision({ mode: "preflight" });
    const { fetchFn, calls } = fakeFetch({
      "POST https://a.example/x403/decide": () => ({ body: decision }),
      "GET https://a.example/x403/decisions/k_test": () => ({ body: decision }),
      "POST https://a.example/x403/receipts": (init) => ({ body: JSON.parse(init!.body as string) }),
    });
    const client = new X403({ authority: "https://a.example", fetch: fetchFn });
    await client.preflight({ direction: "outbound", payment: { type: "payment", amount: "1", currency: "USD", rail: "usdc", executor: { id: "x" } } });
    expect(JSON.parse(calls[0].init!.body as string).mode).toBe("preflight");
    expect(await client.get("k_test")).toEqual(decision);
    const r = await client.receipt({ decision_ref: "k_test", decision_hash: "sha256:" + "00".repeat(32), executed: true, executor: { id: "shop.example" } });
    expect(r.decision_ref).toBe("k_test");
  });

  it("throws X403Error with the server's detail", async () => {
    const { fetchFn } = fakeFetch({ "POST https://a.example/x403/decide": () => ({ status: 409, body: { detail: "nonce_consumed" } }) });
    const client = new X403({ authority: "https://a.example", fetch: fetchFn });
    await expect(client.decide({ direction: "inbound", payment: { type: "payment", amount: "1", currency: "USD", rail: "card", executor: { id: "x" } } })).rejects.toMatchObject({
      name: "X403Error",
      status: 409,
      detail: "nonce_consumed",
    });
    expect(new X403Error(400, { a: 1 }).message).toBe('400: {"a":1}');
  });

  it("verifies a decision against the authority's published keys, fetched once", async () => {
    const key = await generateKey();
    const body = sampleDecision({ authority: { id: "did:web:a.example", kid: key.kid } });
    const decision = { ...body, decision_sig: await sign(body, key.privateJwk) };
    const { fetchFn, calls } = fakeFetch({
      "GET https://a.example/.well-known/x403/authority.json": () => ({
        body: { scheme: "x403", version: "0.2", id: "did:web:a.example", jwks_url: "https://a.example/.well-known/x403/jwks.json", decide: "https://a.example/x403/decide", algorithms: ["ES256"] },
      }),
      "GET https://a.example/.well-known/x403/jwks.json": () => ({ body: { keys: [key.publicJwk] } }),
    });
    const client = new X403({ authority: "https://a.example", fetch: fetchFn });
    expect((await client.verify(decision)).ok).toBe(true);
    expect((await client.verify({ ...decision, id: "other" })).ok).toBe(false);
    expect(calls.filter((c) => c.url.endsWith("jwks.json"))).toHaveLength(1);
  });
});
