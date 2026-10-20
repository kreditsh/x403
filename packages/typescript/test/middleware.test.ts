import { describe, expect, it, vi } from "vitest";
import { X403 } from "../src/client.js";
import { HEADER_DECISION, HEADER_PRESENTATION, decode, encode } from "../src/headers.js";
import { x403 } from "../src/middleware/express.js";
import { preflight, withX403 } from "../src/middleware/fetch.js";
import type { Decision, Payment } from "../src/types.js";
import { sampleDecision } from "./jws.test.js";

const payment: Payment = { type: "payment", amount: "189.00", currency: "USD", rail: "card", executor: { id: "shop.example" } };

function authority(decision: Decision | Error) {
  const sent: unknown[] = [];
  const fetchFn = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    sent.push(JSON.parse(init!.body as string));
    if (decision instanceof Error) throw decision;
    return new Response(JSON.stringify(decision), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { client: new X403({ authority: "https://a.example", fetch: fetchFn }), sent };
}

function fakeExpress(headers: Record<string, string> = {}) {
  const res = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    body: undefined as unknown,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    set(name: string, value: string) {
      this.headers[name] = value;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
  };
  const req = { get: (name: string) => headers[name.toLowerCase()], x403: undefined as Decision | undefined };
  const next = vi.fn();
  return { req, res, next };
}

describe("express middleware", () => {
  it("lets an allow through with the decision on req and the header on res", async () => {
    const { client, sent } = authority(sampleDecision());
    const presentation = encode({ actor: { agent: { status: "asserted", id: "did:key:z6Mk" } }, evidence: [{ type: "kredit.passport", ref: "sha256:" + "11".repeat(32) }] });
    const { req, res, next } = fakeExpress({ [HEADER_PRESENTATION.toLowerCase()]: presentation });
    await x403({ client, payment: () => payment, policyId: "shop-v1", budgetMs: 150 })(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.x403?.id).toBe("k_test");
    expect(decode<Decision>(res.headers[HEADER_DECISION]).id).toBe("k_test");
    expect(sent[0]).toMatchObject({
      policy_id: "shop-v1",
      budget_ms: 150,
      payment,
      actor: { agent: { id: "did:key:z6Mk" } },
      evidence: [{ type: "kredit.passport" }],
    });
  });

  it("answers a non-allow with the decision's status and body", async () => {
    const denied = sampleDecision({ decision: "deny", reasons: ["sanctions_hit"], http_status: 451, constraints: undefined });
    const { client } = authority(denied);
    const { req, res, next } = fakeExpress();
    await x403({ client, payment: () => payment })(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(451);
    expect((res.body as Decision).reasons).toEqual(["sanctions_hit"]);
  });

  it("computes the status when the authority left it out", async () => {
    const escalate = sampleDecision({ decision: "escalate", reasons: ["above_review_threshold"], escalation: { kind: "human_stepup" }, http_status: undefined, constraints: undefined });
    const { client } = authority(escalate);
    const { req, res, next } = fakeExpress();
    await x403({ client, payment: () => payment })(req, res, next);
    expect(res.statusCode).toBe(428);
  });

  it("fails closed when the authority is unreachable", async () => {
    const { client } = authority(new Error("connection refused"));
    const { req, res, next } = fakeExpress();
    const seen: Decision[] = [];
    await x403({ client, payment: () => payment, onDecision: (d) => void seen.push(d) })(req, res, next);
    expect(res.statusCode).toBe(403);
    expect(seen[0].reasons).toEqual(["authority_timeout"]);
    expect(seen[0].authority).toBeNull();
  });

  it("in shadow mode logs and always passes", async () => {
    const denied = sampleDecision({ decision: "deny", reasons: ["blocked_counterparty"], http_status: 403 });
    const { client } = authority(denied);
    const { req, res, next } = fakeExpress();
    await x403({ client, payment: () => payment, mode: "shadow" })(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});

describe("fetch middleware", () => {
  it("gates a handler and attaches the header", async () => {
    const { client } = authority(sampleDecision());
    const handler = withX403(async (_req, decision) => new Response(`ok ${decision.id}`), { client, payment: () => payment });
    const res = await handler(new Request("https://shop.example/checkout", { method: "POST" }));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok k_test");
    expect(decode<Decision>(res.headers.get(HEADER_DECISION)!).decision).toBe("allow");
  });

  it("refuses with the decision as the body", async () => {
    const { client } = authority(sampleDecision({ decision: "deny", reasons: ["velocity_high"], http_status: 429 }));
    const handler = withX403(async () => new Response("never"), { client, payment: () => payment });
    const res = await handler(new Request("https://shop.example/checkout"));
    expect(res.status).toBe(429);
    expect(((await res.json()) as Decision).reasons).toEqual(["velocity_high"]);
  });

  it("preflight answers with a header and no body", async () => {
    const { client, sent } = authority(sampleDecision({ mode: "preflight" }));
    const res = await preflight({ client, payment: () => payment })(new Request("https://shop.example/checkout", { method: "HEAD" }));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("");
    expect(res.headers.get(HEADER_DECISION)).toBeTruthy();
    expect((sent[0] as { mode: string }).mode).toBe("preflight");
  });
});
