import { describe, expect, it, vi } from "vitest";
import { X403 } from "../src/client.js";
import { HEADER_DECISION, HEADER_PRESENTATION, decode, encode } from "../src/headers.js";
import { x403 } from "../src/middleware/express.js";
import { preflight, withX403 } from "../src/middleware/fetch.js";
import { generateKey, verifyLocalDecision } from "../src/jws.js";
import type { AnyDecision, Decision, LocalDecision, Payment } from "../src/types.js";
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
  it("lets an allowed through with the decision on req and the header on res", async () => {
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

  it("answers a non-allowed with the decision's status and body", async () => {
    const denied = sampleDecision({ decision: "denied", reasons: ["sanctions_hit"], binding_hints: { http_status: 451 }, constraints: undefined });
    const { client } = authority(denied);
    const { req, res, next } = fakeExpress();
    await x403({ client, payment: () => payment })(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(451);
    expect((res.body as Decision).reasons).toEqual(["sanctions_hit"]);
  });

  it("computes the status when the authority left it out", async () => {
    const escalate = sampleDecision({ decision: "escalated", reasons: ["above_review_threshold"], escalation: { kind: "human_stepup" }, binding_hints: undefined, constraints: undefined });
    const { client } = authority(escalate);
    const { req, res, next } = fakeExpress();
    await x403({ client, payment: () => payment })(req, res, next);
    expect(res.statusCode).toBe(428);
  });

  it("fails closed with an executor-signed local decision when the authority is unreachable", async () => {
    const { client } = authority(new Error("connection refused"));
    const { req, res, next } = fakeExpress();
    const seen: AnyDecision[] = [];
    const key = await generateKey();
    await x403({ client, payment: () => payment, executor: { id: "shop.example", kid: key.kid }, privateJwk: key.privateJwk, onDecision: (d) => void seen.push(d) })(req, res, next);
    expect(res.statusCode).toBe(403);
    const local = seen[0] as LocalDecision;
    expect(local.local).toBe(true);
    expect(local.decision).toBe("denied");
    expect(local.reasons).toEqual(["authority_timeout"]);
    expect(local.audience).toBe("shop.example");
    expect(local.subject.amount).toBe("189.00");
    expect((await verifyLocalDecision(local, key.publicJwk, { audience: "shop.example", payment })).ok).toBe(true);
    expect(res.headers["Cache-Control"]).toBe("no-store");
  });

  it("never allows on timeout, even when the policy says escalated", async () => {
    const { client } = authority(new Error("connection refused"));
    const { req, res } = fakeExpress();
    await x403({ client, payment: () => payment, onTimeout: "escalated" })(req, res, vi.fn());
    expect((req.x403 as LocalDecision).decision).toBe("escalated");
    expect((req.x403 as LocalDecision).escalation?.kind).toBe("executor_review");
    expect(res.statusCode).toBe(403);
  });

  it("treats an oversized presentation header as no presentation", async () => {
    const { client, sent } = authority(sampleDecision());
    const big = encode({ evidence: [{ type: "other", ref: "sha256:" + "00".repeat(32), inline: "x".repeat(9000) }] });
    const { req, res, next } = fakeExpress({ [HEADER_PRESENTATION.toLowerCase()]: big });
    await x403({ client, payment: () => payment })(req, res, next);
    expect(next).toHaveBeenCalled();
    expect((sent[0] as { evidence: unknown[] }).evidence).toEqual([]);
  });

  it("marks every response that carries the header no-store", async () => {
    const { client } = authority(sampleDecision());
    const { req, res, next } = fakeExpress();
    await x403({ client, payment: () => payment })(req, res, next);
    expect(res.headers["Cache-Control"]).toBe("no-store");
  });

  it("in shadow mode logs and always passes", async () => {
    const denied = sampleDecision({ decision: "denied", reasons: ["blocked_counterparty"], binding_hints: { http_status: 403 } });
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
    expect(decode<Decision>(res.headers.get(HEADER_DECISION)!).decision).toBe("allowed");
  });

  it("refuses with the decision as the body", async () => {
    const { client } = authority(sampleDecision({ decision: "denied", reasons: ["velocity_high"], binding_hints: { http_status: 429 } }));
    const handler = withX403(async () => new Response("never"), { client, payment: () => payment });
    const res = await handler(new Request("https://shop.example/checkout"));
    expect(res.status).toBe(429);
    expect(res.headers.get("cache-control")).toBe("no-store");
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
