import { describe, expect, it } from "vitest";
import {
  decisionHash,
  generateKey,
  paymentHash,
  sign,
  signLocalDecision,
  signOutcome,
  signQuery,
  signReceipt,
  subjectOf,
  thumbprint,
  verify,
  verifyDecision,
  verifyLocalDecision,
  verifyReceipt,
} from "../src/jws.js";
import type { Decision, JWKS, LocalDecision, Payment } from "../src/types.js";

export const samplePayment: Payment = { type: "payment", amount: "189.00", currency: "USD", rail: "card", executor: { id: "shop.example" } };

export function sampleDecision(overrides: Partial<Decision> = {}): Decision {
  const now = Date.now();
  return {
    scheme: "x403",
    version: "0.2",
    id: "k_test",
    decision: "allowed",
    direction: "inbound",
    mode: "inline",
    subject: { payment_ref: "sha256:" + "ef".repeat(32), amount: "189.00", currency: "USD", executor_id: "shop.example" },
    audience: "shop.example",
    policy_id: "shop-checkout-v1",
    policy_hash: "sha256:" + "ab".repeat(32),
    authority: { id: "did:web:authority.example", kid: "k1" },
    checks: [
      { key: "identity", status: "pass" },
      { key: "mandate", status: "pass" },
      { key: "payee", status: "pass" },
      { key: "behavior", status: "pass" },
    ],
    reasons: [],
    constraints: { max_amount: "250.00", currency: "USD" },
    evidence_hashes: [],
    binding_hints: { http_status: 200 },
    supersedes: null,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 600_000).toISOString(),
    ...overrides,
  };
}

describe("ES256 JWS", () => {
  it("signs and verifies a roundtrip, with the thumbprint as kid", async () => {
    const key = await generateKey();
    expect(key.kid).toBe(await thumbprint(key.publicJwk));
    const jws = await sign({ b: 1, a: "x" }, key.privateJwk);
    expect(jws.split(".")).toHaveLength(3);
    const out = await verify(jws, { keys: [key.publicJwk] });
    expect(out.header).toEqual({ alg: "ES256", kid: key.kid });
    expect(out.payload).toEqual({ a: "x", b: 1 });
  });

  it("rejects a signature by another key", async () => {
    const a = await generateKey();
    const b = await generateKey();
    const jws = await sign({ x: 1 }, a.privateJwk);
    await expect(verify(jws, { keys: [b.publicJwk] })).rejects.toThrow();
  });

  it("verifies a decision, and rejects a tampered or expired one", async () => {
    const key = await generateKey();
    const jwks: JWKS = { keys: [key.publicJwk] };
    const body = sampleDecision({ authority: { id: "did:web:a.example", kid: key.kid } });
    const decision: Decision = { ...body, decision_sig: await sign(body, key.privateJwk, { typ: "x403-decision+jws" }) };
    expect((await verifyDecision(decision, jwks)).ok).toBe(true);

    const tampered: Decision = { ...decision, decision: "denied" };
    const t = await verifyDecision(tampered, jwks);
    expect(t.ok).toBe(false);
    expect(t.reason).toMatch(/differs/);

    const stale = await verifyDecision(decision, jwks, new Date(Date.now() + 3_600_000));
    expect(stale).toEqual({ ok: false, reason: "decision_expired", kid: key.kid });

    expect((await verifyDecision({ ...body }, jwks)).ok).toBe(false);
  });

  it("a decision is bound to one payment and one executor", async () => {
    const key = await generateKey();
    const jwks: JWKS = { keys: [key.publicJwk] };
    const body = sampleDecision({ authority: { id: "did:web:a.example", kid: key.kid }, subject: await subjectOf(samplePayment), audience: "shop.example" });
    const decision: Decision = { ...body, decision_sig: await sign(body, key.privateJwk) };
    expect((await verifyDecision(decision, jwks, { audience: "shop.example", payment: samplePayment })).ok).toBe(true);
    expect((await verifyDecision(decision, jwks, { audience: "other.example" })).reason).toBe("audience_mismatch");
    expect((await verifyDecision(decision, jwks, { payment: { ...samplePayment, amount: "289.00" } })).reason).toBe("subject_mismatch");
    // an earlier decision without a subject is void for any payment a verifier names
    const bare = sampleDecision({ authority: { id: "did:web:a.example", kid: key.kid }, subject: undefined, audience: undefined });
    const old: Decision = { ...bare, decision_sig: await sign(bare, key.privateJwk) };
    expect((await verifyDecision(old, jwks)).ok).toBe(true);
    expect((await verifyDecision(old, jwks, { payment: samplePayment })).reason).toBe("subject_mismatch");
    expect(await paymentHash(samplePayment)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("a local decision is signed by the executor and is never an allow", async () => {
    const key = await generateKey();
    const base: Omit<LocalDecision, "local_sig"> = {
      scheme: "x403",
      version: "0.2",
      id: "local_1",
      decision: "denied",
      local: true,
      subject: await subjectOf(samplePayment),
      audience: "shop.example",
      policy_id: "shop-checkout-v1",
      reasons: ["authority_timeout"],
      executor: { id: "shop.example", kid: key.kid },
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };
    const local = await signLocalDecision(base, key.privateJwk);
    expect((await verify(local.local_sig!, key.publicJwk)).header.typ).toBe("x403-local+jws");
    expect((await verifyLocalDecision(local, key.publicJwk, { audience: "shop.example", payment: samplePayment })).ok).toBe(true);
    expect((await verifyLocalDecision({ ...local, decision: "escalated" }, key.publicJwk)).ok).toBe(false);
    const allowed = await signLocalDecision({ ...base, decision: "allowed" as unknown as "denied" }, key.privateJwk);
    expect((await verifyLocalDecision(allowed, key.publicJwk)).reason).toMatch(/never an allow/);
  });

  it("countersigns receipts, outcomes and queries", async () => {
    const key = await generateKey();
    const decision = sampleDecision();
    const receipt = await signReceipt(
      { decision_ref: decision.id, decision_hash: await decisionHash(decision), executed: true, executor: { id: "did:web:shop.example", kid: key.kid } },
      key.privateJwk,
    );
    expect((await verifyReceipt(receipt, key.publicJwk)).ok).toBe(true);
    expect((await verifyReceipt({ ...receipt, executed: false }, key.publicJwk)).ok).toBe(false);

    const outcome = await signOutcome(
      { decision_ref: decision.id, decision_hash: await decisionHash(decision), outcome: "settled", category: "none", reported_via: "executor", at: new Date().toISOString(), reporter: { id: "did:web:shop.example" } },
      key.privateJwk,
    );
    const o = await verify(outcome.sig!, key.publicJwk);
    expect(o.header.typ).toBe("x403-outcome+jws");
    expect((o.payload as { category: string }).category).toBe("none");

    const query = await signQuery(
      { scheme: "x403", version: "0.2", direction: "inbound", payment: samplePayment, requester: { id: "did:web:shop.example" } },
      key.privateJwk,
    );
    expect((await verify(query.requester_sig!, key.publicJwk)).payload).toMatchObject({ direction: "inbound" });
  });
});
