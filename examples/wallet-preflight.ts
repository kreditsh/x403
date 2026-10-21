// The buyer leg: an operator's wallet asks before its agent pays over a final-settlement
// rail. Decide first, then pay citing the decision id, then verify what came back offline.
import { X403, decisionHash, hashString } from "@kredit/x403";

const authority = new X403({ authority: "https://api.kredit.sh", apiKey: process.env.KREDIT_API_KEY });

export async function payWithPreflight(input: {
  merchant: string;
  amount: string;
  passport: string; // from POST /agents/{id}/passport/present
  instanceToken: string; // a kat_ token, hashed below, never sent
  goal: string;
  paymentRequirements: string; // the exact x402 PaymentRequirements the merchant sent
}) {
  const decision = await authority.preflight({
    direction: "outbound",
    policy_id: "acme-agent-wallet-v2",
    payment: {
      type: "payment",
      amount: input.amount,
      currency: "USDC",
      rail: "x402",
      executor: { id: input.merchant },
      references: { payment_requirements_hash: await hashString(input.paymentRequirements) },
    },
    actor: {
      operator: { status: "verified", basis: "kyb", id: "did:web:acme.com", via: "kredit" },
      agent: { status: "verified", basis: "passport", registry: [{ name: "kredit-passport" }], harness: "claude-code" },
      instance: { status: "verified", basis: "token", token_ref: await hashString(input.instanceToken) },
    },
    intent: {
      mandate: { format: "kredit", scope: { executors: [input.merchant], max_amount: "250.00" }, issued_by: "operator", signed: true },
      declared: { goal: input.goal },
    },
    evidence: [{ type: "kredit.passport", ref: await hashString(input.passport), inline: input.passport }],
    budget_ms: 150,
  });

  // The signature is checked here, not trusted because it came over TLS.
  const verified = await authority.verify(decision);
  if (!verified.ok) throw new Error(`decision did not verify: ${verified.reason}`);

  if (decision.decision === "escalated" && decision.escalation?.kind === "agent_adjust" && decision.escalation.reduce_to) {
    // No human is needed: shrink to what the authority said and ask again, citing the first id.
    return payWithPreflight({ ...input, amount: decision.escalation.reduce_to });
  }
  if (decision.decision !== "allowed") {
    // Carry the signed non-allowed to the operator unchanged; it is their record, not ours.
    return { paid: false, decision };
  }

  // Pay over x402 with the decision id in extensions; the merchant verifies it offline.
  const payload = { ...JSON.parse(input.paymentRequirements), extensions: { x403: { id: decision.id, policy_hash: decision.policy_hash } } };
  const tx = await settle(payload);

  await authority.receipt({
    decision_ref: decision.id,
    decision_hash: await decisionHash(decision),
    executed: true,
    executed_at: new Date().toISOString(),
    execution: { rail: "x402", ref: tx, amount: input.amount, currency: "USDC" },
    executor: { id: "did:web:acme.com" },
  });
  return { paid: true, tx, decision };
}

async function settle(_payload: unknown): Promise<string> {
  return `0x${Date.now().toString(16)}`;
}
