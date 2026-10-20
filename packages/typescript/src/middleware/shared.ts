// What the Express and fetch middlewares share: building the query from a request's
// presentation header and the executor's own view of the payment, and the receipt helper.

import { X403, type ClientOptions } from "../client.js";
import { HEADER_PRESENTATION, decode, parseAuthorizationRisk, type Presentation } from "../headers.js";
import { decisionHash, signReceipt } from "../jws.js";
import type { Decision, Direction, Evidence, Intent, JWK, Mode, OnTimeout, Payment, Rail, Receipt } from "../types.js";
import type { Actor } from "../types.js";

export interface GateOptions<Req> {
  client: X403 | ClientOptions;
  /** The executor's own view of what is about to happen. The one required function. */
  payment: (req: Req) => Payment | Promise<Payment>;
  /** What the executor knows about the actor beyond the presentation header. */
  actor?: (req: Req) => Actor | undefined | Promise<Actor | undefined>;
  intent?: (req: Req) => Intent | undefined | Promise<Intent | undefined>;
  evidence?: (req: Req) => Evidence[] | undefined | Promise<Evidence[] | undefined>;
  direction?: Direction;
  policyId?: string;
  mode?: Mode;
  budgetMs?: number;
  onTimeout?: OnTimeout;
  /** With shadow true, every decision is logged through onDecision and the request always passes. */
  onDecision?: (decision: Decision, req: Req) => void | Promise<void>;
  /** When the authority cannot be reached: the executor fails closed by default. */
  onError?: (error: unknown, req: Req) => Decision | undefined | Promise<Decision | undefined>;
}

export function clientOf(options: { client: X403 | ClientOptions }): X403 {
  return options.client instanceof X403 ? options.client : new X403(options.client);
}

/** Read the agent's presentation from X403-Presentation or Authorization: Risk. */
export function presentationOf(headers: { get(name: string): string | null | undefined }): Presentation | null {
  const raw = headers.get(HEADER_PRESENTATION);
  if (raw) {
    try {
      return decode<Presentation>(raw);
    } catch {
      return null;
    }
  }
  return parseAuthorizationRisk(headers.get("authorization"));
}

export async function buildQuery<Req>(
  req: Req,
  headers: { get(name: string): string | null | undefined },
  options: GateOptions<Req>,
) {
  const presentation = presentationOf(headers);
  const [payment, actor, intent, evidence] = await Promise.all([
    options.payment(req),
    options.actor?.(req),
    options.intent?.(req),
    options.evidence?.(req),
  ]);
  return X403.query({
    direction: options.direction ?? "inbound",
    mode: options.mode,
    policy_id: options.policyId,
    payment,
    actor: { ...(presentation?.actor ?? {}), ...(actor ?? {}) },
    intent: intent ?? presentation?.intent,
    evidence: [...(presentation?.evidence ?? []), ...(evidence ?? [])],
    decision_ref: presentation?.decision_ref,
    budget_ms: options.budgetMs,
    on_timeout: options.onTimeout,
  });
}

/** A decision the executor signs itself when the authority gave none inside the budget. */
export function timeoutDecision(query: { policy_id?: string; direction: Direction; on_timeout?: OnTimeout }): Decision {
  const now = new Date();
  const escalate = query.on_timeout === "escalate";
  const allow = query.on_timeout === "allow_flagged";
  return {
    scheme: "x403",
    version: "0.1",
    id: `timeout_${now.getTime().toString(36)}`,
    decision: allow ? "allow" : escalate ? "escalate" : "deny",
    direction: query.direction,
    policy_id: query.policy_id ?? "unknown",
    policy_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    authority: null,
    checks: [
      { key: "identity", status: "skip" },
      { key: "mandate", status: "skip" },
      { key: "payee", status: "skip" },
      { key: "behavior", status: "skip" },
    ],
    reasons: ["authority_timeout"],
    ...(escalate ? { escalation: { kind: "executor_review" as const, options: ["wait" as const], retry_after: 60 } } : {}),
    evidence_hashes: [],
    http_status: allow ? 200 : 403,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 60_000).toISOString(),
  };
}

export interface ReceiptInput {
  decision: Decision;
  executed: boolean;
  execution?: { rail?: Rail; ref?: string; amount?: string; currency?: string };
  executor: { id: string; kid?: string };
  /** With a private key the receipt is countersigned; without, it is posted unsigned (shadow pilots). */
  privateJwk?: JWK;
}

/** Build, countersign and post the receipt for an executed (or refused) decision. */
export async function postReceipt(client: X403, input: ReceiptInput): Promise<Receipt> {
  const base: Omit<Receipt, "executor_sig"> = {
    decision_ref: input.decision.id,
    decision_hash: await decisionHash(input.decision),
    executed: input.executed,
    executed_at: new Date().toISOString(),
    execution: input.execution,
    executor: input.executor,
  };
  const receipt = input.privateJwk ? await signReceipt(base, input.privateJwk, input.executor.kid) : (base as Receipt);
  return client.receipt(receipt);
}
