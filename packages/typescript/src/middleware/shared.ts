// What the Express and fetch middlewares share: building the query from a request's
// presentation header and the executor's own view of the payment, the local decision an
// executor signs when the authority does not answer, and the receipt helper.

import { VERSION, X403, type ClientOptions } from "../client.js";
import { HEADER_PRESENTATION, decode, parseAuthorizationRisk, type Presentation } from "../headers.js";
import { decisionHash, signLocalDecision, subjectOf } from "../jws.js";
import { statusFor } from "../registry.js";
import type {
  AnyDecision,
  Decision,
  Direction,
  Evidence,
  HttpStatus,
  Intent,
  JWK,
  KeyRef,
  LocalDecision,
  Mode,
  OnTimeout,
  Payment,
  Rail,
  Receipt,
  RiskQuery,
} from "../types.js";
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
  /** Who this executor is: the audience of its decisions and the signer of its local decisions. Defaults to the payment's executor id. */
  executor?: KeyRef;
  /** With a private key, local decisions are signed; without, they are posted unsigned. */
  privateJwk?: JWK;
  /** With shadow true, every decision is logged through onDecision and the request always passes. */
  onDecision?: (decision: AnyDecision, req: Req) => void | Promise<void>;
  /** When the authority cannot be reached: the executor fails closed by default. */
  onError?: (error: unknown, req: Req) => Decision | undefined | Promise<Decision | undefined>;
}

export function clientOf(options: { client: X403 | ClientOptions }): X403 {
  return options.client instanceof X403 ? options.client : new X403(options.client);
}

/** Read the agent's presentation from X403-Presentation or Authorization: Risk. An oversized or unreadable header is no presentation. */
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

/** The status an executor answers with: the authority's hint when it gave one, else section 6.3. */
export function statusOf(decision: AnyDecision): HttpStatus {
  return decision.binding_hints?.http_status ?? (decision as Decision).http_status ?? statusFor(decision);
}

/** The executor named for a query: the gate's own id, else the payment's executor. */
export function executorOf(query: Pick<RiskQuery, "payment">, options: { executor?: KeyRef }): KeyRef {
  return options.executor ?? { id: query.payment.executor.id };
}

/**
 * The decision the executor signs itself when the authority gave none inside the budget.
 * Never an allow: denied, or escalated to the executor's own desk when the policy says so.
 */
export async function localDecision(
  query: Pick<RiskQuery, "payment" | "policy_id" | "direction" | "on_timeout">,
  executor: KeyRef,
  privateJwk?: JWK,
): Promise<LocalDecision> {
  const now = new Date();
  const escalate = query.on_timeout === "escalated";
  const local: Omit<LocalDecision, "local_sig"> = {
    scheme: "x403",
    version: VERSION,
    id: `local_${now.getTime().toString(36)}`,
    decision: escalate ? "escalated" : "denied",
    local: true,
    direction: query.direction,
    subject: await subjectOf(query.payment),
    audience: executor.id,
    policy_id: query.policy_id ?? "unknown",
    reasons: ["authority_timeout"],
    ...(escalate ? { escalation: { kind: "executor_review" as const, options: ["wait" as const], retry_after: 60 } } : {}),
    binding_hints: { http_status: 403 },
    executor,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 60_000).toISOString(),
  };
  return privateJwk ? signLocalDecision(local, privateJwk) : (local as LocalDecision);
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
  const { signReceipt } = await import("../jws.js");
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
