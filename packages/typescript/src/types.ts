// The x403 objects, one type per schema in schemas/. Amounts are decimal strings, times are
// RFC 3339, hashes are "sha256:" plus hex: the wire shapes, not convenience shapes.

export type Hash = `sha256:${string}`;
export type Amount = string;
export type Currency = string;
export type Time = string;
export type JWS = string;

export type Direction = "inbound" | "outbound";
export type Mode = "inline" | "preflight" | "shadow";
export type DecisionWord = "allowed" | "escalated" | "denied";
export type EscalationKind = "agent_adjust" | "operator_confirm" | "human_stepup" | "executor_review";
export type CheckKey = "identity" | "mandate" | "payee" | "behavior";
export type CheckStatus = "pass" | "warn" | "fail" | "skip";
export type HopStatus = "verified" | "asserted" | "absent";
/** Never an allow: a slow authority must not be a bypass. */
export type OnTimeout = "denied" | "escalated";
export type Rail =
  | "card"
  | "usdc"
  | "ach"
  | "wire"
  | "skyfire"
  | "kite"
  | "mpp"
  | "x402"
  | "agentic-token"
  | "crypto";

export type HttpStatus = 200 | 400 | 401 | 403 | 404 | 409 | 428 | 429 | 451;

export interface KeyRef {
  id: string;
  kid?: string;
  jwks_url?: string;
}

export interface Payment {
  type: "payment" | "transfer" | "authorization" | "order";
  amount: Amount;
  currency: Currency;
  rail: Rail;
  executor: { id: string; category?: string; jurisdiction?: string };
  counterparty?: {
    id?: string;
    kind?: "merchant" | "wallet" | "address" | "account" | "person";
    age_days?: number;
    name?: string;
  };
  items?: Array<{ sku?: string; description?: string; class?: string; qty?: number; amount?: Amount }>;
  references?: {
    order_id?: string;
    /** x403's own hash of the cart artifact. */
    cart_ref?: Hash;
    /** x403's own hash of the exact x402 PaymentRequirements or MPP challenge. */
    payment_requirements_ref?: Hash;
    /** The AP2 checkout_hash as AP2 made it, verbatim. */
    ap2_checkout_hash?: string;
    /** The Verifiable Intent transaction_id as issued, verbatim. */
    vi_transaction_id?: string;
    po?: string;
    instruction_id?: string;
    /** @deprecated earlier name of cart_ref */
    cart_hash?: Hash;
    /** @deprecated earlier name of payment_requirements_ref */
    payment_requirements_hash?: Hash;
  };
  idempotency_key?: string;
}

export interface Hop {
  status: HopStatus;
  basis?: string;
  id?: string;
  via?: string;
  ref?: Hash;
}

export type RegistryName = "visa-tap" | "mastercard-wba" | "erc-8004" | "kredit-passport" | "skyfire-kya" | "kite";

export interface Actor {
  human?: Hop & { assurance?: "IAL1" | "IAL2" | "IAL3" };
  operator?: Hop;
  agent?: Hop & {
    registry?: Array<{ name: RegistryName; chain?: string; id?: string }>;
    harness?: string;
    model?: string;
    attestation?: string | null;
  };
  instance?: Hop & { token_ref?: Hash; issued_at?: Time; expires_at?: Time; origin?: string };
  session?: { ip?: string; device?: string; ua?: string; provenance?: "mcp" | "api" | "browser" | "store" | "a2a" };
}

export type MandateFormat =
  | "ap2"
  | "verifiable-intent"
  | "x401"
  | "amex-intent"
  | "visa-vic-instruction"
  | "shared-payment-token"
  | "mpp"
  | "kredit";

export interface Intent {
  mandate?: {
    format: MandateFormat;
    ref?: Hash;
    scope?: { executors?: string[]; categories?: string[]; max_amount?: Amount; window?: string; budget?: string };
    issued_by?: "human" | "operator";
    signed?: boolean;
    expires_at?: Time;
  };
  declared?: { goal?: string; expected_amount_range?: [Amount, Amount] };
  task_ref?: Hash;
}

export type EvidenceType =
  | "x401.result"
  | "x403.receipt"
  | "x403.decision"
  | "ap2.intent_mandate"
  | "ap2.cart_mandate"
  | "ap2.payment_mandate"
  | "verifiable-intent.chain"
  | "amex.proof_of_intent"
  | "visa.vic_instruction"
  | "visa.tap_signature"
  | "mastercard.wba_signature"
  | "skyfire.kya"
  | "skyfire.pay"
  | "kite.passport"
  | "stripe.shared_payment_token"
  | "mpp.challenge"
  | "x402.payment_requirements"
  | "erc-8004.registration"
  | "kredit.passport"
  | "kredit.agent_token"
  | "circle.screening"
  | "vgs.alias"
  | "fraud.vendor"
  | "other";

export interface Evidence {
  type: EvidenceType;
  issuer?: string;
  ref: Hash;
  inline?: string;
  jwks_url?: string;
}

export interface RiskQuery {
  scheme: "x403";
  version: string;
  policy_id?: string;
  direction: Direction;
  mode?: Mode;
  payment: Payment;
  actor?: Actor;
  intent?: Intent;
  evidence?: Evidence[];
  challenge?: { nonce?: string; expires_at?: Time };
  budget_ms?: number;
  on_timeout?: OnTimeout;
  requester?: KeyRef;
  requester_sig?: JWS;
  decision_ref?: string;
}

/** What a caller passes to decide(): scheme and version are filled in. */
export type QueryInput = Omit<RiskQuery, "scheme" | "version"> & Partial<Pick<RiskQuery, "scheme" | "version">>;

export interface Check {
  key: CheckKey;
  status: CheckStatus;
  reasons?: string[];
}

export type EscalationOption =
  | "present_x401"
  | "present_mandate"
  | "present_instance_token"
  | "reduce_amount"
  | "staged_amounts"
  | "operator_confirm"
  | "human_stepup"
  | "wait";

/** The one payment a decision is for. A verifier checks it before trusting an allow. */
export interface Subject {
  /** Hash of the payment object as presented. */
  payment_ref: Hash;
  amount: Amount;
  currency: Currency;
  executor_id: string;
}

/** Advisory: how the executor answers on the HTTP binding. Not part of the decision's meaning. */
export interface BindingHints {
  http_status?: HttpStatus;
}

export interface Escalation {
  kind: EscalationKind;
  options?: EscalationOption[];
  reduce_to?: Amount;
  url?: string;
  retry_after?: number;
  step_up_ref?: string;
}

export interface Decision {
  scheme: "x403";
  version: string;
  id: string;
  decision: DecisionWord;
  direction?: Direction;
  mode?: Mode;
  /** The one payment this decision is for. Written by every authority since the binding rule; earlier decisions lack it. */
  subject?: Subject;
  /** The executor this decision is for. Presented anywhere else it is void. */
  audience?: string;
  /** Hash of the risk query as received. */
  query_ref?: Hash;
  policy_id: string;
  policy_hash: Hash;
  authority: KeyRef;
  verified?: { human?: string; operator?: string; agent?: string; instance?: string; session?: string };
  checks: Check[];
  reasons: string[];
  constraints?: {
    max_amount?: Amount;
    currency?: Currency;
    human_stepup_above?: Amount;
    executors?: string[];
    rails?: Rail[];
    expires_at?: Time;
  };
  escalation?: Escalation;
  evidence_hashes: Hash[];
  disclosure?: { history?: "threshold" | "none"; claims?: Array<Record<string, number>> };
  binding_hints?: BindingHints;
  /** @deprecated written by earlier authorities; read binding_hints.http_status */
  http_status?: HttpStatus;
  /** The hash of the decision this one replaces. */
  supersedes?: Hash | null;
  issued_at: Time;
  expires_at: Time;
  decision_sig?: JWS;
}

/**
 * What an executor signs itself when the authority gave no decision inside the budget.
 * Never an allow, never presented as the authority's; the authority stores it as a receipt.
 */
export interface LocalDecision {
  scheme: "x403";
  version: string;
  id: string;
  decision: "denied" | "escalated";
  local: true;
  direction?: Direction;
  subject: Subject;
  audience: string;
  query_ref?: Hash;
  policy_id: string;
  policy_hash?: Hash;
  /** The authority that did not answer. */
  authority?: KeyRef;
  reasons: string[];
  escalation?: Pick<Escalation, "kind" | "options" | "retry_after">;
  binding_hints?: BindingHints;
  executor: KeyRef;
  issued_at: Time;
  expires_at: Time;
  local_sig?: JWS;
}

/** What a gate hands its handler: the authority's decision, or the executor's own on timeout. */
export type AnyDecision = Decision | LocalDecision;

export function isLocal(decision: AnyDecision): decision is LocalDecision {
  return (decision as LocalDecision).local === true;
}

export interface Receipt {
  decision_ref: string;
  decision_hash: Hash;
  executed: boolean;
  executed_at?: Time;
  execution?: { rail?: Rail; ref?: string; amount?: Amount; currency?: Currency };
  executor: KeyRef;
  executor_sig?: JWS;
  /** A local decision the executor made on timeout, filed with the authority as this receipt. */
  local_decision?: LocalDecision;
}

export type OutcomeWord =
  | "settled"
  | "delivered"
  | "disputed"
  | "chargeback"
  | "refund"
  | "reversal"
  | "fraud_confirmed"
  | "false_positive";

export type OutcomeCategory = "attack" | "accident" | "control_failure" | "commercial_dispute" | "none";
export type ReportedVia = "executor" | "requester" | "issuer" | "network" | "facilitator" | "psp" | "authority";

export interface Outcome {
  decision_ref: string;
  /** The decision as signed, so the report cannot be moved to another decision with the same id. */
  decision_hash?: Hash;
  authority_id?: string;
  outcome: OutcomeWord;
  category?: OutcomeCategory;
  reported_via?: ReportedVia;
  at: Time;
  amount?: Amount;
  currency?: Currency;
  reason_code?: string;
  note?: string;
  reporter: KeyRef;
  /** Required on the wire: an authority accepts reports only from parties it can verify. */
  sig?: JWS;
}

export interface Policy {
  scheme: "x403";
  version: string;
  policy_id: string;
  policy_hash: Hash;
  executor?: KeyRef;
  authorities: KeyRef[];
  required_hops: Array<"human" | "operator" | "agent" | "instance">;
  accepted_evidence?: string[];
  accepted_mandates?: string[];
  /** Who may post outcomes besides the executor, the requester and the authority. */
  reporters?: KeyRef[];
  step_up?: { human_above?: Amount; operator_above?: Amount };
  caps?: { max_amount?: Amount; currency?: Currency };
  rails?: Rail[];
  ladder?: "403-401-402" | "401-403-402";
  budget_ms: number;
  on_timeout: OnTimeout;
  modes?: Mode[];
  issued_at?: Time;
}

export interface Authority {
  scheme: "x403";
  version: string;
  id: string;
  name?: string;
  jwks_url: string;
  decide: string;
  receipts?: string;
  outcomes?: string;
  decisions?: string;
  reason_codes?: string;
  revoked?: string;
  algorithms: Array<"ES256" | "EdDSA">;
  evidence_read?: string[];
  modes?: Mode[];
  mcp?: string;
}

export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
  [k: string]: unknown;
}

export interface JWKS {
  keys: JWK[];
}

export type Effect = "denied" | "escalated" | "note";

export interface ReasonCodeEntry {
  group: string;
  effect: Effect;
  escalation?: EscalationKind;
  status?: number;
  says: string;
  retired?: boolean;
}

export interface Registry {
  scheme: "x403";
  version: string;
  groups: Record<string, { check: CheckKey; status: number; says: string }>;
  effects: Record<Effect, string>;
  codes: Record<string, ReasonCodeEntry>;
  status: {
    allowed: number;
    escalated: Record<EscalationKind, number>;
    denied: string;
    non_disclosure: number;
  };
}
