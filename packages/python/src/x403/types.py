"""The x403 objects, one TypedDict per schema in schemas/. Amounts are decimal strings,
times are RFC 3339, hashes are "sha256:" plus hex: the wire shapes, not convenience
shapes. Everything is a plain dict on the wire; these only name the keys."""

from __future__ import annotations

from typing import Literal, TypedDict

Direction = Literal["inbound", "outbound"]
Mode = Literal["inline", "preflight", "shadow"]
DecisionWord = Literal["allow", "escalate", "deny"]
EscalationKind = Literal["agent_adjust", "operator_confirm", "human_stepup", "executor_review"]
CheckKey = Literal["identity", "mandate", "payee", "behavior"]
CheckStatus = Literal["pass", "warn", "fail", "skip"]
HopStatus = Literal["verified", "asserted", "absent"]
OnTimeout = Literal["deny", "escalate", "allow_flagged"]
Effect = Literal["deny", "escalate", "note"]
Rail = Literal["card", "usdc", "ach", "wire", "skyfire", "kite", "mpp", "x402", "agentic-token", "crypto"]
OutcomeWord = Literal[
    "settled", "delivered", "disputed", "chargeback", "refund", "reversal", "fraud_confirmed", "false_positive"
]

VERSION = "0.1"


class KeyRef(TypedDict, total=False):
    id: str
    kid: str
    jwks_url: str


class Executor(TypedDict, total=False):
    id: str
    category: str
    jurisdiction: str


class Counterparty(TypedDict, total=False):
    id: str
    kind: Literal["merchant", "wallet", "address", "account", "person"]
    age_days: int
    name: str


class Item(TypedDict, total=False):
    sku: str
    description: str
    cls: str
    qty: int
    amount: str


class References(TypedDict, total=False):
    order_id: str
    cart_hash: str
    po: str
    payment_requirements_hash: str
    instruction_id: str


class Payment(TypedDict, total=False):
    type: Literal["payment", "transfer", "authorization", "order"]
    amount: str
    currency: str
    rail: Rail
    executor: Executor
    counterparty: Counterparty
    items: list[dict]
    references: References
    idempotency_key: str


class Hop(TypedDict, total=False):
    status: HopStatus
    basis: str
    id: str
    via: str
    ref: str
    assurance: str
    registry: list[dict]
    harness: str
    model: str
    attestation: str | None
    token_ref: str
    issued_at: str
    expires_at: str
    origin: str


class Session(TypedDict, total=False):
    ip: str
    device: str
    ua: str
    provenance: Literal["mcp", "api", "browser", "store", "a2a"]


class Actor(TypedDict, total=False):
    human: Hop
    operator: Hop
    agent: Hop
    instance: Hop
    session: Session


class MandateScope(TypedDict, total=False):
    executors: list[str]
    categories: list[str]
    max_amount: str
    window: str
    budget: str


class Mandate(TypedDict, total=False):
    format: str
    ref: str
    scope: MandateScope
    issued_by: Literal["human", "operator"]
    signed: bool
    expires_at: str


class Declared(TypedDict, total=False):
    goal: str
    expected_amount_range: list[str]


class Intent(TypedDict, total=False):
    mandate: Mandate
    declared: Declared
    task_ref: str


class Evidence(TypedDict, total=False):
    type: str
    issuer: str
    ref: str
    inline: str
    jwks_url: str


class Challenge(TypedDict, total=False):
    nonce: str
    expires_at: str


class RiskQuery(TypedDict, total=False):
    scheme: Literal["x403"]
    version: str
    policy_id: str
    direction: Direction
    mode: Mode
    payment: Payment
    actor: Actor
    intent: Intent
    evidence: list[Evidence]
    challenge: Challenge
    budget_ms: int
    on_timeout: OnTimeout
    requester: KeyRef
    requester_sig: str
    decision_ref: str


class Check(TypedDict, total=False):
    key: CheckKey
    status: CheckStatus
    reasons: list[str]


class Constraints(TypedDict, total=False):
    max_amount: str
    currency: str
    human_stepup_above: str
    executors: list[str]
    rails: list[str]
    expires_at: str


class Escalation(TypedDict, total=False):
    kind: EscalationKind
    options: list[str]
    reduce_to: str
    url: str
    retry_after: int
    step_up_ref: str


class Disclosure(TypedDict, total=False):
    history: Literal["threshold", "none"]
    claims: list[dict[str, int]]


class Decision(TypedDict, total=False):
    scheme: Literal["x403"]
    version: str
    id: str
    decision: DecisionWord
    direction: Direction
    mode: Mode
    policy_id: str
    policy_hash: str
    authority: KeyRef | None
    verified: dict[str, str]
    checks: list[Check]
    reasons: list[str]
    constraints: Constraints
    escalation: Escalation
    evidence_hashes: list[str]
    disclosure: Disclosure
    http_status: int
    supersedes: str | None
    latency_ms: int
    issued_at: str
    expires_at: str
    decision_sig: str


class Execution(TypedDict, total=False):
    rail: Rail
    ref: str
    amount: str
    currency: str


class Receipt(TypedDict, total=False):
    decision_ref: str
    decision_hash: str
    executed: bool
    executed_at: str
    execution: Execution
    executor: KeyRef
    executor_sig: str


class Outcome(TypedDict, total=False):
    decision_ref: str
    outcome: OutcomeWord
    at: str
    amount: str
    currency: str
    reason_code: str
    note: str
    reporter: KeyRef
    sig: str


class Policy(TypedDict, total=False):
    scheme: Literal["x403"]
    version: str
    policy_id: str
    policy_hash: str
    executor: KeyRef
    authorities: list[KeyRef]
    required_hops: list[str]
    accepted_evidence: list[str]
    accepted_mandates: list[str]
    step_up: dict[str, str]
    caps: dict[str, str]
    rails: list[str]
    ladder: Literal["403-401-402", "401-403-402"]
    budget_ms: int
    on_timeout: OnTimeout
    modes: list[Mode]
    issued_at: str


class Authority(TypedDict, total=False):
    scheme: Literal["x403"]
    version: str
    id: str
    name: str
    jwks_url: str
    decide: str
    receipts: str
    outcomes: str
    decisions: str
    reason_codes: str
    revoked: str
    algorithms: list[str]
    evidence_read: list[str]
    modes: list[Mode]
    mcp: str


class JWK(TypedDict, total=False):
    kty: str
    crv: str
    x: str
    y: str
    d: str
    kid: str
    alg: str
    use: str


class JWKS(TypedDict):
    keys: list[JWK]


class ReasonCodeEntry(TypedDict, total=False):
    group: str
    effect: Effect
    escalation: EscalationKind
    status: int
    says: str
    retired: bool
