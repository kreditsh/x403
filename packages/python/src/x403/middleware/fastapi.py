"""FastAPI: ask before the route runs. `X403Gate` is a dependency that returns the
decision on allowed and raises the decision as the response on anything else, with the
status the decision names and X403-Decision on it. `decision_response` is the same
mapping for anyone building a response by hand. Every response that carries the header
is no-store."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

from ..client import AsyncX403, build_query
from ..headers import CACHE_CONTROL, HEADER_DECISION, HEADER_PRESENTATION, decode, encode, parse_authorization_risk
from ..jws import decision_hash, sign_local_decision, sign_receipt, subject_of
from ..registry import status_for
from ..types import JWK, VERSION, Decision, KeyRef, LocalDecision, Payment, Receipt

PaymentFn = Callable[[Request], Payment | Awaitable[Payment]]
PartFn = Callable[[Request], Any]


async def _maybe(fn: PartFn | None, request: Request) -> Any:
    if fn is None:
        return None
    out = fn(request)
    if hasattr(out, "__await__"):
        out = await out
    return out


def presentation_of(request: Request) -> dict[str, Any] | None:
    """Read the agent's presentation from X403-Presentation or Authorization: Risk. An
    oversized or unreadable header is no presentation."""
    raw = request.headers.get(HEADER_PRESENTATION)
    if raw:
        try:
            return decode(raw)
        except (ValueError, UnicodeDecodeError):
            return None
    return parse_authorization_risk(request.headers.get("authorization"))


def status_of(decision: dict[str, Any]) -> int:
    """The status an executor answers with: the authority's hint when it gave one, else section 6.3."""
    hint = (decision.get("binding_hints") or {}).get("http_status")
    return int(hint or decision.get("http_status") or status_for(decision))


def decision_response(decision: Decision | LocalDecision) -> Response:
    """The decision as the response: its status, X403-Decision, and no caching."""
    return JSONResponse(
        decision,
        status_code=status_of(decision),  # type: ignore[arg-type]
        headers={HEADER_DECISION: encode(decision), "Cache-Control": CACHE_CONTROL},
    )


def attach(response: Response, decision: Decision | LocalDecision) -> Response:
    response.headers[HEADER_DECISION] = encode(decision)
    response.headers["Cache-Control"] = CACHE_CONTROL
    return response


def executor_of(query: dict[str, Any], executor: KeyRef | None) -> KeyRef:
    """The executor named for a query: the gate's own id, else the payment's executor."""
    return executor or {"id": query["payment"]["executor"]["id"]}


def local_decision(query: dict[str, Any], executor: KeyRef, private_jwk: JWK | None = None) -> LocalDecision:
    """The decision the executor signs itself when the authority gave none inside the budget.
    Never an allow: denied, or escalated to the executor's own desk when the policy says so."""
    now = datetime.now(timezone.utc)
    escalate = (query.get("on_timeout") or "denied") == "escalated"
    local: dict[str, Any] = {
        "scheme": "x403",
        "version": VERSION,
        "id": f"local_{int(now.timestamp())}",
        "decision": "escalated" if escalate else "denied",
        "local": True,
        "direction": query.get("direction"),
        "subject": subject_of(query["payment"]),
        "audience": executor["id"],
        "policy_id": query.get("policy_id") or "unknown",
        "reasons": ["authority_timeout"],
        "binding_hints": {"http_status": 403},
        "executor": executor,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
    }
    if escalate:
        local["escalation"] = {"kind": "executor_review", "options": ["wait"], "retry_after": 60}
    if private_jwk:
        return sign_local_decision(local, private_jwk)  # type: ignore[arg-type]
    return local  # type: ignore[return-value]


class X403Decided(HTTPException):
    """Raised by the gate on a non-allowed; the handler below turns it into the decision response."""

    def __init__(self, decision: Decision | LocalDecision):
        self.decision = decision
        super().__init__(status_code=status_of(decision), detail=decision)  # type: ignore[arg-type]


class X403Gate:
    """A FastAPI dependency. `payment` is the one required function: the executor's own
    view of what is about to happen. The presentation header, when present, fills the
    actor, intent and evidence the agent brought. `executor` names this executor, the
    audience of its decisions and the signer of its local decisions; `private_jwk` signs them."""

    def __init__(
        self,
        client: AsyncX403,
        payment: PaymentFn,
        *,
        actor: PartFn | None = None,
        intent: PartFn | None = None,
        evidence: PartFn | None = None,
        direction: str = "inbound",
        policy_id: str | None = None,
        mode: str | None = None,
        budget_ms: int | None = None,
        on_timeout: str | None = None,
        executor: KeyRef | None = None,
        private_jwk: JWK | None = None,
        on_decision: Callable[[Decision | LocalDecision, Request], Any] | None = None,
        pass_through: bool = False,
    ):
        self.client = client
        self.payment = payment
        self.actor = actor
        self.intent = intent
        self.evidence = evidence
        self.direction = direction
        self.policy_id = policy_id
        self.mode = mode
        self.budget_ms = budget_ms
        self.on_timeout = on_timeout
        self.executor = executor
        self.private_jwk = private_jwk
        self.on_decision = on_decision
        self.pass_through = pass_through

    async def query(self, request: Request) -> dict[str, Any]:
        presentation = presentation_of(request) or {}
        actor = {**(presentation.get("actor") or {}), **(await _maybe(self.actor, request) or {})}
        intent = await _maybe(self.intent, request) or presentation.get("intent")
        evidence = [*(presentation.get("evidence") or []), *(await _maybe(self.evidence, request) or [])]
        return build_query(
            direction=self.direction,
            mode=self.mode,
            policy_id=self.policy_id,
            payment=await _maybe(self.payment, request),
            actor=actor or None,
            intent=intent,
            evidence=evidence or None,
            decision_ref=presentation.get("decision_ref"),
            budget_ms=self.budget_ms,
            on_timeout=self.on_timeout,
        )

    async def __call__(self, request: Request, response: Response) -> Decision | LocalDecision:
        query = await self.query(request)
        decision: Decision | LocalDecision
        try:
            decision = await self.client.decide(**{k: v for k, v in query.items() if k not in ("scheme", "version")})
        except Exception:  # noqa: BLE001 - any failure to reach the authority fails closed
            decision = local_decision(query, executor_of(query, self.executor), self.private_jwk)
        if self.on_decision:
            out = self.on_decision(decision, request)
            if hasattr(out, "__await__"):
                await out
        request.state.x403 = decision
        # Headers set on the injected response reach the route's own response on allowed.
        attach(response, decision)
        shadow = decision.get("mode") == "shadow" or self.mode == "shadow"
        if decision.get("decision") == "allowed" or shadow or self.pass_through:
            return decision
        raise X403Decided(decision)


def install(app: Any) -> None:
    """Register the handler that answers a gate's non-allowed with the decision itself."""

    @app.exception_handler(X403Decided)
    async def _handle(_request: Request, exc: X403Decided) -> Response:
        return decision_response(exc.decision)


async def post_receipt(
    client: AsyncX403,
    decision: Decision,
    *,
    executed: bool,
    executor: dict[str, str],
    execution: dict[str, Any] | None = None,
    private_jwk: JWK | None = None,
) -> Receipt:
    """Build, countersign and post the receipt for an executed (or refused) decision."""
    receipt: dict[str, Any] = {
        "decision_ref": decision["id"],
        "decision_hash": decision_hash(decision),
        "executed": executed,
        "executed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "executor": executor,
    }
    if execution:
        receipt["execution"] = execution
    if private_jwk:
        receipt = sign_receipt(receipt, private_jwk, executor.get("kid"))  # type: ignore[arg-type]
    return await client.receipt(receipt)  # type: ignore[arg-type]
