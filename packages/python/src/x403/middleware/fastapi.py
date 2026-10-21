"""FastAPI: ask before the route runs. `X403Gate` is a dependency that returns the
decision on allowed and raises the decision as the response on anything else, with the
status the decision names and X403-Decision on it. `decision_response` is the same
mapping for anyone building a response by hand."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

from ..client import AsyncX403, build_query
from ..headers import HEADER_DECISION, HEADER_PRESENTATION, decode, encode, parse_authorization_risk
from ..jws import decision_hash, sign_receipt
from ..registry import status_for
from ..types import JWK, Decision, Payment, Receipt

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
    """Read the agent's presentation from X403-Presentation or Authorization: Risk."""
    raw = request.headers.get(HEADER_PRESENTATION)
    if raw:
        try:
            return decode(raw)
        except (ValueError, UnicodeDecodeError):
            return None
    return parse_authorization_risk(request.headers.get("authorization"))


def decision_response(decision: Decision) -> Response:
    """The decision as the response: its status and the X403-Decision header."""
    status = decision.get("http_status") or status_for(decision)
    return JSONResponse(decision, status_code=status, headers={HEADER_DECISION: encode(decision)})


def attach(response: Response, decision: Decision) -> Response:
    response.headers[HEADER_DECISION] = encode(decision)
    return response


def timeout_decision(query: dict[str, Any]) -> Decision:
    """A decision the executor signs itself when the authority gave none inside the budget."""
    now = datetime.now(timezone.utc)
    on_timeout = query.get("on_timeout") or "denied"
    word = "allowed" if on_timeout == "allowed_flagged" else "escalated" if on_timeout == "escalated" else "denied"
    decision: dict[str, Any] = {
        "scheme": "x403",
        "version": "0.1",
        "id": f"timeout_{int(now.timestamp())}",
        "decision": word,
        "direction": query.get("direction"),
        "policy_id": query.get("policy_id") or "unknown",
        "policy_hash": "sha256:" + "0" * 64,
        "authority": None,
        "checks": [{"key": k, "status": "skip"} for k in ("identity", "mandate", "payee", "behavior")],
        "reasons": ["authority_timeout"],
        "evidence_hashes": [],
        "http_status": 200 if word == "allowed" else 403,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
    }
    if word == "escalated":
        decision["escalation"] = {"kind": "executor_review", "options": ["wait"], "retry_after": 60}
    return decision  # type: ignore[return-value]


class X403Decided(HTTPException):
    """Raised by the gate on a non-allowed; the handler below turns it into the decision response."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(status_code=decision.get("http_status") or status_for(decision), detail=decision)


class X403Gate:
    """A FastAPI dependency. `payment` is the one required function: the executor's own
    view of what is about to happen. The presentation header, when present, fills the
    actor, intent and evidence the agent brought."""

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
        on_decision: Callable[[Decision, Request], Any] | None = None,
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

    async def __call__(self, request: Request, response: Response) -> Decision:
        query = await self.query(request)
        try:
            decision = await self.client.decide(**{k: v for k, v in query.items() if k not in ("scheme", "version")})
        except Exception:  # noqa: BLE001 - any failure to reach the authority fails closed
            decision = timeout_decision(query)
        if self.on_decision:
            out = self.on_decision(decision, request)
            if hasattr(out, "__await__"):
                await out
        request.state.x403 = decision
        # Headers set on the injected response reach the route's own response on allowed.
        response.headers[HEADER_DECISION] = encode(decision)
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
