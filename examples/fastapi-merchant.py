"""A merchant on FastAPI: ask kredit before accepting, countersign the receipt, report
the outcome when the processor says what happened."""

import os
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel

from x403 import AsyncX403, generate_key
from x403.middleware.fastapi import X403Gate, install, post_receipt

app = FastAPI()
install(app)
authority = AsyncX403("https://api.kredit.sh", api_key=os.environ["KREDIT_API_KEY"])
# In production the key is loaded, not generated; its public half is served below so a
# dispute desk can verify the receipts offline.
pair = generate_key()


class Order(BaseModel):
    order_id: str
    amount: str
    items: list[dict] = []


async def payment_of(request: Request) -> dict:
    order = Order.model_validate(await request.json())
    return {
        "type": "payment",
        "amount": order.amount,
        "currency": "USD",
        "rail": "card",
        "executor": {"id": "shop.example", "category": "5732", "jurisdiction": "US"},
        "items": order.items,
        "references": {"order_id": order.order_id},
        "idempotency_key": order.order_id,
    }


gate = X403Gate(authority, payment=payment_of, policy_id="shop-checkout-v1", budget_ms=150, on_timeout="deny")


@app.get("/.well-known/x403/jwks.json")
def jwks() -> dict:
    return {"keys": [pair.public_jwk]}


@app.post("/checkout")
async def checkout(order: Order, decision: dict = Depends(gate)) -> dict:
    ceiling = (decision.get("constraints") or {}).get("max_amount")
    if ceiling and float(order.amount) > float(ceiling):
        return {"ok": False, "why": "above the decision's ceiling"}
    auth_id = f"auth_{order.order_id}"
    await post_receipt(
        authority,
        decision,
        executed=True,
        execution={"rail": "card", "ref": auth_id, "amount": order.amount, "currency": "USD"},
        executor={"id": "did:web:shop.example", "kid": pair.kid},
        private_jwk=pair.private_jwk,
    )
    return {"ok": True, "auth": auth_id, "decision": decision["id"]}


@app.post("/webhooks/processor")
async def processor(event: dict) -> dict:
    await authority.outcome(
        {
            "decision_ref": event["decision_id"],
            "outcome": "settled" if event["event"] == "settled" else "chargeback",
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "amount": str(event["amount"]),
            "currency": "USD",
            "reason_code": event.get("reason_code"),
            "reporter": {"id": "did:web:shop.example", "kid": pair.kid},
        }
    )
    return {"ok": True}
