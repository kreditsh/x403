# x403

**0.1.1:** the decision word is a state, `allowed`, `escalated` or `denied` (0.1.0 used `allow`, `escalate`, `deny`). Reason-code effects are unchanged.

The x403 protocol for Python: the objects, RFC 8785 canonical JSON, ES256 signing and verifying, the HTTP binding, a sync and an async client for any authority, and a FastAPI gate. One dependency, `cryptography`. Python 3.10+.

```
pip install x403            # objects, canonical JSON, signing, verifying
pip install "x403[client]"  # plus the HTTP client (httpx)
pip install "x403[fastapi]" # plus the FastAPI gate
```

## Ask before you execute

```python
from x403 import X403

x403 = X403(authority="https://api.kredit.sh", api_key=os.environ["KREDIT_API_KEY"])

decision = x403.decide(
    direction="inbound",
    policy_id="shop-checkout-v1",
    payment={"type": "payment", "amount": "189.00", "currency": "USD", "rail": "card", "executor": {"id": "shop.example"}},
    actor={"agent": {"status": "asserted", "id": "did:key:z6Mk..."}},
    evidence=[{"type": "kredit.passport", "ref": passport_hash, "inline": passport}],
    budget_ms=150,
)

if decision["decision"] == "allowed":
    ...  # within decision["constraints"]
else:
    ...  # decision["http_status"], decision["reasons"], decision.get("escalation")
```

## Verify offline

```python
result = x403.verify(decision)   # keys fetched once from authority.json
assert result, result.reason
```

Or without a client, against keys you already hold:

```python
from x403 import verify_decision
ok = verify_decision(decision, jwks)
```

## FastAPI

```python
from fastapi import Depends, FastAPI
from x403 import AsyncX403
from x403.middleware.fastapi import X403Gate, install, post_receipt

app = FastAPI()
install(app)
authority = AsyncX403("https://api.kredit.sh", api_key=os.environ["KREDIT_API_KEY"])

gate = X403Gate(
    authority,
    payment=lambda request: {"type": "payment", "amount": "189.00", "currency": "USD", "rail": "card", "executor": {"id": "shop.example"}},
    policy_id="shop-checkout-v1",
    budget_ms=150,
)

@app.post("/checkout")
async def checkout(decision: dict = Depends(gate)):
    auth = await charge(decision["constraints"])
    await post_receipt(authority, decision, executed=True, execution={"rail": "card", "ref": auth.id},
                       executor={"id": "did:web:shop.example", "kid": kid}, private_jwk=private_jwk)
    return {"ok": True}
```

On allowed the route receives the decision. On anything else the gate answers with the decision's `http_status`, the decision as the body and `X403-Decision` on the response. If the authority cannot be reached it fails closed with an executor-signed `authority_timeout` decision.

## Sign your side

```python
from x403 import generate_key, sign_receipt, decision_hash

pair = generate_key()   # publish pair.public_jwk at /.well-known/x403/jwks.json
receipt = sign_receipt({"decision_ref": d["id"], "decision_hash": decision_hash(d), "executed": True,
                        "executor": {"id": "did:web:shop.example", "kid": pair.kid}}, pair.private_jwk)
```

## Status codes

`status_for(decision)` implements section 6.3 of the spec. The decision already carries `http_status`; use the function to pin the table in your own tests.

Apache-2.0. Spec and registry: https://github.com/kreditsh/x403
