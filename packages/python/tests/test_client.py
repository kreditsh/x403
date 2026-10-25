import json

import httpx
import pytest

from x403.client import AsyncX403, X403, X403Error
from x403.jws import generate_key, sign


def transport(routes, sent):
    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.method} {request.url}"
        sent.append((key, dict(request.headers), request.content))
        if key not in routes:
            return httpx.Response(404, json={"detail": f"no route {key}"})
        status, body = routes[key](request)
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def test_decide_fills_scheme_and_sends_key(sample_decision, payment):
    decision = sample_decision()
    sent = []
    client = X403("https://a.example/", api_key="kr_live_x", client=httpx.Client(transport=transport({"POST https://a.example/x403/decide": lambda r: (200, decision)}, sent)))
    out = client.decide(direction="inbound", payment=payment)
    assert out == decision
    body = json.loads(sent[0][2])
    assert body["scheme"] == "x403" and body["version"] == "0.2" and body["direction"] == "inbound"
    assert sent[0][1]["authorization"] == "Bearer kr_live_x"


def test_preflight_get_and_receipt(sample_decision, payment):
    decision = sample_decision(mode="preflight")
    sent = []
    routes = {
        "POST https://a.example/x403/decide": lambda r: (200, decision),
        "GET https://a.example/x403/decisions/k_test": lambda r: (200, decision),
        "POST https://a.example/x403/receipts": lambda r: (200, json.loads(r.content)),
    }
    client = X403("https://a.example", client=httpx.Client(transport=transport(routes, sent)))
    client.preflight(direction="outbound", payment=payment)
    assert json.loads(sent[0][2])["mode"] == "preflight"
    assert client.get("k_test") == decision
    receipt = client.receipt({"decision_ref": "k_test", "decision_hash": "sha256:" + "00" * 32, "executed": True, "executor": {"id": "shop.example"}})
    assert receipt["decision_ref"] == "k_test"


def test_raises_x403_error_with_detail(payment):
    client = X403("https://a.example", client=httpx.Client(transport=transport({"POST https://a.example/x403/decide": lambda r: (409, {"detail": "nonce_consumed"})}, [])))
    with pytest.raises(X403Error) as err:
        client.decide(direction="inbound", payment=payment)
    assert (err.value.status, err.value.detail) == (409, "nonce_consumed")


def test_verify_fetches_keys_once(sample_decision):
    key = generate_key()
    body = sample_decision(authority={"id": "did:web:a.example", "kid": key.kid})
    decision = {**body, "decision_sig": sign(body, key.private_jwk)}
    sent = []
    routes = {
        "GET https://a.example/.well-known/x403/authority.json": lambda r: (200, {"scheme": "x403", "version": "0.2", "id": "did:web:a.example", "jwks_url": "https://a.example/.well-known/x403/jwks.json", "decide": "https://a.example/x403/decide", "algorithms": ["ES256"]}),
        "GET https://a.example/.well-known/x403/jwks.json": lambda r: (200, {"keys": [key.public_jwk]}),
    }
    client = X403("https://a.example", client=httpx.Client(transport=transport(routes, sent)))
    assert client.verify(decision).ok
    assert not client.verify({**decision, "id": "other"}).ok
    assert len([s for s in sent if s[0].endswith("jwks.json")]) == 1


async def test_async_client(sample_decision, payment):
    decision = sample_decision()
    sent = []
    client = AsyncX403("https://a.example", client=httpx.AsyncClient(transport=transport({"POST https://a.example/x403/decide": lambda r: (200, decision)}, sent)))
    assert await client.decide(direction="inbound", payment=payment) == decision
