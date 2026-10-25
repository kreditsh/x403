import httpx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from x403.client import AsyncX403
from x403.headers import HEADER_DECISION, HEADER_PRESENTATION, decode, encode
from x403.middleware.fastapi import X403Gate, decision_response, install


def authority(decision):
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if isinstance(decision, Exception):
            raise decision
        return httpx.Response(200, json=decision)

    return AsyncX403("https://a.example", client=httpx.AsyncClient(transport=httpx.MockTransport(handler))), sent


def app_with(client, payment, **gate_options):
    app = FastAPI()
    install(app)
    gate = X403Gate(client, payment=lambda request: payment, **gate_options)

    @app.post("/checkout")
    async def checkout(decision: dict = Depends(gate)):
        return {"ok": True, "decision": decision["id"]}

    return TestClient(app)


def test_allow_passes_with_header(sample_decision, payment):
    client, sent = authority(sample_decision())
    app = app_with(client, payment, policy_id="shop-v1", budget_ms=150)
    presentation = encode({"actor": {"agent": {"status": "asserted", "id": "did:key:z6Mk"}}, "evidence": [{"type": "kredit.passport", "ref": "sha256:" + "11" * 32}]})
    res = app.post("/checkout", headers={HEADER_PRESENTATION: presentation})
    assert res.status_code == 200 and res.json() == {"ok": True, "decision": "k_test"}
    assert decode(res.headers[HEADER_DECISION])["id"] == "k_test"
    import json

    body = json.loads(sent[0].content)
    assert body["policy_id"] == "shop-v1" and body["budget_ms"] == 150 and body["payment"] == payment
    assert body["actor"]["agent"]["id"] == "did:key:z6Mk" and body["evidence"][0]["type"] == "kredit.passport"


def test_non_allow_is_the_decision_with_its_status(sample_decision, payment):
    client, _ = authority(sample_decision(decision="denied", reasons=["sanctions_hit"], binding_hints={"http_status": 451}))
    res = app_with(client, payment).post("/checkout")
    assert res.status_code == 451 and res.json()["reasons"] == ["sanctions_hit"]
    assert HEADER_DECISION in res.headers
    assert res.headers["cache-control"] == "no-store"


def test_status_computed_when_missing(sample_decision, payment):
    d = sample_decision(decision="escalated", reasons=["above_review_threshold"], escalation={"kind": "human_stepup"})
    d.pop("binding_hints")
    client, _ = authority(d)
    assert app_with(client, payment).post("/checkout").status_code == 428


def test_fails_closed_with_a_local_decision_when_unreachable(sample_decision, payment):
    from x403.jws import generate_key, verify_local_decision

    key = generate_key()
    client, _ = authority(httpx.ConnectError("refused"))
    seen = []
    app = app_with(client, payment, executor={"id": "shop.example", "kid": key.kid}, private_jwk=key.private_jwk, on_decision=lambda d, r: seen.append(d))
    res = app.post("/checkout")
    assert res.status_code == 403 and res.headers["cache-control"] == "no-store"
    local = seen[0]
    assert local["local"] is True and local["decision"] == "denied" and local["reasons"] == ["authority_timeout"]
    assert local["audience"] == "shop.example" and local["subject"]["amount"] == "189.00"
    assert verify_local_decision(local, key.public_jwk, audience="shop.example", payment=payment).ok


def test_never_allows_on_timeout(payment):
    client, _ = authority(httpx.ConnectError("refused"))
    seen = []
    res = app_with(client, payment, on_timeout="escalated", on_decision=lambda d, r: seen.append(d)).post("/checkout")
    assert res.status_code == 403 and seen[0]["decision"] == "escalated" and seen[0]["escalation"]["kind"] == "executor_review"


def test_oversized_presentation_is_no_presentation(sample_decision, payment):
    import json

    client, sent = authority(sample_decision())
    big = encode({"evidence": [{"type": "other", "ref": "sha256:" + "00" * 32, "inline": "x" * 9000}]})
    res = app_with(client, payment).post("/checkout", headers={HEADER_PRESENTATION: big})
    assert res.status_code == 200
    assert json.loads(sent[0].content).get("evidence") is None


def test_shadow_mode_always_passes(sample_decision, payment):
    client, _ = authority(sample_decision(decision="denied", reasons=["blocked_counterparty"], binding_hints={"http_status": 403}))
    assert app_with(client, payment, mode="shadow").post("/checkout").status_code == 200


def test_decision_response(sample_decision):
    res = decision_response(sample_decision(decision="denied", reasons=["velocity_high"], binding_hints={"http_status": 429}))
    assert res.status_code == 429 and res.headers[HEADER_DECISION] and res.headers["cache-control"] == "no-store"
