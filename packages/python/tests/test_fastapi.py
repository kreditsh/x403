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
    client, _ = authority(sample_decision(decision="deny", reasons=["sanctions_hit"], http_status=451))
    res = app_with(client, payment).post("/checkout")
    assert res.status_code == 451 and res.json()["reasons"] == ["sanctions_hit"]
    assert HEADER_DECISION in res.headers


def test_status_computed_when_missing(sample_decision, payment):
    d = sample_decision(decision="escalate", reasons=["above_review_threshold"], escalation={"kind": "human_stepup"})
    d.pop("http_status")
    client, _ = authority(d)
    assert app_with(client, payment).post("/checkout").status_code == 428


def test_fails_closed_when_unreachable(sample_decision, payment):
    client, _ = authority(httpx.ConnectError("refused"))
    seen = []
    res = app_with(client, payment, on_decision=lambda d, r: seen.append(d)).post("/checkout")
    assert res.status_code == 403
    assert seen[0]["reasons"] == ["authority_timeout"] and seen[0]["authority"] is None


def test_shadow_mode_always_passes(sample_decision, payment):
    client, _ = authority(sample_decision(decision="deny", reasons=["blocked_counterparty"], http_status=403))
    assert app_with(client, payment, mode="shadow").post("/checkout").status_code == 200


def test_decision_response(sample_decision):
    res = decision_response(sample_decision(decision="deny", reasons=["velocity_high"], http_status=429))
    assert res.status_code == 429 and res.headers[HEADER_DECISION]
