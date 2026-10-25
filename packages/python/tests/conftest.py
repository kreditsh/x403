from datetime import datetime, timedelta, timezone

import pytest


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


@pytest.fixture
def sample_decision():
    def make(**overrides):
        now = datetime.now(timezone.utc)
        decision = {
            "scheme": "x403",
            "version": "0.2",
            "id": "k_test",
            "decision": "allowed",
            "direction": "inbound",
            "mode": "inline",
            "subject": {"payment_ref": "sha256:" + "ef" * 32, "amount": "189.00", "currency": "USD", "executor_id": "shop.example"},
            "audience": "shop.example",
            "policy_id": "shop-checkout-v1",
            "policy_hash": "sha256:" + "ab" * 32,
            "authority": {"id": "did:web:authority.example", "kid": "k1"},
            "checks": [
                {"key": "identity", "status": "pass"},
                {"key": "mandate", "status": "pass"},
                {"key": "payee", "status": "pass"},
                {"key": "behavior", "status": "pass"},
            ],
            "reasons": [],
            "constraints": {"max_amount": "250.00", "currency": "USD"},
            "evidence_hashes": [],
            "binding_hints": {"http_status": 200},
            "supersedes": None,
            "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(minutes=10)),
        }
        decision.update(overrides)
        return {k: v for k, v in decision.items() if v is not ...}

    return make


@pytest.fixture
def payment():
    return {"type": "payment", "amount": "189.00", "currency": "USD", "rail": "card", "executor": {"id": "shop.example"}}
