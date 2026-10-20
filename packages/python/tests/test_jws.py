from datetime import datetime, timedelta, timezone

import pytest

from x403.jws import (
    decision_hash,
    generate_key,
    sign,
    sign_outcome,
    sign_query,
    sign_receipt,
    thumbprint,
    verify,
    verify_decision,
    verify_receipt,
)


def test_sign_and_verify_roundtrip_with_thumbprint_kid():
    key = generate_key()
    assert key.kid == thumbprint(key.public_jwk)
    jws = sign({"b": 1, "a": "x"}, key.private_jwk)
    assert len(jws.split(".")) == 3
    out = verify(jws, {"keys": [key.public_jwk]})
    assert out.header == {"alg": "ES256", "kid": key.kid}
    assert out.payload == {"a": "x", "b": 1}


def test_rejects_another_key():
    a, b = generate_key(), generate_key()
    with pytest.raises(ValueError):
        verify(sign({"x": 1}, a.private_jwk), {"keys": [b.public_jwk]})


def test_verify_decision_tampered_and_expired(sample_decision):
    key = generate_key()
    jwks = {"keys": [key.public_jwk]}
    body = sample_decision(authority={"id": "did:web:a.example", "kid": key.kid})
    decision = {**body, "decision_sig": sign(body, key.private_jwk, typ="x403-decision+jws")}
    assert verify_decision(decision, jwks).ok

    tampered = verify_decision({**decision, "decision": "deny"}, jwks)
    assert not tampered.ok and "differs" in tampered.reason

    stale = verify_decision(decision, jwks, now=datetime.now(timezone.utc) + timedelta(hours=1))
    assert (stale.ok, stale.reason, stale.kid) == (False, "decision_expired", key.kid)

    assert not verify_decision(body, jwks).ok


def test_countersigns_receipts_outcomes_queries(sample_decision):
    key = generate_key()
    decision = sample_decision()
    receipt = sign_receipt(
        {"decision_ref": decision["id"], "decision_hash": decision_hash(decision), "executed": True, "executor": {"id": "did:web:shop.example", "kid": key.kid}},
        key.private_jwk,
    )
    assert verify_receipt(receipt, key.public_jwk).ok
    assert not verify_receipt({**receipt, "executed": False}, key.public_jwk).ok

    outcome = sign_outcome({"decision_ref": decision["id"], "outcome": "settled", "at": "2026-10-20T10:00:00Z", "reporter": {"id": "did:web:shop.example"}}, key.private_jwk)
    assert verify(outcome["sig"], key.public_jwk).header["typ"] == "x403-outcome+jws"

    query = sign_query(
        {"scheme": "x403", "version": "0.1", "direction": "inbound", "payment": {"type": "payment", "amount": "1.00", "currency": "USD", "rail": "card", "executor": {"id": "x"}}, "requester": {"id": "did:web:shop.example"}},
        key.private_jwk,
    )
    assert verify(query["requester_sig"], key.public_jwk).payload["direction"] == "inbound"
