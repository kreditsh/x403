"""Writes the test vectors from fixed keys and fixed times, so every implementation checks
the same bytes. Run from the repo root with the Python package's environment:

    packages/python/.venv/bin/python test-vectors/make.py

Keys here are test keys and nothing else; they sign nothing outside this directory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "packages" / "python" / "src"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from x403.jcs import hash_object  # noqa: E402
from x403.jws import (  # noqa: E402
    decision_hash,
    key_pair_from_private,
    sign,
    sign_local_decision,
    sign_outcome,
    sign_query,
    sign_receipt,
    subject_of,
)
from x403.types import VERSION  # noqa: E402

AUTHORITY = key_pair_from_private(ec.derive_private_key(int("1" * 64, 16), ec.SECP256R1()))
EXECUTOR = key_pair_from_private(ec.derive_private_key(int("2" * 64, 16), ec.SECP256R1()))
AUTHORITY_ID = "did:web:authority.example"
EXECUTOR_ID = "did:web:shop.example"
ISSUED = "2026-10-25T00:00:00Z"
VALID_UNTIL = "2099-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"

PAYMENT = {
    "type": "payment",
    "amount": "189.00",
    "currency": "USD",
    "rail": "card",
    "executor": {"id": EXECUTOR_ID, "category": "5732", "jurisdiction": "US"},
    "counterparty": {"id": "shop.example", "kind": "merchant"},
    "references": {"order_id": "ORD-1", "ap2_checkout_hash": "Zm9vYmFyYmF6cXV4Cg", "cart_ref": "sha256:" + "ab" * 32},
    "idempotency_key": "ord_ORD-1",
}
PAYMENT_OTHER = {**PAYMENT, "amount": "289.00", "idempotency_key": "ord_ORD-2"}


def write(name: str, obj: dict) -> None:
    (HERE / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def decision_body(expires: str = VALID_UNTIL) -> dict:
    return {
        "scheme": "x403",
        "version": VERSION,
        "id": "k_vector_1",
        "decision": "allowed",
        "direction": "inbound",
        "mode": "inline",
        "subject": subject_of(PAYMENT),
        "audience": EXECUTOR_ID,
        "query_ref": hash_object(QUERY),
        "policy_id": "shop-checkout-v1",
        "policy_hash": "sha256:" + "cd" * 32,
        "authority": {"id": AUTHORITY_ID, "kid": AUTHORITY.kid},
        "verified": {"human": "absent", "operator": "kyb", "agent": "kredit-passport", "instance": "token", "session": "present"},
        "checks": [
            {"key": "identity", "status": "pass"},
            {"key": "mandate", "status": "pass"},
            {"key": "payee", "status": "pass"},
            {"key": "behavior", "status": "warn", "reasons": ["first_use_of_product_class"]},
        ],
        "reasons": ["first_use_of_product_class"],
        "constraints": {"max_amount": "250.00", "currency": "USD", "expires_at": expires},
        "evidence_hashes": [],
        "disclosure": {"history": "threshold", "claims": [{"clean_payments_gte": 50}]},
        "binding_hints": {"http_status": 200},
        "supersedes": None,
        "issued_at": ISSUED,
        "expires_at": expires,
    }


QUERY = sign_query(
    {
        "scheme": "x403",
        "version": VERSION,
        "policy_id": "shop-checkout-v1",
        "direction": "inbound",
        "mode": "inline",
        "payment": PAYMENT,
        "challenge": {"nonce": "n_vector_0001", "expires_at": VALID_UNTIL},
        "budget_ms": 150,
        "on_timeout": "denied",
        "requester": {"id": EXECUTOR_ID, "kid": EXECUTOR.kid},
    },
    EXECUTOR.private_jwk,
)


def main() -> None:
    body = decision_body()
    decision = {**body, "decision_sig": sign(body, AUTHORITY.private_jwk, typ="x403-decision+jws")}
    expired_body = decision_body(PAST)
    expired = {**expired_body, "decision_sig": sign(expired_body, AUTHORITY.private_jwk, typ="x403-decision+jws")}
    tampered = {**decision, "decision": "denied"}

    receipt = sign_receipt(
        {
            "decision_ref": decision["id"],
            "decision_hash": decision_hash(decision),
            "executed": True,
            "executed_at": ISSUED,
            "execution": {"rail": "card", "ref": "auth_vector", "amount": "189.00", "currency": "USD"},
            "executor": {"id": EXECUTOR_ID, "kid": EXECUTOR.kid},
        },
        EXECUTOR.private_jwk,
    )
    local = sign_local_decision(
        {
            "scheme": "x403",
            "version": VERSION,
            "id": "local_vector_1",
            "decision": "denied",
            "local": True,
            "direction": "inbound",
            "subject": subject_of(PAYMENT),
            "audience": EXECUTOR_ID,
            "policy_id": "shop-checkout-v1",
            "authority": {"id": AUTHORITY_ID},
            "reasons": ["authority_timeout"],
            "binding_hints": {"http_status": 403},
            "executor": {"id": EXECUTOR_ID, "kid": EXECUTOR.kid},
            "issued_at": ISSUED,
            "expires_at": VALID_UNTIL,
        },
        EXECUTOR.private_jwk,
    )
    local_allowed = sign_local_decision({**{k: v for k, v in local.items() if k != "local_sig"}, "id": "local_vector_bad", "decision": "allowed"}, EXECUTOR.private_jwk)
    outcome = sign_outcome(
        {
            "decision_ref": decision["id"],
            "decision_hash": decision_hash(decision),
            "authority_id": AUTHORITY_ID,
            "outcome": "settled",
            "category": "none",
            "reported_via": "executor",
            "at": ISSUED,
            "amount": "189.00",
            "currency": "USD",
            "reporter": {"id": EXECUTOR_ID, "kid": EXECUTOR.kid},
        },
        EXECUTOR.private_jwk,
    )

    write("keys.json", {
        "note": "test keys only; they sign nothing outside this directory",
        "authority": {"private": AUTHORITY.private_jwk, "public": AUTHORITY.public_jwk},
        "executor": {"private": EXECUTOR.private_jwk, "public": EXECUTOR.public_jwk},
    })
    write("payment.json", PAYMENT)
    write("payment_other.json", PAYMENT_OTHER)
    write("query.json", QUERY)
    write("decision.json", decision)
    write("decision_tampered.json", tampered)
    write("decision_expired.json", expired)
    write("receipt.json", receipt)
    write("local_decision.json", local)
    write("local_allowed.json", local_allowed)
    write("outcome.json", outcome)
    write("expectations.json", {
        "note": "each case names the file, which keys verify it, where it is presented, and the result every implementation must give",
        "cases": [
            {"name": "a decision verifies against the authority's key", "file": "decision.json", "object": "decision", "keys": "authority", "expect": {"ok": True}},
            {"name": "the same decision, presented at its audience for its payment", "file": "decision.json", "object": "decision", "keys": "authority", "audience": EXECUTOR_ID, "payment": "payment.json", "expect": {"ok": True}},
            {"name": "presented at another executor it is void", "file": "decision.json", "object": "decision", "keys": "authority", "audience": "did:web:other.example", "expect": {"ok": False, "reason": "audience_mismatch"}},
            {"name": "presented for another payment it is void", "file": "decision.json", "object": "decision", "keys": "authority", "audience": EXECUTOR_ID, "payment": "payment_other.json", "expect": {"ok": False, "reason": "subject_mismatch"}},
            {"name": "a field changed after signing", "file": "decision_tampered.json", "object": "decision", "keys": "authority", "expect": {"ok": False, "reason": "object differs from signed payload"}},
            {"name": "past its expiry", "file": "decision_expired.json", "object": "decision", "keys": "authority", "expect": {"ok": False, "reason": "decision_expired"}},
            {"name": "the executor's key does not verify the authority's decision", "file": "decision.json", "object": "decision", "keys": "executor", "expect": {"ok": False}},
            {"name": "a receipt verifies against the executor's key", "file": "receipt.json", "object": "receipt", "keys": "executor", "expect": {"ok": True}},
            {"name": "a local decision verifies against the executor's key, for its payment", "file": "local_decision.json", "object": "local", "keys": "executor", "audience": EXECUTOR_ID, "payment": "payment.json", "expect": {"ok": True}},
            {"name": "a local decision is never an allow", "file": "local_allowed.json", "object": "local", "keys": "executor", "expect": {"ok": False, "reason": "a local decision is never an allow"}},
            {"name": "a local decision does not verify against the authority's key", "file": "local_decision.json", "object": "local", "keys": "authority", "expect": {"ok": False}},
        ],
    })
    print("wrote", len(list(HERE.glob("*.json"))), "vectors")


if __name__ == "__main__":
    main()
