"""The repo's test vectors: every implementation must give the result expectations.json names."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from x403.jws import verify_decision, verify_local_decision, verify_receipt

DIR = Path(__file__).resolve().parents[3] / "test-vectors"


def read(name: str):
    return json.loads((DIR / name).read_text(encoding="utf-8"))


KEYS = read("keys.json")
CASES = read("expectations.json")["cases"]
NOW = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_vector(case):
    jwk = KEYS[case["keys"]]["public"]
    payment = read(case["payment"]) if case.get("payment") else None
    if case["object"] == "decision":
        result = verify_decision(read(case["file"]), jwk, NOW, audience=case.get("audience"), payment=payment)
    elif case["object"] == "local":
        result = verify_local_decision(read(case["file"]), jwk, audience=case.get("audience"), payment=payment)
    else:
        result = verify_receipt(read(case["file"]), jwk)
    assert result.ok == case["expect"]["ok"], result.reason
    if case["expect"].get("reason"):
        assert result.reason == case["expect"]["reason"]
