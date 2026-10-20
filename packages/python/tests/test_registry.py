import json
from pathlib import Path

import pytest

from x403.registry import REGISTRY, check_of, effect_of, escalation_of, group_of, status_for

ROOT = Path(__file__).resolve().parents[3]


def test_bundled_registry_is_the_repo_registry():
    source = json.loads((ROOT / "registry" / "reason-codes.json").read_text(encoding="utf-8"))
    assert REGISTRY == source


def test_every_code_has_a_group_and_every_escalate_a_kind():
    for code, entry in REGISTRY["codes"].items():
        assert entry["group"] in REGISTRY["groups"], code
        if entry["effect"] == "escalate":
            assert entry.get("escalation"), code
    assert group_of("sanctions_hit") == "compliance"
    assert check_of("sanctions_hit") == "payee"
    assert effect_of("amount_over_cap") == "escalate"
    assert escalation_of("amount_over_cap") == "agent_adjust"
    assert group_of("no_such_code") is None


def deny(*reasons):
    return status_for({"decision": "deny", "reasons": list(reasons)})


def escalate(kind):
    return status_for({"decision": "escalate", "reasons": [], "escalation": {"kind": kind}})


def test_allow_is_200():
    assert status_for({"decision": "allow", "reasons": ["amount_at_cap"]}) == 200


@pytest.mark.parametrize("kind,status", [("agent_adjust", 403), ("operator_confirm", 428), ("human_stepup", 428), ("executor_review", 403)])
def test_escalate_by_kind(kind, status):
    assert escalate(kind) == status
    assert status_for({"decision": "escalate", "reasons": []}) == 403


def test_deny_groups():
    assert deny("instance_token_expired") == 401
    assert deny("human_unverified", "amount_over_cap") == 401
    assert deny("sanctions_hit") == 451
    assert deny("agent_frozen", "jurisdiction_blocked") == 451
    assert deny("velocity_high") == 429
    assert deny("rate_cap_exceeded", "blocked_counterparty") == 429
    assert deny("blocked_counterparty") == 403
    assert deny("injection_pattern") == 403
    assert deny("dispute_history") == 403
    assert deny() == 403


@pytest.mark.parametrize("code", ["nonce_consumed", "decision_expired", "decision_consumed", "decision_superseded"])
def test_replay_and_expiry_409(code):
    assert deny(code) == 409


@pytest.mark.parametrize("code", ["policy_unknown", "presentation_malformed", "evidence_hash_mismatch"])
def test_wrong_request_400(code):
    assert deny(code) == 400


def test_bad_signatures_401_timeout_403():
    assert deny("evidence_signature_invalid") == 401
    assert deny("requester_signature_invalid") == 401
    assert deny("evidence_expired") == 401
    assert deny("authority_timeout") == 403


def test_system_code_wins_and_a_note_does_not():
    assert deny("sanctions_hit", "nonce_consumed") == 409
    assert deny("shadow_mode", "sanctions_hit") == 451
    assert deny("evidence_unsupported", "velocity_high") == 429
