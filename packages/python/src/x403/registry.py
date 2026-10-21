"""The reason-code registry and the status mapping of spec section 6.3. The decision
carries http_status already; this is for an executor that wants to recompute it, and
for the tests that pin the table."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

from .types import Decision, ReasonCodeEntry

with resources.files(__package__).joinpath("reason-codes.json").open("r", encoding="utf-8") as _f:
    REGISTRY: dict[str, Any] = json.load(_f)

CODES: dict[str, ReasonCodeEntry] = REGISTRY["codes"]
GROUPS: dict[str, dict[str, Any]] = REGISTRY["groups"]

# The six statuses a client must handle; anything else may be treated as 403.
NORMATIVE_STATUSES = (200, 401, 403, 428, 429, 451)

# The denied groups in the order section 6.3 consults them, after system codes.
_DENY_ORDER = (("compliance", 451), ("identity", 401), ("velocity", 429))


def entry_of(code: str) -> ReasonCodeEntry | None:
    return CODES.get(code)


def group_of(code: str) -> str | None:
    entry = CODES.get(code)
    return entry["group"] if entry else None


def check_of(code: str) -> str | None:
    group = group_of(code)
    return GROUPS[group]["check"] if group and group in GROUPS else None


def effect_of(code: str) -> str | None:
    entry = CODES.get(code)
    return entry["effect"] if entry else None


def escalation_of(code: str) -> str | None:
    entry = CODES.get(code)
    return entry.get("escalation") if entry else None


def status_for(decision: Decision | dict[str, Any]) -> int:
    """Section 6.3. allowed is 200. escalated is by kind. denied is the status of the first
    group, in order, that has a code on the decision: a system code with its own status
    and a deny effect (a note such as shadow_mode never turns a deny into a 200), then
    compliance, identity, velocity, else 403."""
    word = decision.get("decision")
    if word == "allowed":
        return 200
    if word == "escalated":
        kind = (decision.get("escalation") or {}).get("kind")
        return int(REGISTRY["status"]["escalated"].get(kind, 403)) if kind else 403
    reasons = decision.get("reasons") or []
    for code in reasons:
        entry = CODES.get(code)
        if entry and entry["group"] == "system" and entry["effect"] == "deny" and entry.get("status"):
            return int(entry["status"])
    groups = {CODES[c]["group"] for c in reasons if c in CODES}
    for group, status in _DENY_ORDER:
        if group in groups:
            return status
    return 403
