"""x403: a signed risk decision before money moves."""

from .client import AsyncX403, X403, X403Error, build_query
from .headers import (
    AUTH_SCHEME,
    HEADER_DECISION,
    HEADER_PRESENTATION,
    HEADER_REQUIRED,
    HEADER_RISK_DECISION,
    authorization_risk,
    decode,
    encode,
    parse_authorization_risk,
    parse_www_authenticate,
    www_authenticate,
)
from .jcs import canonicalize, hash_object, hash_string
from .jws import (
    KeyPair,
    VerifyResult,
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
from .registry import CODES, GROUPS, NORMATIVE_STATUSES, REGISTRY, check_of, effect_of, entry_of, escalation_of, group_of, status_for
from .types import VERSION

__version__ = "0.2.2"

__all__ = [
    "AsyncX403", "X403", "X403Error", "build_query",
    "AUTH_SCHEME", "HEADER_DECISION", "HEADER_PRESENTATION", "HEADER_REQUIRED", "HEADER_RISK_DECISION",
    "authorization_risk", "decode", "encode", "parse_authorization_risk", "parse_www_authenticate", "www_authenticate",
    "canonicalize", "hash_object", "hash_string",
    "KeyPair", "VerifyResult", "decision_hash", "generate_key", "sign", "sign_outcome", "sign_query", "sign_receipt",
    "thumbprint", "verify", "verify_decision", "verify_receipt",
    "CODES", "GROUPS", "NORMATIVE_STATUSES", "REGISTRY", "check_of", "effect_of", "entry_of", "escalation_of", "group_of", "status_for",
    "VERSION", "__version__",
]
