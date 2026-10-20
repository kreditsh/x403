"""Compact JWS with ES256 over the RFC 8785 form. Signatures are raw r||s as JWS wants;
`cryptography` hands back DER, so the two are converted at the edge and nowhere else."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .jcs import canonical_bytes, canonicalize, sha256_hex
from .types import JWK, JWKS, Decision, Outcome, Receipt, RiskQuery

CURVE = ec.SECP256R1()
COORD = 32


def base64url(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def from_base64url(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))


def _int(text: str) -> int:
    return int.from_bytes(from_base64url(text), "big")


def _b64int(n: int) -> str:
    return base64url(n.to_bytes(COORD, "big"))


def thumbprint(jwk: JWK) -> str:
    """RFC 7638: over exactly these members, in this order."""
    if jwk.get("kty") != "EC":
        raise TypeError("thumbprint: only EC keys")
    text = canonicalize({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]})
    return base64url(bytes.fromhex(sha256_hex(text)))


@dataclass
class KeyPair:
    private_jwk: JWK
    public_jwk: JWK
    kid: str


def generate_key() -> KeyPair:
    """A fresh P-256 pair as JWKs, with the RFC 7638 thumbprint as kid."""
    private = ec.generate_private_key(CURVE)
    return key_pair_from_private(private)


def key_pair_from_private(private: ec.EllipticCurvePrivateKey) -> KeyPair:
    numbers = private.private_numbers()
    pub = numbers.public_numbers
    public_jwk: JWK = {"kty": "EC", "crv": "P-256", "x": _b64int(pub.x), "y": _b64int(pub.y)}
    kid = thumbprint(public_jwk)
    public_jwk.update({"kid": kid, "alg": "ES256", "use": "sig"})
    private_jwk: JWK = {**public_jwk, "d": _b64int(numbers.private_value)}
    private_jwk.pop("use", None)
    return KeyPair(private_jwk=private_jwk, public_jwk=public_jwk, kid=kid)


def private_key(jwk: JWK) -> ec.EllipticCurvePrivateKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" not in jwk:
        raise TypeError("a P-256 private JWK is needed")
    return ec.derive_private_key(_int(jwk["d"]), CURVE)


def public_key(jwk: JWK) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise TypeError("a P-256 public JWK is needed")
    return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), CURVE).public_key()


def sign(payload: Any, private_jwk: JWK, kid: str | None = None, typ: str | None = None) -> str:
    """Sign the canonical form of `payload` as a compact JWS."""
    kid = kid or private_jwk.get("kid") or thumbprint(private_jwk)
    header: dict[str, Any] = {"alg": "ES256", "kid": kid}
    if typ:
        header["typ"] = typ
    signing_input = base64url(canonicalize(header)) + "." + base64url(canonical_bytes(payload))
    der = private_key(private_jwk).sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + base64url(r.to_bytes(COORD, "big") + s.to_bytes(COORD, "big"))


@dataclass
class Verified:
    header: dict[str, Any]
    payload: Any
    payload_text: str


def _pick_key(jwks: JWKS | JWK, kid: str | None) -> JWK:
    if "keys" not in jwks:
        return jwks  # type: ignore[return-value]
    keys = [k for k in jwks["keys"] if k.get("kty") == "EC" and k.get("crv") == "P-256"]  # type: ignore[index]
    match = next((k for k in keys if kid and k.get("kid") == kid), None)
    if match is None and len(keys) == 1:
        match = keys[0]
    if match is None:
        raise ValueError(f"no key with kid {kid}" if kid else "no single P-256 key to verify with")
    return match


def verify(jws: str, jwks: JWKS | JWK) -> Verified:
    """Verify a compact JWS against a key set and return its header and payload. Raises when it does not verify."""
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    h, p, s = parts
    header = json.loads(from_base64url(h))
    if header.get("alg") != "ES256":
        raise ValueError(f"unsupported alg {header.get('alg')}")
    raw = from_base64url(s)
    if len(raw) != 2 * COORD:
        raise ValueError("signature is not raw r||s")
    der = encode_dss_signature(int.from_bytes(raw[:COORD], "big"), int.from_bytes(raw[COORD:], "big"))
    key = public_key(_pick_key(jwks, header.get("kid")))
    try:
        key.verify(der, f"{h}.{p}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise ValueError("signature does not verify") from e
    payload_text = from_base64url(p).decode("utf-8")
    return Verified(header=header, payload=json.loads(payload_text), payload_text=payload_text)


@dataclass
class VerifyResult:
    ok: bool
    reason: str | None = None
    kid: str | None = None

    def __bool__(self) -> bool:
        return self.ok


def _parse_time(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def verify_decision(decision: Decision, jwks: JWKS | JWK, now: datetime | None = None) -> VerifyResult:
    """A decision verifies when decision_sig is a valid ES256 signature by one of the
    authority's keys over the object without decision_sig, and it has not expired."""
    sig = decision.get("decision_sig")
    if not sig:
        return VerifyResult(False, "unsigned")
    body = {k: v for k, v in decision.items() if k != "decision_sig"}
    try:
        verified = verify(sig, jwks)
    except ValueError as e:
        return VerifyResult(False, str(e))
    kid = verified.header.get("kid")
    # The signed payload must be this object, byte for byte in canonical form: a decision
    # whose fields were edited after signing carries a signature over something else.
    if verified.payload_text != canonicalize(body):
        return VerifyResult(False, "object differs from signed payload", kid)
    expires = decision.get("expires_at")
    if expires and _parse_time(expires) <= (now or datetime.now(timezone.utc)):
        return VerifyResult(False, "decision_expired", kid)
    return VerifyResult(True, None, kid)


def verify_receipt(receipt: Receipt, jwks: JWKS | JWK) -> VerifyResult:
    sig = receipt.get("executor_sig")
    if not sig:
        return VerifyResult(False, "unsigned")
    body = {k: v for k, v in receipt.items() if k != "executor_sig"}
    try:
        verified = verify(sig, jwks)
    except ValueError as e:
        return VerifyResult(False, str(e))
    if verified.payload_text != canonicalize(body):
        return VerifyResult(False, "object differs from signed payload", verified.header.get("kid"))
    return VerifyResult(True, None, verified.header.get("kid"))


def sign_receipt(receipt: Receipt, private_jwk: JWK, kid: str | None = None) -> Receipt:
    """Countersign a receipt: executor_sig is over the receipt without executor_sig."""
    body = {k: v for k, v in receipt.items() if k != "executor_sig"}
    kid = kid or (receipt.get("executor") or {}).get("kid")
    return {**body, "executor_sig": sign(body, private_jwk, kid=kid, typ="x403-receipt+jws")}  # type: ignore[return-value]


def sign_outcome(outcome: Outcome, private_jwk: JWK, kid: str | None = None) -> Outcome:
    body = {k: v for k, v in outcome.items() if k != "sig"}
    kid = kid or (outcome.get("reporter") or {}).get("kid")
    return {**body, "sig": sign(body, private_jwk, kid=kid, typ="x403-outcome+jws")}  # type: ignore[return-value]


def sign_query(query: RiskQuery, private_jwk: JWK, kid: str | None = None) -> RiskQuery:
    body = {k: v for k, v in query.items() if k != "requester_sig"}
    kid = kid or (query.get("requester") or {}).get("kid")
    return {**body, "requester_sig": sign(body, private_jwk, kid=kid, typ="x403-query+jws")}  # type: ignore[return-value]


def decision_hash(decision: Decision) -> str:
    """The hash a receipt must carry: the decision as signed, decision_sig included."""
    return "sha256:" + sha256_hex(canonical_bytes(decision))
