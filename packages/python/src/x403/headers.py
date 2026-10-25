"""The HTTP binding: X403-* headers carry base64url JSON without padding, and the
auth-scheme binding carries the same objects under WWW-Authenticate: Risk."""

from __future__ import annotations

import json
import re
from typing import Any

from .jws import base64url, from_base64url

HEADER_REQUIRED = "X403-Required"
HEADER_PRESENTATION = "X403-Presentation"
HEADER_DECISION = "X403-Decision"
HEADER_RISK_DECISION = "Risk-Decision"
AUTH_SCHEME = "Risk"
# A single header value never exceeds this; anything larger travels in a body as application/x403+json.
MAX_HEADER_BYTES = 8192
MEDIA_TYPE = "application/x403+json"
# Every response that carries an x403 header carries this too: signed objects are never cached.
CACHE_CONTROL = "no-store"


def encode(value: Any) -> str:
    return base64url(json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def decode(text: str) -> Any:
    text = text.strip()
    if len(text) > MAX_HEADER_BYTES:
        raise ValueError(f"header value exceeds {MAX_HEADER_BYTES} bytes")
    return json.loads(from_base64url(text).decode("utf-8"))


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def www_authenticate(policy: str, realm: str | None = None, request: str | None = None, expires: str | None = None) -> str:
    """`WWW-Authenticate: Risk policy="...", realm="...", request="...", expires="..."`"""
    parts = [f"policy={_quote(policy)}"]
    if realm:
        parts.append(f"realm={_quote(realm)}")
    if request:
        parts.append(f"request={_quote(request)}")
    if expires:
        parts.append(f"expires={_quote(expires)}")
    return f"{AUTH_SCHEME} " + ", ".join(parts)


_PARAM = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))')


def parse_www_authenticate(header: str) -> dict[str, str] | None:
    m = re.match(r"^\s*Risk\s+(.*)$", header, re.S)
    if not m:
        return None
    out: dict[str, str] = {}
    for name, quoted, bare in _PARAM.findall(m.group(1)):
        out[name] = re.sub(r"\\(.)", r"\1", quoted if quoted else bare)
    return out if "policy" in out else None


def authorization_risk(presentation: dict[str, Any]) -> str:
    """`Authorization: Risk <base64url presentation>`"""
    return f"{AUTH_SCHEME} {encode(presentation)}"


def parse_authorization_risk(header: str | None) -> dict[str, Any] | None:
    if not header:
        return None
    m = re.match(r"^\s*Risk\s+([A-Za-z0-9_-]+)\s*$", header)
    if not m:
        return None
    try:
        return decode(m.group(1))
    except (ValueError, UnicodeDecodeError):
        return None
