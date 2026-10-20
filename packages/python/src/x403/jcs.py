"""RFC 8785 (JSON Canonicalization Scheme). Every hash and every signature in x403 is
over this form, so two implementations that agree here agree everywhere. Numbers print
the way ES6 Number.prototype.toString prints them, which is the form the RFC fixes."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _es6_number(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JCS: non-finite number")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    x = abs(x)
    # repr gives the shortest digits that round-trip, which is the digit string ES6 uses;
    # only the placement of the point and the exponent form differ, handled below.
    text = repr(x)
    if "e" in text:
        mantissa, exponent = text.split("e")
        e = int(exponent)
    else:
        mantissa, e = text, 0
    if "." in mantissa:
        whole, frac = mantissa.split(".")
    else:
        whole, frac = mantissa, ""
    digits = whole + frac
    point = e - len(frac)  # value = int(digits) * 10 ** point
    digits = digits.lstrip("0")
    while digits.endswith("0"):
        digits = digits[:-1]
        point += 1
    k = len(digits)
    n = point + k  # value = 0.digits * 10 ** n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    exp = n - 1
    exp_text = ("+" if exp >= 0 else "-") + str(abs(exp))
    if k == 1:
        return sign + digits + "e" + exp_text
    return sign + digits[0] + "." + digits[1:] + "e" + exp_text


def _key(name: str) -> bytes:
    # The RFC sorts by UTF-16 code units; comparing UTF-16BE bytes is the same order.
    return name.encode("utf-16-be")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) < 2**53:
            return str(value)
        return _es6_number(float(value))
    if isinstance(value, float):
        return _es6_number(value)
    if isinstance(value, str):
        # json.dumps escapes only what the RFC escapes, with lowercase hex.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(((str(k), v) for k, v in value.items()), key=lambda kv: _key(kv[0]))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _serialize(v) for k, v in items) + "}"
    raise TypeError(f"JCS: cannot serialize {type(value).__name__}")


def canonicalize(value: Any) -> str:
    """The canonical JSON text of a value."""
    return _serialize(value)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def hash_object(value: Any) -> str:
    """`sha256:<hex>` of the canonical form of an object."""
    return "sha256:" + sha256_hex(canonical_bytes(value))


def hash_string(text: str) -> str:
    """`sha256:<hex>` of a string as given: a JWT, an SD-JWT, any opaque artifact."""
    return "sha256:" + sha256_hex(text)
