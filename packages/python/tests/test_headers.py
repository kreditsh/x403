from x403.headers import authorization_risk, decode, encode, parse_authorization_risk, parse_www_authenticate, www_authenticate


def test_roundtrips_base64url_json():
    value = {"actor": {"agent": {"status": "asserted", "id": "did:key:z6Mk"}}, "note": chr(0x20AC) + ' and "quotes"'}
    text = encode(value)
    assert not any(c in text for c in "=+/")
    assert decode(text) == value


def test_auth_scheme_challenge():
    header = www_authenticate("shop-v1", realm="checkout", request="abc_-", expires="2026-10-20T10:00:00Z")
    assert header == 'Risk policy="shop-v1", realm="checkout", request="abc_-", expires="2026-10-20T10:00:00Z"'
    assert parse_www_authenticate(header) == {"policy": "shop-v1", "realm": "checkout", "request": "abc_-", "expires": "2026-10-20T10:00:00Z"}
    assert parse_www_authenticate("Bearer realm=x") is None


def test_refuses_a_header_value_over_8kb():
    import pytest

    from x403.headers import MAX_HEADER_BYTES

    big = encode({"inline": "x" * 9000})
    assert len(big) > MAX_HEADER_BYTES
    with pytest.raises(ValueError):
        decode(big)
    assert parse_authorization_risk(f"Risk {big}") is None


def test_authorization_risk():
    presentation = {"decision_ref": "k_1"}
    assert parse_authorization_risk(authorization_risk(presentation)) == presentation
    assert parse_authorization_risk("Bearer abc") is None
    assert parse_authorization_risk(None) is None
