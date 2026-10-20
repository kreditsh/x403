import json

import pytest

from x403.jcs import canonicalize, hash_object, hash_string

BS = chr(92)


def esc(hexa: str) -> str:
    return BS + "u" + hexa


def test_rfc_8785_appendix_example():
    # RFC 8785 section 3.2.3: the input JSON text, parsed, and its expected canonical form.
    input_text = (
        "{" + chr(34) + "numbers" + chr(34) + ": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],"
        + chr(34) + "string" + chr(34) + ": " + chr(34)
        + esc("20ac") + "$" + esc("000F") + esc("000a") + "A'" + esc("0042") + esc("0022") + esc("005c")
        + BS + BS + BS + chr(34) + BS + "/" + chr(34) + ","
        + chr(34) + "literals" + chr(34) + ": [null, true, false]}"
    )
    expected = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        + '"string":"' + chr(0x20AC) + "$" + esc("000f") + BS + "nA'B" + BS + '"' + BS + BS + BS + BS + BS + '"/"}'
    )
    assert canonicalize(json.loads(input_text)) == expected


def test_sorts_keys_by_utf16_code_units():
    smile = chr(0x1F600)
    wide = chr(0xFF5A)
    # U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5A in UTF-16.
    assert canonicalize({smile: 1, wide: 2, "a": 3}) == '{"a":3,"' + smile + '":1,"' + wide + '":2}'


@pytest.mark.parametrize(
    "value,text",
    [
        (1, "1"),
        (-0.0, "0"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (0.00001, "0.00001"),
        (123456789012345680000.0, "123456789012345680000"),
        (1.5e-7, "1.5e-7"),
        (4.5, "4.5"),
        (100.0, "100"),
        (2 ** 53, "9007199254740992"),
    ],
)
def test_es6_numbers(value, text):
    assert canonicalize(value) == text


def test_refuses_what_json_cannot_carry():
    with pytest.raises(ValueError):
        canonicalize({"a": float("nan")})
    with pytest.raises(TypeError):
        canonicalize({"a": object()})


def test_hashes_the_canonical_form():
    assert hash_object({"b": 1, "a": 2}) == hash_object({"a": 2, "b": 1})
    assert hash_string("abc") == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
