"""Unit tests for RFC 8785 canonical JSON serialization and hashing."""

from athar.crypto.canonical_json import canonical_json_encode, canonical_json_hash


def test_canonical_json_key_sorting() -> None:
    data = {"z": 1, "a": 2, "m": 3}
    encoded = canonical_json_encode(data)
    assert encoded == b'{"a":2,"m":3,"z":1}'


def test_canonical_json_no_whitespace() -> None:
    data = {"list": [1, 2, 3], "nested": {"key": "value"}}
    encoded = canonical_json_encode(data)
    assert b" " not in encoded
    assert encoded == b'{"list":[1,2,3],"nested":{"key":"value"}}'


def test_canonical_json_boolean_and_null() -> None:
    data = {"active": True, "archived": False, "details": None}
    encoded = canonical_json_encode(data)
    assert encoded == b'{"active":true,"archived":false,"details":null}'


def test_canonical_json_hash_deterministic() -> None:
    data1 = {"b": 2, "a": 1}
    data2 = {"a": 1, "b": 2}
    hash1 = canonical_json_hash(data1)
    hash2 = canonical_json_hash(data2)
    assert hash1 == hash2
    assert len(hash1) == 64
