"""RFC 3161 parser/builder: round trips, malformed input and fail-closed behaviour."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from athar.log import rfc3161 as r

DIGEST = bytes(range(32))
WHEN = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _token(**kwargs: object) -> bytes:
    return r.build_timestamp_token(DIGEST, gen_time=WHEN, serial_number=7, nonce=99, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("length", [0, 1, 127, 128, 255, 256, 65535, 65536, 2**24])
def test_der_length_round_trip(length: int) -> None:
    encoded = r.der_encode_length(length)
    decoded, offset = r.der_decode_length(encoded, 0)
    assert (decoded, offset) == (length, len(encoded))


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 2**31, 2**64])
def test_der_integer_round_trip(value: int) -> None:
    tag, content, end = r.der_read_tlv(r.der_encode_integer(value))
    assert tag == 0x02
    assert r.der_decode_integer(content) == value


@pytest.mark.parametrize("oid", ["1.2.840.113549.1.7.2", "2.16.840.1.101.3.4.2.1", "1.3.101.112"])
def test_der_oid_round_trip(oid: str) -> None:
    tag, content, _ = r.der_read_tlv(r.der_encode_oid(oid))
    assert tag == 0x06
    assert r.der_decode_oid(content) == oid


def test_der_generalized_time_round_trip() -> None:
    tag, content, _ = r.der_read_tlv(r.der_encode_generalized_time(WHEN))
    assert tag == 0x18
    assert r.der_decode_generalized_time(content) == WHEN


@pytest.mark.parametrize(
    "bad",
    [b"\x80", b"\x82\x01"],
)
def test_malformed_lengths_are_rejected(bad: bytes) -> None:
    with pytest.raises(ValueError):
        r.der_decode_length(bad, 0)


def test_truncated_tlv_is_rejected() -> None:
    with pytest.raises(ValueError):
        r.der_read_tlv(b"\x30\x05\x01", 0)


def test_token_round_trip_preserves_fields() -> None:
    info = r.parse_timestamp_token(_token())
    assert info.version == 1
    assert info.serial_number == 7
    assert info.nonce == 99
    assert info.gen_time == WHEN
    assert info.hashed_message == DIGEST
    assert info.hash_algorithm_oid == r.OID_SHA256


def test_verify_accepts_matching_digest_only() -> None:
    info = r.parse_timestamp_token(_token())
    assert r.verify_timestamp_token(info, DIGEST) is True
    assert r.verify_timestamp_token(info, bytes(32)) is False


def test_verify_fails_closed_when_trust_verification_is_requested() -> None:
    """The TSA signature/chain is not verified, so asking for it must not return True."""
    info = r.parse_timestamp_token(_token())
    with pytest.raises(NotImplementedError):
        r.verify_timestamp_token(info, DIGEST, trusted_certs=[b"not-a-real-cert"])


def test_trailing_bytes_after_the_token_are_rejected() -> None:
    with pytest.raises(ValueError, match="Trailing"):
        r.parse_timestamp_token(_token() + b"x")


@pytest.mark.parametrize("cut", [0, 1, 5, 20, 60])
def test_truncated_tokens_are_rejected(cut: int) -> None:
    with pytest.raises(ValueError):
        r.parse_timestamp_token(_token()[:cut])


def test_wrong_outer_tag_is_rejected() -> None:
    token = _token()
    with pytest.raises(ValueError):
        r.parse_timestamp_token(bytes([token[0] ^ 0x01]) + token[1:])


def test_indefinite_length_is_rejected() -> None:
    with pytest.raises(ValueError):
        r.parse_timestamp_token(b"\x30\x80\x00\x00")
