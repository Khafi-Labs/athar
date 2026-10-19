"""RFC 3161 Timestamp Protocol parser and builder for Athar.

Implements ASN.1 DER parsing and encoding for RFC 3161 TimeStampReq and
TimeStampToken (CMS ContentInfo / SignedData wrapping TSTInfo).
Follows RFC 3161 and RFC 5652 (CMS).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# OIDs
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_DEFAULT_POLICY = "1.3.6.1.4.1.99999.1"
OID_ED25519 = "1.3.101.112"


# ---------------------------------------------------------------------------
# ASN.1 DER primitives
# ---------------------------------------------------------------------------


def der_encode_length(length: int) -> bytes:
    """Encode length according to DER definite length rules."""
    if length < 128:
        return bytes([length])
    num_bytes = (length.bit_length() + 7) // 8
    return bytes([0x80 | num_bytes]) + length.to_bytes(num_bytes, "big")


def der_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode DER length starting at offset. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("Unexpected end of data reading length")
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length encoding not permitted in DER")
    if offset + num_bytes > len(data):
        raise ValueError("Truncated DER length bytes")
    length = int.from_bytes(data[offset : offset + num_bytes], "big")
    return length, offset + num_bytes


def der_read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read a single Tag-Length-Value element. Returns (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        raise ValueError(f"Offset {offset} beyond data length {len(data)}")
    tag = data[offset]
    offset += 1
    length, offset = der_decode_length(data, offset)
    if offset + length > len(data):
        raise ValueError("Truncated DER value content")
    value = data[offset : offset + length]
    return tag, value, offset + length


def der_encode_integer(value: int) -> bytes:
    """Encode an integer in DER format."""
    if value == 0:
        return b"\x02\x01\x00"
    num_bytes = (value.bit_length() + 8) // 8
    val_bytes = value.to_bytes(num_bytes, "big", signed=True)
    return b"\x02" + der_encode_length(len(val_bytes)) + val_bytes


def der_decode_integer(content: bytes) -> int:
    """Decode a DER integer value."""
    if not content:
        raise ValueError("Empty integer content")
    return int.from_bytes(content, "big", signed=True)


def der_encode_boolean(value: bool) -> bytes:
    """Encode a boolean in DER format."""
    return b"\x01\x01\xff" if value else b"\x01\x01\x00"


def der_decode_boolean(content: bytes) -> bool:
    """Decode a DER boolean value."""
    if not content:
        raise ValueError("Empty boolean content")
    return content[0] != 0


def der_encode_octet_string(data: bytes) -> bytes:
    """Encode bytes as a DER OCTET STRING (tag 0x04)."""
    return b"\x04" + der_encode_length(len(data)) + data


def der_encode_oid(oid_str: str) -> bytes:
    """Encode a dot-separated OID string into DER format (tag 0x06)."""
    parts = [int(p) for p in oid_str.split(".")]
    if len(parts) < 2:
        raise ValueError("OID must have at least 2 components")
    first_byte = 40 * parts[0] + parts[1]
    encoded = bytearray([first_byte])
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
            continue
        sub: list[int] = []
        val = part
        while val > 0:
            sub.append(val & 0x7F)
            val >>= 7
        sub.reverse()
        for i in range(len(sub) - 1):
            sub[i] |= 0x80
        encoded.extend(sub)
    return b"\x06" + der_encode_length(len(encoded)) + bytes(encoded)


def der_decode_oid(content: bytes) -> str:
    """Decode a DER OID value into dot-separated string."""
    if not content:
        raise ValueError("Empty OID content")
    first = content[0]
    p1 = first // 40
    p2 = first % 40
    parts = [str(p1), str(p2)]
    val = 0
    for b in content[1:]:
        val = (val << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def der_encode_generalized_time(dt: datetime) -> bytes:
    """Encode datetime in DER GeneralizedTime format (tag 0x18)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    utc_dt = dt.astimezone(UTC)
    formatted = utc_dt.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    return b"\x18" + der_encode_length(len(formatted)) + formatted


def der_decode_generalized_time(content: bytes) -> datetime:
    """Decode a DER GeneralizedTime string to a UTC datetime."""
    text = content.decode("ascii")
    # Format YYYYMMDDhhmmssZ or YYYYMMDDhhmmss.fffZ
    if text.endswith("Z"):
        core = text[:-1]
        if "." in core:
            dt = datetime.strptime(core, "%Y%m%d%H%M%S.%f")
        else:
            dt = datetime.strptime(core, "%Y%m%d%H%M%S")
        return dt.replace(tzinfo=UTC)
    raise ValueError(f"Unsupported GeneralizedTime format: {text}")


def der_encode_sequence(parts: list[bytes]) -> bytes:
    """Construct a DER SEQUENCE (tag 0x30)."""
    body = b"".join(parts)
    return b"\x30" + der_encode_length(len(body)) + body


def der_encode_set(parts: list[bytes]) -> bytes:
    """Construct a DER SET (tag 0x31)."""
    body = b"".join(parts)
    return b"\x31" + der_encode_length(len(body)) + body


def der_encode_context(tag_num: int, content: bytes, constructed: bool = True) -> bytes:
    """Construct a context-specific tag element (e.g. [0] or [1])."""
    tag = (0xA0 if constructed else 0x80) | tag_num
    return bytes([tag]) + der_encode_length(len(content)) + content


# ---------------------------------------------------------------------------
# Data Models and Parsers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimestampTokenInfo:
    """Extracted attributes from an RFC 3161 Timestamp Token.

    Attributes:
        version: TSTInfo version (1).
        policy_oid: TSA policy identifier OID.
        hash_algorithm_oid: Digest algorithm OID (e.g., SHA-256).
        hashed_message: Raw hash bytes embedded in the token.
        serial_number: Monotonically increasing serial number assigned by TSA.
        gen_time: UTC timestamp when the token was issued.
        nonce: Cryptographic nonce matching request (if present).
        ordering: True if TSA guarantees chronological ordering.
        signer_certificate: DER-encoded certificate of TSA signer (if present).
        signature: Raw signature bytes (if present).
        raw_token: Original complete DER token bytes.
    """

    version: int
    policy_oid: str
    hash_algorithm_oid: str
    hashed_message: bytes
    serial_number: int
    gen_time: datetime
    nonce: int | None
    ordering: bool
    signer_certificate: bytes | None
    signature: bytes | None
    raw_token: bytes

    @property
    def hashed_message_hex(self) -> str:
        """Hex string of hashed message."""
        return self.hashed_message.hex()

    def to_dict(self) -> dict[str, Any]:
        """Convert token info to serializable dictionary."""
        return {
            "gen_time": self.gen_time.isoformat(),
            "has_certificate": self.signer_certificate is not None,
            "has_signature": self.signature is not None,
            "hash_algorithm_oid": self.hash_algorithm_oid,
            "hashed_message": self.hashed_message.hex(),
            "nonce": self.nonce,
            "ordering": self.ordering,
            "policy_oid": self.policy_oid,
            "serial_number": self.serial_number,
            "version": self.version,
        }


def build_tst_info(
    digest: bytes,
    gen_time: datetime | None = None,
    policy_oid: str = OID_DEFAULT_POLICY,
    serial_number: int = 1,
    nonce: int | None = None,
    ordering: bool = False,
    hash_alg_oid: str = OID_SHA256,
) -> bytes:
    """Build a DER-encoded RFC 3161 TSTInfo structure.

    Args:
        digest: 32-byte SHA-256 digest.
        gen_time: Optional timestamp; defaults to UTC now.
        policy_oid: TSA policy OID string.
        serial_number: Integer serial number.
        nonce: Optional random integer nonce.
        ordering: Boolean ordering flag.
        hash_alg_oid: OID of the hash algorithm.

    Returns:
        DER-encoded TSTInfo bytes.
    """
    ts = gen_time or datetime.now(UTC)
    v_der = der_encode_integer(1)
    p_der = der_encode_oid(policy_oid)

    # messageImprint: SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    alg_id = der_encode_sequence([der_encode_oid(hash_alg_oid), b"\x05\x00"])
    imprint = der_encode_sequence([alg_id, der_encode_octet_string(digest)])

    serial_der = der_encode_integer(serial_number)
    time_der = der_encode_generalized_time(ts)
    ordering_der = der_encode_boolean(ordering)

    parts = [v_der, p_der, imprint, serial_der, time_der, ordering_der]
    if nonce is not None:
        parts.append(der_encode_integer(nonce))

    return der_encode_sequence(parts)


def build_timestamp_token(
    digest: bytes,
    gen_time: datetime | None = None,
    policy_oid: str = OID_DEFAULT_POLICY,
    serial_number: int = 1,
    nonce: int | None = None,
    signer_cert: bytes | None = None,
    signature: bytes | None = None,
) -> bytes:
    """Build a DER-encoded CMS ContentInfo wrapping SignedData and TSTInfo.

    Args:
        digest: 32-byte digest being timestamped.
        gen_time: Time of issuance.
        policy_oid: TSA policy OID.
        serial_number: Token serial number.
        nonce: Optional nonce integer.
        signer_cert: Optional DER-encoded certificate.
        signature: Optional signature bytes.

    Returns:
        Complete DER-encoded RFC 3161 timestamp token.
    """
    tst_info = build_tst_info(
        digest=digest,
        gen_time=gen_time,
        policy_oid=policy_oid,
        serial_number=serial_number,
        nonce=nonce,
    )

    # encapContentInfo:
    # eContentType: 1.2.840.113549.1.9.16.1.4 (id-ct-TSTInfo)
    # eContent: [0] EXPLICIT OCTET STRING containing tst_info
    econtent = der_encode_context(0, der_encode_octet_string(tst_info), constructed=True)
    encap = der_encode_sequence([der_encode_oid(OID_CT_TSTINFO), econtent])

    sd_version = der_encode_integer(3)
    digest_algs = der_encode_set([der_encode_sequence([der_encode_oid(OID_SHA256), b"\x05\x00"])])

    sd_parts = [sd_version, digest_algs, encap]

    if signer_cert is not None:
        sd_parts.append(der_encode_context(0, signer_cert, constructed=True))

    if signature is not None:
        signer_info = der_encode_sequence(
            [
                der_encode_integer(1),
                der_encode_sequence([der_encode_integer(1)]),  # dummy sid
                der_encode_sequence([der_encode_oid(OID_SHA256), b"\x05\x00"]),
                der_encode_sequence([der_encode_oid(OID_ED25519), b"\x05\x00"]),
                der_encode_octet_string(signature),
            ]
        )
        sd_parts.append(der_encode_set([signer_info]))
    else:
        sd_parts.append(der_encode_set([]))

    signed_data = der_encode_sequence(sd_parts)

    # CMS ContentInfo:
    return der_encode_sequence(
        [
            der_encode_oid(OID_SIGNED_DATA),
            der_encode_context(0, signed_data, constructed=True),
        ]
    )


def _extract_tst_info_der(token_data: bytes) -> tuple[bytes, bytes | None, bytes | None]:
    """Navigate CMS ContentInfo and SignedData to extract raw TSTInfo DER bytes.

    Returns:
        (tst_info_bytes, signer_certificate, signature)
    """
    tag, content, end = der_read_tlv(token_data)
    if tag != 0x30:
        raise ValueError(f"Expected outer SEQUENCE (0x30), got {hex(tag)}")
    if end != len(token_data):
        raise ValueError("Trailing bytes after the DER token")

    # ContentInfo: contentType OID, content [0]
    sub_tag, ct_bytes, offset = der_read_tlv(content, 0)
    if sub_tag != 0x06:
        raise ValueError("Expected contentType OID in ContentInfo")
    oid = der_decode_oid(ct_bytes)
    if oid != OID_SIGNED_DATA:
        raise ValueError(f"Expected SignedData OID {OID_SIGNED_DATA}, got {oid}")

    # [0] content
    next_tag, sd_wrapper, _ = der_read_tlv(content, offset)
    if (next_tag & 0x1F) != 0:
        raise ValueError("Expected [0] tag for SignedData content")

    # Inside SignedData SEQUENCE
    sd_tag, sd_bytes, _ = der_read_tlv(sd_wrapper, 0)
    if sd_tag != 0x30:
        raise ValueError("SignedData content is not a SEQUENCE")

    offset = 0
    # version
    _, _, offset = der_read_tlv(sd_bytes, offset)
    # digestAlgorithms
    _, _, offset = der_read_tlv(sd_bytes, offset)

    # encapContentInfo
    encap_tag, encap_bytes, offset = der_read_tlv(sd_bytes, offset)
    if encap_tag != 0x30:
        raise ValueError("encapContentInfo is not a SEQUENCE")

    e_offset = 0
    e_tag, e_type_bytes, e_offset = der_read_tlv(encap_bytes, e_offset)
    if e_tag != 0x06:
        raise ValueError("eContentType must be an OID")
    e_oid = der_decode_oid(e_type_bytes)
    if e_oid != OID_CT_TSTINFO:
        raise ValueError(f"Expected id-ct-TSTInfo {OID_CT_TSTINFO}, got {e_oid}")

    # eContent [0]
    econt_tag, econt_val, _ = der_read_tlv(encap_bytes, e_offset)
    if (econt_tag & 0x1F) != 0:
        raise ValueError("eContent missing [0] tag")

    # eContent holds an OCTET STRING with TSTInfo
    oct_tag, tst_info_bytes, _ = der_read_tlv(econt_val, 0)
    if oct_tag != 0x04:
        # Some encoders omit the octet string encapsulation
        tst_info_bytes = econt_val

    cert_bytes: bytes | None = None
    sig_bytes: bytes | None = None

    # Inspect remaining elements in SignedData for certificates [0] and signerInfos SET
    while offset < len(sd_bytes):
        elem_tag, elem_val, offset = der_read_tlv(sd_bytes, offset)
        if (elem_tag & 0x1F) == 0 and (elem_tag & 0x80):
            # [0] IMPLICIT CertificateSet
            cert_bytes = elem_val
        elif elem_tag == 0x31:
            # SET of SignerInfo
            if elem_val:
                try:
                    s_tag, s_val, _ = der_read_tlv(elem_val, 0)
                    if s_tag == 0x30:
                        # Scan signer info for signature OCTET STRING
                        s_offset = 0
                        while s_offset < len(s_val):
                            st, sv, s_offset = der_read_tlv(s_val, s_offset)
                            if st == 0x04:
                                sig_bytes = sv
                except Exception:
                    pass

    return tst_info_bytes, cert_bytes, sig_bytes


def parse_timestamp_token(token_data: bytes) -> TimestampTokenInfo:
    """Parse and extract all attributes from an RFC 3161 Timestamp Token.

    Handles CMS ContentInfo wrapper and inner TSTInfo sequence.

    Args:
        token_data: Raw DER-encoded timestamp token bytes.

    Returns:
        TimestampTokenInfo dataclass with extracted fields.

    Raises:
        ValueError: If token format is invalid or malformed.
    """
    tst_info_bytes, cert_bytes, sig_bytes = _extract_tst_info_der(token_data)

    tag, content, _ = der_read_tlv(tst_info_bytes, 0)
    if tag != 0x30:
        raise ValueError(f"TSTInfo is not a SEQUENCE (tag: {hex(tag)})")

    offset = 0

    # 1. version: INTEGER
    v_tag, v_val, offset = der_read_tlv(content, offset)
    if v_tag != 0x02:
        raise ValueError("TSTInfo version is not an INTEGER")
    version = der_decode_integer(v_val)

    # 2. policy: TSAPolicyId (OID)
    p_tag, p_val, offset = der_read_tlv(content, offset)
    if p_tag != 0x06:
        raise ValueError("TSTInfo policy is not an OID")
    policy_oid = der_decode_oid(p_val)

    # 3. messageImprint: SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    mi_tag, mi_val, offset = der_read_tlv(content, offset)
    if mi_tag != 0x30:
        raise ValueError("messageImprint is not a SEQUENCE")

    mi_offset = 0
    alg_tag, alg_val, mi_offset = der_read_tlv(mi_val, mi_offset)
    if alg_tag != 0x30:
        raise ValueError("hashAlgorithm is not a SEQUENCE")
    alg_oid_tag, alg_oid_val, _ = der_read_tlv(alg_val, 0)
    if alg_oid_tag != 0x06:
        raise ValueError("hashAlgorithm algorithm is not an OID")
    hash_algorithm_oid = der_decode_oid(alg_oid_val)

    hash_tag, hashed_message, _ = der_read_tlv(mi_val, mi_offset)
    if hash_tag != 0x04:
        raise ValueError("hashedMessage is not an OCTET STRING")

    # 4. serialNumber: INTEGER
    sn_tag, sn_val, offset = der_read_tlv(content, offset)
    if sn_tag != 0x02:
        raise ValueError("serialNumber is not an INTEGER")
    serial_number = der_decode_integer(sn_val)

    # 5. genTime: GeneralizedTime
    gt_tag, gt_val, offset = der_read_tlv(content, offset)
    if gt_tag != 0x18:
        raise ValueError("genTime is not GeneralizedTime")
    gen_time = der_decode_generalized_time(gt_val)

    ordering = False
    nonce: int | None = None

    # Inspect remaining optional elements: ordering (BOOLEAN), nonce (INTEGER)
    while offset < len(content):
        elem_tag, elem_val, offset = der_read_tlv(content, offset)
        if elem_tag == 0x01:
            ordering = der_decode_boolean(elem_val)
        elif elem_tag == 0x02:
            nonce = der_decode_integer(elem_val)

    return TimestampTokenInfo(
        version=version,
        policy_oid=policy_oid,
        hash_algorithm_oid=hash_algorithm_oid,
        hashed_message=hashed_message,
        serial_number=serial_number,
        gen_time=gen_time,
        nonce=nonce,
        ordering=ordering,
        signer_certificate=cert_bytes,
        signature=sig_bytes,
        raw_token=token_data,
    )


def verify_timestamp_token(
    token_info: TimestampTokenInfo,
    digest: bytes,
    trusted_certs: list[bytes] | None = None,
) -> bool:
    """Verify an RFC 3161 timestamp token matches the provided digest.

    Checks:
    - Message imprint hashedMessage matches digest.
    - Algorithm is SHA-256 (2.16.840.1.101.3.4.2.1).
    - Version is 1.
    - Does NOT verify the TSA signature or certificate chain. Passing
      ``trusted_certs`` raises NotImplementedError instead of returning True.

    Args:
        token_info: Extracted TimestampTokenInfo.
        digest: 32-byte expected hash.
        trusted_certs: Optional list of DER-encoded trusted CA certificates.

    Returns:
        True if the message imprint, version and algorithm match the digest,
        False otherwise. This is not proof that a TSA issued the token.
    """
    if token_info.version != 1:
        return False

    if token_info.hashed_message != digest:
        return False

    if token_info.hash_algorithm_oid != OID_SHA256:
        return False

    # The TSA's signature and certificate chain are NOT verified by this module.
    # Callers that ask for trust verification must not be told "valid" anyway,
    # so fail closed rather than silently skipping the check.
    if trusted_certs is not None:
        raise NotImplementedError(
            "RFC 3161 signature and trust-chain verification is not implemented; "
            "this function only checks the message imprint, version and algorithm."
        )

    return True
