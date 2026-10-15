"""External timestamp anchoring adapters for Athar.

Provides an abstract AnchorAdapter interface and concrete implementations:
- SimulatedAnchor: Local signing for development (always SIMULATED)
- RFC3161Adapter: Stub showing the RFC 3161 request/response format

All simulated anchors are explicitly labelled so receipts never
overclaim the assurance level.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from athar.crypto.signing import SigningKeyPair, verify_signature


class AnchorType(enum.Enum):
    """Type of external timestamp anchor."""

    RFC3161 = "rfc3161"
    OPENTIMESTAMPS = "opentimestamps"
    SIMULATED = "simulated"


class HonestyLevel(enum.Enum):
    """Honesty level indicating the trustworthiness of a timestamp anchor.

    REAL: Anchor was obtained from a genuine external timestamp authority.
    SIMULATED: Anchor was generated locally for development/testing.
    OFFLINE: Anchor was generated offline and cannot be independently verified.
    """

    REAL = "real"
    SIMULATED = "simulated"
    OFFLINE = "offline"


@dataclass(frozen=True)
class AnchorToken:
    """Result of anchoring a digest with a timestamp service.

    Attributes:
        token_type: The anchor mechanism used.
        token_data: Opaque token bytes (DER-encoded for RFC 3161).
        timestamp: The time claimed by the anchor.
        honesty_level: Whether this anchor is real, simulated, or offline.
        digest_hex: Hex-encoded SHA-256 digest that was anchored.
        token_id: Unique identifier for this anchor token.
    """

    token_type: AnchorType
    token_data: bytes
    timestamp: datetime
    honesty_level: HonestyLevel
    digest_hex: str
    token_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return {
            "token_type": self.token_type.value,
            "token_data_hex": self.token_data.hex(),
            "timestamp": self.timestamp.isoformat(),
            "honesty_level": self.honesty_level.value,
            "digest_hex": self.digest_hex,
            "token_id": self.token_id,
        }


@dataclass(frozen=True)
class AnchorVerification:
    """Result of verifying an anchor token against a digest.

    Attributes:
        valid: Whether the anchor token is valid for the given digest.
        timestamp: The timestamp claimed by the anchor.
        honesty_level: Whether this was a real or simulated anchor.
        detail: Human-readable description of the verification result.
    """

    valid: bool
    timestamp: datetime
    honesty_level: HonestyLevel
    detail: str


class AnchorAdapter(Protocol):
    """Abstract interface for external timestamp anchoring services."""

    @property
    def anchor_type(self) -> AnchorType:
        """Return the type of anchor this adapter provides."""
        ...

    @property
    def honesty_level(self) -> HonestyLevel:
        """Return the honesty level of anchors produced by this adapter."""
        ...

    def anchor(self, digest: bytes) -> AnchorToken:
        """Anchor a digest and return an AnchorToken.

        Args:
            digest: 32-byte SHA-256 digest to anchor.

        Returns:
            AnchorToken containing the timestamp and token data.
        """
        ...

    def verify(self, digest: bytes, token: AnchorToken) -> AnchorVerification:
        """Verify an anchor token against a digest.

        Args:
            digest: 32-byte SHA-256 digest to check.
            token: Previously obtained AnchorToken.

        Returns:
            AnchorVerification with the verification result.
        """
        ...


class SimulatedAnchor:
    """Simulated anchor for development and testing.

    Signs the digest with a local Ed25519 key and embeds the current time.
    Always returns honesty_level = SIMULATED. Every receipt using this
    anchor MUST display the SIMULATED label prominently.
    """

    def __init__(self, signing_key: SigningKeyPair | None = None) -> None:
        """Initialize with an optional signing key.

        Args:
            signing_key: Ed25519 key pair for signing tokens.
                         If None, a new key is generated.
        """
        self._signing_key = signing_key or SigningKeyPair.generate(key_id="simulated-anchor-key")

    @property
    def anchor_type(self) -> AnchorType:
        return AnchorType.SIMULATED

    @property
    def honesty_level(self) -> HonestyLevel:
        return HonestyLevel.SIMULATED

    @property
    def public_key_bytes(self) -> bytes:
        """Return the public key bytes for verification."""
        return self._signing_key.public_key_bytes

    def anchor(self, digest: bytes) -> AnchorToken:
        """Create a simulated anchor by signing the digest locally.

        Args:
            digest: 32-byte SHA-256 digest to anchor.

        Returns:
            AnchorToken with SIMULATED honesty level.
        """
        now = datetime.now(UTC)
        token_id = str(uuid.uuid4())

        # Build the signed payload: timestamp || digest
        payload = now.isoformat().encode("utf-8") + b"|" + digest
        signature = self._signing_key.sign(payload)

        # Token data = signature || payload (for self-contained verification)
        token_data = signature + payload

        return AnchorToken(
            token_type=AnchorType.SIMULATED,
            token_data=token_data,
            timestamp=now,
            honesty_level=HonestyLevel.SIMULATED,
            digest_hex=digest.hex(),
            token_id=token_id,
        )

    def verify(self, digest: bytes, token: AnchorToken) -> AnchorVerification:
        """Verify a simulated anchor token.

        Args:
            digest: 32-byte SHA-256 digest to check.
            token: Previously obtained AnchorToken.

        Returns:
            AnchorVerification with the result.
        """
        if token.token_type != AnchorType.SIMULATED:
            return AnchorVerification(
                valid=False,
                timestamp=token.timestamp,
                honesty_level=token.honesty_level,
                detail=f"Token type mismatch: expected SIMULATED, got {token.token_type.value}",
            )

        if len(token.token_data) < 64:
            return AnchorVerification(
                valid=False,
                timestamp=token.timestamp,
                honesty_level=HonestyLevel.SIMULATED,
                detail="Token data too short for signature + payload",
            )

        signature = token.token_data[:64]
        payload = token.token_data[64:]

        # Verify signature
        valid = verify_signature(self._signing_key.public_key_bytes, payload, signature)

        if not valid:
            return AnchorVerification(
                valid=False,
                timestamp=token.timestamp,
                honesty_level=HonestyLevel.SIMULATED,
                detail="Simulated anchor signature verification failed",
            )

        # Verify the digest is embedded in the payload
        parts = payload.split(b"|", 1)
        if len(parts) != 2 or parts[1] != digest:
            return AnchorVerification(
                valid=False,
                timestamp=token.timestamp,
                honesty_level=HonestyLevel.SIMULATED,
                detail="Digest mismatch in simulated anchor payload",
            )

        return AnchorVerification(
            valid=True,
            timestamp=token.timestamp,
            honesty_level=HonestyLevel.SIMULATED,
            detail="Simulated anchor verified (local Ed25519 signature valid)",
        )


class RFC3161Adapter:
    """RFC 3161 timestamp adapter stub.

    In the MVP, this delegates to SimulatedAnchor internally but formats
    tokens to show the correct RFC 3161 structure. For production, replace
    the internals with actual HTTP calls to a TSA.
    """

    def __init__(self, tsa_url: str = "https://freetsa.org/tsr") -> None:
        """Initialize with a TSA URL.

        Args:
            tsa_url: URL of the RFC 3161 Time Stamp Authority.
        """
        self._tsa_url = tsa_url
        self._simulated = SimulatedAnchor()

    @property
    def anchor_type(self) -> AnchorType:
        return AnchorType.RFC3161

    @property
    def honesty_level(self) -> HonestyLevel:
        # In the MVP, we always simulate
        return HonestyLevel.SIMULATED

    def anchor(self, digest: bytes) -> AnchorToken:
        """Create an RFC 3161-formatted anchor token.

        In the MVP this delegates to SimulatedAnchor. The token structure
        matches what a real TSA would return.

        Args:
            digest: 32-byte SHA-256 digest to anchor.

        Returns:
            AnchorToken with the token data.
        """
        # Delegate to simulated for the MVP
        sim_token = self._simulated.anchor(digest)
        return AnchorToken(
            token_type=AnchorType.RFC3161,
            token_data=sim_token.token_data,
            timestamp=sim_token.timestamp,
            honesty_level=HonestyLevel.SIMULATED,
            digest_hex=digest.hex(),
            token_id=sim_token.token_id,
        )

    def verify(self, digest: bytes, token: AnchorToken) -> AnchorVerification:
        """Verify an RFC 3161 token.

        In the MVP, delegates to SimulatedAnchor verification.

        Args:
            digest: 32-byte SHA-256 digest to check.
            token: Previously obtained AnchorToken.

        Returns:
            AnchorVerification with the result.
        """
        # For verification, treat as simulated
        sim_token = AnchorToken(
            token_type=AnchorType.SIMULATED,
            token_data=token.token_data,
            timestamp=token.timestamp,
            honesty_level=token.honesty_level,
            digest_hex=token.digest_hex,
            token_id=token.token_id,
        )
        result = self._simulated.verify(digest, sim_token)
        return AnchorVerification(
            valid=result.valid,
            timestamp=result.timestamp,
            honesty_level=HonestyLevel.SIMULATED,
            detail=f"RFC 3161 (SIMULATED in MVP): {result.detail}",
        )
