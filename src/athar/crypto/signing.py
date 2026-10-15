"""Ed25519 digital signature signing and verification for Athar.

Follows RFC 8032 (Ed25519) using standard cryptographic primitives.
Provides key pair generation, serialization, signing, and verification.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass(frozen=True)
class SigningPublicKey:
    """Public key component of an Ed25519 key pair."""

    key_id: str
    public_bytes: bytes

    @property
    def public_hex(self) -> str:
        """Hex-encoded public key bytes."""
        return self.public_bytes.hex()

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature over message bytes.

        Args:
            message: Raw data bytes that were signed.
            signature: 64-byte Ed25519 signature.

        Returns:
            True if signature is cryptographically valid, False otherwise.
        """
        if len(signature) != 64 or len(self.public_bytes) != 32:
            return False
        try:
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(self.public_bytes)
            verifier.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False


class SigningKeyPair:
    """Ed25519 signing key pair for receipt and batch attestation."""

    def __init__(
        self,
        key_id: str,
        private_bytes: bytes,
        public_bytes: bytes,
    ) -> None:
        """Initialize key pair with raw 32-byte private and public key bytes.

        Args:
            key_id: Unique identifier for this signer key.
            private_bytes: Raw 32-byte Ed25519 private seed.
            public_bytes: Raw 32-byte Ed25519 public key.
        """
        self.key_id = key_id
        self._private_bytes = private_bytes
        self._public_bytes = public_bytes
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)

    @classmethod
    def generate(cls, key_id: str | None = None) -> SigningKeyPair:
        """Generate a new random Ed25519 signing key pair.

        Args:
            key_id: Optional key identifier; defaults to a new UUID.

        Returns:
            A new SigningKeyPair instance.
        """
        kid = key_id or str(uuid.uuid4())
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return cls(key_id=kid, private_bytes=priv_bytes, public_bytes=pub_bytes)

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte public key."""
        return self._public_bytes

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded public key."""
        return self._public_bytes.hex()

    @property
    def public_key(self) -> SigningPublicKey:
        """Get the public key component."""
        return SigningPublicKey(key_id=self.key_id, public_bytes=self._public_bytes)

    def sign(self, message: bytes) -> bytes:
        """Sign a message using Ed25519.

        Args:
            message: Raw data bytes to sign.

        Returns:
            64-byte detached signature.
        """
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against this key pair's public key.

        Args:
            message: Raw data bytes that were signed.
            signature: 64-byte Ed25519 signature.

        Returns:
            True if signature is valid, False otherwise.
        """
        return self.public_key.verify(message, signature)


def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Standalone verification of an Ed25519 signature.

    Args:
        public_key_bytes: 32-byte Ed25519 public key.
        message: Raw message bytes.
        signature: 64-byte Ed25519 signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if len(signature) != 64 or len(public_key_bytes) != 32:
        return False
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
