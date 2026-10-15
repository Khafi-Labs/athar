"""Blind index implementation for privacy-preserving exact match queries.

Blind indexes map plaintext identifiers (e.g. email, national ID, phone number)
to an uninvertible, pseudorandom token using HMAC-SHA256 with a dedicated secret key.

Security Properties:
- Never use plain hashes (SHA-256 without key) for identifiers because low-entropy
  identifiers are vulnerable to rainbow table and dictionary attacks.
- The HMAC key must be kept separate from data encryption keys (DEKs/PPKs/KEKs).
- The output is deterministic for a given HMAC key, allowing exact-match lookups
  in indexed databases without decrypting all records or storing plaintext identifiers.
"""

from __future__ import annotations

import hashlib
import hmac
import os


def generate_blind_index_key() -> bytes:
    """Generate a high-entropy 256-bit secret key for blind index computation.

    Returns:
        32 cryptographically secure random bytes.
    """
    return os.urandom(32)


def compute_blind_index(identifier: str, hmac_key: bytes) -> str:
    """Compute a blind index for a subject identifier using HMAC-SHA256.

    Never use a plain hash of personal data. Blind indexes allow exact-match
    lookups without exposing plaintext identifiers or allowing rainbow table
    attacks against low-entropy data (e.g. emails, phone numbers).

    Args:
        identifier: Plaintext subject identifier (e.g., email, national ID).
        hmac_key: Dedicated HMAC secret key (at least 16 bytes, 32 bytes recommended).

    Returns:
        Hex-encoded HMAC-SHA256 string (64 characters).

    Raises:
        TypeError: If identifier is not a string or hmac_key is not bytes.
        ValueError: If identifier is empty or hmac_key is insufficient length.
    """
    if not isinstance(identifier, str):
        raise TypeError(f"identifier must be str, got {type(identifier).__name__}")
    if not isinstance(hmac_key, (bytes, bytearray)):
        raise TypeError(f"hmac_key must be bytes, got {type(hmac_key).__name__}")
    if len(hmac_key) < 16:
        raise ValueError("HMAC key must be at least 16 bytes for security")
    if not identifier:
        raise ValueError("Identifier cannot be empty")

    # Canonicalize string representation (UTF-8)
    identifier_bytes = identifier.strip().encode("utf-8")

    # Compute HMAC-SHA256
    digest = hmac.new(hmac_key, identifier_bytes, hashlib.sha256).hexdigest()
    return digest
