"""Verifiable erasure receipt generation for Athar.

This module provides:
- Erasure receipt data model and builder
- Canonical JSON serialization of receipt payloads under RFC 8785
- Ed25519 digital signature signing and packaging
- Complete audit bundle assembly with cryptographic inclusion proofs
"""

from __future__ import annotations

from athar.receipt.builder import (
    MANDATORY_LIMITS,
    SPEC_VERSION,
    ReceiptBuilder,
    RetrievalTestResult,
)

__all__ = [
    "MANDATORY_LIMITS",
    "ReceiptBuilder",
    "RetrievalTestResult",
    "SPEC_VERSION",
]
