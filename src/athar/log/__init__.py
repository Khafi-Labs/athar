"""Verifiable fact log and anchoring adapters for Athar.

This module provides:
- Append-only fact log recording immutable erasure lifecycle events
- Periodic batching and cryptographic commitment via RFC 6962 Merkle trees
- External anchoring adapters (transparency logs, block headers, timestamping services)
- Merkle inclusion proof generation for individual log entries
"""

from __future__ import annotations

from athar.log.anchoring import (
    AnchorAdapter,
    AnchorToken,
    AnchorType,
    AnchorVerification,
    HonestyLevel,
    RFC3161Adapter,
    SimulatedAnchor,
)
from athar.log.fact_log import (
    BatchRecord,
    Fact,
    FactLog,
    compute_subject_commitment,
)

__all__ = [
    "AnchorAdapter",
    "AnchorToken",
    "AnchorType",
    "AnchorVerification",
    "BatchRecord",
    "Fact",
    "FactLog",
    "HonestyLevel",
    "RFC3161Adapter",
    "SimulatedAnchor",
    "compute_subject_commitment",
]
