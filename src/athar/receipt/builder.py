"""Receipt builder for Athar verifiable erasure receipts v0.1.

Assembles a complete receipt from an erasure fact, Merkle inclusion proof,
batch record, anchor token, and retrieval test results. The signature
covers the canonical JSON of all fields EXCEPT the signatures array.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from athar.crypto.canonical_json import canonical_json
from athar.crypto.signing import SigningKeyPair
from athar.log.anchoring import AnchorToken
from athar.log.fact_log import BatchRecord, Fact

SPEC_VERSION = "athar-receipt/0.1"

# Mandatory limit disclosures that every receipt must include
MANDATORY_LIMITS = [
    "Does not prove absence of copies outside the manifest.",
    "Key destruction is SIMULATED in this MVP.",
    "Self-run retrieval test does not raise assurance level.",
    "Timestamp anchor honesty depends on the external TSA.",
    "Detection time is the company's claim unless independently verified.",
]


@dataclass(frozen=True)
class RetrievalTestResult:
    """Result of a self-run retrieval test.

    Attributes:
        date: ISO 8601 date when the test was run.
        surfaces_tested: Number of storage surfaces tested.
        outcome: 'not_recoverable', 'partially_recoverable', or 'recoverable'.
        details: Optional human-readable details.
    """

    date: str
    surfaces_tested: int
    outcome: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "date": self.date,
            "surfaces": self.surfaces_tested,
            "outcome": self.outcome,
        }
        if self.details:
            d["details"] = self.details
        return d


class ReceiptBuilder:
    """Builds verifiable erasure receipts following the Athar v0.1 spec.

    A receipt binds together:
    - The erasure fact (subject commitment, purpose, policy hash)
    - The Merkle tree inclusion proof
    - The external timestamp anchor
    - The retrieval test result
    - Mandatory limit disclosures

    The Ed25519 signature covers the canonical JSON of all fields
    EXCEPT the signatures array itself.
    """

    @staticmethod
    def build(
        fact: Fact,
        leaf_index: int,
        inclusion_proof: list[bytes],
        batch: BatchRecord,
        anchor_token: AnchorToken,
        retrieval_test: RetrievalTestResult,
        signing_key: SigningKeyPair,
        assurance_level: int = 2,
        extra_limits: list[str] | None = None,
        jurisdiction: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build and sign a complete receipt.

        Args:
            fact: The erasure fact being receipted.
            leaf_index: 0-based Merkle tree leaf index for this fact.
            inclusion_proof: Audit path hashes for inclusion proof.
            batch: The batch record containing the signed Merkle root.
            anchor_token: External timestamp anchor for the batch root.
            retrieval_test: Result of the self-run retrieval test.
            signing_key: Ed25519 key pair for signing the receipt.
            assurance_level: 1-4 per the assurance level definitions.
            extra_limits: Additional limit disclosures beyond mandatory ones.
            jurisdiction: Optional signed block describing the legal context, e.g.
                {"code": "EG", "regime": "CBE_BANK", "legal_review": "NOT_REVIEWED",
                 "anchor_location": "UNSPECIFIED"}. Included in the signed payload.

        Returns:
            Complete receipt dictionary with signature.
        """
        # Assemble the limits array
        limits = list(MANDATORY_LIMITS)
        if extra_limits:
            limits.extend(extra_limits)

        # Build the receipt body (everything except signatures)
        receipt: dict[str, Any] = {
            "spec": SPEC_VERSION,
            "subject_commitment": fact.subject_commitment,
            "purpose": fact.purpose,
            "period": batch.batch_id.split("-")[0] if "-" in batch.batch_id else "unknown",
            "scope_hash": f"sha256:{fact.scope_hash}",
            "policy_hash": f"sha256:{fact.policy_hash}",
            "assurance_level": assurance_level,
            "key_destruction": "SIMULATED",
            "fact": {
                "fact_id": fact.fact_id,
                "ts": fact.timestamp.isoformat()
                if isinstance(fact.timestamp, datetime)
                else fact.timestamp,
                "nonce": fact.nonce,
                "surfaces_purged": fact.surfaces_purged,
                "retrieval_test_outcome": fact.retrieval_test_outcome,
                "event_type": fact.event_type,
            },
            "inclusion_proof": {
                "batch_id": batch.batch_id,
                "leaf_index": leaf_index,
                "tree_size": batch.leaf_count,
                "path": [h.hex() for h in inclusion_proof],
            },
            "merkle_root": f"sha256:{batch.merkle_root}",
            "timestamp_token": anchor_token.to_dict(),
            "retrieval_test": retrieval_test.to_dict(),
            "limits": limits,
        }
        if jurisdiction:
            receipt["jurisdiction"] = dict(jurisdiction)

        # Sign the receipt
        return ReceiptBuilder.sign_receipt(receipt, signing_key)

    @staticmethod
    def sign_receipt(
        receipt: dict[str, Any],
        signing_key: SigningKeyPair,
    ) -> dict[str, Any]:
        """Add an Ed25519 signature to a receipt.

        The signature covers the canonical JSON of all fields EXCEPT
        the 'signatures' array. Multiple signatures can be added by
        calling this method repeatedly with different keys.

        Args:
            receipt: Receipt dict (may or may not already have signatures).
            signing_key: Ed25519 key pair for signing.

        Returns:
            Receipt dict with the new signature appended.
        """
        # Remove existing signatures for canonical form
        signable = {k: v for k, v in receipt.items() if k != "signatures"}
        message = canonical_json(signable)

        signature = signing_key.sign(message)

        sig_entry = {
            "alg": "Ed25519",
            "kid": signing_key.key_id,
            "pub": signing_key.public_key_hex,
            "sig": signature.hex(),
        }

        result = dict(receipt)
        existing = result.get("signatures", [])
        result["signatures"] = existing + [sig_entry]
        return result

    @staticmethod
    def extract_signable_bytes(receipt: dict[str, Any]) -> bytes:
        """Extract the canonical JSON bytes that signatures cover.

        Args:
            receipt: Full receipt dict.

        Returns:
            Canonical JSON bytes of receipt without 'signatures'.
        """
        signable = {k: v for k, v in receipt.items() if k != "signatures"}
        return canonical_json(signable)
