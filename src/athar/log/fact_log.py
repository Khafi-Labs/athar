"""Append-only fact log backed by RFC 6962 Merkle tree for Athar.

Maintains an immutable sequence of erasure facts, signs batch commitments,
and provides inclusion and consistency proofs.
NO personal data is stored in this log structure.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from athar.crypto.canonical_json import canonical_json
from athar.crypto.merkle import MerkleTree
from athar.crypto.signing import SigningKeyPair


def compute_subject_commitment(pseudonym: str, salt: bytes | str) -> str:
    """Compute HMAC-SHA256 salted subject commitment.

    Never hashes raw personal data. Operates exclusively on random pseudonyms.

    Args:
        pseudonym: Opaque pseudonym string representing the subject.
        salt: Per-fact random salt (bytes or hex string).

    Returns:
        Hex-encoded HMAC-SHA256 digest string.
    """
    salt_bytes = bytes.fromhex(salt) if isinstance(salt, str) else salt
    return hmac.new(salt_bytes, pseudonym.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Fact:
    """Immutable audit fact recording an erasure or lifecycle event.

    Attributes:
        fact_id: Unique UUID string for this fact.
        subject_commitment: Salted HMAC commitment of subject pseudonym.
        purpose: Business or statutory processing purpose.
        scope_hash: SHA-256 hex digest of scope description.
        policy_hash: Cryptographic hash of policy rules governing this erasure.
        timestamp: Time when erasure event occurred.
        nonce: Random 32-byte hex-encoded nonce for replay resistance.
        surfaces_purged: Count of storage surfaces successfully erased.
        retrieval_test_outcome: Verification result (e.g. 'PASSED', 'FAILED').
        event_type: One of 'erasure', 'incident', 'hold_placed', 'hold_released'.
    """

    fact_id: str
    subject_commitment: str
    purpose: str
    scope_hash: str
    policy_hash: str
    timestamp: datetime
    nonce: str
    surfaces_purged: int
    retrieval_test_outcome: str
    event_type: str = "erasure"

    def __post_init__(self) -> None:
        """Validate event_type."""
        valid_events = {"erasure", "incident", "hold_placed", "hold_released"}
        if self.event_type not in valid_events:
            raise ValueError(
                f"Invalid event_type '{self.event_type}'. Must be one of {valid_events}"
            )

    @classmethod
    def create(
        cls,
        subject_pseudonym: str,
        purpose: str,
        scope_description: str,
        policy_hash: str,
        surfaces_purged: int,
        retrieval_test_outcome: str = "PASSED",
        event_type: str = "erasure",
        salt: bytes | None = None,
        fact_id: str | None = None,
        timestamp: datetime | None = None,
        nonce: str | None = None,
    ) -> Fact:
        """Factory helper creating a Fact with cryptographic salt and nonce.

        Args:
            subject_pseudonym: Random pseudonym identifying the subject.
            purpose: Processing purpose.
            scope_description: Textual description of erasure scope.
            policy_hash: Hex hash of governing retention policy.
            surfaces_purged: Total storage surfaces wiped.
            retrieval_test_outcome: Retrieval test status.
            event_type: Event category.
            salt: Optional per-fact salt (generates 32 random bytes if omitted).
            fact_id: Optional UUID string.
            timestamp: Optional datetime; defaults to UTC now.
            nonce: Optional 32-byte hex nonce; generated if omitted.

        Returns:
            New Fact instance.
        """
        salt_bytes = salt or os.urandom(32)
        commitment = compute_subject_commitment(subject_pseudonym, salt_bytes)
        scope_h = hashlib.sha256(scope_description.encode("utf-8")).hexdigest()
        fact_ts = timestamp or datetime.now(UTC)
        fact_nonce = nonce or os.urandom(32).hex()

        return cls(
            fact_id=fact_id or str(uuid.uuid4()),
            subject_commitment=commitment,
            purpose=purpose,
            scope_hash=scope_h,
            policy_hash=policy_hash,
            timestamp=fact_ts,
            nonce=fact_nonce,
            surfaces_purged=surfaces_purged,
            retrieval_test_outcome=retrieval_test_outcome,
            event_type=event_type,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert Fact to a dictionary with deterministic string representations."""
        return {
            "event_type": self.event_type,
            "fact_id": self.fact_id,
            "nonce": self.nonce,
            "policy_hash": self.policy_hash,
            "purpose": self.purpose,
            "retrieval_test_outcome": self.retrieval_test_outcome,
            "scope_hash": self.scope_hash,
            "subject_commitment": self.subject_commitment,
            "surfaces_purged": self.surfaces_purged,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_canonical_json(self) -> bytes:
        """Serialize Fact to RFC 8785 canonical JSON bytes."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Fact:
        """Instantiate Fact from dictionary."""
        ts_raw = data["timestamp"]
        if isinstance(ts_raw, datetime):
            ts = ts_raw
        else:
            ts = datetime.fromisoformat(ts_raw)

        return cls(
            fact_id=data["fact_id"],
            subject_commitment=data["subject_commitment"],
            purpose=data["purpose"],
            scope_hash=data["scope_hash"],
            policy_hash=data["policy_hash"],
            timestamp=ts,
            nonce=data["nonce"],
            surfaces_purged=int(data["surfaces_purged"]),
            retrieval_test_outcome=data["retrieval_test_outcome"],
            event_type=data.get("event_type", "erasure"),
        )


@dataclass
class BatchRecord:
    """Signed root attestation over a batch of logged erasure facts.

    Attributes:
        batch_id: Unique UUID string for this batch attestation.
        merkle_root: Hex-encoded SHA-256 root hash of the Merkle tree.
        leaf_count: Total number of facts accumulated in the tree at batch creation.
        signature: Hex-encoded Ed25519 signature over the 32-byte root hash.
        signer_key_id: Key ID of the signing key pair.
        created_at: UTC timestamp when the batch was signed.
        anchor_token: Optional external timestamp anchor token (RFC 3161 or OpenTimestamps).
    """

    batch_id: str
    merkle_root: str
    leaf_count: int
    signature: str
    signer_key_id: str
    created_at: datetime
    anchor_token: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert BatchRecord to dictionary."""
        return {
            "anchor_token": self.anchor_token,
            "batch_id": self.batch_id,
            "created_at": self.created_at.isoformat(),
            "leaf_count": self.leaf_count,
            "merkle_root": self.merkle_root,
            "signature": self.signature,
            "signer_key_id": self.signer_key_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BatchRecord:
        """Instantiate BatchRecord from dictionary."""
        created_raw = data["created_at"]
        created_at = (
            created_raw
            if isinstance(created_raw, datetime)
            else datetime.fromisoformat(created_raw)
        )
        return cls(
            batch_id=data["batch_id"],
            merkle_root=data["merkle_root"],
            leaf_count=int(data["leaf_count"]),
            signature=data["signature"],
            signer_key_id=data["signer_key_id"],
            created_at=created_at,
            anchor_token=data.get("anchor_token"),
        )


class FactLog:
    """Append-only fact log backed by an RFC 6962 Merkle tree."""

    def __init__(self, merkle_tree: MerkleTree, signing_key: SigningKeyPair) -> None:
        """Initialize FactLog with Merkle tree and signing key pair.

        Args:
            merkle_tree: Underlying Merkle tree instance.
            signing_key: Ed25519 signing key pair for batch signatures.
        """
        self._tree = merkle_tree
        self._signing_key = signing_key
        self._facts: list[Fact] = []
        self._batches: list[BatchRecord] = []

    def append_fact(self, fact: Fact) -> int:
        """Serialize fact to RFC 8785 canonical JSON, append to tree, and return leaf index.

        Args:
            fact: Fact instance to append.

        Returns:
            0-based leaf index in the Merkle tree.
        """
        fact_bytes = fact.to_canonical_json()
        leaf_index = self._tree.append(fact_bytes)
        self._facts.append(fact)
        return leaf_index

    def get_fact(self, leaf_index: int) -> Fact:
        """Retrieve fact at the specified leaf index.

        Args:
            leaf_index: 0-based leaf index.

        Returns:
            Fact instance.

        Raises:
            IndexError: If leaf_index is out of range.
        """
        if not (0 <= leaf_index < len(self._facts)):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(self._facts)})")
        return self._facts[leaf_index]

    def get_root(self) -> bytes:
        """Retrieve current 32-byte Merkle tree root hash.

        Returns:
            32-byte root hash.
        """
        return self._tree.get_root()

    def get_inclusion_proof(self, leaf_index: int) -> list[bytes]:
        """Generate audit path (inclusion proof) for the given leaf index.

        Args:
            leaf_index: 0-based leaf index.

        Returns:
            List of 32-byte node hashes.
        """
        return self._tree.get_inclusion_proof(leaf_index)

    def get_consistency_proof(self, old_size: int) -> list[bytes]:
        """Generate consistency proof between old_size and current tree size.

        Args:
            old_size: Prior tree size.

        Returns:
            List of 32-byte node hashes.
        """
        return self._tree.get_consistency_proof(old_size)

    def batch_sign(self) -> BatchRecord:
        """Sign current Merkle root and produce a BatchRecord.

        Returns:
            BatchRecord containing signature, root, and leaf count.
        """
        root = self.get_root()
        sig = self._signing_key.sign(root)
        record = BatchRecord(
            batch_id=str(uuid.uuid4()),
            merkle_root=root.hex(),
            leaf_count=self.fact_count,
            signature=sig.hex(),
            signer_key_id=self._signing_key.key_id,
            created_at=datetime.now(UTC),
            anchor_token=None,
        )
        self._batches.append(record)
        return record

    @property
    def fact_count(self) -> int:
        """Current number of facts in the log."""
        return len(self._facts)

    @property
    def tree(self) -> MerkleTree:
        """Underlying MerkleTree instance."""
        return self._tree

    @property
    def signing_key(self) -> SigningKeyPair:
        """Signing key pair used for batches."""
        return self._signing_key

    @property
    def batches(self) -> list[BatchRecord]:
        """List of all signed batch records."""
        return list(self._batches)
