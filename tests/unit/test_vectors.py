"""Test vector verification for Athar cryptographic primitives.

Loads JSON test vectors from the vectors/ directory and verifies them
against the production implementations. These vectors are the source
of truth per the project's design decisions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "vectors"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_vectors(filename: str) -> list | dict:
    path = VECTORS_DIR / filename
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 1. Canonical JSON vectors
# ---------------------------------------------------------------------------

_canonical_vectors = load_vectors("canonical_json.json")


@pytest.mark.parametrize(
    "case",
    _canonical_vectors,
    ids=[c["description"] for c in _canonical_vectors],
)
def test_canonical_json_vector(case: dict) -> None:
    """Verify canonical JSON serialization matches expected output."""
    from athar.crypto.canonical_json import canonical_json

    result = canonical_json(case["input"])
    expected_canonical = case["expected_canonical"].encode("utf-8")
    assert result == expected_canonical, (
        f"Canonical mismatch for '{case['description']}':\n"
        f"  expected: {expected_canonical!r}\n"
        f"  got:      {result!r}"
    )


@pytest.mark.parametrize(
    "case",
    _canonical_vectors,
    ids=[c["description"] for c in _canonical_vectors],
)
def test_canonical_json_hash_vector(case: dict) -> None:
    """Verify SHA-256 of canonical JSON matches expected hash."""
    from athar.crypto.canonical_json import canonical_json

    result = canonical_json(case["input"])
    computed_hash = hashlib.sha256(result).hexdigest()
    assert computed_hash == case["expected_hash_hex"], (
        f"Hash mismatch for '{case['description']}':\n"
        f"  expected: {case['expected_hash_hex']}\n"
        f"  got:      {computed_hash}"
    )


# ---------------------------------------------------------------------------
# 2. Merkle tree vectors
# ---------------------------------------------------------------------------

_merkle_vectors = load_vectors("merkle_tree.json")


@pytest.mark.parametrize(
    "tree_case",
    _merkle_vectors,
    ids=[t["description"] for t in _merkle_vectors],
)
def test_merkle_root_vector(tree_case: dict) -> None:
    """Verify Merkle tree root matches expected hash."""
    from athar.crypto.merkle import MerkleTree

    leaves = [bytes.fromhex(h) for h in tree_case["leaves_hex"]]
    tree = MerkleTree(leaves)
    expected = bytes.fromhex(tree_case["expected_root_hex"])
    assert tree.get_root() == expected, f"Root mismatch for {tree_case['description']}"


@pytest.mark.parametrize(
    "tree_case",
    _merkle_vectors,
    ids=[t["description"] for t in _merkle_vectors],
)
def test_merkle_inclusion_proof_vectors(tree_case: dict) -> None:
    """Verify inclusion proofs match expected paths and verify correctly."""
    from athar.crypto.merkle import MerkleTree

    leaves = [bytes.fromhex(h) for h in tree_case["leaves_hex"]]
    tree = MerkleTree(leaves)
    root = tree.get_root()

    for proof_case in tree_case["inclusion_proofs"]:
        idx = proof_case["leaf_index"]
        size = proof_case["tree_size"]
        expected_path = [bytes.fromhex(h) for h in proof_case["path_hex"]]

        actual_path = tree.get_inclusion_proof(idx)
        assert actual_path == expected_path, (
            f"Inclusion proof mismatch for leaf {idx} in tree of size {size}"
        )

        # Verify the proof
        assert MerkleTree.verify_inclusion(leaves[idx], idx, size, actual_path, root), (
            f"Inclusion proof verification failed for leaf {idx}"
        )


@pytest.mark.parametrize(
    "tree_case",
    _merkle_vectors,
    ids=[t["description"] for t in _merkle_vectors],
)
def test_merkle_consistency_proof_vectors(tree_case: dict) -> None:
    """Verify consistency proofs match expected paths and verify correctly."""
    from athar.crypto.merkle import MerkleTree

    leaves = [bytes.fromhex(h) for h in tree_case["leaves_hex"]]
    tree = MerkleTree(leaves)

    for proof_case in tree_case["consistency_proofs"]:
        old_size = proof_case["old_size"]
        new_size = proof_case["new_size"]
        old_root = bytes.fromhex(proof_case["old_root_hex"])
        new_root = bytes.fromhex(proof_case["new_root_hex"])
        expected_path = [bytes.fromhex(h) for h in proof_case["path_hex"]]

        actual_path = tree.get_consistency_proof(old_size)
        assert actual_path == expected_path, (
            f"Consistency proof mismatch for {old_size} -> {new_size}"
        )

        # Verify the proof
        assert MerkleTree.verify_consistency(
            old_size, new_size, old_root, new_root, actual_path
        ), f"Consistency proof verification failed for {old_size} -> {new_size}"


# ---------------------------------------------------------------------------
# 3. Ed25519 signature vectors
# ---------------------------------------------------------------------------

_ed25519_vectors = load_vectors("ed25519_signatures.json")


@pytest.mark.parametrize(
    "case",
    _ed25519_vectors,
    ids=[c["description"] for c in _ed25519_vectors],
)
def test_ed25519_key_id_vector(case: dict) -> None:
    """Verify key ID computation (first 8 bytes of SHA-256 of public key, hex)."""
    pub_bytes = bytes.fromhex(case["public_key_hex"])
    expected_kid = case["key_id"]
    computed_kid = hashlib.sha256(pub_bytes).hexdigest()[:16]
    assert computed_kid == expected_kid, (
        f"Key ID mismatch: expected {expected_kid}, got {computed_kid}"
    )


@pytest.mark.parametrize(
    "case",
    _ed25519_vectors,
    ids=[c["description"] for c in _ed25519_vectors],
)
def test_ed25519_signature_verification_vector(case: dict) -> None:
    """Verify Ed25519 signatures by reconstructing from seed and verifying."""
    from athar.crypto.signing import SigningKeyPair

    seed = bytes.fromhex(case["seed_hex"])
    pub_bytes = bytes.fromhex(case["public_key_hex"])
    message = bytes.fromhex(case["message_hex"]) if case["message_hex"] else b""
    expected_sig = bytes.fromhex(case["signature_hex"])

    # Reconstruct key pair from seed
    key_pair = SigningKeyPair(
        key_id="test",
        private_bytes=seed,
        public_bytes=pub_bytes,
    )

    # Verify the stored signature
    assert len(expected_sig) == 64, f"Signature must be 64 bytes, got {len(expected_sig)}"
    assert key_pair.verify(message, expected_sig), (
        f"Signature verification failed for '{case['description']}'"
    )

    # Also verify a fresh sign-verify round trip
    fresh_sig = key_pair.sign(message)
    assert key_pair.verify(message, fresh_sig), "Fresh sign-verify round trip failed"


# ---------------------------------------------------------------------------
# 4. Receipt sample structure
# ---------------------------------------------------------------------------


def test_receipt_sample_has_all_required_fields() -> None:
    """Verify the sample receipt contains all required fields."""
    receipt = load_vectors("receipt_sample.json")

    required = [
        "spec",
        "subject_commitment",
        "purpose",
        "scope_hash",
        "policy_hash",
        "assurance_level",
        "key_destruction",
        "fact",
        "inclusion_proof",
        "merkle_root",
        "limits",
        "signatures",
    ]
    for field in required:
        assert field in receipt, f"Missing required field: {field}"

    # Check fact sub-fields
    assert "ts" in receipt["fact"]
    assert "nonce" in receipt["fact"]
    assert "surfaces_purged" in receipt["fact"]

    # Check inclusion proof sub-fields
    assert "batch_id" in receipt["inclusion_proof"]
    assert "leaf_index" in receipt["inclusion_proof"]
    assert "tree_size" in receipt["inclusion_proof"]
    assert "path" in receipt["inclusion_proof"]

    # Limits must be non-empty
    assert len(receipt["limits"]) > 0

    # key_destruction must say SIMULATED for level < 3
    if receipt["assurance_level"] < 3:
        assert receipt["key_destruction"] == "SIMULATED"


def test_shipped_receipt_sample_verifies() -> None:
    """The shipped sample receipt must verify against its published key."""
    import json
    import pathlib

    from verifier.verifier import ReceiptVerifier

    vec = pathlib.Path(__file__).resolve().parents[2] / "vectors"
    receipt = json.loads((vec / "receipt_sample.json").read_text(encoding="utf-8"))
    pub = bytes.fromhex((vec / "receipt_sample.pub").read_text().strip())
    result = ReceiptVerifier().verify(receipt, pub)
    assert result.valid, result.checks_failed
