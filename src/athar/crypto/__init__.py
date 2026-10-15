"""Cryptographic primitives and utilities for Athar."""

from athar.crypto.canonical_json import (
    canonical_hash,
    canonical_json,
    canonical_json_encode,
    canonical_json_hash,
)
from athar.crypto.merkle import (
    LEAF_PREFIX,
    NODE_PREFIX,
    MerkleTree,
    empty_tree_hash,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from athar.crypto.signing import (
    SigningKeyPair,
    SigningPublicKey,
    verify_signature,
)

__all__ = [
    "LEAF_PREFIX",
    "NODE_PREFIX",
    "MerkleTree",
    "SigningKeyPair",
    "SigningPublicKey",
    "canonical_hash",
    "canonical_json",
    "canonical_json_encode",
    "canonical_json_hash",
    "empty_tree_hash",
    "leaf_hash",
    "node_hash",
    "verify_consistency",
    "verify_inclusion",
    "verify_signature",
]
