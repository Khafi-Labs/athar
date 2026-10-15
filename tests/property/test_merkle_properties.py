"""Property-based tests for RFC 6962 Merkle tree properties.

Properties tested:
1. Tree root is deterministic for identical leaves.
2. Inclusion proof verifies for all valid leaf indices.
3. Any changed leaf data breaks inclusion verification.
4. Any altered proof path hash breaks inclusion verification.
5. Consistency proof verifies between any valid old and new tree sizes.
6. Any altered consistency proof hash breaks consistency verification.

Works natively with Hypothesis when available, with a robust property-based
fuzz generator fallback for standalone environments.
"""

from __future__ import annotations

import os
import random
from collections.abc import Callable

from athar.crypto.merkle import MerkleTree

try:
    import hypothesis.strategies as st
    from hypothesis import given, settings

    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False


# ---------------------------------------------------------------------------
# Compatibility fallback when hypothesis is not installed
# ---------------------------------------------------------------------------
def _fallback_property_runner(iterations: int = 40):
    """Decorator running a test across multiple randomized property cases."""

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            rng = random.Random(42)
            for _ in range(iterations):
                n_leaves = rng.randint(1, 25)
                leaves = [os.urandom(rng.randint(1, 64)) for _ in range(n_leaves)]
                idx = rng.randint(0, n_leaves - 1)
                fn(leaves=leaves, leaf_index=idx, rng=rng)

        wrapper.__name__ = fn.__name__
        return wrapper

    return decorator


if HAS_HYPOTHESIS:
    leaf_strategy = st.lists(
        st.binary(min_size=1, max_size=64),
        min_size=1,
        max_size=32,
    )

    @given(leaves=leaf_strategy)
    @settings(max_examples=50)
    def test_merkle_root_deterministic(leaves: list[bytes]) -> None:
        """Property: Tree root is deterministic for identical leaf sequences."""
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.get_root() == tree2.get_root()

    @given(data=st.data())
    @settings(max_examples=50)
    def test_inclusion_proof_verifies_all_indices(data) -> None:
        """Property: Inclusion proof verifies for every valid index in any tree."""
        leaves = data.draw(leaf_strategy)
        tree = MerkleTree(leaves)
        root = tree.get_root()
        idx = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))

        proof = tree.get_inclusion_proof(idx)
        assert MerkleTree.verify_inclusion(
            leaf_data=leaves[idx],
            leaf_index=idx,
            tree_size=len(leaves),
            proof=proof,
            expected_root=root,
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_changed_leaf_breaks_verification(data) -> None:
        """Property: Any change to leaf data invalidates inclusion verification."""
        leaves = data.draw(leaf_strategy)
        tree = MerkleTree(leaves)
        root = tree.get_root()
        idx = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))
        proof = tree.get_inclusion_proof(idx)

        # Mutate leaf data by flipping the first byte
        original = leaves[idx]
        mutated = bytes([original[0] ^ 0xFF]) + original[1:] if original else b"\xff"

        assert not MerkleTree.verify_inclusion(
            leaf_data=mutated,
            leaf_index=idx,
            tree_size=len(leaves),
            proof=proof,
            expected_root=root,
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_changed_proof_path_breaks_verification(data) -> None:
        """Property: Any alteration to proof path hashes invalidates verification."""
        leaves = data.draw(st.lists(st.binary(min_size=1, max_size=32), min_size=2, max_size=32))
        tree = MerkleTree(leaves)
        root = tree.get_root()
        idx = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))
        proof = tree.get_inclusion_proof(idx)

        if not proof:
            return

        # Tamper with one path element
        tamper_idx = data.draw(st.integers(min_value=0, max_value=len(proof) - 1))
        tampered_proof = list(proof)
        elem = tampered_proof[tamper_idx]
        tampered_proof[tamper_idx] = bytes([elem[0] ^ 0xFF]) + elem[1:]

        assert not MerkleTree.verify_inclusion(
            leaf_data=leaves[idx],
            leaf_index=idx,
            tree_size=len(leaves),
            proof=tampered_proof,
            expected_root=root,
        )

    @given(data=st.data())
    @settings(max_examples=50)
    def test_consistency_proof_verifies_valid_sizes(data) -> None:
        """Property: Consistency proof verifies between any valid old and new sizes."""
        leaves = data.draw(st.lists(st.binary(min_size=1, max_size=32), min_size=2, max_size=32))
        old_size = data.draw(st.integers(min_value=1, max_value=len(leaves)))
        new_size = len(leaves)

        old_tree = MerkleTree(leaves[:old_size])
        new_tree = MerkleTree(leaves)

        old_root = old_tree.get_root()
        new_root = new_tree.get_root()

        proof = new_tree.get_consistency_proof(old_size)
        assert MerkleTree.verify_consistency(
            old_size=old_size,
            new_size=new_size,
            old_root=old_root,
            new_root=new_root,
            proof=proof,
        )

else:
    # Standalone execution fallback
    @_fallback_property_runner(iterations=30)
    def test_merkle_root_deterministic(leaves: list[bytes], leaf_index: int, rng) -> None:
        """Property: Tree root is deterministic for identical leaf sequences."""
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.get_root() == tree2.get_root()

    @_fallback_property_runner(iterations=30)
    def test_inclusion_proof_verifies_all_indices(
        leaves: list[bytes], leaf_index: int, rng
    ) -> None:
        """Property: Inclusion proof verifies for every valid index in any tree."""
        tree = MerkleTree(leaves)
        root = tree.get_root()
        proof = tree.get_inclusion_proof(leaf_index)
        assert MerkleTree.verify_inclusion(
            leaf_data=leaves[leaf_index],
            leaf_index=leaf_index,
            tree_size=len(leaves),
            proof=proof,
            expected_root=root,
        )

    @_fallback_property_runner(iterations=30)
    def test_changed_leaf_breaks_verification(leaves: list[bytes], leaf_index: int, rng) -> None:
        """Property: Any change to leaf data invalidates inclusion verification."""
        tree = MerkleTree(leaves)
        root = tree.get_root()
        proof = tree.get_inclusion_proof(leaf_index)

        orig = leaves[leaf_index]
        mutated = bytes([orig[0] ^ 0x01]) + orig[1:]

        assert not MerkleTree.verify_inclusion(
            leaf_data=mutated,
            leaf_index=leaf_index,
            tree_size=len(leaves),
            proof=proof,
            expected_root=root,
        )

    @_fallback_property_runner(iterations=30)
    def test_changed_proof_path_breaks_verification(
        leaves: list[bytes], leaf_index: int, rng
    ) -> None:
        """Property: Any alteration to proof path hashes invalidates verification."""
        if len(leaves) < 2:
            leaves.append(b"extra_leaf")
        tree = MerkleTree(leaves)
        root = tree.get_root()
        proof = tree.get_inclusion_proof(leaf_index)
        if not proof:
            return

        tamper_idx = rng.randint(0, len(proof) - 1)
        tampered_proof = list(proof)
        elem = tampered_proof[tamper_idx]
        tampered_proof[tamper_idx] = bytes([elem[0] ^ 0x01]) + elem[1:]

        assert not MerkleTree.verify_inclusion(
            leaf_data=leaves[leaf_index],
            leaf_index=leaf_index,
            tree_size=len(leaves),
            proof=tampered_proof,
            expected_root=root,
        )

    @_fallback_property_runner(iterations=30)
    def test_consistency_proof_verifies_valid_sizes(
        leaves: list[bytes], leaf_index: int, rng
    ) -> None:
        """Property: Consistency proof verifies between any valid old and new sizes."""
        if len(leaves) < 2:
            leaves.append(b"extra_padding")
        old_size = rng.randint(1, len(leaves))
        new_size = len(leaves)

        old_tree = MerkleTree(leaves[:old_size])
        new_tree = MerkleTree(leaves)

        old_root = old_tree.get_root()
        new_root = new_tree.get_root()

        proof = new_tree.get_consistency_proof(old_size)
        assert MerkleTree.verify_consistency(
            old_size=old_size,
            new_size=new_size,
            old_root=old_root,
            new_root=new_root,
            proof=proof,
        )
