"""RFC 6962 compliant Merkle Tree implementation for Athar.

Uses SHA-256 with standard domain separation:
- Leaf hash prefix: 0x00 (RFC 6962 Section 2.1)
- Node hash prefix: 0x01 (RFC 6962 Section 2.1)

Provides:
- Append-only Merkle tree construction
- Root calculation
- Inclusion proof generation and verification (RFC 6962 Section 2.1.1)
- Consistency proof generation and verification (RFC 6962 Section 2.1.2)
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """Compute leaf hash according to RFC 6962: SHA-256(0x00 || data).

    Args:
        data: Raw leaf data.

    Returns:
        32-byte SHA-256 leaf hash.
    """
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute internal node hash according to RFC 6962: SHA-256(0x01 || left || right).

    Args:
        left: 32-byte left child hash.
        right: 32-byte right child hash.

    Returns:
        32-byte SHA-256 node hash.
    """
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_tree_hash() -> bytes:
    """Compute hash of an empty tree: SHA-256("")."""
    return hashlib.sha256(b"").digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Find the largest power of 2 strictly less than n (for n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


class MerkleTree:
    """Append-only Merkle Tree following RFC 6962."""

    def __init__(self, leaves: Sequence[bytes] | None = None) -> None:
        """Initialize tree with optional initial leaves.

        Args:
            leaves: Optional list of raw leaf byte strings.
        """
        self._leaves: list[bytes] = list(leaves) if leaves else []

    @property
    def leaf_count(self) -> int:
        """Total number of leaves in the tree."""
        return len(self._leaves)

    @property
    def leaves(self) -> list[bytes]:
        """List of raw leaf byte strings."""
        return list(self._leaves)

    def append(self, leaf_data: bytes) -> int:
        """Append a new leaf to the tree.

        Args:
            leaf_data: Raw bytes of the leaf to add.

        Returns:
            The 0-based index of the newly added leaf.
        """
        index = len(self._leaves)
        self._leaves.append(leaf_data)
        return index

    def get_leaf(self, index: int) -> bytes:
        """Get the raw leaf data at the specified index.

        Args:
            index: 0-based leaf index.

        Returns:
            Raw leaf bytes.
        """
        return self._leaves[index]

    def get_root(self) -> bytes:
        """Calculate the current root hash of the tree.

        Returns:
            32-byte root hash.
        """
        return self._mth(self._leaves)

    root = get_root

    @classmethod
    def _mth(cls, leaves_slice: Sequence[bytes]) -> bytes:
        """Calculate Merkle Tree Hash (MTH) for a slice of leaves per RFC 6962 Section 2.1."""
        n = len(leaves_slice)
        if n == 0:
            return empty_tree_hash()
        if n == 1:
            return leaf_hash(leaves_slice[0])
        k = _largest_power_of_two_less_than(n)
        left = cls._mth(leaves_slice[:k])
        right = cls._mth(leaves_slice[k:])
        return node_hash(left, right)

    def get_inclusion_proof(self, leaf_index: int) -> list[bytes]:
        """Generate an audit path (inclusion proof) for a leaf per RFC 6962 Section 2.1.1.

        Args:
            leaf_index: 0-based index of the leaf.

        Returns:
            List of 32-byte node hashes forming the audit path.

        Raises:
            IndexError: If leaf_index is out of range.
        """
        n = len(self._leaves)
        if not (0 <= leaf_index < n):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {n})")
        return self._path(leaf_index, self._leaves)

    @classmethod
    def _path(cls, m: int, leaves_slice: Sequence[bytes]) -> list[bytes]:
        """Compute RFC 6962 PATH(m, D)."""
        n = len(leaves_slice)
        if n <= 1:
            return []
        k = _largest_power_of_two_less_than(n)
        if m < k:
            return cls._path(m, leaves_slice[:k]) + [cls._mth(leaves_slice[k:])]
        else:
            return cls._path(m - k, leaves_slice[k:]) + [cls._mth(leaves_slice[:k])]

    def get_consistency_proof(self, old_size: int) -> list[bytes]:
        """Generate a consistency proof between old_size and current tree size per RFC 6962 Section 2.1.2.

        Args:
            old_size: Number of leaves in the prior tree.

        Returns:
            List of 32-byte node hashes proving consistency.

        Raises:
            ValueError: If old_size is invalid (negative or greater than current size).
        """
        n = len(self._leaves)
        if not (0 <= old_size <= n):
            raise ValueError(f"Invalid old_size {old_size}; current size is {n}")
        if old_size == 0 or old_size == n:
            return []
        return self._subproof(old_size, self._leaves, True)

    @classmethod
    def _subproof(cls, m: int, leaves_slice: Sequence[bytes], b: bool) -> list[bytes]:
        """Compute RFC 6962 SUBPROOF(m, D, b)."""
        n = len(leaves_slice)
        if m == n:
            if not b:
                return [cls._mth(leaves_slice)]
            return []
        k = _largest_power_of_two_less_than(n)
        if m <= k:
            return cls._subproof(m, leaves_slice[:k], b) + [cls._mth(leaves_slice[k:])]
        else:
            return cls._subproof(m - k, leaves_slice[k:], False) + [cls._mth(leaves_slice[:k])]

    @classmethod
    def verify_inclusion(
        cls,
        leaf_data: bytes,
        leaf_index: int,
        tree_size: int,
        proof: Sequence[bytes],
        expected_root: bytes,
    ) -> bool:
        """Verify an RFC 6962 inclusion proof.

        Args:
            leaf_data: Raw leaf data.
            leaf_index: 0-based leaf index.
            tree_size: Total leaves in tree when proof was generated.
            proof: Audit path hashes.
            expected_root: Root hash against which to verify.

        Returns:
            True if leaf is proven to be included, False otherwise.
        """
        if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
            return False

        lh = leaf_hash(leaf_data)
        computed_root = cls._reconstruct_inclusion_root(lh, leaf_index, tree_size, list(proof))
        return computed_root == expected_root

    @classmethod
    def _reconstruct_inclusion_root(
        cls,
        lh: bytes,
        m: int,
        n: int,
        proof: list[bytes],
    ) -> bytes | None:
        """Reconstruct root top-down from leaf hash and proof path."""
        if n == 1:
            if len(proof) != 0:
                return None
            return lh

        if not proof:
            return None

        k = _largest_power_of_two_less_than(n)
        sibling = proof[-1]
        remaining = proof[:-1]

        if m < k:
            left = cls._reconstruct_inclusion_root(lh, m, k, remaining)
            if left is None:
                return None
            return node_hash(left, sibling)
        else:
            right = cls._reconstruct_inclusion_root(lh, m - k, n - k, remaining)
            if right is None:
                return None
            return node_hash(sibling, right)

    @classmethod
    def verify_consistency(
        cls,
        old_size: int,
        new_size: int,
        old_root: bytes,
        new_root: bytes,
        proof: Sequence[bytes],
    ) -> bool:
        """Verify an RFC 6962 consistency proof between two tree sizes.

        Follows RFC 6962 Section 2.1.2 algorithm.

        Args:
            old_size: Number of leaves in older tree.
            new_size: Number of leaves in newer tree.
            old_root: Root hash of older tree.
            new_root: Root hash of newer tree.
            proof: Consistency proof hashes.

        Returns:
            True if the tree is consistent across sizes, False otherwise.
        """
        if old_size == new_size:
            return len(proof) == 0 and old_root == new_root
        if not (0 < old_size < new_size):
            return False
        if not proof:
            return False

        p = list(proof)
        fn = old_size - 1
        sn = new_size - 1

        while fn & 1:
            fn >>= 1
            sn >>= 1

        if fn != 0:
            if not p:
                return False
            fr = p[0]
            sr = p[0]
            c = p[1:]
        else:
            fr = old_root
            sr = old_root
            c = p

        for c_val in c:
            if sn == 0:
                return False
            if (fn & 1) or (fn == sn):
                fr = node_hash(c_val, fr)
                sr = node_hash(c_val, sr)
                while (fn & 1 == 0) and (fn != 0):
                    fn >>= 1
                    sn >>= 1
            else:
                sr = node_hash(sr, c_val)
            fn >>= 1
            sn >>= 1

        return fr == old_root and sr == new_root and sn == 0


def verify_inclusion(
    leaf_data: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    expected_root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof.

    Args:
        leaf_data: Raw leaf data.
        leaf_index: 0-based leaf index.
        tree_size: Total leaves in tree when proof was generated.
        proof: Audit path hashes.
        expected_root: Root hash against which to verify.

    Returns:
        True if leaf is proven to be included, False otherwise.
    """
    return MerkleTree.verify_inclusion(leaf_data, leaf_index, tree_size, proof, expected_root)


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """Verify an RFC 6962 consistency proof between two tree sizes.

    Args:
        old_size: Number of leaves in older tree.
        new_size: Number of leaves in newer tree.
        old_root: Root hash of older tree.
        new_root: Root hash of newer tree.
        proof: Consistency proof hashes.

    Returns:
        True if the tree is consistent across sizes, False otherwise.
    """
    return MerkleTree.verify_consistency(old_size, new_size, old_root, new_root, proof)
