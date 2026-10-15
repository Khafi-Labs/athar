"""Standalone verifier for Athar verifiable erasure receipts.

This module has NO dependency on the vault, keystore, or any internal
Athar module. It uses only:
- hashlib (stdlib)
- json (stdlib)
- cryptography (for Ed25519 verification)

An external auditor can run this on a clean machine to verify a receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Merkle primitives (duplicated here to avoid vault dependency)
# ---------------------------------------------------------------------------

LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    """SHA-256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Largest power of 2 strictly less than n, for n > 1."""
    return 1 << ((n - 1).bit_length() - 1)


def _format_es6_number(val: float | int) -> str:
    """Format float per RFC 8785 / ES6 rules without external dependencies."""
    fval = float(val)
    if fval == 0:
        return "0"
    s = str(fval)
    if "n" in s:
        raise ValueError(f"Invalid JSON number: {s}")
    sign = ""
    if s.startswith("-"):
        sign = "-"
        s = s[1:]
    exp_str = ""
    exp_val = 0
    q = s.find("e")
    if q > 0:
        exp_str = s[q:]
        if len(exp_str) > 2 and exp_str[2] == "0":
            exp_str = exp_str[:2] + exp_str[3:]
        s = s[:q]
        exp_val = int(exp_str[1:])
    first = s
    dot = ""
    last = ""
    q = s.find(".")
    if q > 0:
        dot = "."
        first = s[:q]
        last = s[q + 1 :]
    if last == "0":
        dot = ""
        last = ""
    if 0 < exp_val < 21:
        first += last
        last = ""
        dot = ""
        exp_str = ""
        q = exp_val - len(first)
        while q >= 0:
            q -= 1
            first += "0"
    elif -7 < exp_val < 0:
        last = first + last
        first = "0"
        dot = "."
        exp_str = ""
        q = exp_val
        while q < -1:
            q += 1
            last = "0" + last
    return sign + first + dot + last + exp_str


def _serialize_rfc8785(obj: Any) -> str:
    """Serialize object to string per RFC 8785."""
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return _format_es6_number(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize_rfc8785(x) for x in obj) + "]"
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys(), key=lambda k: str(k).encode("utf-16-be"))
        items = [
            json.dumps(str(k), ensure_ascii=False) + ":" + _serialize_rfc8785(obj[k])
            for k in sorted_keys
        ]
        return "{" + ",".join(items) + "}"
    if isinstance(obj, bytes):
        return json.dumps(obj.hex(), ensure_ascii=False)
    return json.dumps(str(obj), ensure_ascii=False)


def _canonical_json(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for verification."""
    return _serialize_rfc8785(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Ed25519 verification (using cryptography library)
# ---------------------------------------------------------------------------


def _verify_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Result of receipt verification.

    Attributes:
        valid: Overall result — True only if all checks pass.
        checks_passed: List of check names that passed.
        checks_failed: List of check names that failed with reasons.
        warnings: Non-fatal observations.
        assurance_level: The claimed assurance level from the receipt.
        limits: The limit disclosures from the receipt.
    """

    valid: bool = True
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    assurance_level: int = 0
    limits: list[str] = field(default_factory=list)

    def fail(self, check: str, reason: str) -> None:
        """Record a failed check."""
        self.valid = False
        self.checks_failed.append(f"{check}: {reason}")

    def passed(self, check: str) -> None:
        """Record a passed check."""
        self.checks_passed.append(check)

    def warn(self, message: str) -> None:
        """Record a warning."""
        self.warnings.append(message)


# ---------------------------------------------------------------------------
# Required receipt fields
# ---------------------------------------------------------------------------

REQUIRED_TOP_LEVEL = [
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

REQUIRED_FACT_FIELDS = ["ts", "nonce", "surfaces_purged"]

REQUIRED_INCLUSION_FIELDS = ["batch_id", "leaf_index", "tree_size", "path"]


# ---------------------------------------------------------------------------
# Receipt Verifier
# ---------------------------------------------------------------------------


class ReceiptVerifier:
    """Standalone receipt verifier with no vault or keystore dependency.

    Verification checks are performed in order:
    1. Schema: all required fields present and correctly typed
    2. Signature: Ed25519 over canonical JSON of receipt minus signatures
    3. Inclusion proof: Merkle audit path from leaf to root
    4. Timestamp: anchor token structure and digest match
    5. Anchor timing: timestamp >= fact timestamp
    6. Limits: limits array must be non-empty
    7. Assurance level: must be 1-4, SIMULATED label for level < 3
    """

    def verify(
        self,
        receipt: dict[str, Any],
        public_key: bytes | None = None,
        trust_embedded_key: bool = False,
        require_timestamp: bool = True,
    ) -> VerificationResult:
        """Verify a receipt.

        Args:
            receipt: The full receipt dictionary.
            public_key: 32-byte Ed25519 issuer public key obtained out-of-band
                       (pinned). Required unless trust_embedded_key is True.
            trust_embedded_key: If True, accept the public key embedded in the
                       receipt. This only proves the receipt is self-consistent,
                       NOT that it was issued by any particular party, so a
                       warning is always recorded.
            require_timestamp: If True (default), a receipt without a structured
                       timestamp token fails verification.

        Returns:
            VerificationResult with all check outcomes.
        """
        result = VerificationResult()

        # 1. Schema check
        self._check_schema(receipt, result)
        if not result.valid:
            return result

        result.assurance_level = receipt.get("assurance_level", 0)
        result.limits = receipt.get("limits", [])

        # 2. Signature check
        self._check_signature(receipt, public_key, result, trust_embedded_key)

        # 3. Inclusion proof check
        self._check_inclusion_proof(receipt, result)

        # 4. Timestamp token check
        self._check_timestamp(receipt, result, require_timestamp)

        # 5. Anchor timing check
        self._check_anchor_timing(receipt, result)

        # 6. Limits check
        self._check_limits(receipt, result)

        # 7. Assurance level check
        self._check_assurance_level(receipt, result)

        return result

    def _check_schema(self, receipt: dict[str, Any], result: VerificationResult) -> None:
        """Check 1: Verify all required fields are present and correctly typed."""
        for field_name in REQUIRED_TOP_LEVEL:
            if field_name not in receipt:
                result.fail("schema", f"Missing required field: {field_name}")
                return

        # Check spec version
        spec = receipt.get("spec", "")
        if not spec.startswith("athar-receipt/"):
            result.fail("schema", f"Invalid spec version format: {spec}")
            return

        # Check fact sub-fields
        fact = receipt.get("fact", {})
        if not isinstance(fact, dict):
            result.fail("schema", "Field 'fact' must be an object")
            return
        for f in REQUIRED_FACT_FIELDS:
            if f not in fact:
                result.fail("schema", f"Missing required fact field: {f}")
                return

        # Check inclusion proof sub-fields
        proof = receipt.get("inclusion_proof", {})
        if not isinstance(proof, dict):
            result.fail("schema", "Field 'inclusion_proof' must be an object")
            return
        for f in REQUIRED_INCLUSION_FIELDS:
            if f not in proof:
                result.fail("schema", f"Missing required inclusion_proof field: {f}")
                return

        # Check signatures is a non-empty array
        sigs = receipt.get("signatures", [])
        if not isinstance(sigs, list) or len(sigs) == 0:
            result.fail("schema", "Field 'signatures' must be a non-empty array")
            return

        result.passed("schema")

    def _check_signature(
        self,
        receipt: dict[str, Any],
        public_key: bytes | None,
        result: VerificationResult,
        trust_embedded_key: bool = False,
    ) -> None:
        """Check 2: Verify Ed25519 signature over canonical JSON."""
        if public_key is None:
            if not trust_embedded_key:
                result.fail(
                    "signature",
                    "No pinned issuer public key supplied. Provide the issuer's key "
                    "(obtained out-of-band) or explicitly opt in to trusting the "
                    "embedded key; otherwise anyone can forge a receipt.",
                )
                return
            result.warn(
                "Signature checked against the key embedded in the receipt: this proves "
                "self-consistency only, not the issuer's identity."
            )
        sigs = receipt.get("signatures", [])
        if not sigs:
            result.fail("signature", "No signatures found")
            return

        # Build the signable content: everything except 'signatures'
        signable = {k: v for k, v in receipt.items() if k != "signatures"}
        message = _canonical_json(signable)

        any_valid = False
        for i, sig_entry in enumerate(sigs):
            alg = sig_entry.get("alg", "")
            if alg != "Ed25519":
                result.warn(f"Signature {i}: unsupported algorithm '{alg}'")
                continue

            sig_hex = sig_entry.get("sig", "")
            try:
                sig_bytes = bytes.fromhex(sig_hex)
            except ValueError:
                result.fail("signature", f"Signature {i}: invalid hex encoding")
                return

            if len(sig_bytes) != 64:
                result.fail("signature", f"Signature {i}: expected 64 bytes, got {len(sig_bytes)}")
                return

            # Determine the public key to use
            pk = public_key
            if pk is None and trust_embedded_key:
                pub_hex = sig_entry.get("pub", "")
                if pub_hex:
                    try:
                        pk = bytes.fromhex(pub_hex)
                    except ValueError:
                        result.fail("signature", f"Signature {i}: invalid public key hex")
                        return

            if pk is None or len(pk) != 32:
                result.fail("signature", f"Signature {i}: no valid 32-byte public key available")
                return

            if _verify_ed25519(pk, message, sig_bytes):
                any_valid = True
            else:
                result.fail("signature", f"Signature {i}: Ed25519 verification failed")
                return

        if any_valid:
            result.passed("signature")
        else:
            result.fail("signature", "No valid signatures found")

    def _check_inclusion_proof(self, receipt: dict[str, Any], result: VerificationResult) -> None:
        """Check 3: Verify Merkle inclusion proof from leaf to root."""
        proof_section = receipt.get("inclusion_proof", {})
        leaf_index = proof_section.get("leaf_index", -1)
        tree_size = proof_section.get("tree_size", 0)
        path_hex = proof_section.get("path", [])

        merkle_root_str = receipt.get("merkle_root", "")
        if merkle_root_str.startswith("sha256:"):
            merkle_root_str = merkle_root_str[7:]

        try:
            expected_root = bytes.fromhex(merkle_root_str)
        except ValueError:
            result.fail("inclusion_proof", f"Invalid merkle_root hex: {merkle_root_str}")
            return

        if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
            result.fail(
                "inclusion_proof",
                f"Invalid tree parameters: leaf_index={leaf_index}, tree_size={tree_size}",
            )
            return

        try:
            proof_hashes = [bytes.fromhex(h) for h in path_hex]
        except ValueError:
            result.fail("inclusion_proof", "Invalid hex in proof path")
            return

        # Reconstruct the fact's canonical JSON to get the leaf data
        fact = receipt.get("fact", {})
        fact_for_hash = {
            "fact_id": fact.get("fact_id", ""),
            "subject_commitment": receipt.get("subject_commitment", ""),
            "purpose": receipt.get("purpose", ""),
            "scope_hash": receipt.get("scope_hash", "").replace("sha256:", ""),
            "policy_hash": receipt.get("policy_hash", "").replace("sha256:", ""),
            "timestamp": fact.get("ts", ""),
            "nonce": fact.get("nonce", ""),
            "surfaces_purged": fact.get("surfaces_purged", 0),
            "retrieval_test_outcome": fact.get("retrieval_test_outcome", ""),
            "event_type": fact.get("event_type", ""),
        }

        # The leaf data is the canonical JSON of the fact
        leaf_data = _canonical_json(fact_for_hash)
        leaf_h = _leaf_hash(leaf_data)

        # Verify the inclusion proof by reconstructing the root
        computed_root = self._reconstruct_root(leaf_h, leaf_index, tree_size, proof_hashes)
        if computed_root is None:
            result.fail("inclusion_proof", "Proof reconstruction failed")
            return

        if computed_root == expected_root:
            result.passed("inclusion_proof")
        else:
            result.fail(
                "inclusion_proof",
                "Merkle audit path does not reconstruct the stated merkle_root "
                "from the receipt's fact fields",
            )

    def _reconstruct_root(
        self,
        leaf_h: bytes,
        index: int,
        tree_size: int,
        proof: list[bytes],
    ) -> bytes | None:
        """Reconstruct the Merkle root from a leaf hash and audit path."""
        if tree_size == 1:
            return leaf_h if len(proof) == 0 else None

        if not proof:
            return None

        k = _largest_power_of_two_less_than(tree_size)
        sibling = proof[-1]
        remaining = proof[:-1]

        if index < k:
            left = self._reconstruct_root(leaf_h, index, k, remaining)
            if left is None:
                return None
            return _node_hash(left, sibling)
        else:
            right = self._reconstruct_root(leaf_h, index - k, tree_size - k, remaining)
            if right is None:
                return None
            return _node_hash(sibling, right)

    def _check_timestamp(
        self,
        receipt: dict[str, Any],
        result: VerificationResult,
        require_timestamp: bool = True,
    ) -> None:
        """Check 4: Verify timestamp token structure."""
        token = receipt.get("timestamp_token")
        if token is None:
            if require_timestamp:
                result.fail("timestamp", "Receipt has no timestamp_token")
            else:
                result.warn("No timestamp_token in receipt")
            return

        if isinstance(token, dict):
            digest_hex = token.get("digest_hex", "")
            merkle_root_str = receipt.get("merkle_root", "")
            if merkle_root_str.startswith("sha256:"):
                merkle_root_str = merkle_root_str[7:]

            if digest_hex and digest_hex != merkle_root_str:
                result.fail(
                    "timestamp",
                    f"Timestamp digest ({digest_hex[:16]}...) does not match "
                    f"merkle_root ({merkle_root_str[:16]}...)",
                )
                return

            honesty = token.get("honesty_level", "")
            if honesty == "simulated":
                result.warn("Timestamp anchor is SIMULATED (not independently verifiable)")

            result.passed("timestamp_structure")
        elif isinstance(token, str):
            # Opaque token — can't verify without the TSA
            result.warn("Timestamp token is opaque; TSA verification not performed")
            result.passed("timestamp_present")
        else:
            result.fail("timestamp", "Unrecognized timestamp_token format")

    def _check_anchor_timing(self, receipt: dict[str, Any], result: VerificationResult) -> None:
        """Check 5: Anchor timestamp must be >= fact timestamp."""
        fact = receipt.get("fact", {})
        fact_ts_str = fact.get("ts", "")
        token = receipt.get("timestamp_token", {})

        if not isinstance(token, dict):
            result.warn("Cannot check anchor timing: no structured timestamp token")
            return

        anchor_ts_str = token.get("timestamp", "")

        if not fact_ts_str or not anchor_ts_str:
            result.warn("Cannot check anchor timing: missing timestamp(s)")
            return

        try:
            fact_ts = datetime.fromisoformat(fact_ts_str)
            anchor_ts = datetime.fromisoformat(anchor_ts_str)
        except ValueError:
            result.warn("Cannot parse timestamps for anchor timing check")
            return

        if anchor_ts < fact_ts:
            result.fail(
                "anchor_timing",
                f"Anchor timestamp ({anchor_ts.isoformat()}) predates "
                f"fact timestamp ({fact_ts.isoformat()}). "
                "This suggests the anchor was back-dated.",
            )
        else:
            result.passed("anchor_timing")

    def _check_limits(self, receipt: dict[str, Any], result: VerificationResult) -> None:
        """Check 6: Limits array must be non-empty."""
        limits = receipt.get("limits", [])
        if not isinstance(limits, list) or len(limits) == 0:
            result.fail("limits", "Receipt must include non-empty limits disclosures")
        else:
            result.passed("limits")

    def _check_assurance_level(self, receipt: dict[str, Any], result: VerificationResult) -> None:
        """Check 7: Assurance level must be 1-4 with correct SIMULATED label."""
        level = receipt.get("assurance_level", 0)
        if not isinstance(level, int) or level < 1 or level > 4:
            result.fail("assurance_level", f"Invalid assurance level: {level} (must be 1-4)")
            return

        key_destruction = receipt.get("key_destruction", "")
        if level < 3 and key_destruction != "SIMULATED":
            result.warn(
                f"Assurance level {level} should have key_destruction='SIMULATED' "
                f"but found '{key_destruction}'"
            )

        if level >= 3 and key_destruction == "SIMULATED":
            result.fail(
                "assurance_level",
                f"Assurance level {level} claims real key destruction "
                "but key_destruction is 'SIMULATED'",
            )
            return

        result.passed("assurance_level")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Standalone verifier CLI.

    Usage:
        python -m verifier.verifier receipt.json --public-key key.pub
    """
    parser = argparse.ArgumentParser(
        prog="athar-verifier",
        description="Standalone verifier for Athar verifiable erasure receipts",
    )
    parser.add_argument(
        "receipt",
        help="Path to the receipt JSON file",
    )
    parser.add_argument(
        "--public-key",
        help="Path to file containing hex-encoded Ed25519 public key",
        default=None,
    )
    parser.add_argument(
        "--trust-embedded-key",
        action="store_true",
        help="Accept the public key embedded in the receipt (self-consistency only; "
        "does NOT authenticate the issuer)",
    )
    parser.add_argument(
        "--allow-missing-timestamp",
        action="store_true",
        help="Do not fail receipts that lack a timestamp token",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON",
    )

    args = parser.parse_args(argv)

    # Load receipt
    try:
        with open(args.receipt, encoding="utf-8") as f:
            receipt = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Receipt file not found: {args.receipt}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in receipt: {e}", file=sys.stderr)
        return 1

    # Load public key if provided
    public_key: bytes | None = None
    if args.public_key:
        try:
            with open(args.public_key, encoding="utf-8") as f:
                pk_hex = f.read().strip()
            public_key = bytes.fromhex(pk_hex)
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: Cannot load public key: {e}", file=sys.stderr)
            return 1

    # Verify
    verifier = ReceiptVerifier()
    result = verifier.verify(
        receipt,
        public_key,
        trust_embedded_key=args.trust_embedded_key,
        require_timestamp=not args.allow_missing_timestamp,
    )

    if args.json:
        output = {
            "valid": result.valid,
            "assurance_level": result.assurance_level,
            "checks_passed": result.checks_passed,
            "checks_failed": result.checks_failed,
            "warnings": result.warnings,
            "limits": result.limits,
        }
        print(json.dumps(output, indent=2))
    else:
        status = "VALID" if result.valid else "INVALID"
        print(f"\n{'=' * 60}")
        print(f"  ATHAR RECEIPT VERIFICATION: {status}")
        print(f"{'=' * 60}")
        print(f"  Assurance Level: {result.assurance_level}")
        print()

        if result.checks_passed:
            print("  Checks PASSED:")
            for check in result.checks_passed:
                print(f"    ✓ {check}")
            print()

        if result.checks_failed:
            print("  Checks FAILED:")
            for check in result.checks_failed:
                print(f"    ✗ {check}")
            print()

        if result.warnings:
            print("  Warnings:")
            for w in result.warnings:
                print(f"    ⚠ {w}")
            print()

        if result.limits:
            print("  Limits of the Claim:")
            for limit in result.limits:
                print(f"    • {limit}")
            print()

        print(f"{'=' * 60}")

    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
