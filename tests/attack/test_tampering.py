"""Attack scenario tests for Athar receipts and verification.

Tests the M8 adversarial attack table:
- Tamper with any byte in a signed receipt -> verification fails
- Replace anchor token -> verification fails
- Edit a logged fact -> Merkle proof fails
- Back-date a timestamp -> anchor timing check fails
- Receipt with empty limits -> verification fails
- Receipt claiming level 3 with SIMULATED -> verification fails
"""

from __future__ import annotations

import copy

import pytest

from athar.crypto.canonical_json import canonical_json
from athar.crypto.merkle import MerkleTree
from athar.crypto.signing import SigningKeyPair
from verifier.verifier import ReceiptVerifier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_valid_receipt() -> tuple[dict, SigningKeyPair]:
    """Build a minimal valid receipt for testing."""
    key = SigningKeyPair.generate(key_id="test-key-001")

    # Create a small Merkle tree with a real fact
    fact_data = canonical_json(
        {
            "fact_id": "fact-001",
            "subject_commitment": "commit-abc",
            "purpose": "kyc",
            "scope_hash": "aabbccdd",
            "policy_hash": "eeff0011",
            "timestamp": "2026-10-13T12:00:00+00:00",
            "nonce": "aa" * 32,
            "surfaces_purged": 3,
            "retrieval_test_outcome": "PASSED",
            "event_type": "erasure",
        }
    )

    tree = MerkleTree([fact_data, b"other_fact_1", b"other_fact_2", b"other_fact_3"])
    root = tree.get_root()
    proof = tree.get_inclusion_proof(0)

    receipt = {
        "spec": "athar-receipt/0.1",
        "subject_commitment": "commit-abc",
        "purpose": "kyc",
        "period": "2026",
        "scope_hash": "sha256:aabbccdd",
        "policy_hash": "sha256:eeff0011",
        "assurance_level": 2,
        "key_destruction": "SIMULATED",
        "fact": {
            "fact_id": "fact-001",
            "ts": "2026-10-13T12:00:00+00:00",
            "nonce": "aa" * 32,
            "surfaces_purged": 3,
            "retrieval_test_outcome": "PASSED",
            "event_type": "erasure",
        },
        "inclusion_proof": {
            "batch_id": "batch-2026-Q4",
            "leaf_index": 0,
            "tree_size": 4,
            "path": [h.hex() for h in proof],
        },
        "merkle_root": f"sha256:{root.hex()}",
        "timestamp_token": {
            "token_type": "simulated",
            "token_data_hex": "00" * 64,
            "timestamp": "2026-10-13T12:00:01+00:00",
            "honesty_level": "simulated",
            "digest_hex": root.hex(),
            "token_id": "tok-001",
        },
        "retrieval_test": {
            "date": "2026-10-13",
            "surfaces": 3,
            "outcome": "not_recoverable",
        },
        "limits": [
            "Does not prove absence of copies outside the manifest.",
            "Key destruction is SIMULATED in this MVP.",
        ],
    }

    # Sign it
    signable = {k: v for k, v in receipt.items() if k != "signatures"}
    message = canonical_json(signable)
    sig = key.sign(message)

    receipt["signatures"] = [
        {
            "alg": "Ed25519",
            "kid": key.key_id,
            "pub": key.public_key_hex,
            "sig": sig.hex(),
        }
    ]

    return receipt, key


# ---------------------------------------------------------------------------
# Attack 1: Tamper with receipt fields
# ---------------------------------------------------------------------------


class TestBytesTampering:
    """Any modification to a signed receipt must cause verification failure."""

    def test_tamper_purpose_field(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        # Verify original is valid
        result = verifier.verify(receipt, key.public_key_bytes)
        assert result.valid, f"Original should be valid: {result.checks_failed}"

        # Tamper with purpose
        tampered = copy.deepcopy(receipt)
        tampered["purpose"] = "fraud"
        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Tampered purpose should fail verification"
        assert any("signature" in f.lower() for f in result.checks_failed)

    def test_tamper_assurance_level(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["assurance_level"] = 4
        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Elevated assurance level should fail"

    def test_tamper_surfaces_purged(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["fact"]["surfaces_purged"] = 999
        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Tampered surfaces_purged should fail"

    def test_tamper_merkle_root(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["merkle_root"] = "sha256:" + "ff" * 32
        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Tampered merkle_root should fail"

    def test_tamper_subject_commitment(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["subject_commitment"] = "FORGED"
        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Tampered subject_commitment should fail"


# ---------------------------------------------------------------------------
# Attack 2: Replace anchor token
# ---------------------------------------------------------------------------


class TestAnchorReplacement:
    """Replacing the anchor token must cause verification failure."""

    def test_replace_anchor_token_digest(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["timestamp_token"]["digest_hex"] = "00" * 32
        result = verifier.verify(tampered, key.public_key_bytes)
        # Should fail signature (token is part of signed content)
        assert not result.valid, "Replaced anchor digest should fail"

    def test_replace_anchor_timestamp(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["timestamp_token"]["timestamp"] = "2020-01-01T00:00:00+00:00"
        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Replaced anchor timestamp should fail"


# ---------------------------------------------------------------------------
# Attack 3: Back-date timestamp (anchor before fact)
# ---------------------------------------------------------------------------


class TestBackdatedTimestamp:
    """Anchor timestamp before fact timestamp must be detected."""

    def test_anchor_predates_fact(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        # Create a receipt where anchor timestamp is BEFORE fact timestamp
        # We need to re-sign it so the signature check passes
        tampered = copy.deepcopy(receipt)
        tampered["fact"]["ts"] = "2026-10-13T12:00:00+00:00"
        tampered["timestamp_token"]["timestamp"] = "2026-10-12T11:00:00+00:00"

        # Re-sign the tampered receipt
        del tampered["signatures"]
        signable = {k: v for k, v in tampered.items() if k != "signatures"}
        message = canonical_json(signable)
        sig = key.sign(message)
        tampered["signatures"] = [
            {
                "alg": "Ed25519",
                "kid": key.key_id,
                "pub": key.public_key_hex,
                "sig": sig.hex(),
            }
        ]

        result = verifier.verify(tampered, key.public_key_bytes)
        # Should fail anchor timing check
        assert any("anchor_timing" in f.lower() for f in result.checks_failed), (
            f"Back-dated anchor should fail timing check. Failed: {result.checks_failed}"
        )


# ---------------------------------------------------------------------------
# Attack 4: Empty limits
# ---------------------------------------------------------------------------


class TestEmptyLimits:
    """Receipt with empty limits must fail verification."""

    def test_empty_limits_array(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["limits"] = []

        # Re-sign
        del tampered["signatures"]
        signable = {k: v for k, v in tampered.items() if k != "signatures"}
        message = canonical_json(signable)
        sig = key.sign(message)
        tampered["signatures"] = [
            {
                "alg": "Ed25519",
                "kid": key.key_id,
                "pub": key.public_key_hex,
                "sig": sig.hex(),
            }
        ]

        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Empty limits should fail"
        assert any("limits" in f.lower() for f in result.checks_failed)


# ---------------------------------------------------------------------------
# Attack 5: Level 3 with SIMULATED
# ---------------------------------------------------------------------------


class TestAssuranceLevelMismatch:
    """Claiming level 3 with SIMULATED key destruction must fail."""

    def test_level_3_simulated_fails(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["assurance_level"] = 3
        tampered["key_destruction"] = "SIMULATED"

        # Re-sign
        del tampered["signatures"]
        signable = {k: v for k, v in tampered.items() if k != "signatures"}
        message = canonical_json(signable)
        sig = key.sign(message)
        tampered["signatures"] = [
            {
                "alg": "Ed25519",
                "kid": key.key_id,
                "pub": key.public_key_hex,
                "sig": sig.hex(),
            }
        ]

        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Level 3 + SIMULATED should fail"
        assert any("assurance_level" in f.lower() for f in result.checks_failed)


# ---------------------------------------------------------------------------
# Attack 6: Missing required fields
# ---------------------------------------------------------------------------


class TestMissingFields:
    """Receipts with missing required fields must fail schema check."""

    @pytest.mark.parametrize(
        "field",
        [
            "spec",
            "subject_commitment",
            "purpose",
            "assurance_level",
            "fact",
            "inclusion_proof",
            "merkle_root",
            "limits",
            "signatures",
        ],
    )
    def test_missing_required_field(self, field: str) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        del tampered[field]

        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, f"Missing '{field}' should fail schema check"
        assert any("schema" in f.lower() for f in result.checks_failed)


# ---------------------------------------------------------------------------
# Attack 7: Wrong signature key
# ---------------------------------------------------------------------------


class TestWrongKey:
    """Verification with a different key must fail."""

    def test_wrong_public_key_fails(self) -> None:
        receipt, _ = make_valid_receipt()
        verifier = ReceiptVerifier()

        # Use a completely different key
        wrong_key = SigningKeyPair.generate(key_id="wrong-key")
        result = verifier.verify(receipt, wrong_key.public_key_bytes)
        assert not result.valid, "Wrong public key should fail verification"
        assert any("signature" in f.lower() for f in result.checks_failed)


# ---------------------------------------------------------------------------
# Attack 8: Forged signature
# ---------------------------------------------------------------------------


class TestForgedSignature:
    """A completely fabricated signature must fail."""

    def test_random_signature_fails(self) -> None:
        receipt, key = make_valid_receipt()
        verifier = ReceiptVerifier()

        tampered = copy.deepcopy(receipt)
        tampered["signatures"][0]["sig"] = "00" * 64

        result = verifier.verify(tampered, key.public_key_bytes)
        assert not result.valid, "Forged signature should fail"


# ---------------------------------------------------------------------------
# Attack: forged receipts (regression tests for verifier hardening)
# ---------------------------------------------------------------------------


class TestForgery:
    """A receipt signed by an attacker's own key must not verify."""

    def test_embedded_key_rejected_by_default(self) -> None:
        receipt, _ = make_valid_receipt()
        result = ReceiptVerifier().verify(receipt)
        assert not result.valid
        assert any("pinned" in f for f in result.checks_failed)

    def test_embedded_key_opt_in_warns(self) -> None:
        receipt, _ = make_valid_receipt()
        result = ReceiptVerifier().verify(receipt, trust_embedded_key=True)
        assert result.valid
        assert any("self-consistency" in w for w in result.warnings)

    def test_attacker_key_fails_against_pinned_issuer(self) -> None:
        receipt, issuer = make_valid_receipt()
        attacker = SigningKeyPair.generate(key_id="attacker")
        forged = {k: v for k, v in receipt.items() if k != "signatures"}
        forged["signatures"] = [
            {
                "alg": "Ed25519",
                "kid": "attacker",
                "pub": attacker.public_key_hex,
                "sig": attacker.sign(canonical_json(forged)).hex(),
            }
        ]
        assert not ReceiptVerifier().verify(forged, issuer.public_key_bytes).valid

    def test_random_merkle_proof_fails(self) -> None:
        receipt, key = make_valid_receipt()
        forged = {k: v for k, v in receipt.items() if k != "signatures"}
        forged["merkle_root"] = "sha256:" + "ab" * 32
        forged["timestamp_token"]["digest_hex"] = "ab" * 32
        forged["signatures"] = [
            {
                "alg": "Ed25519",
                "kid": key.key_id,
                "pub": key.public_key_hex,
                "sig": key.sign(canonical_json(forged)).hex(),
            }
        ]
        result = ReceiptVerifier().verify(forged, key.public_key_bytes)
        assert not result.valid
        assert any("inclusion_proof" in f for f in result.checks_failed)

    def test_missing_timestamp_fails(self) -> None:
        receipt, key = make_valid_receipt()
        body = {k: v for k, v in receipt.items() if k not in ("signatures", "timestamp_token")}
        body["signatures"] = [
            {
                "alg": "Ed25519",
                "kid": key.key_id,
                "pub": key.public_key_hex,
                "sig": key.sign(canonical_json(body)).hex(),
            }
        ]
        assert not ReceiptVerifier().verify(body, key.public_key_bytes).valid
        assert ReceiptVerifier().verify(body, key.public_key_bytes, require_timestamp=False).valid
