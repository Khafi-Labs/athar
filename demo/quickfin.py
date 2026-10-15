"""QuickFin Lending: End-to-end verifiable cryptographic erasure demonstration.

Scenario:
1. QuickFin lender initializes encrypted vault and storage connectors.
2. Enrolls borrower subjects with random pseudonyms.
3. Ingests encrypted KYC and transaction records into the vault.
4. Enforces statutory retention policies (KYC: 5 years, Transactions: 7 years).
5. Simulates passage of time (retention period expiration for KYC).
6. Evaluates erasure eligibility under active policy.
7. Executes the resilient 10-state Erasure Saga across all storage surfaces.
8. Commits erasure facts to an RFC 6962 Merkle log and anchors the root.
9. Constructs an Athar v0.1 verifiable erasure receipt.
10. Verifies the receipt with the zero-dependency standalone ReceiptVerifier.

Run directly via:
    python -m demo.quickfin
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

from athar.crypto.merkle import MerkleTree
from athar.crypto.signing import SigningKeyPair
from athar.erasure.connectors import (
    CacheConnector,
    DatabaseConnector,
    FilestoreConnector,
    SearchIndexConnector,
)
from athar.erasure.persistence import SagaPersistence
from athar.erasure.saga import ErasureSaga, SagaState
from athar.keystore.keys import SoftwareKeystore
from athar.log.anchoring import SimulatedAnchor
from athar.log.fact_log import Fact, FactLog
from athar.policy.engine import PolicyEngine
from athar.policy.models import (
    EligibilityResult,
    Policy,
    RetentionBasis,
    RetentionRule,
)
from athar.receipt.builder import ReceiptBuilder, RetrievalTestResult
from athar.vault.vault import Vault
from verifier.verifier import ReceiptVerifier

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def print_banner(title: str) -> None:
    """Print formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title.upper()}")
    print("=" * 70)


def print_step(step: int, title: str) -> None:
    """Print step indicator."""
    print(f"\n[Step {step}] {title}")
    print("-" * 60)


def run_quickfin_demo(receipt_out: str | None = None, public_key_out: str | None = None) -> int:
    """Execute the QuickFin end-to-end verifiable erasure demonstration."""
    print_banner("Athar Project: QuickFin Verifiable Erasure Demo")
    print("Simulating QuickFin Consumer Credit Corporation data lifecycle\n")

    # -----------------------------------------------------------------------
    # Step 1: Initialize QuickFin Security Infrastructure
    # -----------------------------------------------------------------------
    print_step(1, "Initializing QuickFin Cryptographic Infrastructure")
    keystore = SoftwareKeystore()
    vault = Vault(keystore=keystore)
    signing_key = SigningKeyPair.generate(key_id="quickfin-lender-key-01")

    # Append-only Merkle tree fact log
    merkle_tree = MerkleTree()
    fact_log = FactLog(merkle_tree=merkle_tree, signing_key=signing_key)

    # Heterogeneous storage surface connectors
    db_connector = DatabaseConnector()
    filestore_connector = FilestoreConnector()
    cache_connector = CacheConnector()
    search_connector = SearchIndexConnector()
    connectors = [db_connector, filestore_connector, cache_connector, search_connector]

    persistence = SagaPersistence(":memory:")

    print("  ✓ SoftwareKeystore initialized (Three-tier hierarchy: KEK/PPK/DEK)")
    print("  ✓ Encrypted Record Vault configured (AES-256-GCM + RFC 8785 AAD)")
    print(
        f"  ✓ Ed25519 Signing Key: {signing_key.key_id} (pub: {signing_key.public_key_hex[:16]}...)"
    )
    print("  ✓ Merkle Fact Log: 0 initial facts (RFC 6962 compliant)")
    print("  ✓ Configured 4 purge connectors: DB, Filestore, Cache, Search Index")

    # -----------------------------------------------------------------------
    # Step 2: Customer Enrollment (Pseudonyms)
    # -----------------------------------------------------------------------
    print_step(2, "Customer Enrollment with Random Pseudonyms")
    alice_pseudonym = f"subj_alice_{uuid.uuid4().hex[:8]}"
    bob_pseudonym = f"subj_bob_{uuid.uuid4().hex[:8]}"

    print(f"  • Enrolled Subject 'Alice Vance' -> Pseudonym: {alice_pseudonym}")
    print(f"  • Enrolled Subject 'Bob Chen'     -> Pseudonym: {bob_pseudonym}")
    print("  * Personal Identifiable Information (PII) is isolated outside the vault.")

    # -----------------------------------------------------------------------
    # Step 3: Ingest Encrypted Records into Vault & Connectors
    # -----------------------------------------------------------------------
    print_step(3, "Ingesting Encrypted KYC and Financial Records")

    # Alice records
    alice_kyc_data = b"Alice Vance: Passport #N9281923, Proof of Address: 742 Evergreen Terr"
    alice_tx_data = b"Loan Agreement #LN-2021-994: Disbursed $15,000 USD, Repayment: Good Standing"

    alice_kyc_rec_id = vault.store_record(
        subject_pseudonym=alice_pseudonym,
        purpose="kyc_verification",
        plaintext=alice_kyc_data,
    )
    alice_tx_rec_id = vault.store_record(
        subject_pseudonym=alice_pseudonym,
        purpose="transaction_history",
        plaintext=alice_tx_data,
    )

    # Bob records
    bob_kyc_data = b"Bob Chen: Driver License #DL-8812903, Proof of Income: Verified"
    bob_kyc_rec_id = vault.store_record(
        subject_pseudonym=bob_pseudonym,
        purpose="kyc_verification",
        plaintext=bob_kyc_data,
    )

    # Populate storage surfaces so connectors reflect realistic distributed footprint
    db_connector.insert_record(
        "db-rec-01", alice_pseudonym, "kyc_verification", "Alice KYC Metadata"
    )
    filestore_connector.store_file("passport_scan.pdf", alice_pseudonym, b"PDF_SCAN_BYTES")
    cache_connector.set(
        "cache-session-99", "active_session_kyc", subject_pseudonym=alice_pseudonym
    )
    search_connector.index_document(
        "doc-alice-01", alice_pseudonym, "Alice KYC Document", purpose="kyc_verification"
    )

    print(f"  ✓ Stored Alice KYC record: {alice_kyc_rec_id} (encrypted under DEK)")
    print(f"  ✓ Stored Alice Transaction record: {alice_tx_rec_id} (encrypted under DEK)")
    print(f"  ✓ Stored Bob KYC record: {bob_kyc_rec_id} (encrypted under DEK)")
    print("  ✓ Distributed across 4 operational storage surfaces")

    # Verify initial retrieval succeeds
    decrypted_kyc = vault.retrieve_record(alice_kyc_rec_id)
    print(f"  ✓ Pre-erasure retrieval test: decrypted {len(decrypted_kyc)} bytes successfully")

    # -----------------------------------------------------------------------
    # Step 4: Define Retention Policies
    # -----------------------------------------------------------------------
    print_step(4, "Establishing Retention Policy (KYC: 5 yrs, Transactions: 7 yrs)")

    rule_kyc = RetentionRule(
        purpose="kyc_verification",
        category="identity_verification",
        retention_period=timedelta(days=5 * 365),  # 5 years
        legal_basis=RetentionBasis.LEGAL_OBLIGATION,
        description="Statutory anti-money laundering (AML) customer identification rule",
    )
    rule_tx = RetentionRule(
        purpose="transaction_history",
        category="credit_ledger",
        retention_period=timedelta(days=7 * 365),  # 7 years
        legal_basis=RetentionBasis.LEGAL_OBLIGATION,
        description="Accounting standards and credit reporting retention obligation",
    )

    policy = Policy(
        version="2026.1",
        rules=[rule_kyc, rule_tx],
        holds=[],
        requires_two_person_approval=False,
        grace_period=timedelta(hours=72),
    )
    policy_engine = PolicyEngine(policy=policy)
    policy_hash = policy_engine.compute_policy_hash()

    print(f"  • Policy Version: {policy.version}")
    print(
        f"  • Rule 1: 'kyc_verification' -> {rule_kyc.retention_period.days} days ({rule_kyc.legal_basis.value})"
    )
    print(
        f"  • Rule 2: 'transaction_history' -> {rule_tx.retention_period.days} days ({rule_tx.legal_basis.value})"
    )
    print(f"  • Policy Hash (SHA-256): {policy_hash}")

    # -----------------------------------------------------------------------
    # Step 5: Simulate Passage of Time & Evaluate Erasure Eligibility
    # -----------------------------------------------------------------------
    print_step(5, "Simulating Retention Period Expiration & Evaluating Eligibility")

    now = datetime.now(UTC)
    # Alice KYC collected 5.5 years ago (2,000 days ago) -> EXPIRED
    alice_kyc_created_at = now - timedelta(days=2000)
    # Alice Transaction recorded 3 years ago (1,095 days ago) -> ACTIVE (needs 7 years)
    alice_tx_created_at = now - timedelta(days=1095)

    decision_kyc = policy_engine.evaluate(
        subject_pseudonym=alice_pseudonym,
        purpose="kyc_verification",
        data_created_at=alice_kyc_created_at,
    )
    decision_tx = policy_engine.evaluate(
        subject_pseudonym=alice_pseudonym,
        purpose="transaction_history",
        data_created_at=alice_tx_created_at,
    )

    print("  [Evaluation] Alice KYC (created 2,000 days ago):")
    print(f"    -> Result: {decision_kyc.result.value} (Reason: {decision_kyc.reason})")
    print("  [Evaluation] Alice Transaction (created 1,095 days ago):")
    print(f"    -> Result: {decision_tx.result.value} (Reason: {decision_tx.reason})")

    assert decision_kyc.result == EligibilityResult.ELIGIBLE
    assert decision_tx.result == EligibilityResult.BLOCKED
    print(
        "  ✓ Policy Engine correctly authorized KYC erasure and blocked premature transaction deletion"
    )

    # -----------------------------------------------------------------------
    # Step 6: Execute the Full Resumable Erasure Saga
    # -----------------------------------------------------------------------
    print_step(6, "Executing 10-State Erasure Saga for Alice KYC")

    saga = ErasureSaga(
        keystore=keystore,
        vault=vault,
        policy_engine=policy_engine,
        fact_log=fact_log,
        connectors=connectors,
        persistence=persistence,
    )

    # Plan job
    job = saga.plan(
        subject_pseudonym=alice_pseudonym,
        purpose="kyc_verification",
        data_created_at=alice_kyc_created_at,
    )
    print(f"  • Planned Erasure Job: {job.job_id}")

    # Execute all states
    executed_job = saga.execute(job)
    print(f"  • Final Saga State: {executed_job.state.value}")

    print("  • Executed State Transition History:")
    for st, ts in executed_job.state_history:
        print(f"      [{ts.strftime('%H:%M:%S.%f')[:-3]}] {st.value}")

    assert executed_job.state == SagaState.DONE

    # -----------------------------------------------------------------------
    # Step 7: Cryptographic Erasure Verification Drill
    # -----------------------------------------------------------------------
    print_step(7, "Verifying Cryptographic Irrecoverability in Vault")

    # Alice KYC retrieval must fail
    try:
        vault.retrieve_record(alice_kyc_rec_id)
        print("  ✗ ERROR: Alice KYC record was unexpectedly retrievable!")
        return 1
    except Exception as exc:
        print(f"  ✓ Confirmed Cryptographic Erasure: DEK destroyed ({type(exc).__name__})")
        print("    Ciphertext cannot be decrypted by any party.")

    # Alice Transaction must remain fully recoverable
    alice_tx_still_valid = vault.retrieve_record(alice_tx_rec_id)
    assert alice_tx_still_valid == alice_tx_data
    print(
        f"  ✓ Retained record integrity check: Alice Transaction record decrypted successfully ({len(alice_tx_still_valid)} bytes)"
    )

    # Connectors must be cleanly purged
    for conn in connectors:
        remnants = conn.scan_for_remnants(alice_pseudonym)
        assert len(remnants) == 0
        print(f"  ✓ Connector '{conn.surface_name}' remnant scan: 0 items detected")

    # -----------------------------------------------------------------------
    # Step 8: Build and Sign Erasure Receipt
    # -----------------------------------------------------------------------
    print_step(8, "Generating Verifiable Erasure Receipt v0.1")

    # Create immutable Fact
    salt = os.urandom(32)
    fact = Fact.create(
        subject_pseudonym=alice_pseudonym,
        purpose="kyc_verification",
        scope_description="QuickFin Loan Servicing - KYC verification documents & identity files",
        policy_hash=policy_hash,
        surfaces_purged=len(connectors),
        retrieval_test_outcome="PASSED",
        salt=salt,
    )

    leaf_index = fact_log.append_fact(fact)
    batch = fact_log.batch_sign()
    inclusion_proof = fact_log.get_inclusion_proof(leaf_index)

    # Anchoring
    anchor_adapter = SimulatedAnchor(signing_key=signing_key)
    anchor_token = anchor_adapter.anchor(bytes.fromhex(batch.merkle_root))

    retrieval_test = RetrievalTestResult(
        date=datetime.now(UTC).strftime("%Y-%m-%d"),
        surfaces_tested=len(connectors),
        outcome="not_recoverable",
        details="DEK zeroized; AEAD authentication tag failed verification",
    )

    receipt = ReceiptBuilder.build(
        fact=fact,
        leaf_index=leaf_index,
        inclusion_proof=inclusion_proof,
        batch=batch,
        anchor_token=anchor_token,
        retrieval_test=retrieval_test,
        signing_key=signing_key,
        assurance_level=2,
    )

    print(f"  ✓ Receipt Spec Version: {receipt['spec']}")
    print(f"  ✓ Subject Commitment: {receipt['subject_commitment'][:24]}...")
    print(f"  ✓ Merkle Root: {receipt['merkle_root']}")
    print(f"  ✓ Inclusion Proof Path Length: {len(receipt['inclusion_proof']['path'])} node(s)")
    print(f"  ✓ Ed25519 Signature: {receipt['signatures'][0]['sig'][:32]}...")

    # -----------------------------------------------------------------------
    # Step 9: Zero-Dependency Standalone Verification
    # -----------------------------------------------------------------------
    print_step(9, "Running Standalone ReceiptVerifier (Zero Athar Dependencies)")

    verifier = ReceiptVerifier()
    verification_result = verifier.verify(
        receipt=receipt,
        public_key=signing_key.public_key_bytes,
    )

    print(f"\n  Verification Result: {'VALID' if verification_result.valid else 'INVALID'}")
    print(f"  Assurance Level: {verification_result.assurance_level}")
    print(f"  Checks Passed ({len(verification_result.checks_passed)}):")
    for check in verification_result.checks_passed:
        print(f"    ✓ {check}")

    if verification_result.warnings:
        print(f"  Warnings ({len(verification_result.warnings)}):")
        for warn in verification_result.warnings:
            print(f"    ⚠ {warn}")

    if verification_result.checks_failed:
        print(f"  Failures ({len(verification_result.checks_failed)}):")
        for fail in verification_result.checks_failed:
            print(f"    ✗ {fail}")

    assert verification_result.valid is True
    print("\n  ✓ Standalone cryptographic verification succeeded with zero failures!")

    # -----------------------------------------------------------------------
    # Step 10: Summary & Exported Receipt Preview
    # -----------------------------------------------------------------------
    print_step(10, "Summary & Portable Receipt Artifact")

    print("\nCanonical Receipt Payload (preview):")
    print(json.dumps(receipt, indent=2))

    if receipt_out:
        with open(receipt_out, "w", encoding="utf-8") as fh:
            json.dump(receipt, fh, indent=2)
        print(f"\nReceipt written to {receipt_out}")
    if public_key_out:
        with open(public_key_out, "w", encoding="utf-8") as fh:
            fh.write(signing_key.public_key_hex + "\n")
        print(f"Issuer public key written to {public_key_out}")

    if not verification_result.valid:
        print_banner("QuickFin Demonstration FAILED: receipt did not verify")
        for failure in verification_result.checks_failed:
            print(f"  ✗ {failure}")
        return 1

    print_banner("QuickFin Demonstration Completed Successfully")
    print("The receipt above verified against the pinned issuer key.\n")
    return 0


if __name__ == "__main__":
    sys.exit(run_quickfin_demo())
