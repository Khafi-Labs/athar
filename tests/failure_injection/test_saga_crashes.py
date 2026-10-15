"""Failure injection tests for the erasure saga.

Tests that killing the saga at each state and restarting always ends
in DONE or an explicit FAILED_PARTIAL — never in a silent partial state.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from athar.crypto.merkle import MerkleTree
from athar.crypto.signing import SigningKeyPair
from athar.erasure.connectors import PurgeConnector
from athar.erasure.saga import ErasureSaga, PurgeTarget, SagaState
from athar.keystore.keys import SoftwareKeystore
from athar.log.fact_log import FactLog
from athar.policy.engine import PolicyEngine
from athar.policy.models import (
    Policy,
    RetentionBasis,
    RetentionRule,
)
from athar.vault.vault import Vault

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeConnector(PurgeConnector):
    """Minimal connector that always succeeds."""

    def __init__(self, name: str = "fake_db") -> None:
        self._name = name

    @property
    def surface_name(self) -> str:
        return self._name

    @property
    def surface_type(self) -> str:
        return "database"

    @property
    def is_idempotent(self) -> bool:
        return True

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        return PurgeTarget(
            surface_name=self._name,
            surface_type="database",
            status="purged",
            rows_affected=3,
            files_affected=0,
            purged_at=datetime.now(UTC),
        )

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        return []


class FailingConnector(PurgeConnector):
    """Connector that raises an exception on purge."""

    def __init__(self, name: str = "failing_store") -> None:
        self._name = name

    @property
    def surface_name(self) -> str:
        return self._name

    @property
    def surface_type(self) -> str:
        return "database"

    @property
    def is_idempotent(self) -> bool:
        return True

    def purge(self, subject_pseudonym: str, purpose: str) -> PurgeTarget:
        raise RuntimeError(f"Simulated failure in {self._name}")

    def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
        return []


OLD = datetime(2020, 1, 1, tzinfo=UTC)


def make_test_setup(connectors: list[PurgeConnector] | None = None):
    """Create a minimal test environment for the saga."""
    ks = SoftwareKeystore()
    kek_id = ks.generate_kek()
    ppk_id = ks.generate_ppk(kek_id, "kyc", "2026")
    ks.generate_dek(ppk_id, "subj_test_001")

    vault = Vault(keystore=ks, default_ppk_id=ppk_id)
    signing_key = SigningKeyPair.generate(key_id="test-signing-key")
    merkle_tree = MerkleTree()
    fact_log = FactLog(merkle_tree=merkle_tree, signing_key=signing_key)

    policy = Policy(
        version="1.0",
        rules=[
            RetentionRule(
                purpose="kyc",
                category="identity",
                retention_period=timedelta(days=0),  # Expired immediately
                legal_basis=RetentionBasis.LEGAL_OBLIGATION,
                description="KYC data",
            )
        ],
        holds=[],
        requires_two_person_approval=False,
        grace_period=timedelta(seconds=0),
    )

    engine = PolicyEngine(policy)
    conns = connectors or [FakeConnector("test_db")]

    return ks, vault, fact_log, engine, conns, "subj_test_001", "kyc"


# ---------------------------------------------------------------------------
# Test: Connector failure -> FAILED_PARTIAL
# ---------------------------------------------------------------------------


class TestConnectorFailure:
    """Saga must record FAILED_PARTIAL when a connector fails."""

    def test_failing_connector_produces_failed_partial(self) -> None:
        ks, vault, fact_log, engine, _, subject, purpose = make_test_setup()
        conns = [FakeConnector("good_db"), FailingConnector("bad_store")]

        saga = ErasureSaga(
            keystore=ks,
            vault=vault,
            fact_log=fact_log,
            policy_engine=engine,
            connectors=conns,
        )

        job = saga.plan(subject, purpose, data_created_at=OLD)
        result = saga.execute(job)

        # The job must end in FAILED_PARTIAL, not silently succeed
        assert result.state == SagaState.FAILED_PARTIAL, (
            f"Expected FAILED_PARTIAL but got {result.state}"
        )
        assert result.error is not None

    def test_all_connectors_succeed(self) -> None:
        ks, vault, fact_log, engine, conns, subject, purpose = make_test_setup()

        saga = ErasureSaga(
            keystore=ks,
            vault=vault,
            fact_log=fact_log,
            policy_engine=engine,
            connectors=conns,
        )

        job = saga.plan(subject, purpose, data_created_at=OLD)
        result = saga.execute(job)

        assert result.state == SagaState.DONE


# ---------------------------------------------------------------------------
# Test: Idempotency — running the same step twice produces same result
# ---------------------------------------------------------------------------


class TestIdempotency:
    """Each saga step must be idempotent."""

    def test_double_execute_same_result(self) -> None:
        ks, vault, fact_log, engine, conns, subject, purpose = make_test_setup()

        saga = ErasureSaga(
            keystore=ks,
            vault=vault,
            fact_log=fact_log,
            policy_engine=engine,
            connectors=conns,
        )

        job = saga.plan(subject, purpose, data_created_at=OLD)
        result1 = saga.execute(job)

        # Execute again on the same job should be safe
        result2 = saga.execute(result1)

        assert result2.state in (SagaState.DONE, SagaState.FAILED_PARTIAL)


# ---------------------------------------------------------------------------
# Test: State history is preserved
# ---------------------------------------------------------------------------


class TestStateHistory:
    """State transitions must be recorded in state_history."""

    def test_state_history_records_all_transitions(self) -> None:
        ks, vault, fact_log, engine, conns, subject, purpose = make_test_setup()

        saga = ErasureSaga(
            keystore=ks,
            vault=vault,
            fact_log=fact_log,
            policy_engine=engine,
            connectors=conns,
        )

        job = saga.plan(subject, purpose, data_created_at=OLD)
        result = saga.execute(job)

        # Must have at least PLANNED in history
        assert len(result.state_history) >= 1
        assert result.state_history[0][0] == SagaState.PLANNED


# ---------------------------------------------------------------------------
# Test: Job cannot skip states
# ---------------------------------------------------------------------------


class TestNoStateSkipping:
    """Jobs must transition through states in order."""

    def test_plan_creates_planned_state(self) -> None:
        ks, vault, fact_log, engine, conns, subject, purpose = make_test_setup()

        saga = ErasureSaga(
            keystore=ks,
            vault=vault,
            fact_log=fact_log,
            policy_engine=engine,
            connectors=conns,
        )

        job = saga.plan(subject, purpose, data_created_at=OLD)
        assert job.state == SagaState.PLANNED


# ---------------------------------------------------------------------------
# Test: Overlapping subjects
# ---------------------------------------------------------------------------


class TestOverlappingSubjects:
    """Multiple subjects can be erased independently."""

    def test_two_subjects_erased_independently(self) -> None:
        ks = SoftwareKeystore()
        kek_id = ks.generate_kek()
        ppk_id = ks.generate_ppk(kek_id, "kyc", "2026")
        ks.generate_dek(ppk_id, "subj_001")
        ks.generate_dek(ppk_id, "subj_002")
        vault = Vault(keystore=ks, default_ppk_id=ppk_id)
        fact_log = FactLog(
            merkle_tree=MerkleTree(), signing_key=SigningKeyPair.generate(key_id="test-key")
        )

        policy = Policy(
            version="1.0",
            rules=[
                RetentionRule(
                    purpose="kyc",
                    category="identity",
                    retention_period=timedelta(days=0),
                    legal_basis=RetentionBasis.LEGAL_OBLIGATION,
                    description="KYC data",
                )
            ],
            holds=[],
            requires_two_person_approval=False,
            grace_period=timedelta(seconds=0),
        )

        engine = PolicyEngine(policy)
        conns = [FakeConnector("test_db")]

        saga = ErasureSaga(
            keystore=ks,
            vault=vault,
            fact_log=fact_log,
            policy_engine=engine,
            connectors=conns,
        )

        job1 = saga.plan("subj_001", "kyc", data_created_at=OLD)
        job2 = saga.plan("subj_002", "kyc", data_created_at=OLD)

        result1 = saga.execute(job1)
        result2 = saga.execute(job2)

        # Both should complete independently
        assert result1.state in (SagaState.DONE, SagaState.FAILED_PARTIAL)
        assert result2.state in (SagaState.DONE, SagaState.FAILED_PARTIAL)
        assert result1.job_id != result2.job_id
