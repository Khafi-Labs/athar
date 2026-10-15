"""Comprehensive unit and failure-injection tests for Athar ErasureSaga state machine."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from athar.erasure import (
    CacheConnector,
    DatabaseConnector,
    ErasureSaga,
    FileStoreConnector,
    LogConnector,
    SagaPersistence,
    SagaState,
    SearchIndexConnector,
)
from athar.policy import (
    LegalHold,
    Policy,
    PolicyEngine,
    RetentionBasis,
    RetentionRule,
)


class MockKeystore:
    """Mock Keystore tracking simulated DEK and PPK destructions."""

    def __init__(self) -> None:
        self.scheduled_destructions: list[tuple[str, str, datetime]] = []
        self.destroyed_deks: list[tuple[str, str]] = []
        self.destroyed_ppks: list[str] = []
        self.fail_destruction: bool = False

    def schedule_destruction(
        self,
        subject_pseudonym: str,
        purpose: str,
        scheduled_time: datetime,
    ) -> None:
        self.scheduled_destructions.append((subject_pseudonym, purpose, scheduled_time))

    def destroy_dek(self, subject_pseudonym: str, purpose: str) -> None:
        if self.fail_destruction:
            raise RuntimeError("SIMULATED Hardware Security Module error")
        self.destroyed_deks.append((subject_pseudonym, purpose))

    def has_remaining_purposes(self, subject_pseudonym: str) -> bool:
        # If no remaining purposes, returns False so PPK can be destroyed
        return False

    def destroy_ppk(self, subject_pseudonym: str) -> None:
        self.destroyed_ppks.append(subject_pseudonym)


class MockVault:
    """Mock Vault simulating encrypted record retrieval tests."""

    def __init__(self) -> None:
        self.records: dict[str, Any] = {}

    def retrieve(self, subject_pseudonym: str, purpose: str = "") -> Any:
        return self.records.get(subject_pseudonym)


class MockFactLog:
    """Mock append-only fact log recording intent and completion events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> None:
        self.events.append(event)


@pytest.fixture
def policy_engine() -> PolicyEngine:
    rules = [
        RetentionRule(
            purpose="kyc_verification",
            category="identity",
            retention_period=timedelta(days=365),
            legal_basis=RetentionBasis.LEGAL_OBLIGATION,
            description="1-year statutory KYC rule",
        ),
    ]
    policy = Policy(version="1.0.0", rules=rules, grace_period=timedelta(hours=24))
    return PolicyEngine(policy)


def test_erasure_saga_happy_path(policy_engine: PolicyEngine) -> None:
    keystore = MockKeystore()
    vault = MockVault()
    fact_log = MockFactLog()
    persistence = SagaPersistence(":memory:")

    db_conn = DatabaseConnector()
    fs_conn = FileStoreConnector()
    cache_conn = CacheConnector()
    search_conn = SearchIndexConnector()
    log_conn = LogConnector()

    connectors = [db_conn, fs_conn, cache_conn, search_conn, log_conn]

    subject = "sub_happy_path_01"
    purpose = "kyc_verification"

    # Prepopulate data on surfaces
    db_conn.insert_record("rec1", subject, purpose, "encrypted_kyc_data")
    fs_conn.store_file("f1", subject, b"encrypted_pdf")
    cache_conn.set(f"sess:{subject}", "auth_token", subject_pseudonym=subject)
    search_conn.index_document("doc1", subject, "searchable index text", purpose=purpose)
    log_conn.append_log("l1", f"Access granted to {subject}", subject_pseudonym=subject)

    saga = ErasureSaga(
        keystore=keystore,
        vault=vault,
        policy_engine=policy_engine,
        fact_log=fact_log,
        connectors=connectors,
        persistence=persistence,
    )

    # 1. Plan job (data created 2 years ago, retention expired)
    created_at = datetime.now(UTC) - timedelta(days=730)
    job = saga.plan(
        subject_pseudonym=subject,
        purpose=purpose,
        data_created_at=created_at,
    )

    assert job.state == SagaState.PLANNED
    assert len(job.manifest.targets) == 5

    # 2. Execute job to completion
    completed_job = saga.execute(job)

    assert completed_job.state == SagaState.DONE
    assert completed_job.error is None

    # Verify transitions history
    history_states = [s for s, _ in completed_job.state_history]
    assert history_states == [
        SagaState.PLANNED,
        SagaState.INTENT_LOGGED,
        SagaState.HOLD_REVALIDATED,
        SagaState.KEY_SCHEDULED,
        SagaState.SURFACES_PURGED,
        SagaState.KEY_DESTROYED,
        SagaState.VERIFIED,
        SagaState.FACT_APPENDED,
        SagaState.DONE,
    ]

    # Verify key destruction occurred (SIMULATED in MVP)
    assert (subject, purpose) in keystore.destroyed_deks
    assert subject in keystore.destroyed_ppks

    # Verify surfaces are completely purged
    assert db_conn.scan_for_remnants(subject) == []
    assert fs_conn.scan_for_remnants(subject) == []
    assert cache_conn.scan_for_remnants(subject) == []
    assert search_conn.scan_for_remnants(subject) == []
    assert log_conn.scan_for_remnants(subject) == []

    # Verify fact log events
    assert len(fact_log.events) == 2
    assert fact_log.events[0]["type"] == "erasure_intent"
    assert fact_log.events[1]["type"] == "erasure_completed"
    assert fact_log.events[1]["key_destruction"] == "SIMULATED"


def test_erasure_saga_hold_revalidation_failure(policy_engine: PolicyEngine) -> None:
    keystore = MockKeystore()
    vault = MockVault()
    fact_log = MockFactLog()
    persistence = SagaPersistence(":memory:")
    db_conn = DatabaseConnector()

    saga = ErasureSaga(
        keystore=keystore,
        vault=vault,
        policy_engine=policy_engine,
        fact_log=fact_log,
        connectors=[db_conn],
        persistence=persistence,
    )

    subject = "sub_investigation_hold"
    created_at = datetime.now(UTC) - timedelta(days=730)

    # Plan job when eligible
    job = saga.plan(subject, "kyc_verification", data_created_at=created_at)
    assert job.state == SagaState.PLANNED

    # Inject an active legal hold before execution starts
    now = datetime.now(UTC)
    policy_engine.add_hold(
        LegalHold(
            hold_id="HOLD-FREEZE-77",
            scope=subject,
            reason="Investigation order received",
            issuer="Federal Prosecutor",
            started_at=now,
            active=True,
        )
    )

    # Execute job
    result_job = saga.execute(job)

    assert result_job.state == SagaState.FAILED_PARTIAL
    assert "Active legal hold detected during revalidation" in result_job.error
    assert "HOLD-FREEZE-77" in result_job.error

    # Keys must NOT be destroyed!
    assert len(keystore.destroyed_deks) == 0
    assert len(keystore.destroyed_ppks) == 0


def test_erasure_saga_verification_remnant_failure(policy_engine: PolicyEngine) -> None:
    keystore = MockKeystore()
    vault = MockVault()
    fact_log = MockFactLog()
    persistence = SagaPersistence(":memory:")

    # Faulty connector that fails to purge remnants
    class FaultyConnector(DatabaseConnector):
        def scan_for_remnants(self, subject_pseudonym: str) -> list[str]:
            return ["unpurged_ghost_record_id_999"]

    faulty_conn = FaultyConnector()
    saga = ErasureSaga(
        keystore=keystore,
        vault=vault,
        policy_engine=policy_engine,
        fact_log=fact_log,
        connectors=[faulty_conn],
        persistence=persistence,
    )

    subject = "sub_ghost_remnants"
    created_at = datetime.now(UTC) - timedelta(days=730)

    job = saga.plan(subject, "kyc_verification", data_created_at=created_at)
    result_job = saga.execute(job)

    assert result_job.state == SagaState.FAILED_PARTIAL
    assert "Erasure verification failed" in result_job.error
    assert "unpurged_ghost_record_id_999" in result_job.error


def test_erasure_saga_resumability(policy_engine: PolicyEngine) -> None:
    keystore = MockKeystore()
    vault = MockVault()
    fact_log = MockFactLog()
    persistence = SagaPersistence(":memory:")
    db_conn = DatabaseConnector()

    subject = "sub_resume_test"
    db_conn.insert_record("rec1", subject, "kyc_verification", "data")

    saga = ErasureSaga(
        keystore=keystore,
        vault=vault,
        policy_engine=policy_engine,
        fact_log=fact_log,
        connectors=[db_conn],
        persistence=persistence,
    )

    created_at = datetime.now(UTC) - timedelta(days=730)
    job = saga.plan(subject, "kyc_verification", data_created_at=created_at)

    # Manually transition job to SURFACES_PURGED and persist to simulate crash recovery
    db_conn.purge(subject, "kyc_verification")
    now = datetime.now(UTC)
    job.state = SagaState.SURFACES_PURGED
    job.state_history.append((SagaState.SURFACES_PURGED, now))
    persistence.save_job(job)

    # Resume the job
    resumed_job = saga.resume(job.job_id)

    assert resumed_job.state == SagaState.DONE
    # Transitions should pick up from SURFACES_PURGED onwards
    states = [s for s, _ in resumed_job.state_history]
    assert SagaState.KEY_DESTROYED in states
    assert SagaState.VERIFIED in states
    assert SagaState.DONE in states


def test_plan_ineligible_raises_value_error(policy_engine: PolicyEngine) -> None:
    keystore = MockKeystore()
    vault = MockVault()
    fact_log = MockFactLog()
    persistence = SagaPersistence(":memory:")
    db_conn = DatabaseConnector()

    saga = ErasureSaga(
        keystore=keystore,
        vault=vault,
        policy_engine=policy_engine,
        fact_log=fact_log,
        connectors=[db_conn],
        persistence=persistence,
    )

    # Data created yesterday; KYC rule requires 365 days
    yesterday = datetime.now(UTC) - timedelta(days=1)
    with pytest.raises(ValueError) as excinfo:
        saga.plan("sub_active_user", "kyc_verification", data_created_at=yesterday)

    assert "Erasure plan blocked by policy" in str(excinfo.value)
