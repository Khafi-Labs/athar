"""Unit tests for SQLite SagaPersistence repository."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from athar.erasure.connectors import PurgeTarget
from athar.erasure.persistence import SagaPersistence
from athar.erasure.saga import ErasureJob, ErasureManifest, SagaState
from athar.policy.models import EligibilityDecision, EligibilityResult


def create_sample_job(job_id: str, state: SagaState = SagaState.PLANNED) -> ErasureJob:
    now = datetime.now(UTC)
    manifest = ErasureManifest(
        job_id=job_id,
        subject_pseudonym="sub_persist_test",
        purpose="kyc_verification",
        targets=[
            PurgeTarget(surface_name="database", surface_type="relational_db", status="pending"),
            PurgeTarget(surface_name="filestore", surface_type="file_storage", status="pending"),
        ],
        known_gaps=["offline_tapes"],
    )
    decision = EligibilityDecision(
        result=EligibilityResult.ELIGIBLE,
        reason="Test eligibility granted",
        blocking_holds=[],
        retention_expires_at=now,
        evaluated_at=now,
        policy_version="1.0.0",
    )
    return ErasureJob(
        job_id=job_id,
        state=state,
        manifest=manifest,
        policy_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        eligibility_decision=decision,
        created_at=now,
        updated_at=now,
        state_history=[(state, now)],
        error=None,
    )


def test_save_and_load_job() -> None:
    store = SagaPersistence(":memory:")
    job = create_sample_job("job-001", SagaState.PLANNED)

    store.save_job(job)
    loaded = store.load_job("job-001")

    assert loaded.job_id == job.job_id
    assert loaded.state == SagaState.PLANNED
    assert loaded.policy_hash == job.policy_hash
    assert loaded.manifest.subject_pseudonym == "sub_persist_test"
    assert len(loaded.manifest.targets) == 2
    assert loaded.manifest.known_gaps == ["offline_tapes"]
    assert loaded.eligibility_decision.result == EligibilityResult.ELIGIBLE
    assert len(loaded.state_history) == 1
    assert loaded.state_history[0][0] == SagaState.PLANNED


def test_load_nonexistent_job_raises_key_error() -> None:
    store = SagaPersistence(":memory:")
    with pytest.raises(KeyError):
        store.load_job("non-existent-uuid")


def test_list_jobs_and_filter() -> None:
    store = SagaPersistence(":memory:")
    j1 = create_sample_job("job-001", SagaState.PLANNED)
    j2 = create_sample_job("job-002", SagaState.SURFACES_PURGED)
    j3 = create_sample_job("job-003", SagaState.DONE)

    store.save_job(j1)
    store.save_job(j2)
    store.save_job(j3)

    all_jobs = store.list_jobs()
    assert len(all_jobs) == 3

    purged_jobs = store.list_jobs(state=SagaState.SURFACES_PURGED)
    assert len(purged_jobs) == 1
    assert purged_jobs[0].job_id == "job-002"


def test_list_incomplete_jobs() -> None:
    store = SagaPersistence(":memory:")
    j1 = create_sample_job("job-001", SagaState.PLANNED)
    j2 = create_sample_job("job-002", SagaState.KEY_SCHEDULED)
    j3 = create_sample_job("job-003", SagaState.DONE)
    j4 = create_sample_job("job-004", SagaState.FAILED_PARTIAL)

    store.save_job(j1)
    store.save_job(j2)
    store.save_job(j3)
    store.save_job(j4)

    incomplete = store.list_incomplete()
    assert len(incomplete) == 2
    incomplete_ids = {j.job_id for j in incomplete}
    assert incomplete_ids == {"job-001", "job-002"}


def test_file_backed_persistence() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "saga.db"
        store = SagaPersistence(db_path)
        job = create_sample_job("job-file-01", SagaState.DONE)
        store.save_job(job)
        store.close()

        # Open new connection pointing to same file
        store2 = SagaPersistence(db_path)
        loaded = store2.load_job("job-file-01")
        assert loaded.job_id == "job-file-01"
        assert loaded.state == SagaState.DONE
        store2.close()
