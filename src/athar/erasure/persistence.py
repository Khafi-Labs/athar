"""SQLite-backed persistence provider for Athar erasure jobs.

Provides durable transactional storage, retrieval, and querying of erasure jobs
across restarts and lifecycle stage transitions.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from athar.crypto.canonical_json import canonical_json_encode
from athar.erasure.saga import ErasureJob, ErasureManifest, SagaState
from athar.policy.models import EligibilityDecision


class SagaPersistence:
    """SQLite-backed repository for persisting ErasureJob lifecycle states."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        """Initialize SagaPersistence.

        Args:
            db_path: Path to SQLite database file. If None, an in-memory database is used.
        """
        self.db_path = str(db_path) if db_path else ":memory:"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        """Create erasure jobs table and indexes."""
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS erasure_jobs (
                    job_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    subject_pseudonym TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    eligibility_decision_json TEXT NOT NULL,
                    state_history_json TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_state ON erasure_jobs(state)")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_subject ON erasure_jobs(subject_pseudonym)"
            )

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def save_job(self, job: ErasureJob) -> None:
        """Persist or update an ErasureJob.

        Args:
            job: ErasureJob to save.
        """
        manifest_json = canonical_json_encode(job.manifest.to_dict()).decode("utf-8")
        eligibility_json = canonical_json_encode(job.eligibility_decision.to_dict()).decode(
            "utf-8"
        )
        state_history_data = [
            [s.value if isinstance(s, SagaState) else str(s), dt.isoformat()]
            for s, dt in job.state_history
        ]
        state_history_json = json.dumps(state_history_data)

        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO erasure_jobs (
                    job_id,
                    state,
                    subject_pseudonym,
                    purpose,
                    policy_hash,
                    manifest_json,
                    eligibility_decision_json,
                    state_history_json,
                    error,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.job_id,
                    job.state.value if isinstance(job.state, SagaState) else str(job.state),
                    job.manifest.subject_pseudonym,
                    job.manifest.purpose,
                    job.policy_hash,
                    manifest_json,
                    eligibility_json,
                    state_history_json,
                    job.error,
                    job.created_at.isoformat(),
                    job.updated_at.isoformat(),
                ),
            )

    def load_job(self, job_id: str) -> ErasureJob:
        """Load an ErasureJob by its unique UUID.

        Args:
            job_id: UUID of the job.

        Returns:
            Instantiated ErasureJob.

        Raises:
            KeyError: If no job with the specified job_id exists.
        """
        cursor = self._conn.execute(
            """
            SELECT
                job_id,
                state,
                manifest_json,
                policy_hash,
                eligibility_decision_json,
                state_history_json,
                error,
                created_at,
                updated_at
            FROM erasure_jobs
            WHERE job_id = ?
            """,
            (job_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise KeyError(f"Erasure job '{job_id}' not found in persistence store")

        return self._row_to_job(row)

    def list_jobs(self, state: SagaState | None = None) -> list[ErasureJob]:
        """List all persisted erasure jobs, optionally filtered by state.

        Args:
            state: Optional SagaState to filter by.

        Returns:
            List of matching ErasureJob instances ordered by creation timestamp.
        """
        if state is not None:
            cursor = self._conn.execute(
                """
                SELECT
                    job_id,
                    state,
                    manifest_json,
                    policy_hash,
                    eligibility_decision_json,
                    state_history_json,
                    error,
                    created_at,
                    updated_at
                FROM erasure_jobs
                WHERE state = ?
                ORDER BY created_at ASC
                """,
                (state.value if isinstance(state, SagaState) else str(state),),
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT
                    job_id,
                    state,
                    manifest_json,
                    policy_hash,
                    eligibility_decision_json,
                    state_history_json,
                    error,
                    created_at,
                    updated_at
                FROM erasure_jobs
                ORDER BY created_at ASC
                """
            )

        return [self._row_to_job(row) for row in cursor.fetchall()]

    def list_incomplete(self) -> list[ErasureJob]:
        """List all erasure jobs that are incomplete (not in DONE or FAILED_PARTIAL state).

        Returns:
            List of incomplete ErasureJob instances ordered by creation timestamp.
        """
        cursor = self._conn.execute(
            """
            SELECT
                job_id,
                state,
                manifest_json,
                policy_hash,
                eligibility_decision_json,
                state_history_json,
                error,
                created_at,
                updated_at
            FROM erasure_jobs
            WHERE state NOT IN (?, ?)
            ORDER BY created_at ASC
            """,
            (SagaState.DONE.value, SagaState.FAILED_PARTIAL.value),
        )
        return [self._row_to_job(row) for row in cursor.fetchall()]

    def _row_to_job(self, row: sqlite3.Row) -> ErasureJob:
        """Helper to deserialize a database row into an ErasureJob."""
        manifest_data = json.loads(row["manifest_json"])
        manifest = ErasureManifest.from_dict(manifest_data)

        eligibility_data = json.loads(row["eligibility_decision_json"])
        eligibility_decision = EligibilityDecision.from_dict(eligibility_data)

        state_history_raw = json.loads(row["state_history_json"])
        state_history: list[tuple[SagaState, datetime]] = [
            (
                SagaState(item[0]),
                datetime.fromisoformat(item[1]),
            )
            for item in state_history_raw
        ]

        return ErasureJob(
            job_id=row["job_id"],
            state=SagaState(row["state"]),
            manifest=manifest,
            policy_hash=row["policy_hash"],
            eligibility_decision=eligibility_decision,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            state_history=state_history,
            error=row["error"],
        )


# Global default persistence instance for module-level convenience functions
_default_persistence = SagaPersistence()


def save_job(job: ErasureJob) -> None:
    """Save an erasure job using default persistence repository."""
    _default_persistence.save_job(job)


def load_job(job_id: str) -> ErasureJob:
    """Load an erasure job by UUID using default persistence repository."""
    return _default_persistence.load_job(job_id)


def list_jobs(state: SagaState | None = None) -> list[ErasureJob]:
    """List erasure jobs using default persistence repository."""
    return _default_persistence.list_jobs(state=state)


def list_incomplete() -> list[ErasureJob]:
    """List incomplete erasure jobs using default persistence repository."""
    return _default_persistence.list_incomplete()
