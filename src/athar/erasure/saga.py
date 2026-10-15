"""Core resumable Erasure Saga state machine for Athar.

This module orchestrates verifiable erasure across heterogeneous storage surfaces,
cryptographic key destruction (SIMULATED in MVP), remnant canary verification,
and append-only fact logging.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from athar.erasure.connectors import PurgeConnector, PurgeTarget
from athar.policy.engine import PolicyEngine
from athar.policy.models import EligibilityDecision, EligibilityResult


class SagaState(str, Enum):
    """Discrete states of the erasure saga lifecycle."""

    PLANNED = "PLANNED"
    INTENT_LOGGED = "INTENT_LOGGED"
    HOLD_REVALIDATED = "HOLD_REVALIDATED"
    KEY_SCHEDULED = "KEY_SCHEDULED"
    SURFACES_PURGED = "SURFACES_PURGED"
    KEY_DESTROYED = "KEY_DESTROYED"
    VERIFIED = "VERIFIED"
    FACT_APPENDED = "FACT_APPENDED"
    DONE = "DONE"
    FAILED_PARTIAL = "FAILED_PARTIAL"


@dataclass
class ErasureManifest:
    """Detailed erasure specification enumerating purge targets and known coverage gaps.

    Attributes:
        job_id: Unique UUID string identifying this erasure job.
        subject_pseudonym: Opaque pseudonym identifying the subject.
        purpose: Processing purpose being erased.
        targets: List of storage surfaces targeted for purging.
        known_gaps: Surfaces intentionally not purged (e.g. immutable legal archives, offline tapes).
    """

    job_id: str
    subject_pseudonym: str
    purpose: str
    targets: list[PurgeTarget] = field(default_factory=list)
    known_gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to JSON-serializable dictionary."""
        return {
            "job_id": self.job_id,
            "subject_pseudonym": self.subject_pseudonym,
            "purpose": self.purpose,
            "targets": [t.to_dict() for t in self.targets],
            "known_gaps": list(self.known_gaps),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ErasureManifest:
        """Instantiate ErasureManifest from dictionary."""
        return cls(
            job_id=data["job_id"],
            subject_pseudonym=data["subject_pseudonym"],
            purpose=data["purpose"],
            targets=[PurgeTarget.from_dict(t) for t in data.get("targets", [])],
            known_gaps=data.get("known_gaps", []),
        )


@dataclass
class ErasureJob:
    """Stateful erasure job tracking lifecycle progression, policy context, and history.

    Attributes:
        job_id: Unique UUID of the job.
        state: Current SagaState.
        manifest: ErasureManifest specifying targets and known gaps.
        policy_hash: SHA-256 canonical hash of the policy under which erasure was authorized.
        eligibility_decision: Initial EligibilityDecision authorizing the job.
        created_at: Timestamp when job was created.
        updated_at: Timestamp of last state change.
        state_history: Audit history of (SagaState, timestamp) tuples.
        error: Error description if the job transitioned to FAILED_PARTIAL.
    """

    job_id: str
    state: SagaState
    manifest: ErasureManifest
    policy_hash: str
    eligibility_decision: EligibilityDecision
    created_at: datetime
    updated_at: datetime
    state_history: list[tuple[SagaState, datetime]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert ErasureJob to JSON-serializable dictionary."""
        return {
            "job_id": self.job_id,
            "state": self.state.value,
            "manifest": self.manifest.to_dict(),
            "policy_hash": self.policy_hash,
            "eligibility_decision": self.eligibility_decision.to_dict(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "state_history": [
                [s.value if isinstance(s, SagaState) else str(s), dt.isoformat()]
                for s, dt in self.state_history
            ],
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ErasureJob:
        """Instantiate ErasureJob from dictionary."""
        state_val = data["state"]
        state = state_val if isinstance(state_val, SagaState) else SagaState(state_val)

        state_history: list[tuple[SagaState, datetime]] = []
        for item in data.get("state_history", []):
            st = item[0] if isinstance(item[0], SagaState) else SagaState(item[0])
            dt = datetime.fromisoformat(item[1]) if isinstance(item[1], str) else item[1]
            state_history.append((st, dt))

        return cls(
            job_id=data["job_id"],
            state=state,
            manifest=ErasureManifest.from_dict(data["manifest"]),
            policy_hash=data["policy_hash"],
            eligibility_decision=EligibilityDecision.from_dict(data["eligibility_decision"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            state_history=state_history,
            error=data.get("error"),
        )


class ErasureSaga:
    """Resumable state machine orchestrating end-to-end verifiable cryptographic erasure.

    Lifecycle transitions:
        1. PLANNED -> INTENT_LOGGED: Record intent in append-only fact log.
        2. INTENT_LOGGED -> HOLD_REVALIDATED: Re-check active legal holds.
        3. HOLD_REVALIDATED -> KEY_SCHEDULED: Schedule key destruction (respecting grace period).
        4. KEY_SCHEDULED -> SURFACES_PURGED: Invoke connectors across storage surfaces.
        5. SURFACES_PURGED -> KEY_DESTROYED: Destroy DEK (and PPK if last subject) [SIMULATED].
        6. KEY_DESTROYED -> VERIFIED: Execute canary scans and vault retrieval tests.
        7. VERIFIED -> FACT_APPENDED: Append verifiable erasure fact to log.
        8. FACT_APPENDED -> DONE: Erasure completed successfully.

    Failure at any point transitions to FAILED_PARTIAL and records the diagnostic error.
    All transitions are persisted before moving to subsequent stages.
    """

    def __init__(
        self,
        keystore: Any,
        vault: Any,
        policy_engine: PolicyEngine,
        fact_log: Any,
        connectors: list[PurgeConnector],
        persistence: Any | None = None,
    ) -> None:
        """Initialize ErasureSaga.

        Args:
            keystore: Keystore managing DEK/PPK cryptographic keys (SIMULATED destruction in MVP).
            vault: Vault managing encrypted records and retrieval tests.
            policy_engine: PolicyEngine for eligibility checks and hold revalidation.
            fact_log: Append-only log recording intent and completion facts.
            connectors: List of PurgeConnector instances for storage surfaces.
            persistence: Storage provider for persisting saga job states. If None,
                an in-memory SagaPersistence instance is instantiated.
        """
        self.keystore = keystore
        self.vault = vault
        self.policy_engine = policy_engine
        self.fact_log = fact_log
        self.connectors = connectors

        if persistence is None:
            from athar.erasure.persistence import SagaPersistence

            self.persistence = SagaPersistence()
        else:
            self.persistence = persistence

    def plan(
        self,
        subject_pseudonym: str,
        purpose: str,
        data_created_at: datetime | None = None,
        approvers: tuple[str, str] | None = None,
        manifest: ErasureManifest | None = None,
        known_gaps: list[str] | None = None,
    ) -> ErasureJob:
        """Plan a new erasure job and evaluate eligibility under active policy.

        Args:
            subject_pseudonym: Opaque pseudonym identifying the subject.
            purpose: Processing purpose targeted for erasure.
            data_created_at: Creation timestamp of the data. REQUIRED: retention
                periods are measured from it, so there is no safe default.
            approvers: Optional dual-approver identities if two-person approval required.
            manifest: Optional custom manifest. If omitted, default targets are generated
                from registered connectors.
            known_gaps: Optional coverage gaps to record in manifest.

        Returns:
            ErasureJob in PLANNED state.

        Raises:
            ValueError: If data_created_at is missing, or policy evaluation
                determines data is BLOCKED from erasure.
        """
        if data_created_at is None:
            raise ValueError(
                "data_created_at is required: retention cannot be evaluated without "
                "the data's creation time"
            )
        eval_created_at = data_created_at
        decision = self.policy_engine.evaluate(
            subject_pseudonym=subject_pseudonym,
            purpose=purpose,
            data_created_at=eval_created_at,
            approvers=approvers,
        )

        if decision.result == EligibilityResult.BLOCKED:
            raise ValueError(f"Erasure plan blocked by policy: {decision.reason}")

        job_id = str(uuid.uuid4())
        now = datetime.now(UTC)

        if manifest is None:
            targets = [
                PurgeTarget(
                    surface_name=c.surface_name,
                    surface_type=c.surface_type,
                    status="pending",
                )
                for c in self.connectors
            ]
            manifest = ErasureManifest(
                job_id=job_id,
                subject_pseudonym=subject_pseudonym,
                purpose=purpose,
                targets=targets,
                known_gaps=known_gaps or [],
            )
        else:
            manifest.job_id = job_id

        policy_hash = self.policy_engine.compute_policy_hash()

        job = ErasureJob(
            job_id=job_id,
            state=SagaState.PLANNED,
            manifest=manifest,
            policy_hash=policy_hash,
            eligibility_decision=decision,
            created_at=now,
            updated_at=now,
            state_history=[(SagaState.PLANNED, now)],
            error=None,
        )

        self.persistence.save_job(job)
        return job

    def execute(self, job: ErasureJob) -> ErasureJob:
        """Drive the erasure state machine forward through all remaining lifecycle states.

        Args:
            job: ErasureJob to execute.

        Returns:
            Updated ErasureJob in DONE or FAILED_PARTIAL state.
        """
        if job.state == SagaState.DONE:
            return job

        if job.state == SagaState.FAILED_PARTIAL:
            return job

        # 1. PLANNED -> INTENT_LOGGED
        if job.state == SagaState.PLANNED:
            try:
                self._log_intent(job)
                self._transition(job, SagaState.PLANNED, SagaState.INTENT_LOGGED)
            except Exception as ex:
                self._transition_to_failed(job, f"Failed logging intent: {ex}")
                return job

        # 2. INTENT_LOGGED -> HOLD_REVALIDATED
        if job.state == SagaState.INTENT_LOGGED:
            active_holds = self.policy_engine.get_active_holds(job.manifest.subject_pseudonym)
            if active_holds:
                hold_ids = [h.hold_id for h in active_holds]
                err = f"Active legal hold detected during revalidation: {', '.join(hold_ids)}"
                self._transition_to_failed(job, err)
                return job

            self._transition(job, SagaState.INTENT_LOGGED, SagaState.HOLD_REVALIDATED)

        # 3. HOLD_REVALIDATED -> KEY_SCHEDULED
        if job.state == SagaState.HOLD_REVALIDATED:
            try:
                grace = self.policy_engine.policy.grace_period
                scheduled_time = datetime.now(UTC) + grace
                if hasattr(self.keystore, "schedule_destruction"):
                    self.keystore.schedule_destruction(
                        job.manifest.subject_pseudonym,
                        job.manifest.purpose,
                        scheduled_time,
                    )
                self._transition(job, SagaState.HOLD_REVALIDATED, SagaState.KEY_SCHEDULED)
            except Exception as ex:
                self._transition_to_failed(job, f"Failed scheduling key destruction: {ex}")
                return job

        # 4. KEY_SCHEDULED -> SURFACES_PURGED
        if job.state == SagaState.KEY_SCHEDULED:
            success = self._purge_surfaces(job)
            if not success:
                return job
            self._transition(job, SagaState.KEY_SCHEDULED, SagaState.SURFACES_PURGED)

        # 5. SURFACES_PURGED -> KEY_DESTROYED
        if job.state == SagaState.SURFACES_PURGED:
            try:
                self._destroy_keys(job)
                self._transition(job, SagaState.SURFACES_PURGED, SagaState.KEY_DESTROYED)
            except Exception as ex:
                self._transition_to_failed(job, f"SIMULATED key destruction failed: {ex}")
                return job

        # 6. KEY_DESTROYED -> VERIFIED
        if job.state == SagaState.KEY_DESTROYED:
            verified, error_msg = self._verify_erasure(job)
            if not verified:
                self._transition_to_failed(job, f"Erasure verification failed: {error_msg}")
                return job
            self._transition(job, SagaState.KEY_DESTROYED, SagaState.VERIFIED)

        # 7. VERIFIED -> FACT_APPENDED
        if job.state == SagaState.VERIFIED:
            try:
                self._append_erasure_fact(job)
                self._transition(job, SagaState.VERIFIED, SagaState.FACT_APPENDED)
            except Exception as ex:
                self._transition_to_failed(job, f"Failed appending fact to log: {ex}")
                return job

        # 8. FACT_APPENDED -> DONE
        if job.state == SagaState.FACT_APPENDED:
            self._transition(job, SagaState.FACT_APPENDED, SagaState.DONE)

        return job

    def resume(self, job_id: str) -> ErasureJob:
        """Load persisted job state and resume execution from its last recorded state.

        Args:
            job_id: Identifier of the persisted job.

        Returns:
            Resumed and progressed ErasureJob.
        """
        job = self.persistence.load_job(job_id)
        if job.state in (SagaState.DONE, SagaState.FAILED_PARTIAL):
            return job
        return self.execute(job)

    def _transition(self, job: ErasureJob, from_state: SagaState, to_state: SagaState) -> None:
        """Validate and persist an orderly state transition.

        Args:
            job: Job being transitioned.
            from_state: Expected current state.
            to_state: Target state.

        Raises:
            ValueError: If job.state does not match from_state.
        """
        if job.state != from_state:
            raise ValueError(
                f"Invalid saga state transition for job {job.job_id}: "
                f"expected {from_state.value}, but current state is {job.state.value}"
            )

        now = datetime.now(UTC)
        job.state = to_state
        job.updated_at = now
        job.state_history.append((to_state, now))
        self.persistence.save_job(job)

    def _transition_to_failed(self, job: ErasureJob, error: str) -> None:
        """Transition job to FAILED_PARTIAL with error description and persist.

        Args:
            job: Job that encountered a failure.
            error: Descriptive error message.
        """
        now = datetime.now(UTC)
        job.state = SagaState.FAILED_PARTIAL
        job.error = error
        job.updated_at = now
        job.state_history.append((SagaState.FAILED_PARTIAL, now))
        self.persistence.save_job(job)

    def _log_intent(self, job: ErasureJob) -> None:
        """Append an erasure intent record to the fact log."""
        intent_payload = {
            "type": "erasure_intent",
            "job_id": job.job_id,
            "subject_pseudonym": job.manifest.subject_pseudonym,
            "purpose": job.manifest.purpose,
            "policy_hash": job.policy_hash,
            "targets": [t.surface_name for t in job.manifest.targets],
            "timestamp": datetime.now(UTC).isoformat(),
        }
        if hasattr(self.fact_log, "log_intent"):
            self.fact_log.log_intent(intent_payload)
        elif hasattr(self.fact_log, "append"):
            self.fact_log.append(intent_payload)

    def _purge_surfaces(self, job: ErasureJob) -> bool:
        """Invoke purge across all configured connectors for targets in manifest.

        Args:
            job: ErasureJob being processed.

        Returns:
            True if all surfaces purged without fatal errors; False otherwise.
        """
        connector_by_name = {c.surface_name: c for c in self.connectors}
        failed_targets: list[str] = []

        for target in job.manifest.targets:
            conn = connector_by_name.get(target.surface_name)
            if conn is None:
                target.status = "skipped"
                target.error = f"No connector configured for {target.surface_name}"
                continue

            try:
                res = conn.purge(job.manifest.subject_pseudonym, job.manifest.purpose)
                target.status = res.status
                target.rows_affected = res.rows_affected
                target.files_affected = res.files_affected
                target.error = res.error
                target.purged_at = res.purged_at or datetime.now(UTC)
                if res.status == "failed":
                    failed_targets.append(f"{target.surface_name}: {res.error}")
            except Exception as ex:
                target.status = "failed"
                target.error = str(ex)
                target.purged_at = datetime.now(UTC)
                failed_targets.append(f"{target.surface_name}: {ex}")

        # Update job in persistence after running purges
        self.persistence.save_job(job)

        if failed_targets:
            err_msg = f"Surfaces purge failure: {'; '.join(failed_targets)}"
            self._transition_to_failed(job, err_msg)
            return False

        return True

    def _destroy_keys(self, job: ErasureJob) -> None:
        """Invoke cryptographic key destruction (SIMULATED in MVP).

        Destroys Data Encryption Key (DEK) and Pseudonym Protection Key (PPK)
        if this is the last remaining purpose for the subject.
        """
        subject = job.manifest.subject_pseudonym
        purpose = job.manifest.purpose

        # 1. Destroy DEK
        if hasattr(self.keystore, "destroy_dek"):
            self.keystore.destroy_dek(subject_pseudonym=subject, purpose=purpose)
        elif hasattr(self.keystore, "destroy_key"):
            self.keystore.destroy_key(subject_pseudonym=subject, purpose=purpose)

        # 2. Check if PPK should be destroyed (last subject data check)
        is_last = True
        if hasattr(self.keystore, "has_remaining_purposes"):
            is_last = not self.keystore.has_remaining_purposes(subject)
        elif hasattr(self.keystore, "is_last_purpose_for_subject"):
            is_last = self.keystore.is_last_purpose_for_subject(subject, purpose)

        if is_last:
            if hasattr(self.keystore, "destroy_ppk"):
                self.keystore.destroy_ppk(subject_pseudonym=subject)

    def _verify_erasure(self, job: ErasureJob) -> tuple[bool, str]:
        """Perform retrieval test in vault and remnant canary scans across connectors.

        Args:
            job: ErasureJob being verified.

        Returns:
            Tuple of (is_verified, error_details).
        """
        subject = job.manifest.subject_pseudonym

        # 1. Vault retrieval test
        if self.vault is not None:
            try:
                retrieved = None
                if hasattr(self.vault, "retrieve"):
                    retrieved = self.vault.retrieve(
                        subject_pseudonym=subject, purpose=job.manifest.purpose
                    )
                elif hasattr(self.vault, "get_record"):
                    retrieved = self.vault.get_record(subject)

                if retrieved is not None and retrieved != "" and retrieved != []:
                    return (
                        False,
                        f"Vault retrieval test returned non-empty record for subject {subject}",
                    )
            except Exception as ex:
                # In cryptographic erasure, decryption failure (e.g. KeyNotFoundError)
                # is expected and proves the record is unrecoverable.
                # If the exception indicates decryption failure, that confirms erasure.
                err_str = str(ex).lower()
                if "key not found" in err_str or "destroyed" in err_str or "decrypt" in err_str:
                    pass
                else:
                    return False, f"Unexpected vault retrieval error: {ex}"

        # 2. Canary scan across connectors
        remnants_found: list[str] = []
        for conn in self.connectors:
            try:
                remnants = conn.scan_for_remnants(subject)
                if remnants:
                    remnants_found.append(
                        f"{conn.surface_name} ({len(remnants)} items: {remnants})"
                    )
            except Exception as ex:
                remnants_found.append(f"{conn.surface_name} scan error: {ex}")

        if remnants_found:
            return False, f"Remnants detected: {'; '.join(remnants_found)}"

        return True, ""

    def _append_erasure_fact(self, job: ErasureJob) -> None:
        """Append verified erasure fact to the append-only fact log."""
        fact_payload = {
            "type": "erasure_completed",
            "job_id": job.job_id,
            "subject_pseudonym": job.manifest.subject_pseudonym,
            "purpose": job.manifest.purpose,
            "policy_hash": job.policy_hash,
            "purged_targets": [
                {
                    "surface_name": t.surface_name,
                    "rows_affected": t.rows_affected,
                    "files_affected": t.files_affected,
                    "purged_at": t.purged_at.isoformat() if t.purged_at else None,
                }
                for t in job.manifest.targets
                if t.status == "purged"
            ],
            "key_destruction": "SIMULATED",
            "verified_at": datetime.now(UTC).isoformat(),
        }

        if hasattr(self.fact_log, "log_erasure"):
            self.fact_log.log_erasure(fact_payload)
        elif hasattr(self.fact_log, "append"):
            self.fact_log.append(fact_payload)
