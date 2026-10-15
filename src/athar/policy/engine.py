"""Policy Engine evaluating retention rules, legal holds, and two-person authorization.

The PolicyEngine determines whether personal data associated with a pseudonymized
subject can be legally scheduled for cryptographic erasure.
"""

from __future__ import annotations

from datetime import UTC, datetime

from athar.policy.models import (
    EligibilityDecision,
    EligibilityResult,
    LegalHold,
    Policy,
    RetentionRule,
)


class PolicyEngine:
    """Evaluates retention policies and legal holds for cryptographic erasure requests.

    Attributes:
        policy: The active policy configuration containing rules and holds.
    """

    def __init__(self, policy: Policy) -> None:
        """Initialize the policy engine with a given Policy.

        Args:
            policy: Organizational Policy defining retention rules and safety constraints.
        """
        self.policy = policy
        if not self.policy.policy_hash:
            self.policy.policy_hash = self.compute_policy_hash()

    def compute_policy_hash(self) -> str:
        """Compute the RFC 8785 canonical JSON SHA-256 hash of all policy rules.

        Returns:
            Hex-encoded SHA-256 digest string.
        """
        return self.policy.compute_rules_hash()

    def add_hold(self, hold: LegalHold) -> None:
        """Register or update a legal hold in the policy.

        If a hold with the same `hold_id` exists, it is updated in-place;
        otherwise, the new hold is appended.

        Args:
            hold: LegalHold instance to register.
        """
        for i, existing in enumerate(self.policy.holds):
            if existing.hold_id == hold.hold_id:
                self.policy.holds[i] = hold
                return
        self.policy.holds.append(hold)

    def release_hold(self, hold_id: str) -> None:
        """Release an active legal hold by marking its status inactive.

        Args:
            hold_id: Identifier of the legal hold to release.

        Raises:
            KeyError: If no legal hold with the given identifier exists.
        """
        for hold in self.policy.holds:
            if hold.hold_id == hold_id:
                hold.active = False
                return
        raise KeyError(f"Legal hold '{hold_id}' not found in active policy")

    def get_active_holds(
        self,
        subject_pseudonym: str,
        current_time: datetime | None = None,
    ) -> list[LegalHold]:
        """Retrieve all currently active legal holds that apply to the given subject.

        A hold applies if its scope is 'ALL' or matches the subject pseudonym,
        and its status is active and unexpired.

        Args:
            subject_pseudonym: Opaque pseudonym identifying the subject.
            current_time: Evaluation timestamp (defaults to current UTC time).

        Returns:
            List of matching active LegalHold instances.
        """
        eval_time = current_time or datetime.now(UTC)
        if eval_time.tzinfo is None:
            eval_time = eval_time.replace(tzinfo=UTC)

        matching_holds: list[LegalHold] = []
        for hold in self.policy.holds:
            if hold.is_currently_active(eval_time):
                if hold.scope in ("ALL", subject_pseudonym):
                    matching_holds.append(hold)
        return matching_holds

    def is_within_grace_period(
        self,
        scheduled_destruction: datetime,
        current_time: datetime | None = None,
    ) -> bool:
        """Check whether the current time is within the mandatory grace period before destruction.

        During the grace period (current_time < scheduled_destruction), destruction
        must not proceed, permitting revocation or legal hold intervention.

        Args:
            scheduled_destruction: Earliest timestamp when key destruction may proceed.
            current_time: Timestamp to test (defaults to current UTC time).

        Returns:
            True if currently within grace period (i.e. before scheduled destruction time).
        """
        now = current_time or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        target = scheduled_destruction
        if target.tzinfo is None:
            target = target.replace(tzinfo=UTC)
        return now < target

    def validate_two_person_approval(self, approver1: str, approver2: str) -> bool:
        """Validate that two-person approval requirements are satisfied by distinct actors.

        Args:
            approver1: Identity/username of first approver.
            approver2: Identity/username of second approver.

        Returns:
            True if both approvers are non-empty and distinct strings.
        """
        if not approver1 or not approver2:
            return False
        clean1 = approver1.strip().lower()
        clean2 = approver2.strip().lower()
        return bool(clean1 and clean2 and clean1 != clean2)

    def evaluate(
        self,
        subject_pseudonym: str,
        purpose: str,
        data_created_at: datetime,
        approvers: tuple[str, str] | None = None,
        current_time: datetime | None = None,
    ) -> EligibilityDecision:
        """Evaluate whether data for a subject and purpose is eligible for erasure.

        Evaluation algorithm:
        1. Identify applicable retention rules matching `purpose`.
        2. Compute required retention expiry and check if retention period has elapsed.
        3. Check for any active legal holds applicable to the subject or system-wide.
        4. If two-person approval is enforced by policy, verify dual distinct authorization.
        5. Return structured EligibilityDecision with all rationale.

        Args:
            subject_pseudonym: Pseudonym of the data subject.
            purpose: Processing purpose of the record (e.g., 'kyc_verification').
            data_created_at: Original creation timestamp of the personal data.
            approvers: Optional tuple of (approver1, approver2) for dual control.
            current_time: Optional evaluation timestamp (defaults to current UTC time).

        Returns:
            EligibilityDecision indicating ELIGIBLE or BLOCKED with detailed reasons.
        """
        eval_time = current_time or datetime.now(UTC)
        if eval_time.tzinfo is None:
            eval_time = eval_time.replace(tzinfo=UTC)

        created_time = data_created_at
        if created_time.tzinfo is None:
            created_time = created_time.replace(tzinfo=UTC)

        # 1. Match retention rules
        matching_rules = [r for r in self.policy.rules if r.purpose == purpose or r.purpose == "*"]
        if not matching_rules:
            return EligibilityDecision(
                result=EligibilityResult.BLOCKED,
                reason=f"No retention rule defined for purpose '{purpose}'",
                blocking_holds=[],
                retention_expires_at=None,
                evaluated_at=eval_time,
                policy_version=self.policy.version,
            )

        # Fail safe: a rule whose period was never established from a legal source
        # must not authorise erasure.
        unconfirmed = [r for r in matching_rules if not r.period_confirmed]
        if unconfirmed:
            names = ", ".join(f"{r.purpose} ({r.citation or 'no citation'})" for r in unconfirmed)
            return EligibilityDecision(
                result=EligibilityResult.BLOCKED,
                reason=(
                    "Retention period not legally confirmed for: "
                    f"{names}. Legal input is required before erasure can be authorised."
                ),
                blocking_holds=[],
                retention_expires_at=None,
                evaluated_at=eval_time,
                policy_version=self.policy.version,
            )

        # Check all matching rules; the maximum retention period governs
        max_expires_at: datetime | None = None
        blocking_rule: RetentionRule | None = None

        for rule in matching_rules:
            rule_expiry = created_time + rule.retention_period
            if max_expires_at is None or rule_expiry > max_expires_at:
                max_expires_at = rule_expiry
            if eval_time < rule_expiry:
                blocking_rule = rule

        if blocking_rule is not None:
            return EligibilityDecision(
                result=EligibilityResult.BLOCKED,
                reason=(
                    f"Retention period has not expired; statutory retention required until "
                    f"{max_expires_at.isoformat() if max_expires_at else ''} under "
                    f"basis {blocking_rule.legal_basis.value} (rule: {blocking_rule.description})"
                ),
                blocking_holds=[],
                retention_expires_at=max_expires_at,
                evaluated_at=eval_time,
                policy_version=self.policy.version,
            )

        # 2. Check active legal holds
        active_holds = self.get_active_holds(subject_pseudonym, current_time=eval_time)
        if active_holds:
            blocking_hold_ids = [h.hold_id for h in active_holds]
            hold_reasons = "; ".join(f"{h.hold_id} ({h.reason})" for h in active_holds)
            return EligibilityDecision(
                result=EligibilityResult.BLOCKED,
                reason=f"Erasure blocked by active legal hold(s): {hold_reasons}",
                blocking_holds=blocking_hold_ids,
                retention_expires_at=max_expires_at,
                evaluated_at=eval_time,
                policy_version=self.policy.version,
            )

        # 3. Check two-person approval requirement
        if self.policy.requires_two_person_approval:
            if approvers is None:
                return EligibilityDecision(
                    result=EligibilityResult.BLOCKED,
                    reason="Policy requires two-person approval, but no approvers were provided",
                    blocking_holds=[],
                    retention_expires_at=max_expires_at,
                    evaluated_at=eval_time,
                    policy_version=self.policy.version,
                )
            app1, app2 = approvers
            if not self.validate_two_person_approval(app1, app2):
                return EligibilityDecision(
                    result=EligibilityResult.BLOCKED,
                    reason="Two-person approval validation failed: two distinct individuals required",
                    blocking_holds=[],
                    retention_expires_at=max_expires_at,
                    evaluated_at=eval_time,
                    policy_version=self.policy.version,
                )

        # 4. All checks passed -> ELIGIBLE
        return EligibilityDecision(
            result=EligibilityResult.ELIGIBLE,
            reason="Retention period expired, no active legal holds, and approvals verified",
            blocking_holds=[],
            retention_expires_at=max_expires_at,
            evaluated_at=eval_time,
            policy_version=self.policy.version,
        )
