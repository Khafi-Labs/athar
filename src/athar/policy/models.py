"""Policy models for retention rules, legal holds, and erasure eligibility.

This module defines the core data structures used by Athar's policy engine to determine
whether personal data associated with a subject pseudonym and processing purpose is
eligible for cryptographic erasure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from athar.crypto.canonical_json import canonical_json_hash


class RetentionBasis(str, Enum):
    """Legal basis underpinning data retention under data protection frameworks (e.g. GDPR)."""

    LEGAL_OBLIGATION = "LEGAL_OBLIGATION"
    CONSENT = "CONSENT"
    LEGITIMATE_INTEREST = "LEGITIMATE_INTEREST"
    CONTRACT = "CONTRACT"
    STATUTORY_AML = "STATUTORY_AML"
    REGULATOR_INSTRUCTION = "REGULATOR_INSTRUCTION"
    PDPL_PURPOSE_LIMITATION = "PDPL_PURPOSE_LIMITATION"


class EligibilityResult(str, Enum):
    """Outcome of an erasure eligibility evaluation."""

    ELIGIBLE = "ELIGIBLE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class RetentionRule:
    """Retention rule defining retention duration and statutory basis for a purpose.

    Attributes:
        purpose: Business or processing purpose (e.g., 'kyc_verification', 'marketing').
        category: Category of data affected (e.g., 'financial_id', 'telemetry').
        retention_period: Mandatory duration after data creation before erasure is permissible.
        legal_basis: Statutory or contractual ground requiring retention.
        description: Human-readable justification of the retention requirement.
        citation: Statute/instruction relied on (article numbers, source, caveats).
        period_confirmed: False means the period has NOT been established from a
            legal source. The engine fails safe: erasure is BLOCKED until a reviewed
            period is supplied.
        retention_trigger: Event the period runs from (DATA_CREATION,
            ACCOUNT_CLOSURE, TRANSACTION_COMPLETION, ...). The caller must pass the
            matching date as ``data_created_at``; the engine cannot infer it.
    """

    purpose: str
    category: str
    retention_period: timedelta
    legal_basis: RetentionBasis
    description: str
    citation: str = ""
    period_confirmed: bool = True
    retention_trigger: str = "DATA_CREATION"

    def to_canonical_dict(self) -> dict[str, Any]:
        """Convert rule into canonical dictionary representation for RFC 8785 hashing.

        Returns:
            Dictionary with stable keys and integer seconds for retention period.
        """
        d: dict[str, Any] = {
            "category": self.category,
            "description": self.description,
            "legal_basis": self.legal_basis.value,
            "purpose": self.purpose,
            "retention_period_seconds": int(self.retention_period.total_seconds()),
        }
        # New fields are hashed only when set, so pre-existing policy hashes are unchanged.
        if self.citation:
            d["citation"] = self.citation
        if not self.period_confirmed:
            d["period_confirmed"] = False
        if self.retention_trigger != "DATA_CREATION":
            d["retention_trigger"] = self.retention_trigger
        return d

    def to_dict(self) -> dict[str, Any]:
        """Convert rule to a JSON-serializable dictionary."""
        return {
            "purpose": self.purpose,
            "category": self.category,
            "retention_period_seconds": int(self.retention_period.total_seconds()),
            "legal_basis": self.legal_basis.value,
            "description": self.description,
            "citation": self.citation,
            "period_confirmed": self.period_confirmed,
            "retention_trigger": self.retention_trigger,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RetentionRule:
        """Instantiate RetentionRule from dictionary.

        Args:
            data: Dictionary containing serialized rule fields.

        Returns:
            RetentionRule instance.
        """
        period_seconds = data.get("retention_period_seconds")
        if period_seconds is not None:
            retention_period = timedelta(seconds=period_seconds)
        else:
            retention_period = timedelta(seconds=data.get("retention_period", 0))

        basis_val = data["legal_basis"]
        legal_basis = (
            basis_val if isinstance(basis_val, RetentionBasis) else RetentionBasis(basis_val)
        )

        return cls(
            purpose=data["purpose"],
            category=data["category"],
            retention_period=retention_period,
            legal_basis=legal_basis,
            description=data.get("description", ""),
            citation=data.get("citation", ""),
            period_confirmed=data.get("period_confirmed", True),
            retention_trigger=data.get("retention_trigger", "DATA_CREATION"),
        )


@dataclass
class LegalHold:
    """Legal hold suspending destruction of records due to active investigation or litigation.

    Attributes:
        hold_id: Unique identifier for the legal hold.
        scope: Subject pseudonym to hold, or 'ALL' for system-wide holds.
        reason: Justification or court case reference for the hold.
        issuer: Authority or officer who issued the legal hold.
        started_at: Timestamp when the hold was imposed.
        expires_at: Optional timestamp when the hold automatically expires.
        active: Boolean flag indicating if the hold is currently enforceable.
    """

    hold_id: str
    scope: str
    reason: str
    issuer: str
    started_at: datetime
    expires_at: datetime | None = None
    active: bool = True

    def is_currently_active(self, at_time: datetime | None = None) -> bool:
        """Check whether the legal hold is active at the specified timestamp.

        Args:
            at_time: Timestamp to test against (defaults to current UTC time).

        Returns:
            True if the hold is marked active and has not expired.
        """
        if not self.active:
            return False
        eval_time = at_time or datetime.now(UTC)
        if eval_time.tzinfo is None:
            eval_time = eval_time.replace(tzinfo=UTC)

        hold_start = self.started_at
        if hold_start.tzinfo is None:
            hold_start = hold_start.replace(tzinfo=UTC)
        if eval_time < hold_start:
            return False

        if self.expires_at is not None:
            hold_exp = self.expires_at
            if hold_exp.tzinfo is None:
                hold_exp = hold_exp.replace(tzinfo=UTC)
            if eval_time >= hold_exp:
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert LegalHold to a JSON-serializable dictionary."""
        return {
            "hold_id": self.hold_id,
            "scope": self.scope,
            "reason": self.reason,
            "issuer": self.issuer,
            "started_at": self.started_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LegalHold:
        """Instantiate LegalHold from dictionary."""
        started_at = datetime.fromisoformat(data["started_at"])
        expires_at = datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
        return cls(
            hold_id=data["hold_id"],
            scope=data["scope"],
            reason=data["reason"],
            issuer=data["issuer"],
            started_at=started_at,
            expires_at=expires_at,
            active=data.get("active", True),
        )


@dataclass
class Policy:
    """Organizational retention policy containing rules, legal holds, and safety parameters.

    Attributes:
        version: Semantic or revision version string for the policy (e.g. '1.0.0').
        rules: List of active retention rules.
        holds: List of legal holds.
        requires_two_person_approval: Whether destruction requires dual authorization.
        grace_period: Time window between intent scheduling and physical key destruction.
        policy_hash: Cryptographic hash of canonical JSON of rules (computed if empty).
        jurisdiction: Jurisdiction code the policy was written for (e.g. "EG"), or "".
        regime: Regulatory regime within the jurisdiction (e.g. "CBE_BANK"), or "".
        legal_review: Review state of the rule set ("NOT_REVIEWED" unless counsel signed off).
    """

    version: str
    rules: list[RetentionRule] = field(default_factory=list)
    holds: list[LegalHold] = field(default_factory=list)
    requires_two_person_approval: bool = False
    grace_period: timedelta = field(default_factory=lambda: timedelta(hours=72))
    policy_hash: str = ""
    jurisdiction: str = ""
    regime: str = ""
    legal_review: str = "NOT_REVIEWED"

    def __post_init__(self) -> None:
        """Ensure policy_hash is computed if not explicitly provided."""
        if not self.policy_hash:
            self.policy_hash = self.compute_rules_hash()

    def compute_rules_hash(self) -> str:
        """Compute the canonical JSON SHA-256 digest of all retention rules.

        Rules are sorted by purpose and category to guarantee determinism.

        Returns:
            SHA-256 hex digest string.
        """
        canonical_rules = [
            rule.to_canonical_dict()
            for rule in sorted(self.rules, key=lambda r: (r.purpose, r.category))
        ]
        payload: dict[str, Any] = {
            "rules": canonical_rules,
            "version": self.version,
        }
        if self.jurisdiction:
            payload["jurisdiction"] = self.jurisdiction
        if self.regime:
            payload["regime"] = self.regime
        return canonical_json_hash(payload)

    def to_dict(self) -> dict[str, Any]:
        """Convert Policy to a JSON-serializable dictionary."""
        return {
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
            "holds": [hold.to_dict() for hold in self.holds],
            "requires_two_person_approval": self.requires_two_person_approval,
            "grace_period_seconds": int(self.grace_period.total_seconds()),
            "policy_hash": self.policy_hash,
            "jurisdiction": self.jurisdiction,
            "regime": self.regime,
            "legal_review": self.legal_review,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        """Instantiate Policy from dictionary."""
        rules = [RetentionRule.from_dict(r) for r in data.get("rules", [])]
        holds = [LegalHold.from_dict(h) for h in data.get("holds", [])]
        grace_seconds = data.get("grace_period_seconds", 72 * 3600)
        policy = cls(
            version=data["version"],
            rules=rules,
            holds=holds,
            requires_two_person_approval=data.get("requires_two_person_approval", False),
            grace_period=timedelta(seconds=grace_seconds),
            policy_hash=data.get("policy_hash", ""),
            jurisdiction=data.get("jurisdiction", ""),
            regime=data.get("regime", ""),
            legal_review=data.get("legal_review", "NOT_REVIEWED"),
        )
        return policy


@dataclass
class EligibilityDecision:
    """Detailed result of evaluating whether data can be scheduled for erasure.

    Attributes:
        result: ELIGIBLE or BLOCKED.
        reason: Explanation of the eligibility assessment outcome.
        blocking_holds: Identifiers of active legal holds that prevented erasure.
        retention_expires_at: Timestamp when statutory retention period expires/expired.
        evaluated_at: Timestamp when this decision was computed.
        policy_version: Version of the policy used for evaluation.
    """

    result: EligibilityResult
    reason: str
    blocking_holds: list[str] = field(default_factory=list)
    retention_expires_at: datetime | None = None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    policy_version: str = ""

    @property
    def is_eligible(self) -> bool:
        """Convenience property returning True if erasure is eligible."""
        return self.result == EligibilityResult.ELIGIBLE

    def to_dict(self) -> dict[str, Any]:
        """Convert EligibilityDecision to a JSON-serializable dictionary."""
        return {
            "result": self.result.value,
            "reason": self.reason,
            "blocking_holds": list(self.blocking_holds),
            "retention_expires_at": self.retention_expires_at.isoformat()
            if self.retention_expires_at
            else None,
            "evaluated_at": self.evaluated_at.isoformat(),
            "policy_version": self.policy_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EligibilityDecision:
        """Instantiate EligibilityDecision from dictionary."""
        result_val = data["result"]
        result = (
            result_val
            if isinstance(result_val, EligibilityResult)
            else EligibilityResult(result_val)
        )
        retention_expires_at = (
            datetime.fromisoformat(data["retention_expires_at"])
            if data.get("retention_expires_at")
            else None
        )
        evaluated_at = (
            datetime.fromisoformat(data["evaluated_at"])
            if data.get("evaluated_at")
            else datetime.now(UTC)
        )
        return cls(
            result=result,
            reason=data["reason"],
            blocking_holds=data.get("blocking_holds", []),
            retention_expires_at=retention_expires_at,
            evaluated_at=evaluated_at,
            policy_version=data.get("policy_version", ""),
        )
