"""Comprehensive unit tests for Athar policy models and policy engine."""

from datetime import UTC, datetime, timedelta

import pytest

from athar.policy import (
    EligibilityResult,
    LegalHold,
    Policy,
    PolicyEngine,
    RetentionBasis,
    RetentionRule,
)


@pytest.fixture
def sample_retention_rules() -> list[RetentionRule]:
    return [
        RetentionRule(
            purpose="kyc_verification",
            category="financial_id",
            retention_period=timedelta(days=1825),  # 5 years
            legal_basis=RetentionBasis.LEGAL_OBLIGATION,
            description="Anti-Money Laundering (AML) 5-year retention obligation",
        ),
        RetentionRule(
            purpose="marketing",
            category="behavioral_telemetry",
            retention_period=timedelta(days=90),
            legal_basis=RetentionBasis.CONSENT,
            description="Consent-based telemetry expires after 90 days",
        ),
    ]


@pytest.fixture
def sample_policy(sample_retention_rules: list[RetentionRule]) -> Policy:
    return Policy(
        version="1.0.0",
        rules=sample_retention_rules,
        holds=[],
        requires_two_person_approval=False,
        grace_period=timedelta(hours=72),
    )


def test_retention_rule_serialization() -> None:
    rule = RetentionRule(
        purpose="kyc_verification",
        category="identity",
        retention_period=timedelta(days=365),
        legal_basis=RetentionBasis.LEGAL_OBLIGATION,
        description="Statutory KYC retention",
    )
    d = rule.to_dict()
    restored = RetentionRule.from_dict(d)
    assert restored.purpose == rule.purpose
    assert restored.category == rule.category
    assert restored.retention_period == rule.retention_period
    assert restored.legal_basis == rule.legal_basis


def test_legal_hold_lifecycle() -> None:
    now = datetime.now(UTC)
    hold = LegalHold(
        hold_id="HOLD-2026-001",
        scope="sub_pseudonym_alpha",
        reason="Subpoena case #88219",
        issuer="Legal Compliance Dept",
        started_at=now - timedelta(days=5),
        expires_at=now + timedelta(days=30),
        active=True,
    )

    assert hold.is_currently_active(now) is True

    # Test expired hold
    expired_hold = LegalHold(
        hold_id="HOLD-2026-002",
        scope="ALL",
        reason="Temporary injunction",
        issuer="District Court",
        started_at=now - timedelta(days=20),
        expires_at=now - timedelta(days=1),
        active=True,
    )
    assert expired_hold.is_currently_active(now) is False

    # Test manually deactivated hold
    hold.active = False
    assert hold.is_currently_active(now) is False


def test_policy_hash_determinism(sample_retention_rules: list[RetentionRule]) -> None:
    # Reverse the order of rules passed in
    p1 = Policy(version="1.0.0", rules=sample_retention_rules)
    p2 = Policy(version="1.0.0", rules=list(reversed(sample_retention_rules)))

    assert p1.policy_hash != ""
    assert p1.policy_hash == p2.policy_hash
    assert len(p1.policy_hash) == 64


def test_evaluate_retention_not_expired(sample_policy: Policy) -> None:
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)
    # KYC requires 5 years; data created 2 years ago
    created_at = now - timedelta(days=730)

    decision = engine.evaluate(
        subject_pseudonym="sub_xyz",
        purpose="kyc_verification",
        data_created_at=created_at,
        current_time=now,
    )

    assert decision.result == EligibilityResult.BLOCKED
    assert "Retention period has not expired" in decision.reason
    assert decision.retention_expires_at is not None
    assert decision.retention_expires_at > now


def test_evaluate_retention_expired(sample_policy: Policy) -> None:
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)
    # Marketing requires 90 days; data created 120 days ago
    created_at = now - timedelta(days=120)

    decision = engine.evaluate(
        subject_pseudonym="sub_xyz",
        purpose="marketing",
        data_created_at=created_at,
        current_time=now,
    )

    assert decision.result == EligibilityResult.ELIGIBLE
    assert decision.is_eligible is True
    assert decision.retention_expires_at is not None
    assert decision.retention_expires_at <= now


def test_evaluate_unknown_purpose(sample_policy: Policy) -> None:
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)

    decision = engine.evaluate(
        subject_pseudonym="sub_xyz",
        purpose="unregistered_analytics",
        data_created_at=now - timedelta(days=1000),
        current_time=now,
    )

    assert decision.result == EligibilityResult.BLOCKED
    assert "No retention rule defined" in decision.reason


def test_evaluate_active_legal_hold(sample_policy: Policy) -> None:
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)

    hold = LegalHold(
        hold_id="HOLD-AML-991",
        scope="sub_investigated",
        reason="Pending regulatory audit",
        issuer="Regulatory Affairs",
        started_at=now - timedelta(days=1),
        active=True,
    )
    engine.add_hold(hold)

    # Marketing retention expired
    created_at = now - timedelta(days=200)

    decision = engine.evaluate(
        subject_pseudonym="sub_investigated",
        purpose="marketing",
        data_created_at=created_at,
        current_time=now,
    )

    assert decision.result == EligibilityResult.BLOCKED
    assert "HOLD-AML-991" in decision.blocking_holds
    assert (
        "Active legal hold" in decision.reason
        or "blocked by active legal hold" in decision.reason.lower()
    )

    # Another subject without hold should be eligible
    decision_other = engine.evaluate(
        subject_pseudonym="sub_clean",
        purpose="marketing",
        data_created_at=created_at,
        current_time=now,
    )
    assert decision_other.result == EligibilityResult.ELIGIBLE


def test_evaluate_systemwide_legal_hold(sample_policy: Policy) -> None:
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)

    hold = LegalHold(
        hold_id="HOLD-GLOBAL-01",
        scope="ALL",
        reason="Litigation freeze",
        issuer="General Counsel",
        started_at=now - timedelta(days=1),
        active=True,
    )
    engine.add_hold(hold)

    decision = engine.evaluate(
        subject_pseudonym="any_subject",
        purpose="marketing",
        data_created_at=now - timedelta(days=200),
        current_time=now,
    )
    assert decision.result == EligibilityResult.BLOCKED
    assert "HOLD-GLOBAL-01" in decision.blocking_holds

    # Release hold and re-evaluate
    engine.release_hold("HOLD-GLOBAL-01")
    decision_after = engine.evaluate(
        subject_pseudonym="any_subject",
        purpose="marketing",
        data_created_at=now - timedelta(days=200),
        current_time=now,
    )
    assert decision_after.result == EligibilityResult.ELIGIBLE


def test_two_person_approval_validation(sample_policy: Policy) -> None:
    sample_policy.requires_two_person_approval = True
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)
    created_at = now - timedelta(days=200)

    # Without approvers -> BLOCKED
    d1 = engine.evaluate("sub_xyz", "marketing", created_at, approvers=None, current_time=now)
    assert d1.result == EligibilityResult.BLOCKED
    assert "two-person approval" in d1.reason.lower()

    # Identical approvers -> BLOCKED
    d2 = engine.evaluate(
        "sub_xyz",
        "marketing",
        created_at,
        approvers=("alice@example.com", "alice@example.com"),
        current_time=now,
    )
    assert d2.result == EligibilityResult.BLOCKED
    assert "distinct" in d2.reason.lower()

    # Distinct approvers -> ELIGIBLE
    d3 = engine.evaluate(
        "sub_xyz",
        "marketing",
        created_at,
        approvers=("alice@example.com", "bob@example.com"),
        current_time=now,
    )
    assert d3.result == EligibilityResult.ELIGIBLE


def test_grace_period_calculation(sample_policy: Policy) -> None:
    engine = PolicyEngine(sample_policy)
    now = datetime.now(UTC)
    scheduled = now + timedelta(hours=72)

    assert engine.is_within_grace_period(scheduled, current_time=now) is True
    assert (
        engine.is_within_grace_period(scheduled, current_time=now + timedelta(hours=73)) is False
    )
