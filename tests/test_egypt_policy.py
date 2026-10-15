"""Tests for the Egypt jurisdiction pack."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from athar.crypto.merkle import MerkleTree
from athar.crypto.signing import SigningKeyPair
from athar.erasure.saga import ErasureSaga
from athar.log.anchoring import SimulatedAnchor
from athar.log.fact_log import Fact, FactLog
from athar.policy.engine import PolicyEngine
from athar.policy.jurisdictions import (
    EGYPT_LIMITS_AR,
    EGYPT_LIMITS_EN,
    EgyptRegime,
    egypt_policy,
)
from athar.policy.models import (
    EligibilityResult,
    Policy,
    RetentionBasis,
    RetentionRule,
)
from athar.receipt.builder import ReceiptBuilder, RetrievalTestResult
from verifier.verifier import ReceiptVerifier

NOW = datetime(2026, 10, 15, tzinfo=UTC)


def _engine(regime: EgyptRegime, approvals: bool = False) -> PolicyEngine:
    return PolicyEngine(egypt_policy(regime, requires_two_person_approval=approvals))


@pytest.mark.parametrize("regime", list(EgyptRegime))
def test_every_regime_builds_unreviewed_egypt_policy(regime: EgyptRegime) -> None:
    policy = egypt_policy(regime)
    assert policy.jurisdiction == "EG"
    assert policy.regime == regime.value
    assert policy.legal_review == "NOT_REVIEWED"
    assert policy.rules


def test_aml_records_blocked_inside_five_years_eligible_after() -> None:
    eng = _engine(EgyptRegime.CBE_BANK)
    recent = eng.evaluate(
        "subj", "aml_transaction_records", NOW - timedelta(days=3 * 365), current_time=NOW
    )
    old = eng.evaluate(
        "subj", "aml_transaction_records", NOW - timedelta(days=6 * 365), current_time=NOW
    )
    assert recent.result == EligibilityResult.BLOCKED
    assert old.result == EligibilityResult.ELIGIBLE


@pytest.mark.parametrize(
    "regime,purpose",
    [
        (EgyptRegime.CBE_BANK, "cbe_customer_records"),
        (EgyptRegime.FRA_NBFI, "fra_regulated_records"),
        (EgyptRegime.PDPL_CONTROLLER, "pdpl_general_processing"),
        (EgyptRegime.CBE_BANK, "commercial_and_tax_records"),
    ],
)
def test_unconfirmed_rules_block_even_ancient_data(regime: EgyptRegime, purpose: str) -> None:
    eng = _engine(regime)
    decision = eng.evaluate("subj", purpose, NOW - timedelta(days=50 * 365), current_time=NOW)
    assert decision.result == EligibilityResult.BLOCKED
    assert "not legally confirmed" in decision.reason


def test_aml_rules_cite_sources_and_trigger() -> None:
    rule = next(
        r
        for r in egypt_policy(EgyptRegime.CBE_BANK).rules
        if r.purpose == "aml_customer_identification"
    )
    assert "Law 80/2002" in rule.citation
    assert rule.retention_trigger == "ACCOUNT_CLOSURE"
    assert rule.period_confirmed


def test_regime_changes_policy_hash() -> None:
    assert (
        egypt_policy(EgyptRegime.CBE_BANK).compute_rules_hash()
        != egypt_policy(EgyptRegime.FRA_NBFI).compute_rules_hash()
    )


def test_legacy_rule_hash_unchanged_by_new_fields() -> None:
    rule = RetentionRule("p", "c", timedelta(days=1), RetentionBasis.CONTRACT, "d")
    assert set(rule.to_canonical_dict()) == {
        "category",
        "description",
        "legal_basis",
        "purpose",
        "retention_period_seconds",
    }
    legacy = Policy(version="1", rules=[rule])
    assert "jurisdiction" not in legacy.to_dict()["rules"][0]


def test_policy_roundtrip_keeps_egypt_fields() -> None:
    policy = egypt_policy(EgyptRegime.CBE_BANK)
    clone = Policy.from_dict(policy.to_dict())
    assert clone.jurisdiction == "EG" and clone.regime == "CBE_BANK"
    assert clone.compute_rules_hash() == policy.compute_rules_hash()
    assert [r.period_confirmed for r in clone.rules] == [r.period_confirmed for r in policy.rules]


def test_saga_refuses_to_plan_unconfirmed_purpose() -> None:
    saga = ErasureSaga(
        keystore=None,
        vault=None,
        policy_engine=_engine(EgyptRegime.CBE_BANK),
        fact_log=None,
        connectors=[],
    )
    with pytest.raises(ValueError, match="not legally confirmed"):
        saga.plan("subj", "cbe_customer_records", data_created_at=NOW - timedelta(days=9999))


def _receipt(jurisdiction: dict | None, extra: list[str] | None) -> tuple[dict, SigningKeyPair]:
    key = SigningKeyPair.generate(key_id="eg-test")
    fact = Fact.create("subj_eg", "aml_transaction_records", "scope", "11" * 32, 2)
    log = FactLog(MerkleTree(), key)
    idx = log.append_fact(fact)
    batch = log.batch_sign()
    token = SimulatedAnchor(signing_key=key).anchor(bytes.fromhex(batch.merkle_root))
    receipt = ReceiptBuilder.build(
        fact=fact,
        leaf_index=idx,
        inclusion_proof=log.get_inclusion_proof(idx),
        batch=batch,
        anchor_token=token,
        retrieval_test=RetrievalTestResult("2026-10-15", 2, "not_recoverable"),
        signing_key=key,
        extra_limits=extra,
        jurisdiction=jurisdiction,
    )
    return receipt, key


def test_receipt_carries_signed_jurisdiction_and_bilingual_limits() -> None:
    jur = {
        "code": "EG",
        "regime": "CBE_BANK",
        "legal_review": "NOT_REVIEWED",
        "anchor_location": "UNSPECIFIED",
    }
    receipt, key = _receipt(jur, EGYPT_LIMITS_EN + EGYPT_LIMITS_AR)
    assert receipt["jurisdiction"]["code"] == "EG"
    assert all(line in receipt["limits"] for line in EGYPT_LIMITS_AR)
    result = ReceiptVerifier().verify(receipt, key.public_key_bytes)
    assert result.valid, result.checks_failed

    tampered = copy.deepcopy(receipt)
    tampered["jurisdiction"]["legal_review"] = "REVIEWED"
    assert not ReceiptVerifier().verify(tampered, key.public_key_bytes).valid


def test_receipt_without_jurisdiction_still_valid() -> None:
    receipt, key = _receipt(None, None)
    assert "jurisdiction" not in receipt
    assert ReceiptVerifier().verify(receipt, key.public_key_bytes).valid
