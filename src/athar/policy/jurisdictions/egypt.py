"""Egypt jurisdiction pack (policy template + receipt disclosures).

IMPORTANT: this is NOT a statement that using Athar makes an organisation compliant.
It encodes only what could be read from sources during the 2026-10 review, and marks
everything else as unconfirmed, in which case the policy engine BLOCKS erasure.

Sources actually read (see docs/egypt_legal_notes.md for caveats):
  * Law 151/2020 (PDPL), English translation: Arts. 1-4, 7, 8, 12, 14.
  * Law 80/2002 (Anti-Money Laundering), Art. 9: records kept for no less than five
    years from the date the transaction is finalised, or from account closure.
  * AML Executive Regulations (draft text read): Arts. 22(2), 34, 40: five years;
    suspicious-transaction files for five years or until a final verdict, whichever
    is longer.
  * Banking Law 194/2020, Arts. 140-142 (secondary summary): customer data are
    confidential, including after the relationship ends. No retention period found.

NOT verified: CBE instructions on customer-data retention, FRA decisions on record
retention, commercial/tax record-keeping periods, and the current amended text of the
AML provisions. Those rules are included as unconfirmed slots.
"""

from __future__ import annotations

from datetime import timedelta
from enum import Enum

from athar.policy.models import Policy, RetentionBasis, RetentionRule

FIVE_YEARS = timedelta(days=5 * 365)

_AML_CAVEAT = (
    "Read from the 2005 English text of Law 80/2002 and a draft of the Executive "
    "Regulations; the law has since been amended. Treat five years as a MINIMUM and "
    "confirm the current text with Egyptian counsel."
)


class EgyptRegime(str, Enum):
    """Regulatory regime that governs the data controller. Counsel must decide which."""

    CBE_BANK = "CBE_BANK"
    CBE_MONEY_TRANSFER_OR_EXCHANGE = "CBE_MONEY_TRANSFER_OR_EXCHANGE"
    FRA_NBFI = "FRA_NBFI"
    PDPL_CONTROLLER = "PDPL_CONTROLLER"


def _aml_rules() -> list[RetentionRule]:
    return [
        RetentionRule(
            purpose="aml_customer_identification",
            category="customer_identification",
            retention_period=FIVE_YEARS,
            legal_basis=RetentionBasis.STATUTORY_AML,
            description="Customer and beneficiary identification records (minimum five years).",
            citation=f"Law 80/2002 Art. 9; AML Exec. Regs Art. 22(2), 34. {_AML_CAVEAT}",
            retention_trigger="ACCOUNT_CLOSURE",
        ),
        RetentionRule(
            purpose="aml_transaction_records",
            category="transaction_records",
            retention_period=FIVE_YEARS,
            legal_basis=RetentionBasis.STATUTORY_AML,
            description="Records of local and international transactions (minimum five years).",
            citation=f"Law 80/2002 Art. 9; AML Exec. Regs Art. 34. {_AML_CAVEAT}",
            retention_trigger="TRANSACTION_COMPLETION",
        ),
        RetentionRule(
            purpose="aml_suspicious_transaction_file",
            category="suspicious_transaction_report",
            retention_period=FIVE_YEARS,
            legal_basis=RetentionBasis.STATUTORY_AML,
            description=(
                "Suspicious-transaction files: five years OR until a final verdict, whichever "
                "is longer. Place a LegalHold for any pending proceeding; the period alone "
                "is not sufficient."
            ),
            citation=f"AML Exec. Regs Art. 40. {_AML_CAVEAT}",
            retention_trigger="REPORT_DATE",
        ),
    ]


def _unconfirmed(purpose: str, category: str, basis: RetentionBasis, cite: str) -> RetentionRule:
    return RetentionRule(
        purpose=purpose,
        category=category,
        retention_period=timedelta(0),
        legal_basis=basis,
        description="PLACEHOLDER: retention period not established. Legal input required.",
        citation=cite,
        period_confirmed=False,
    )


def egypt_policy(
    regime: EgyptRegime,
    version: str = "egypt-0.1",
    requires_two_person_approval: bool = True,
    grace_period: timedelta = timedelta(hours=72),
) -> Policy:
    """Build an Egypt policy template for the given regime.

    The result has legal_review="NOT_REVIEWED". Rules with ``period_confirmed=False``
    block erasure until counsel supplies a reviewed period (replace the rule).
    """
    rules: list[RetentionRule] = []
    if regime in (
        EgyptRegime.CBE_BANK,
        EgyptRegime.CBE_MONEY_TRANSFER_OR_EXCHANGE,
        EgyptRegime.FRA_NBFI,
    ):
        # Applicability of the AML retention rules to each regime must be confirmed.
        rules += _aml_rules()

    if regime == EgyptRegime.CBE_BANK:
        rules.append(
            _unconfirmed(
                "cbe_customer_records",
                "customer_records",
                RetentionBasis.REGULATOR_INSTRUCTION,
                "Banking Law 194/2020 Arts. 140-142 (confidentiality) and CBE instructions. "
                "No retention period was found in the sources read.",
            )
        )
    if regime == EgyptRegime.FRA_NBFI:
        rules.append(
            _unconfirmed(
                "fra_regulated_records",
                "customer_records",
                RetentionBasis.REGULATOR_INSTRUCTION,
                "FRA decisions on record retention were not located in the sources read.",
            )
        )
    if regime in (EgyptRegime.PDPL_CONTROLLER, EgyptRegime.CBE_MONEY_TRANSFER_OR_EXCHANGE):
        rules.append(
            _unconfirmed(
                "pdpl_general_processing",
                "personal_data",
                RetentionBasis.PDPL_PURPOSE_LIMITATION,
                "PDPL 151/2020 Art. 4: erase when the purpose ends unless there is a "
                "legitimate reason to retain. Define the purpose end per processing activity.",
            )
        )
    rules.append(
        _unconfirmed(
            "commercial_and_tax_records",
            "accounting_records",
            RetentionBasis.LEGAL_OBLIGATION,
            "Commercial-law and tax record-keeping periods were not researched.",
        )
    )

    return Policy(
        version=version,
        rules=rules,
        requires_two_person_approval=requires_two_person_approval,
        grace_period=grace_period,
        jurisdiction="EG",
        regime=regime.value,
        legal_review="NOT_REVIEWED",
    )


EGYPT_LIMITS_EN: list[str] = [
    "This receipt is evidence of a recorded process. It is not a determination that the "
    "issuer complies with Law 151/2020, Banking Law 194/2020, or any Central Bank of Egypt "
    "or Financial Regulatory Authority rule.",
    "Retention rules in the referenced policy have not been reviewed by counsel unless the "
    "policy states otherwise; rules marked unconfirmed block erasure.",
    "Statutory retention (e.g. anti-money-laundering records) may require data to be kept "
    "despite a deletion request; the receipt covers only the data within the declared scope.",
]

# Arabic text drafted by the maintainers, NOT reviewed by a certified legal translator.
EGYPT_LIMITS_AR: list[str] = [
    "هذا الإيصال دليل على إجراء مُسجَّل، وليس إقراراً بأن الجهة المُصدِرة ممتثلة للقانون رقم "
    "151 لسنة 2020 أو لقانون البنوك رقم 194 لسنة 2020 أو لأي قاعدة صادرة عن البنك المركزي "
    "المصري أو الهيئة العامة للرقابة المالية.",
    "لم تُراجَع قواعد الاحتفاظ الواردة في السياسة المرجعية قانونياً ما لم تنص السياسة على "
    "خلاف ذلك، وتمنع القواعد غير المؤكدة تنفيذ المحو.",
    "قد تُلزم أحكام الاحتفاظ القانونية (مثل سجلات مكافحة غسل الأموال) بالإبقاء على "
    "البيانات رغم طلب الحذف، ويقتصر الإيصال على البيانات الواقعة ضمن النطاق المُعلَن.",
]
