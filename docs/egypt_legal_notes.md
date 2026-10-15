# Egypt: Legal Scope Notes (Not Legal Advice)

**Implementation:** `athar.policy.jurisdictions.egypt` (policy template + receipt disclosures).

**Status:** Working notes for the project team. Not legal advice. Verify every point
against the official Arabic text, the Executive Regulations as currently in force,
and current CBE/FRA instructions, with qualified Egyptian counsel.

Athar was designed around GDPR concepts. It has **not** been mapped to Egyptian law.
This note records what is known and what is still open.

## 1. Which regime applies?

Personal Data Protection Law No. 151 of 2020 (PDPL), Article 3, exempts personal data
held by the Central Bank of Egypt and the entities it supervises, with a carve-out for
money-transfer and currency-exchange companies. For CBE-supervised banks, the governing
rules are therefore the Banking Law No. 194 of 2020, CBE instructions (including
information-security and customer-data rules) and AML record-keeping obligations, not
primarily the PDPL. Fintechs, payment firms and other controllers outside CBE
supervision, and the carved-back-in transfer/exchange companies, are within the PDPL.
FRA-supervised non-bank financial entities need their own analysis.

**Open question #1:** For each intended customer type, which regime applies, and does
the CBE/FRA regime contain its own erasure, retention or evidence requirements?

## 2. PDPL provisions relevant to Athar (as read from the English translation)

| Article | Subject | Relevance to Athar |
|---|---|---|
| 2 | Data subject rights, including "deletion" | Receipts attest deletion; terminology should follow the Egyptian text, not GDPR Art. 17 |
| 3 | Scope exclusions (incl. CBE-supervised entities) | See section 1 |
| 4 | Erase when the purpose ends unless a legitimate reason to retain | Policy engine models this as retention rules; Egyptian statutory bases are not yet encoded |
| 7 | Breach notification to the Data Protection Centre within 72 hours | Not covered by Athar |
| 8 | Data Protection Officer, registered with the Centre | Not covered |
| 12 / 1 | Licence and consent for sensitive data, which includes financial data | Not covered |
| 14 / 15 | Cross-border transfer prohibited without Centre licence | Not covered; relevant to any external anchoring/TSA or cloud KMS outside Egypt |

## 3. Gaps between Athar and an Egyptian deployment

1. **Retention rules:** `RetentionBasis` has no Egyptian legal bases. Banking Law, AML and
   tax record-keeping periods (AML minimum of five years was read from source; see section 5) can override an erasure request. These must be modelled
   as policy rules and, ideally, cited by statute in the receipt's policy hash input.
2. **Evidence expectations:** it is unknown what a CBE inspector or the Data Protection
   Centre would accept as proof of deletion. A cryptographic receipt is supporting
   evidence only; `SIMULATED` key destruction would not satisfy a regulator.
3. **Data localisation / cross-border:** external timestamp authorities and KMS/HSM
   providers outside Egypt may be cross-border transfers of data. Receipts are designed
   to contain pseudonymous commitments, not personal data, but this needs legal confirmation.
4. **Arabic:** receipts, limits disclosures and any data-subject-facing output are English only.
5. **Executive Regulations:** confirm their current status and any technical requirements
   (e.g. licensing, DPO, record-of-processing formats) that the design must meet.

## 4. Suggested next steps

1. Obtain written advice on the questions above for the specific target customer.
2. Build an `egypt` policy pack (retention rules with statutory citations, holds model).
3. Replace GDPR/CCPA/HIPAA language in `limits_of_the_claim.md` with the Egyptian analysis.
4. Move key custody to a certified HSM/KMS (assurance level 3) before any production claim.


## 5. What the Egypt pack encodes, and how well each item is sourced

| Item | Where | Source read in the 2026-10 review | Status |
|---|---|---|---|
| AML records: at least 5 years from transaction completion / account closure | `aml_customer_identification`, `aml_transaction_records` | Law 80/2002 Art. 9 (2005 English text); AML Exec. Regs (draft text) Arts. 22(2), 34 | Source read. Law was later amended; confirm current text and applicability to each regime. |
| Suspicious-transaction files: 5 years or until final verdict, if longer | `aml_suspicious_transaction_file` | AML Exec. Regs (draft text) Art. 40 | Source read; same caveat. Pending proceedings must also be modelled as a `LegalHold`. |
| Customer data confidentiality, continuing after the relationship ends | Banking Law 194/2020 Arts. 140-142 | Secondary (press) summary only | Not encoded as a rule. No retention period found. |
| CBE customer-record retention | `cbe_customer_records` | None found | **Unconfirmed. Erasure is blocked.** |
| FRA record retention | `fra_regulated_records` | None found | **Unconfirmed. Erasure is blocked.** |
| Commercial / tax record keeping | `commercial_and_tax_records` | Not researched | **Unconfirmed. Erasure is blocked.** |
| PDPL Art. 4 purpose limitation | `pdpl_general_processing` | Law 151/2020 English translation | Principle only; the purpose end must be defined per activity. Unconfirmed, blocked. |

Design choice: a rule whose period is not legally confirmed makes the policy engine
return BLOCKED. The tool fails safe; it never guesses a retention period.

## 6. Verified facts about the PDPL and its Executive Regulations

- Executive Regulations: Ministerial Decision No. 816/2025, issued 1 November 2025, publicly
  available 25 December 2025 (CMS summary). A one-year compliance period is reported; the
  exact enforcement date is uncertain because publication lagged issuance.
- They create a licensing system (controllers/processors, general licences typically valid
  three years), a DPO registry, 72-hour breach notice to the Centre, and licences or permits
  for cross-border transfers, reported to include cloud environments.
- The CMS summary does not mention a financial-sector exemption, whereas the law's Art. 3
  (translation) and an older Baker McKenzie note say CBE-supervised entities are outside the
  PDPL. How these fit together in practice is an open legal question (Open question #1).

## 7. Still open (needs counsel or the regulators)

1. Which regime applies, and does Art. 3 apply as written after the Executive Regulations?
2. CBE instructions on customer-data retention, deletion, outsourcing and cloud use.
3. FRA decisions (including its cybersecurity/technology-risk frameworks) on retention,
   logging and evidence. No primary FRA text was obtained; a vendor page names the frameworks but gave no requirements.
4. Whether signed deletion receipts are acceptable evidence to either regulator.
5. Whether anchoring to a timestamp authority outside Egypt is a cross-border transfer.
6. A certified Arabic translation of the receipt disclosures (`EGYPT_LIMITS_AR` is an unreviewed draft).
