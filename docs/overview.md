# Athar: Verifiable Erasure Receipts — Discussion Paper (alpha)

**Khafi Labs (My Personal Laboratories)** · version 0.2.0 · open for review

## 1. Problem
When an organisation says it deleted a person's data, nobody outside can check. Regulators, auditors
and data subjects rely on emails, tickets and trust. Deletion is also hard to prove technically:
copies persist in backups, caches, indexes and logs.

## 2. Approach
1. **Per-subject encryption** (key hierarchy KEK → PPK → DEK) so deletion can be done by destroying a key, including for backups.
2. **Erasure saga**: an auditable state machine (intent → hold check → purge surfaces → key destruction → verification → fact), resumable after crashes.
3. **Tamper-evident log**: each completed erasure becomes a fact in an RFC 6962-style Merkle tree.
4. **Signed receipt**: RFC 8785 canonical JSON signed with Ed25519, with inclusion proof, timestamp token and mandatory limits.
5. **Standalone verifier**: checks a receipt against a *pinned* issuer key without any access to the organisation's systems.
6. **Policy engine**: retention rules with citations, legal holds, two-person approval; unconfirmed rules block erasure.

None of these primitives is new. The contribution is their combination, the fail-closed verifier, and the discipline of
stating limits inside every receipt.

## 3. What has been tested
236 automated tests (83% line coverage): unit, property-based (Merkle), failure injection (saga crashes/connector failures) and
attack tests (tampering, forged receipts with attacker keys, bad Merkle paths, missing timestamps). Linting and strict type checking pass.
Not done: independent audit, formal proof, performance evaluation, real-deployment pilot.

## 4. What a receipt does and does not show
Shows: a process ran as recorded, was logged, and was signed by the holder of a given key.
Does not show: absence of other copies, physical media erasure, honesty of the issuer's declared scope, or (at level 2)
real key destruction, which is simulated in this version.

## 5. Egypt context (not legal advice)
An Egypt policy pack encodes the anti-money-laundering retention minimum (five years, with triggers) from the sources read.
CBE, FRA and commercial/tax periods are unconfirmed and block erasure. Open legal questions include whether the PDPL's
Art. 3 exclusion of CBE-supervised entities applies in practice, and what evidence either regulator accepts. See `docs/egypt_legal_notes.md`.

## 6. Questions for the community
- **Cryptographers:** Is the receipt format sound against malleability and log split-view attacks? What anchoring would you require?
- **Banks and fintechs:** What evidence do your auditors actually request for deletion and retention? Where would this fit your process?
- **Lawyers and regulators:** Under which conditions is cryptographic erasure acceptable? Which rules should the Egypt pack encode, and from which sources?
- **Engineers:** Which keystore/HSM integrations would you need first?

## 7. How to engage
Open an issue or pull request (see CONTRIBUTING.md); report vulnerabilities privately (SECURITY.md).
