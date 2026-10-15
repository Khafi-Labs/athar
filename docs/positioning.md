# Positioning and Communication Guide

**Owner:** Khafi Labs (My Personal Laboratories)
**Status of the project:** alpha research prototype and reference implementation (v0.1.0).

## 1. How to designate the project

Use: **"Athar, an open-source research prototype for verifiable data-erasure receipts,
by Khafi Labs."**

Do not use: "compliance solution", "PDPL/CBE/FRA compliant", "certified", "regulator-approved",
"production-ready", or "proves data is deleted". None is true today (see section 4).

## 2. Defensible claims (each is backed by code and tests in this repository)

- Produces signed, canonical receipts bound to a tamper-evident Merkle log.
- A standalone verifier checks receipts against a pinned issuer key; forged or inconsistent
  receipts fail (see `tests/attack/`).
- Receipts state their own limits, and key destruction is labelled SIMULATED.
- Includes a first Egypt policy pack: sourced AML retention rules, and unconfirmed rules that block erasure.

## 3. Message by audience

**Scientific / academic.** Frame it as a design and a testbed: the threat model, the receipt
specification, the test vectors and the "limits of the claim" document. Invite review, and state
what is missing: no formal security proof, no independent audit, a simulated key-destruction layer
and an in-memory keystore. Cite via `CITATION.cff`. Suitable venues are workshops and preprints, not
claims of novelty beyond the combination of known primitives (RFC 6962 logs, RFC 8785, Ed25519, crypto-shredding).

**Financial sector (banks, fintechs, regulators).** Lead with the problem: erasure claims today
are unverifiable. Offer a pilot or a design discussion, not a product. State plainly: which regime applies to
the institution is a legal question; retention rules marked unconfirmed block erasure; no CBE or FRA
text beyond AML retention has been encoded; assurance level 2 is not acceptable as proof of key destruction.
Ask for the institution's counsel and security team to define requirements.

**Business / investors / partners.** Present the opportunity as "evidence infrastructure for deletion
and retention accountability" at the prototype stage. Be explicit about the work required before revenue
claims are credible: HSM/KMS integration, persistent storage, an independent security review, legal
validation per regime, and pilot customers. Do not quote market size, customer interest or compliance
status you cannot document.

## 4. Disclosures to repeat in every deck, page and email

1. Alpha prototype; not independently audited.
2. Not legal advice; not reviewed by Egyptian counsel; no regulator has endorsed it.
3. Key destruction is simulated in this version.
4. Receipts cover only the declared scope and do not prove that no other copies exist.
5. Parts of the code and documents were drafted with AI assistance and reviewed by the maintainers.

## 5. Housekeeping before going public

- Confirm you hold the rights to everything in the repository (the original authorship of the
  inherited code is not documented here) and keep any third-party notices.
- Check that the names "Athar" and "Khafi Labs" are free to use (trademark and domain search) in the
  markets you target.
- Fill in the real repository URL in the README; the earlier placeholder was removed.
- Add a contact address and a vulnerability-reporting policy (SECURITY.md).
- Commission an independent cryptographic review and an Egyptian legal opinion before pilots.
