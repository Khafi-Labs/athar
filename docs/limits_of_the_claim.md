# Limits of the Claim: What Verifiable Erasure Receipts Prove and Do Not Prove

**Status:** Normative Guidance / Legal & Technical Disclosure  
**System:** Athar Verifiable Erasure Core  
**Author:** Khafi Labs (My Personal Laboratories)  

---

## 1. Executive Summary

A verifiable erasure receipt is a cryptographic attestation bounding the state of data within an explicitly defined computing environment. In information security and privacy compliance, overclaiming guarantees destroys credibility with regulators and courts.

This document formally delineates what an Athar receipt **proves** mathematically and what it **does not prove** in the physical world.

---

## 2. What an Athar Receipt PROVES

When verified by the standalone `ReceiptVerifier`, an Athar receipt provides non-repudiable mathematical proof of the following statements:

### 2.1 Authorized Issuance & Integrity
- **Non-Repudiation:** The receipt was signed by the specific private key corresponding to `signatures[].pub`. The issuer cannot claim after the fact that a third party fabricated the statement.
- **Payload Integrity:** Every byte of the receipt—including the subject commitment, purpose, policy hash, timestamps, surface counts, and limits—was unaltered since the signature was generated (guaranteed by RFC 8785 Canonical JSON and Ed25519).

### 2.2 Proof of Log Inclusion & Batch Commitment
- **Merkle Audit Path:** The erasure fact was committed at leaf position $i$ in an append-only RFC 6962 Merkle tree of size $N$, producing the exact `merkle_root`.
- **Chronological Ordering:** The fact cannot be retroactively inserted into a past batch without altering all subsequent Merkle roots and breaking consistency proofs.

### 2.3 Temporal Bounding
- **Lower Bound:** The erasure execution did not occur *after* the timestamp verified by the external Timestamp Authority (TSA).
- **Upper Bound Invariant:** If `timestamp_token.timestamp >= fact.ts`, the receipt proves the claim was anchored at or after the stated fact timestamp.

### 2.4 Policy & Scope Governance
- **Policy Binding:** The erasure was governed by the exact retention rules and legal holds hashed into `policy_hash`.
- **Manifest Scope:** The controller explicitly bound their liability to the storage surfaces listed in `scope_hash` and the underlying manifest.

### 2.5 Cryptographic Unrecoverability (Vault Level)
- If the Data Encryption Key (DEK) is destroyed, all ciphertexts encrypted under that DEK are computationally indistinguishable from random noise under the security bounds of AES-256-GCM ($2^{128}$ or $2^{256}$ work factor).

---

## 3. What an Athar Receipt DOES NOT PROVE

To prevent deceptive compliance claims, every Athar receipt mandates explicit disclosures acknowledging the following fundamental physical limitations:

### 3.1 Copies Outside the Declared Manifest
> **Receipt Disclosure:** *"Does not prove absence of copies outside the manifest."*

- **The Air-Gap Problem:** A cryptographic receipt cannot prove that an engineer did not copy a customer's record onto a USB flash drive, export it to an unmanaged staging S3 bucket, print it on paper, or take a screenshot six months before the erasure saga was run.
- **The Guarantee:** Athar guarantees that all storage surfaces *enumerated in the manifest* were subjected to the purge connectors and that the active DEK was destroyed. The completeness of the manifest itself remains an organizational governance claim.

### 3.2 Backup Tapes and Immutable Disaster Recovery Archives
- In enterprise environments, write-once-read-many (WORM) optical media, air-gapped tape cartridges, and continuous database transaction logs may retain historical blocks for months or years.
- **How Athar Handles Backups:** Because Athar encrypts all records with subject-specific DEKs, the backup archives contain only ciphertext. When the DEK is destroyed in the keystore/KMS, the backup copies are simultaneously rendered unrecoverable ("Cryptographic Erasure"). However, the raw physical blocks on the tape are not overwritten until the tape rotation cycle expires.

### 3.3 Software vs. Hardware Key Destruction
> **Receipt Disclosure:** *"Key destruction is SIMULATED in this MVP."*

- In Athar Level 1 and Level 2, key destruction is performed in software memory or local persistent stores. While memory is overwritten with zeros, software-based destruction cannot defend against hypervisor memory dumps, cold-boot attacks, or underlying SSD wear-leveling remapping tables where old flash blocks might retain remnant electrons.
- **Hardware Requirement (Level 3+):** Physical zeroization guarantees require hardware security modules (HSMs) certified to FIPS 140-2 Level 3 or higher.

### 3.4 Self-Run Retrieval Drills Are Not Forensic Audits
> **Receipt Disclosure:** *"Self-run retrieval test does not raise assurance level."*

- The `retrieval_test` recorded in the receipt is executed by the data controller's own automated systems. While valuable for continuous operational hygiene, it does not substitute for an independent third-party penetration test or forensic inspection.

### 3.5 Timestamp Authority Honesty
> **Receipt Disclosure:** *"Timestamp anchor honesty depends on the external TSA."*

- A receipt anchored to a timestamp authority inherits the trust profile of that authority. If a private timestamp server's clock is maliciously manipulated or its private signing key is stolen, the temporal claim may be compromised. Real-world high-assurance deployments must anchor to accredited public TSAs or public decentralized blockchains.

### 3.6 Discovery Latency
> **Receipt Disclosure:** *"Detection time is the company's claim unless independently verified."*

- The interval between when a data subject becomes legally eligible for erasure and when the company detects the eligibility and schedules the job is reported by the controller. The receipt proves when the job ran, not whether the controller should have run it earlier.

---

## 4. Assurance Levels and Claim Boundaries

| Level | Formal Claim | Bound of Claim |
|---|---|---|
| **Level 1: Administrative** | Controller asserts data was deleted using standard software routines. | No cryptographic proof of unrecoverability; subject to database backup retention. |
| **Level 2: Cryptographic (MVP)** | Controller asserts DEK was zeroized in software and surfaces purged; anchored to Merkle log. | Ciphertext is unrecoverable; key destruction is labeled SIMULATED; depends on software keystore security. |
| **Level 3: Hardware Enforced** | DEK zeroization executed inside certified FIPS 140-2 L3 HSM; anchored to public RFC 3161 TSA. | Physically non-recoverable keys; hardware audit trail; legally defensible non-repudiation. |
| **Level 4: Multi-Party Attestation** | M-of-N threshold key destruction with direct hardware cryptographic attestations anchored to public ledgers. | Resists colluding insider and administrative coercion; verifiable by hostile third parties. |

---

## 5. Legal Standing (Informational Only)

**This section is not legal advice and has not been reviewed by counsel.** Athar's
policy model follows GDPR concepts. It has not been mapped to Egypt's Personal Data
Protection Law No. 151 of 2020 or to CBE/FRA requirements; see
[`egypt_legal_notes.md`](egypt_legal_notes.md). In particular, the PDPL (Art. 3) exempts
data held by CBE-supervised entities, so a bank's obligations may sit under the Banking
Law and CBE instructions instead.

1. **Cryptographic erasure is not automatically accepted as deletion.** Regulators in
   some jurisdictions have treated key destruction as sufficient where physical deletion is
   infeasible, but acceptance depends on the regulator, the key-management standard and the
   facts. Do not assume it; obtain advice for each jurisdiction.
2. **Accountability evidence.** A receipt is machine-readable evidence that a process ran
   as recorded. It is not a defence by itself, and at assurance level 2 (simulated key
   destruction) it should not be presented as proof of unrecoverability.
3. **Retention can override erasure.** Statutory retention (e.g. AML and banking record
   keeping) may require keeping data despite a request. The policy engine records this
   decision; it does not decide what the law requires.
