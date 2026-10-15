# Athar Security Threat Model

**Status:** Informational / Security Guidance  
**Scope:** Verifiable Erasure Receipts Architecture  
**Author:** Khafi Labs (My Personal Laboratories)  

---

## 1. Introduction and Trust Boundaries

Athar provides verifiable cryptographic evidence that a specific processing purpose for a pseudonymous data subject was purged and its Data Encryption Key (DEK) rendered irrecoverable.

Security guarantees in Athar rely on distinct operational and cryptographic trust boundaries:

```
[ Data Subject / Auditor / Regulator ]
                   ▲
                   │ Verifiable Receipt (RFC 8785, RFC 6962, Ed25519)
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY: Public / Independent Verifier               │
├─────────────────────────────────────────────────────────────┤
│ • Standalone ReceiptVerifier (Zero Athar Dependencies)       │
│ • Public Key Distribution & RFC 3161 Timestamp Authorities  │
└─────────────────────────────────────────────────────────────┘
                   ▲
                   │ Merkle Inclusion Proofs & Anchors
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY: Append-Only Fact Log & Key Management       │
├─────────────────────────────────────────────────────────────┤
│ • Merkle Tree Log (RFC 6962 Domain Separation)              │
│ • Three-Tier Keystore (KEK -> PPK -> DEK)                   │
│ • Policy Engine & Two-Person Authorization                  │
└─────────────────────────────────────────────────────────────┘
                   ▲
                   │ Purge Connector Actions
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY: Operational Storage Surfaces                │
├─────────────────────────────────────────────────────────────┤
│ • Relational DBs, Document Stores, Object Filestores        │
│ • In-Memory Caches, Full-Text Indexes, Log Aggregators      │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Threat Analysis Matrix

The following analysis details six primary adversarial threat vectors against the Athar erasure architecture.

---

### Threat 1: Malicious Insider

| Dimension | Assessment |
|---|---|
| **Description** | A rogue employee (e.g. database administrator, developer, or operator) attempts to secretly retain copies of personal data before erasure, or unauthorizedly triggers mass erasure to sabotage operations. |
| **Likelihood** | **Medium** (High impact in regulated financial / healthcare environments). |
| **Mitigation** | 1. **Per-Subject/Purpose Encryption:** Data at rest is encrypted with individual DEKs under ephemeral nonces; raw data cannot be read without keystore unwrapping authorization.<br>2. **Two-Person Approval:** Mass or sensitive erasures require dual cryptographic authorization (`requires_two_person_approval: true`).<br>3. **Blind Indexing:** Insiders querying database storage cannot correlate subjects without the keyed HMAC master secret.<br>4. **Mandatory Limit Disclosure:** Receipts explicitly declare: *"Does not prove absence of copies outside the manifest."* |
| **Detection** | Keystore access logs reveal abnormal key unwrap requests; Fact Log records intent events before execution; canary retrieval drills identify unauthorized remnants. |

---

### Threat 2: Rogue Administrator

| Dimension | Assessment |
|---|---|
| **Description** | A privileged systems engineer or root user attempts to forge a false erasure receipt without actually wiping database records or destroying keys, or tampers with the log after the fact. |
| **Likelihood** | **Medium-Low** |
| **Mitigation** | 1. **Append-Only Merkle Tree:** Once facts are committed to the RFC 6962 Merkle tree, any retroactive alteration alters the root hash and invalidates the signed batch record.<br>2. **Standalone Verification Drill:** Receipt generation requires an active retrieval test result where the ciphertext fails AEAD authentication.<br>3. **Separation of Duties:** Signing keys for receipts are isolated from surface administrative accounts. |
| **Detection** | Merkle consistency proofs between consecutive batches detect split-view histories; external auditors running `ReceiptVerifier` against real storage detect retrievable plaintext. |

---

### Threat 3: Colluding Key Custodian

| Dimension | Assessment |
|---|---|
| **Description** | The custodian of the KMS or HSM colludes with the data controller to claim keys were destroyed while secretly preserving an escrow copy of DEKs or PPKs in an offline vault. |
| **Likelihood** | **Low-Medium** |
| **Mitigation** | 1. **Clear Assurance Level Grading:** Software-simulated destruction is strictly graded at **Level 2** with mandatory `"key_destruction": "SIMULATED"` disclosures.<br>2. **Hardware Enclaves (Level 3/4):** In Level 3+, keys reside exclusively inside FIPS 140-2 Level 3 HSMs where key extraction is physically resisted and firmware emits verifiable zeroization attestations.<br>3. **Multi-Party Thresholding (Level 4):** Key shares are split via Shamir's Secret Sharing or multi-party threshold schemes so no single custodian can escrow the key. |
| **Detection** | Third-party HSM audit logs; periodic disaster recovery restoration drills that attempt decryption from cold backups and prove failure. |

---

### Threat 4: Company Lying (False Attestation)

| Dimension | Assessment |
|---|---|
| **Description** | The company fabricates a receipt claiming erasure occurred on date $T$, but omitted storage systems from the manifest, or fabricated the signature. |
| **Likelihood** | **Medium** |
| **Mitigation** | 1. **Public Ed25519 Signatures:** Signatures over canonical JSON bind the legal entity to the specific cryptographic statement. Lying constitutes intentional legal fraud with non-repudiable evidence.<br>2. **Erasure Manifest Auditing:** Every receipt embeds the `scope_hash` and `policy_hash` identifying exact surfaces and declared gaps.<br>3. **Mandatory Limit Disclosures:** Every receipt explicitly states: *"Detection time is the company's claim unless independently verified"* and *"Does not prove absence of copies outside the manifest."* |
| **Detection** | Regulators and data subjects can verify the public signature with `ReceiptVerifier`; discovery in litigation comparing actual architecture to the published `ErasureManifest`. |

---

### Threat 5: Back-Dated Timestamps

| Dimension | Assessment |
|---|---|
| **Description** | A controller facing regulatory fines for missing a GDPR 30-day erasure deadline generates a receipt today and falsely claims the erasure took place two months ago. |
| **Likelihood** | **High** (Common audit defense temptation). |
| **Mitigation** | 1. **External RFC 3161 / OpenTimestamps Anchoring:** The Merkle root is submitted to an independent, accredited Timestamp Authority (TSA) or Bitcoin blockchain.<br>2. **Anchor Timing Verification Check:** Standalone verifiers enforce the invariant:
$$\text{timestamp\_token.timestamp} \ge \text{fact.ts}$$
If an anchor token predates the fact, or if the anchor timestamp postdates the statutory deadline, back-dating is mathematically exposed. |
| **Detection** | `ReceiptVerifier` Check 5 (`anchor_timing`) immediately fails and flags the receipt if timestamps are inverted. Cryptographic signature timestamp tokens cannot be forged retroactively without compromising the TSA private key. |

---

### Threat 6: Timestamp Authority (TSA) Failure or Compromise

| Dimension | Assessment |
|---|---|
| **Description** | The external RFC 3161 TSA suffers private key compromise, issues rogue timestamps, or ceases operations, preventing timestamp validation years later. |
| **Likelihood** | **Low** |
| **Mitigation** | 1. **Multi-Anchoring:** Anchor Merkle roots to multiple independent TSAs and decentralized public ledgers (e.g. OpenTimestamps on Bitcoin).<br>2. **Periodic Re-Anchoring:** Long-lived receipts can have their Merkle root re-anchored to current active TSAs before older certificates expire.<br>3. **TSA Honesty Level Flag:** The receipt format explicitly tracks `honesty_level` (`real`, `simulated`, `offline`). |
| **Detection** | TSA Certificate Revocation Lists (CRLs) and OCSP stapling identify compromised authorities; discrepancies between multiple anchors trigger alert. |

---

## 3. Residual Risks and Out-of-Scope Threats

1. **Compromised Client Devices:** If a user downloaded their loan statement to their personal smartphone before erasure, Athar cannot erase copies on consumer-owned hardware.
2. **Side-Channel Memory Dumps:** Active RAM snapshots captured during legitimate processing prior to erasure must be cleared via secure memory allocator configurations.
3. **Physical Hardware Extraction:** Defense against physical electron-microscopy NAND flash chip decapping requires full-disk hardware encryption at the hypervisor level.
