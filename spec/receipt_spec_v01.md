# Athar Verifiable Erasure Receipt Specification v0.1

**Identifier:** `athar-receipt/0.1`  
**Status:** Normative Specification (Draft)  
**Authors:** Khafi Labs (My Personal Laboratories)  
**Date:** 2026-10-14  

---

## 1. Abstract

This document specifies the format, cryptographic construction, encoding rules, and verification semantics for **Athar Verifiable Erasure Receipts** (version `0.1`). An Athar receipt is a portable, cryptographically signed, timestamp-anchored artifact providing verifiable evidence that a specific processing purpose for a pseudonymous subject has undergone an authorized erasure process across specified storage surfaces and cryptographic key tiers.

---

## 2. Terminology and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174].

- **Subject Pseudonym:** An opaque, non-identifying identifier assigned to a data subject.
- **Subject Commitment:** A cryptographic, salted HMAC commitment binding the subject to the receipt without exposing the pseudonym or underlying personal data.
- **DEK (Data Encryption Key):** A symmetric encryption key used to encrypt individual records for a subject and purpose.
- **PPK (Purpose-Period Key):** A key wrapping one or more DEKs scoped to a processing purpose and time window.
- **KEK (Key Encryption Key):** Root key in the key hierarchy wrapping PPKs.
- **Cryptographic Erasure:** Irrevocable destruction of the DEK (and PPK if applicable) rendering all associated ciphertexts permanently unrecoverable.
- **Assurance Level:** A ranked measure (1–4) of the cryptographic and physical guarantees backing the erasure assertion.

---

## 3. Cryptographic Primitives and Canonical Encoding

### 3.1 Hash Function
All digest computations throughout this specification MUST use the SHA-256 cryptographic hash function defined in FIPS 180-4. When digests are serialized as text within the receipt, they MUST use lowercase hexadecimal encoding prefixed with `sha256:` (e.g., `sha256:d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35`).

### 3.2 Canonical JSON Encoding (RFC 8785)
All hashing, signing, and commitment operations MUST operate on bytes generated according to RFC 8785 (JSON Canonicalization Scheme - JCS). Specifically:
1. Object keys MUST be sorted lexicographically by UTF-16 code unit order.
2. No unnecessary whitespace is permitted between tokens (separators MUST be `,` and `:` with no leading or trailing space).
3. Numbers MUST be formatted per RFC 8785 rules.
4. String values MUST use standard JSON escape sequences and MUST be encoded as UTF-8 without Byte Order Mark (BOM).
5. Floating point timestamps are forbidden; ISO 8601 strings in UTC (`YYYY-MM-DDTHH:MM:SSZ` or with microsecond precision) MUST be used.

### 3.3 Digital Signatures
All signatures in `athar-receipt/0.1` MUST use Ed25519 (PureEdDSA with Curve25519 and SHA-512 per RFC 8032). Signatures MUST be 64 bytes in length, encoded as a 128-character lowercase hexadecimal string. Public keys MUST be 32 bytes in length, encoded as a 64-character lowercase hexadecimal string.

### 3.4 Merkle Trees (RFC 6962)
Log audit proofs MUST adhere to RFC 6962:
- Leaf hash prefix: `0x00` (`SHA-256(0x00 || leaf_data)`)
- Internal node hash prefix: `0x01` (`SHA-256(0x01 || left_hash || right_hash)`)
- Empty tree hash: `SHA-256("")`
- Path proofs provide an audit path from leaf to the root of a tree of size $N$.

---

## 4. Receipt Structure

An Athar receipt is a JSON object comprising the following top-level fields:

| Field Name | Type | Constraint | Description |
|---|---|---|---|
| `spec` | `string` | MUST equal `"athar-receipt/0.1"` | Specification identifier and version. |
| `subject_commitment` | `string` | 64-char lowercase hex | Salted HMAC-SHA256 commitment of the subject pseudonym. |
| `purpose` | `string` | Non-empty string | The authorized processing purpose being erased (e.g., `kyc_verification`). |
| `period` | `string` | Format `YYYY-MM` or alphanumeric | Identifier of the operational retention period. |
| `scope_hash` | `string` | `sha256:<hex>` | SHA-256 digest of the textual or structured scope definition. |
| `policy_hash` | `string` | `sha256:<hex>` | Canonical JSON SHA-256 digest of the retention policy authorizing erasure. |
| `assurance_level` | `integer` | Range `1..4` | The assurance level claimed by this receipt (see Section 6). |
| `key_destruction` | `string` | `"SIMULATED"` or `"REAL"` | Key destruction mechanism status. MUST be `"SIMULATED"` for MVP and Level 1–2. |
| `fact` | `object` | See Section 4.1 | Erasure fact details recorded in the append-only log. |
| `inclusion_proof` | `object` | See Section 4.2 | Merkle tree audit path proving fact inclusion in an anchored batch. |
| `merkle_root` | `string` | `sha256:<hex>` | Merkle root hash of the batch containing this fact. |
| `timestamp_token` | `object` | See Section 4.3 | Cryptographic timestamp token anchoring `merkle_root`. |
| `retrieval_test` | `object` | See Section 4.4 | Result of post-erasure canary/retrieval verification. |
| `limits` | `array of string` | Non-empty | Mandatory disclosures and disclaimers bounding the receipt's legal claim. |
| `signatures` | `array of object` | At least 1 entry | Array of Ed25519 signatures covering all fields except `signatures`. |

---

### 4.1 `fact` Object Definition

The `fact` object records the logged erasure event:

```json
{
  "fact_id": "c86a1df0-d1ec-4286-a1d2-094e9f733f11",
  "ts": "2026-10-14T08:30:00Z",
  "nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "surfaces_purged": 4,
  "retrieval_test_outcome": "PASSED",
  "event_type": "erasure"
}
```

- `fact_id` (`string`, UUIDv4): Unique identifier of the logged fact.
- `ts` (`string`, ISO 8601 UTC): Exact timestamp when erasure execution completed.
- `nonce` (`string`, 64-char hex): 32-byte cryptographically secure random value preventing replay attacks.
- `surfaces_purged` (`integer`, $\ge 0$): Number of distinct storage surfaces purged.
- `retrieval_test_outcome` (`string`): Result of post-erasure verification (`PASSED`, `FAILED`, `not_recoverable`).
- `event_type` (`string`): Event classification. MUST be `"erasure"`.

---

### 4.2 `inclusion_proof` Object Definition

The `inclusion_proof` object contains the RFC 6962 audit path:

```json
{
  "batch_id": "b1a41857-e435-4cb3-a5c9-94b2da8534aa",
  "leaf_index": 0,
  "tree_size": 1,
  "path": []
}
```

- `batch_id` (`string`, UUIDv4): Identifier of the batch in which this fact was committed.
- `leaf_index` (`integer`, $0 \le \text{leaf\_index} < \text{tree\_size}$): 0-based leaf position of this fact.
- `tree_size` (`integer`, $\ge 1$): Number of leaves in the Merkle tree at batch signing time.
- `path` (`array of string`): Array of 64-character hex-encoded 32-byte hashes constituting the audit path.

---

### 4.3 `timestamp_token` Object Definition

The `timestamp_token` anchors the `merkle_root` with an independent or simulated time authority:

```json
{
  "token_type": "simulated",
  "token_data_hex": "4a7b...",
  "timestamp": "2026-10-14T08:35:00Z",
  "honesty_level": "simulated",
  "digest_hex": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
  "token_id": "ts-token-001"
}
```

- `token_type` (`string`): One of `"rfc3161"`, `"opentimestamps"`, or `"simulated"`.
- `token_data_hex` (`string`, hex): Raw token bytes (e.g., ASN.1 DER `TimeStampToken` for RFC 3161).
- `timestamp` (`string`, ISO 8601 UTC): Time asserted by the timestamp service. MUST be $\ge \text{fact.ts}$.
- `honesty_level` (`string`): `"real"`, `"simulated"`, or `"offline"`.
- `digest_hex` (`string`, 64-char hex): Digest submitted to the timestamp authority. MUST match `merkle_root` (stripped of prefix).
- `token_id` (`string`): Optional identifier for tracking and correlation.

---

### 4.4 `retrieval_test` Object Definition

Records the active verification drill performed immediately following key destruction:

```json
{
  "date": "2026-10-14",
  "surfaces": 4,
  "outcome": "not_recoverable",
  "details": "Cryptographic DEK destroyed; ciphertext is unrecoverable AES-256-GCM noise"
}
```

- `date` (`string`, `YYYY-MM-DD`): Date test was executed.
- `surfaces` (`integer`, $\ge 0$): Number of surfaces subjected to retrieval attempts.
- `outcome` (`string`): `"not_recoverable"`, `"partially_recoverable"`, or `"recoverable"`.
- `details` (`string`): Optional diagnostic narrative.

---

### 4.5 `signatures` Array Definition

Each entry in the `signatures` array represents an Ed25519 signature:

```json
[
  {
    "alg": "Ed25519",
    "kid": "athar-lender-key-01",
    "pub": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "sig": "3b29074b78ef4c666a4ff5920d0fa85147be27c3f0b2f0a85fa0a190013f416e88126b89e9d9b4b95f208170c0c6c7f566b6e927582b13b7b627ab77c1264d08"
  }
]
```

- `alg` (`string`): MUST equal `"Ed25519"`.
- `kid` (`string`): Identifier of the key within the issuer's key management infrastructure.
- `pub` (`string`, 64-char hex): 32-byte Ed25519 public key.
- `sig` (`string`, 128-char hex): 64-byte Ed25519 signature over the canonical JSON bytes of the receipt excluding the `signatures` key.

---

## 5. Signature Coverage and Verification Algorithm

### 5.1 Signable Payload Construction
To sign or verify a receipt:
1. Create a shallow copy of the receipt object.
2. Remove the top-level key `"signatures"`.
3. Encode the remaining object into canonical JSON bytes according to RFC 8785.
4. The resulting byte array is the exact payload $M$ to which the signature applies.

```
M = canonical_json({ K: V for (K, V) in Receipt if K != "signatures" })
```

### 5.2 Verification Workflow
An independent verifier MUST execute the following checks in order:
1. **Schema Check:** Confirm all required top-level, fact, inclusion proof, and signature fields are present, non-empty, and conform to expected types.
2. **Signature Check:** For each signature in `signatures`:
   - Verify `alg == "Ed25519"`.
   - Verify `pub` is 32 bytes and `sig` is 64 bytes.
   - Verify `Ed25519.verify(pub, M, sig) == True`.
3. **Inclusion Proof Check:**
   - Reconstruct the logged fact dictionary:
     ```python
     fact_for_hash = {
         "fact_id": receipt["fact"]["fact_id"],
         "subject_commitment": receipt["subject_commitment"],
         "purpose": receipt["purpose"],
         "scope_hash": receipt["scope_hash"].replace("sha256:", ""),
         "policy_hash": receipt["policy_hash"].replace("sha256:", ""),
         "timestamp": receipt["fact"]["ts"],
         "nonce": receipt["fact"]["nonce"],
         "surfaces_purged": receipt["fact"]["surfaces_purged"],
         "retrieval_test_outcome": receipt["fact"].get("retrieval_test_outcome", ""),
         "event_type": receipt["fact"].get("event_type", "erasure"),
     }
     ```
   - Compute leaf hash $H_{leaf} = \text{SHA-256}(0x00 \ || \ \text{canonical\_json}(fact\_for\_hash))$.
   - Reconstruct the Merkle root from $H_{leaf}$, `leaf_index`, `tree_size`, and `path` per RFC 6962.
   - Compare reconstructed root with `merkle_root`.
4. **Timestamp Token Check:**
   - Verify `token.digest_hex == receipt.merkle_root` (hex).
   - If `token.honesty_level == "simulated"`, record a formal warning.
5. **Anchor Timing Check:**
   - Parse `timestamp_token.timestamp` and `fact.ts`.
   - Verify `timestamp_token.timestamp >= fact.ts`. If anchor predates fact, REJECT receipt as back-dated.
6. **Limits Check:**
   - Verify `limits` is a non-empty array of strings.
7. **Assurance Level Check:**
   - Verify `1 <= assurance_level <= 4`.
   - If `assurance_level >= 3`, verify `key_destruction != "SIMULATED"`. If `key_destruction == "SIMULATED"`, REJECT.

---

## 6. Assurance Levels

Athar categorizes receipts into four progressive assurance levels:

```
+-------------------------------------------------------------------------------+
| Level 4: Multi-Party Hardware Attestation (Independent HSM + Public TSAs)     |
+-------------------------------------------------------------------------------+
| Level 3: Hardware Cryptographic Erasure (FIPS 140-2 L3 HSM, Real TSA)        |
+-------------------------------------------------------------------------------+
| Level 2: Cryptographic Erasure with Log Anchoring (SIMULATED Key Destruction) |
+-------------------------------------------------------------------------------+
| Level 1: Administrative Attestation (Software Log, Self-Signed)               |
+-------------------------------------------------------------------------------+
```

### Level 1: Administrative Attestation
- Software-level record deletion across registered surfaces.
- Log facts recorded locally; self-signed receipt.
- Key destruction: Not applicable or simulated.
- Suitable for internal operational tracking only.

### Level 2: Cryptographic Erasure with Anchoring (Athar MVP)
- Record encryption using per-subject/purpose DEKs.
- DEK destruction is SIMULATED (in-place memory/key store overwrite).
- Append-only RFC 6962 Merkle log with periodic batching.
- Timestamp token: Simulated or RFC 3161 TSA.
- Retrieval test executed and recorded.
- Every Level 2 receipt MUST label `key_destruction` as `"SIMULATED"`.

### Level 3: Hardware Cryptographic Erasure
- Keys stored and wrapped inside FIPS 140-2 Level 3 Hardware Security Modules (HSMs) or cloud KMS with tamper-evident audit logs.
- Key destruction is REAL: cryptographic keys are zeroized inside hardware and cannot be recovered by any party, including system administrators.
- Receipts MUST be anchored to a public, RFC 3161 certified Trust Service Provider (TSP).
- A Level 3 claim MUST NOT use `key_destruction: "SIMULATED"`.

### Level 4: Independent Multi-Party Hardware Attestation
- All Level 3 requirements plus:
- Multi-party key management (M-of-N threshold quorum for key destruction).
- Cryptographic attestation statements directly emitted by the HSM hardware module.
- Anchored simultaneously to public append-only ledgers (e.g. Bitcoin via OpenTimestamps, Certificate Transparency logs).

---

## 7. Mandatory Limit Disclosures

Every Athar receipt MUST include the `limits` array containing at least the following standard disclosures:

1. `"Does not prove absence of copies outside the manifest."`  
   *The receipt proves that surfaces in the manifest were purged, but cannot prove an attacker or unauthorized rogue process did not export an out-of-band replica prior to erasure.*
2. `"Key destruction is SIMULATED in this MVP."`  
   *Discloses that software-based key zeroization occurred, rather than hardware-enforced non-volatile physical zeroization.*
3. `"Self-run retrieval test does not raise assurance level."`  
   *Canary queries executed by the data controller do not replace third-party forensic audits.*
4. `"Timestamp anchor honesty depends on the external TSA."`  
   *Temporal bounds are only as trustworthy as the timestamp authority issuing the token.*
5. `"Detection time is the company's claim unless independently verified."`  
   *The latency between retention expiry and saga triggering is reported by the controller.*

Additional domain-specific limits MAY be appended by the issuer.

---

## 8. Complete Sample Receipt

```json
{
  "spec": "athar-receipt/0.1",
  "subject_commitment": "472bc0e386ab717b4c6e268a73a4b64e622b7a0d4c82e3c09b6264ff68be798e",
  "purpose": "kyc_verification",
  "period": "2026-10",
  "scope_hash": "sha256:d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
  "policy_hash": "sha256:5f4dbc865e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35aa",
  "assurance_level": 2,
  "key_destruction": "SIMULATED",
  "fact": {
    "fact_id": "7fae451b-c743-4dc9-98ec-673327fce1c4",
    "ts": "2026-10-14T08:30:00Z",
    "nonce": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "surfaces_purged": 4,
    "retrieval_test_outcome": "PASSED",
    "event_type": "erasure"
  },
  "inclusion_proof": {
    "batch_id": "8bb38f28-868c-4a3f-9173-0ff76ee46f7c",
    "leaf_index": 0,
    "tree_size": 1,
    "path": []
  },
  "merkle_root": "sha256:a69f73ccd356d6e9c6acab95f162ec808701e731999443729f8ce0ee209be1e4",
  "timestamp_token": {
    "token_type": "simulated",
    "token_data_hex": "4a7b98ec",
    "timestamp": "2026-10-14T08:31:00Z",
    "honesty_level": "simulated",
    "digest_hex": "a69f73ccd356d6e9c6acab95f162ec808701e731999443729f8ce0ee209be1e4",
    "token_id": "ts-token-001"
  },
  "retrieval_test": {
    "date": "2026-10-14",
    "surfaces": 4,
    "outcome": "not_recoverable",
    "details": "Ciphertexts decrypted with destroyed DEK failed authentication"
  },
  "limits": [
    "Does not prove absence of copies outside the manifest.",
    "Key destruction is SIMULATED in this MVP.",
    "Self-run retrieval test does not raise assurance level.",
    "Timestamp anchor honesty depends on the external TSA.",
    "Detection time is the company's claim unless independently verified."
  ],
  "signatures": [
    {
      "alg": "Ed25519",
      "kid": "quickfin-erasure-key-01",
      "pub": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "sig": "128_hex_character_ed25519_signature"
    }
  ]
}
```
