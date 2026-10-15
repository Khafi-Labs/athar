# Athar Retention Policy and Legal Hold Format Specification

**Status:** Normative Specification  
**System:** Athar Policy Engine  
**Author:** Khafi Labs (My Personal Laboratories)  

---

## 1. Overview

The Athar Policy Framework governs data retention, legal holds, and erasure eligibility. It provides machine-verifiable retention rules, cryptographic policy hashing (binding receipts to exact rule versions), multi-party approval controls, and temporal grace periods.

This document defines the normative schema and serialization rules for:
1. `RetentionRule`
2. `LegalHold`
3. `Policy`
4. `EligibilityDecision`

---

## 2. Model Formats and JSON Schemas

### 2.1 `RetentionRule`

A `RetentionRule` defines the mandatory retention duration and statutory ground for a processing purpose and data category.

#### Properties
- `purpose` (`string`): The processing purpose identifier (e.g., `kyc_verification`, `marketing`, `transaction_history`).
- `category` (`string`): Data classification category (e.g., `financial_id`, `telemetry`, `contract_docs`).
- `retention_period_seconds` (`integer`, $\ge 0$): Retention period in seconds.
- `legal_basis` (`string`): One of `LEGAL_OBLIGATION`, `CONSENT`, `LEGITIMATE_INTEREST`, `CONTRACT`.
- `description` (`string`): Human-readable statutory reference or justification.

#### JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "RetentionRule",
  "type": "object",
  "required": ["purpose", "category", "retention_period_seconds", "legal_basis"],
  "properties": {
    "purpose": { "type": "string", "minLength": 1 },
    "category": { "type": "string", "minLength": 1 },
    "retention_period_seconds": { "type": "integer", "minimum": 0 },
    "legal_basis": {
      "type": "string",
      "enum": ["LEGAL_OBLIGATION", "CONSENT", "LEGITIMATE_INTEREST", "CONTRACT"]
    },
    "description": { "type": "string" }
  },
  "additionalProperties": false
}
```

---

### 2.2 `LegalHold`

A `LegalHold` suspends erasure for an individual subject pseudonym or system-wide (`ALL`) due to active litigation, regulatory investigation, or law enforcement request.

#### Properties
- `hold_id` (`string`, UUIDv4 or string): Unique hold identifier.
- `scope` (`string`): Subject pseudonym to freeze, or `"ALL"` for system-wide holds.
- `reason` (`string`): Case number or legal justification.
- `issuer` (`string`): Legal counsel or compliance officer issuing the hold.
- `started_at` (`string`, ISO 8601 UTC): Timestamp when hold took effect.
- `expires_at` (`string`, ISO 8601 UTC or `null`): Automatic expiration timestamp, if any.
- `active` (`boolean`): Whether the hold is currently enforceable.

#### JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "LegalHold",
  "type": "object",
  "required": ["hold_id", "scope", "reason", "issuer", "started_at", "active"],
  "properties": {
    "hold_id": { "type": "string", "minLength": 1 },
    "scope": { "type": "string", "minLength": 1 },
    "reason": { "type": "string", "minLength": 1 },
    "issuer": { "type": "string", "minLength": 1 },
    "started_at": { "type": "string", "format": "date-time" },
    "expires_at": { "type": ["string", "null"], "format": "date-time" },
    "active": { "type": "boolean" }
  },
  "additionalProperties": false
}
```

---

### 2.3 `Policy`

An organizational policy bundling retention rules, legal holds, safety grace periods, and authorization controls.

#### Properties
- `version` (`string`): Semantic version string (e.g., `1.0.0`, `2026.1`).
- `rules` (`array of RetentionRule`): List of retention rules.
- `holds` (`array of LegalHold`): List of legal holds.
- `requires_two_person_approval` (`boolean`): If `true`, dual distinct authorization is required before planning an erasure.
- `grace_period_seconds` (`integer`, $\ge 0$): Delay duration between intent logging and key zeroization.
- `policy_hash` (`string`, 64-char hex): SHA-256 canonical hash of the rules set.

#### JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Policy",
  "type": "object",
  "required": ["version", "rules", "holds", "requires_two_person_approval", "grace_period_seconds", "policy_hash"],
  "properties": {
    "version": { "type": "string", "minLength": 1 },
    "rules": {
      "type": "array",
      "items": { "$ref": "#/$defs/RetentionRule" }
    },
    "holds": {
      "type": "array",
      "items": { "$ref": "#/$defs/LegalHold" }
    },
    "requires_two_person_approval": { "type": "boolean" },
    "grace_period_seconds": { "type": "integer", "minimum": 0 },
    "policy_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
  },
  "additionalProperties": false
}
```

---

### 2.4 `EligibilityDecision`

The evaluation outcome emitted by `PolicyEngine.evaluate()`.

#### Properties
- `result` (`string`): One of `ELIGIBLE` or `BLOCKED`.
- `reason` (`string`): Human-readable justification of the assessment.
- `blocking_holds` (`array of string`): Array of `hold_id`s preventing erasure.
- `retention_expires_at` (`string`, ISO 8601 UTC or `null`): Calculated expiration timestamp.
- `evaluated_at` (`string`, ISO 8601 UTC): Evaluation execution timestamp.
- `policy_version` (`string`): Version of policy used during evaluation.

#### JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "EligibilityDecision",
  "type": "object",
  "required": ["result", "reason", "blocking_holds", "evaluated_at", "policy_version"],
  "properties": {
    "result": { "type": "string", "enum": ["ELIGIBLE", "BLOCKED"] },
    "reason": { "type": "string" },
    "blocking_holds": {
      "type": "array",
      "items": { "type": "string" }
    },
    "retention_expires_at": { "type": ["string", "null"], "format": "date-time" },
    "evaluated_at": { "type": "string", "format": "date-time" },
    "policy_version": { "type": "string" }
  },
  "additionalProperties": false
}
```

---

## 3. Policy Hash Computation

Every Athar erasure receipt references a `policy_hash` (prefixed with `sha256:`). This hash binds the receipt to the immutable rules authorizing the deletion.

### Computation Algorithm
1. Extract all `RetentionRule` instances from the policy.
2. Sort rules deterministically by `(purpose, category)` in ascending order.
3. Convert each rule to its canonical representation:
   ```json
   {
     "category": "financial_id",
     "description": "AML 5-year retention requirement",
     "legal_basis": "LEGAL_OBLIGATION",
     "purpose": "kyc_verification",
     "retention_period_seconds": 157680000
   }
   ```
4. Assemble the top-level payload:
   ```json
   {
     "rules": [ ...sorted canonical rules... ],
     "version": "1.0.0"
   }
   ```
5. Apply RFC 8785 Canonical JSON serialization.
6. Compute the SHA-256 digest over the resulting bytes:
   $$\text{policy\_hash} = \text{SHA-256}(\text{canonical\_json}(\text{payload}))$$
7. The result is serialized as a 64-character lowercase hex string.

---

## 4. Grace Period Rules

The `grace_period` represents the safety window between the public or auditable declaration of erasure intent (`INTENT_LOGGED`) and physical key destruction (`KEY_DESTROYED`).

1. **Default Duration:** The recommended default grace period is **72 hours** (`259,200 seconds`). Organizations MAY configure longer periods based on compliance risk profiles.
2. **Hold Interception:** During the grace period, if a new legal hold is issued targeting the subject, the saga will halt upon reaching `HOLD_REVALIDATED` (or during scheduled checks), preventing unrecoverable key loss.
3. **Cancellation:** While in the grace period, an authorized compliance officer MAY cancel the pending erasure with appropriate administrative rationale.

---

## 5. Two-Person Approval (Dual Authorization)

When `requires_two_person_approval` is set to `true`:
1. Any erasure plan MUST provide two distinct approver identities: `approvers = (approver_1, approver_2)`.
2. Both approvers MUST be non-empty strings.
3. Approvers MUST be distinct individuals:
   $$\text{approver\_1} \neq \text{approver\_2}$$
4. If `approvers` is `None` or contains identical identities, `PolicyEngine.evaluate()` returns:
   $$\text{result} = \text{BLOCKED}$$
   with reason: `"Two-person approval required but not provided or approvers are identical"`.
5. This control mitigates the risk of a single compromised administrative account executing mass unauthorized cryptographic destruction.


## Jurisdiction and Rule Provenance Extensions (v0.1.1)

Optional fields, hashed into `policy_hash` only when set (existing hashes are unchanged):

- Policy: `jurisdiction` (e.g. `"EG"`), `regime` (e.g. `"CBE_BANK"`), `legal_review` (`"NOT_REVIEWED"` by default; not hashed).
- Rule: `citation` (source and caveats), `period_confirmed` (default `true`), `retention_trigger` (default `"DATA_CREATION"`).

A rule with `period_confirmed: false` makes evaluation return `BLOCKED`. The caller must pass the date matching `retention_trigger` as `data_created_at`.
