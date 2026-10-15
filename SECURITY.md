# Security Policy

Athar is an **alpha research prototype and has not been independently audited**. Do not rely on it to protect real personal data or to produce evidence for a regulator without your own review.

## Reporting a vulnerability

Please report privately; do not open a public issue.

- Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability** (https://github.com/Khafi-Labs/athar/security/advisories/new). Only the maintainers can see the report.
- Include: affected version, a minimal reproduction, and the impact you see.
- We aim to acknowledge reports within 7 days. This is a best-effort project run by a small lab; there is no bug bounty.

## Scope of particular interest

- Any way to make `ReceiptVerifier` accept a forged, altered or non-issuer-signed receipt.
- Canonical-JSON or Merkle-proof ambiguities (second-preimage, malleability).
- Key handling flaws in the keystore/vault (note: key destruction is intentionally SIMULATED and in-memory).

## Known limitations (not vulnerabilities)

See `docs/limits_of_the_claim.md` and `docs/threat_model.md`. In particular: no persistent or HSM-backed keystore, simulated timestamp anchoring by default, and no protection against copies outside the declared scope.
