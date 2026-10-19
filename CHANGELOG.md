# Changelog

## 0.2.1 (alpha)

Found by a full audit (bandit, pip-audit, coverage review).

- Security: the SQL purge connector now accepts only plain identifiers for table and column names (`[A-Za-z_][A-Za-z0-9_]{0,63}`) and raises `ValueError` otherwise. Before, these names were placed into SQL text unvalidated, so a bad or hostile configuration could change which rows a purge deletes.
- Security: `verify_timestamp_token` no longer silently skips trust verification. The TSA signature and certificate chain are still not verified; asking for it with `trusted_certs` now raises `NotImplementedError` instead of returning `True` (fail closed).
- Security: the RFC 3161 token parser rejects trailing bytes after the DER structure.
- Tests: 236 tests (was 162) and 83% line coverage (was 70%). The RFC 3161 module and the CLI had no tests; both are now covered, including tampered-receipt rejection through the CLI.
- CI: bandit (medium and above must pass), package build with `twine check` and a clean wheel install, a coverage floor of 80%, a weekly `pip-audit`, CodeQL, dependency review, Dependabot and a release workflow with SBOM and build-provenance attestation. All actions are pinned to commit SHAs.

## 0.2.0 (alpha)
### Security
- Verifier fails closed: requires a pinned issuer key (`--trust-embedded-key` opt-in only checks self-consistency); a Merkle path that does not reconstruct the root, or a missing timestamp token, now fails.
### Fixed
- `athar verify/demo` call the real verifier/pipeline; unimplemented CLI commands (`enroll`, `erase`, `receipt`, `status`) now exit with an error instead of printing fake success.
- `ErasureSaga.plan()` requires `data_created_at` (previously defaulted to the year 2000, silently bypassing retention).
- Six failing crash-recovery tests repaired; tamper-test fixture corrected; shipped sample receipt now genuinely signed.
- Packaging includes `verifier` and `demo`.
### Added
- Egypt jurisdiction pack: regime templates, AML retention rules with citations, unconfirmed placeholders that block erasure, Arabic/English receipt disclosures (Arabic unreviewed).
- Policy fields `jurisdiction`, `regime`, `citation`, `period_confirmed`, `retention_trigger`; optional signed `jurisdiction` block in receipts.
- Docs: Egypt legal notes, positioning guide, overview paper, roadmap; CI, security and contribution policies.
- Ruff and strict mypy now pass; 162 tests.

## 0.1.0
- Initial prototype.
