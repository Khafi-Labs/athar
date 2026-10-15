# Changelog

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
