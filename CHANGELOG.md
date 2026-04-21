# Changelog

All notable changes to CodeSentinel will be documented in this file.

## [2.0.0] - 2026-03-26

### Added
- **Unified Confidence Scoring (UCS v1)** — structured rationale with normalized confidence levels and policy gating support
- **First-class secret scanning** — pattern + entropy + context heuristics with detector metadata (`secret_type`, `validation_state`, `detector_class`)
- **First-class dependency risk analysis** — manifest/lockfile risk signals with optional policy and advisory inputs
- **Policy pack finding overlays** — rule/category suppression and severity/confidence overrides via `-PolicyFile`
- **Portfolio/batch scanning** — manifest-driven multi-project orchestration (`batch-scan`) with aggregate CI decision contract
- **Incremental/diff scan workflow** — `-Incremental`, `-DiffFrom`, persistent file-hash scan index (`scan-index.v1`)
- **SARIF 2.1.0 adapter** — full SARIF output with policy/incremental/baseline metadata for CI code scanning ecosystems
- **Policy Decision Contract v2** — deterministic `pass|fail|blocked` outcomes with scopes (`all_findings`, `incremental_delta`, `net_new_vs_baseline`)
- **Built-in policy profiles** — `dev_local`, `ci_pr_fast`, `ci_pr_strict`, `ci_main_strict`
- **Stable finding identity** — `finding_id` + `fingerprint_version=v2` + `dedup_key` for baseline/dedup/SARIF stability
- **Scope contract v1.1** — deterministic file selection with include/exclude/gitignore, default-exclude controls, and decision-trace diagnostics
- **Provenance metadata** — run ID, timestamp, binary hash, and ruleset version in every report
- **Machine-readable error envelopes** — structured error codes with details, hints, and doc URLs
- **Partial scan semantics** — `completeness=partial` with dedicated exit code `12`
- **Baseline suppression** — evolved format with structured `entries[]` plus backward-compatible `fingerprints[]`
- Comprehensive JSON schema definitions for all data contracts
- Golden assertion test fixtures for deterministic output verification
- MIT License

### Changed
- Spec version bumped from 1.7.0 to 2.0.0
- Report schema version aligned to 2.0.0
- Policy pack version aligned to 2.0.0
- README rewritten in English for international audience
- `.env.example` translated to English
- `quick_start.bat` translated to English
- `INSTALLATION.md` translated to English

### Fixed
- Consistent version numbering across all components

