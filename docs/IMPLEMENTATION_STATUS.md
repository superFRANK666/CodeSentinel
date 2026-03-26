# Implementation Status (Plan Execution)

## Implemented in this package

- Contracted wrapper CLI: `codesentinel.ps1`
- Command launcher: `codesentinel.cmd`
- CLI spec contract: `docs/CLI_SPEC_v1.md`
- Severity taxonomy and policy thresholds
- Normalized report format and schema
- Config model and validation command
- Analyzer fallback behavior and deterministic exit codes
- Output precedence and effective-config merging
- Dependency diagnostics (`doctor`)
- Provenance metadata in report payloads
- Machine-readable error envelope
- Ruleset listing/pinning scaffolding
- Baseline generation/suppression primitives
- SARIF output generation from normalized findings
- Wrapper-enforced file scope filtering with include/exclude/gitignore
- Deterministic scope contract v1.1 with explicit default-exclude controls and decision-trace diagnostics
- Auxiliary local analyzers for `secrets` and first-class dependency-risk stage (`deps`)
- Fail-open degradation path that can complete with auxiliary findings
- Stable finding identity (`finding_id`, `fingerprint_version=v2`, `dedup_key`)
- Partial scan semantics with authoritative policy marker and dedicated exit code (`12`)
- Baseline format evolved with structured `entries[]` plus backward-compatible `fingerprints[]`
- Incremental/diff scan workflow (`-Incremental`, `-DiffFrom`, `-CachePath`, `-NoCacheWrite`)
- Persistent file-hash scan index (`scan-index.v1`) with signature-based trust checks and deterministic fallback to full scan
- Incremental report semantics (`scan_mode`, `file_change_summary`, `coverage_limitations`, `diagnostics.incremental`)
- Baseline suppression diagnostics with incremental status (`reevaluated`, `not_reevaluated`, `resolved_candidates`)
- Policy Decision Contract v2 (`policy_decision`) with deterministic `pass|fail|blocked` outcomes
- Policy scopes (`all_findings`, `incremental_delta`, `net_new_vs_baseline`) and coverage gating controls
- Built-in policy profiles (`dev_local`, `ci_pr_fast`, `ci_pr_strict`, `ci_main_strict`)
- First-class secret scanning stage with detector metadata (`secret_type`, `validation_state`, `detector_class`)
- Secret-aware incremental trust signatures (secret scanner config changes trigger untrusted incremental fallback)
- First-class dependency risk stage with policy/advisory support and canonical dependency metadata
- Unified confidence scoring v1 (`ucs.v1`) with normalized `confidence_level` and structured rationale
- Policy pack finding overlays via `policy_file` (category/rule gating + severity/confidence overrides)
- Manifest-driven batch/portfolio scan orchestration (`batch-scan`) with deterministic aggregate decisioning
- Language roadmap, architecture direction, detection model, roadmap docs

## Not fully implementable in this package without source-level binary changes

- Deep parser/analyzer implementations for new languages inside `CodeSentinel.exe`
- True include/exclude/gitignore enforcement in the underlying binary engine
- Full taint/dataflow engine integration for additional languages
- Native triage state backend
- Signed plugin runtime and attestation pipeline

These are documented as platform directions in:

- `docs/ROADMAP.md`
- `docs/ARCHITECTURE_DIRECTION.md`
- `docs/LANGUAGE_COVERAGE_PLAN.md`
