# CodeSentinel CLI Specification v2.0.0

This spec defines the stable wrapper contract implemented by `codesentinel.ps1`.

## 1) Commands

- `scan [target]`
- `doctor`
- `config-validate`
- `spec-version`
- `rules-list`
- `rules-pin`
- `baseline-create [report.json]`
- `batch-scan [manifest.json]`

## 2) Global Options

- `-ConfigFile <path>` (default `codesentinel.config.json`)
- `-DumpEffectiveConfig`
- `-ErrorFormat text|json`
- `-Format console|json|markdown|html|xml|sarif`
- `-Output <path>`
- `-Stdout`
- `-BatchManifest <path>` (used by `batch-scan`, default `codesentinel.batch.json`)

## 3) Scan Options

- `-AnalyzerMode local-only|ai-only|hybrid`
- `-FallbackPolicy fail-open|fail-closed`
- `-MinSeverity critical|high|medium|low|info`
- `-ExitZeroOnFindings`
- `-FailOn critical|high|medium|low|info`
- `-MinConfidence <0..1>`
- `-MinConfidenceLevel low|medium|high`
- `-Include <glob[]>`
- `-Exclude <glob[]>`
- `-RespectGitIgnore`
- `-NoRespectGitIgnore`
- `-NoDefaultExcludes`
- `-Enable <feature[]>` (`secrets`, `deps`, `all`)
- `-Incremental`
- `-DiffFrom <path-to-scan-index>`
- `-CachePath <path-to-scan-index>`
- `-NoCacheWrite`
- `-PolicyScope all_findings|incremental_delta|net_new_vs_baseline`
- `-BaselineRequired`
- `-RequireAuthoritative`
- `-RequireTrustedIncremental`
- `-PolicyProfile dev_local|ci_pr_fast|ci_pr_strict|ci_main_strict`
- `-SecretScan`
- `-SecretEntropyThreshold <3.0..8.0>`
- `-SecretMinTokenLength <8..256>`
- `-SecretMaxFileBytes <4096..10485760>`
- `-DependencyScan`
- `-DependencyAdvisoryFile <path>`
- `-DependencyPolicyFile <path>`
- `-DependencyMaxFileBytes <4096..20971520>`
- `-BaselineFile <path>`
- `-PolicyFile <path>`
- `-RulesetVersion <id-version>`

## 4) Config Precedence

Order of precedence (highest to lowest):

1. CLI arguments
2. Environment variables (`CODESENTINEL_*`)
3. Config file (`codesentinel.config.json`)
4. Built-in defaults

Environment variables include:

- `CODESENTINEL_ANALYZER_MODE`
- `CODESENTINEL_FALLBACK_POLICY`
- `CODESENTINEL_MIN_SEVERITY`
- `CODESENTINEL_FORMAT`
- `CODESENTINEL_OUTPUT`
- `CODESENTINEL_ERROR_FORMAT`
- `CODESENTINEL_FAIL_ON`
- `CODESENTINEL_MIN_CONFIDENCE`
- `CODESENTINEL_MIN_CONFIDENCE_LEVEL`
- `CODESENTINEL_EXIT_ZERO_ON_FINDINGS`
- `CODESENTINEL_PROGRESS`
- `CODESENTINEL_RULESET_VERSION`
- `CODESENTINEL_ENABLE` (comma-separated features)
- `CODESENTINEL_INCLUDE` (comma-separated glob patterns)
- `CODESENTINEL_EXCLUDE` (comma-separated glob patterns)
- `CODESENTINEL_RESPECT_GITIGNORE` (`true|false`)
- `CODESENTINEL_NO_DEFAULT_EXCLUDES` (`true|false`)
- `CODESENTINEL_INCREMENTAL`
- `CODESENTINEL_DIFF_FROM`
- `CODESENTINEL_CACHE_PATH`
- `CODESENTINEL_NO_CACHE_WRITE`
- `CODESENTINEL_POLICY_SCOPE`
- `CODESENTINEL_BASELINE_REQUIRED`
- `CODESENTINEL_REQUIRE_AUTHORITATIVE`
- `CODESENTINEL_REQUIRE_TRUSTED_INCREMENTAL`
- `CODESENTINEL_POLICY_PROFILE`
- `CODESENTINEL_POLICY_FILE`
- `CODESENTINEL_BASELINE_FILE`
- `CODESENTINEL_SECRET_SCAN`
- `CODESENTINEL_SECRET_ENTROPY_THRESHOLD`
- `CODESENTINEL_SECRET_MIN_TOKEN_LENGTH`
- `CODESENTINEL_SECRET_MAX_FILE_BYTES`
- `CODESENTINEL_DEPENDENCY_SCAN`
- `CODESENTINEL_DEPENDENCY_ADVISORY_FILE`
- `CODESENTINEL_DEPENDENCY_POLICY_FILE`
- `CODESENTINEL_DEPENDENCY_MAX_FILE_BYTES`

## 5) Analyzer Fallback Rules

- `local-only`: run local analyzer once.
- `ai-only`: run AI analyzer once, fail if AI prerequisites are missing.
- `hybrid`: try local first, then AI fallback.
- `fail-open`: continue to fallback analyzer when prior analyzer fails.
- `fail-closed`: stop on first analyzer failure.
- If primary analyzer fails and `fail-open` is active, auxiliary analyzers selected via `-Enable` may still produce a completed report with degradation diagnostics.

## 6) Severity and Policy

Taxonomy: `critical > high > medium > low > info`.

Policy breach condition:

- finding severity rank >= `fail_on`
- AND finding confidence >= `min_confidence`

## 7) Exit Code Contract

- `0` success (no policy breach; findings may still exist if `exit_zero_on_findings=true`)
- `10` findings present (non-zero findings and `exit_zero_on_findings=false`)
- `11` policy breach
- `12` partial results (scan completed without authoritative coverage)
- `20` usage error
- `30` config validation error
- `40` runtime/analyzer failure
- `50` dependency/preflight failure
- `60` internal wrapper failure

## 7.1) Authoritative vs Partial Semantics

- Authoritative analyzer is:
  - `local` for `local-only` and `hybrid`
  - `ai` for `ai-only`
- `scan_summary.completeness` values:
  - `full`: authoritative analyzer succeeded
  - `partial`: report produced but authoritative coverage missing
  - `failed`: no usable report coverage
- `scan_summary.policy.is_authoritative` indicates whether policy was evaluated on full authoritative coverage.

## 7.2) Stable Finding Identity

Each finding now includes:

- `finding_id`: deterministic stable identifier (`csf_<hash16>`)
- `fingerprint`: SHA-256 over canonical identity fields
- `fingerprint_version`: current identity algorithm version (`v2`)
- `dedup_key`: stable key used for in-run deduplication

Identity seed fields include rule, normalized location, severity, title, evidence hash, language, and analyzer origin.

## 7.3) Incremental / Diff Mode Contract

- `-Incremental` enables file-hash index comparison mode.
- `-DiffFrom <index.json>` selects a specific base index; when omitted, wrapper uses `cache_path` (or default cache path).
- Relative paths for `-DiffFrom` and `-CachePath` are resolved from the current working directory.
- Default cache path is `<target-root>/.codesentinel/cache/scan-index.v1.json`.
- Classification is deterministic over scoped files:
  - `new`: present now, absent in base index
  - `changed`: SHA-256 differs from base index
  - `unchanged`: SHA-256 equal to base index
  - `deleted`: present in base index, absent now
- v1 incremental analyzes only `new + changed` files.
- If base index trust checks fail (missing index, schema mismatch, signature mismatch), wrapper falls back to full scan and reports `incremental_untrusted_fallback_to_full`.
- Report fields:
  - `scan_summary.scan_mode` (`full|incremental`)
  - `scan_summary.file_change_summary`
  - `scan_summary.coverage_limitations`
  - `diagnostics.incremental.*`
- Cache write behavior:
  - Writes `scan-index.v1` for completed scans (`full` or `partial`) unless `-NoCacheWrite` is set.
  - Index records `source_completeness` and `source_is_authoritative` for downstream diagnostics.

## 7.4) File Selection / Scan Scope Contract

- Selection contract version: `1.1` (`diagnostics.scope.selection_contract_version`).
- Deterministic selection order:
  1. `include` filter (`include_patterns`)
  2. effective exclude filter (`exclude_patterns.effective`)
  3. `.gitignore` filter (`gitignore.patterns`) when enabled and target is a directory
- Effective exclude set is deterministic and built as:
  - `exclude_patterns.user` (CLI/env/config `exclude`)
  - `exclude_patterns.default` (built-in defaults) when `use_default_excludes=true`
  - unioned and sorted into `exclude_patterns.effective`
- Built-in default excludes:
  - `**/node_modules/**`
  - `**/.git/**`
  - `.codesentinel/**`
  - `**/.codesentinel/**`
  - `**/dist/**`
  - `**/build/**`
  - `**/bin/**`
  - `**/obj/**`
- Controls:
  - CLI `-RespectGitIgnore` / `-NoRespectGitIgnore` controls `.gitignore` usage.
  - CLI `-NoDefaultExcludes` sets `use_default_excludes=false`.
  - Env `CODESENTINEL_NO_DEFAULT_EXCLUDES=true` sets `use_default_excludes=false`.
  - Config `use_default_excludes: true|false`.
  - `-RespectGitIgnore` and `-NoRespectGitIgnore` are mutually exclusive (validated as configuration error).
- Scope diagnostics are machine-readable and deterministic:
  - counts (`selected_files`, `excluded_by_*`)
  - pattern sets (`include_patterns`, `exclude_patterns.*`, `gitignore.patterns`)
  - digest (`selected_digest`)
  - decision trace samples (`decision_trace.*`)

## 7.5) Scope Precedence Clarification

- Global source precedence remains: `CLI > env > config file > defaults`.
- Inside scope evaluation, file-level precedence is fixed:
  - include gate first
  - exclude gate second (user + default effective set)
  - gitignore gate third
- Matching in each gate uses normalized path globs over relative paths (`/` separators).

## 7.6) Batch / Portfolio Scan Contract

- `batch-scan` executes deterministic multi-project scans from a manifest.
- Manifest schema: `batch-manifest.v1` (see `schemas/batch-manifest.schema.json`).
- Each project run executes wrapper `scan` with project-resolved config overrides and emits an individual JSON report.
- Aggregate portfolio output fields:
  - `report_type = "portfolio"`
  - `portfolio_report_version = "1.0"`
  - `portfolio_summary.*`
  - `projects[]` with per-project `scan_summary`, `policy_decision`, and `report_path`
- Aggregate decision precedence:
  1. project config/manifest project invalid => `blocked` (`exit_code=30`)
  2. project execution/report errors => `blocked` (`exit_code=40`)
  3. any project policy `blocked` => `blocked` (`exit_code=12`)
  4. any project policy `fail` with policy breach => `fail` (`exit_code=11`)
  5. any project policy `fail` for findings-present => `fail` (`exit_code=10`)
  6. otherwise `pass` (`exit_code=0`)
- Batch diagnostics are emitted in `diagnostics`:
  - `orchestration_contract_version`
  - manifest path/schema/hash
  - `project_order`
  - `project_status_counts`
- Output format support:
  - supported: `json`, `console`, `markdown`, `html`, `xml`
  - unsupported: `sarif` for portfolio aggregate (`BATCH_UNSUPPORTED_FORMAT`)

## 8) Machine-Readable Error Envelope

All structured errors use:

```json
{
  "code": "STRING_CODE",
  "message": "human readable message",
  "details": {},
  "hint": "optional remediation hint",
  "doc_url": "docs/CLI_SPEC_v2.md"
}
```

## 9) Trust and Provenance Signals

Every normalized report includes:

- `provenance.run_id`
- `provenance.timestamp`
- `provenance.binary_sha256`
- `provenance.ruleset_version`
- `provenance.analyzer_versions`

## 10) Scope Notes

- Wrapper-level include/exclude/gitignore scope is applied before primary analyzer execution by staging selected files.
- Scope diagnostics are emitted in both successful and runtime-failed reports.
- Primary analyzer semantics still depend on `CodeSentinel.exe` behavior.

## 11) SARIF Adapter Contract

- `-Format sarif` emits SARIF 2.1.0 from the canonical normalized report model.
- Canonical report remains source of truth; SARIF is an adapter layer.
- SARIF run properties include:
  - `codesentinel.scan_summary`
  - `codesentinel.policy_decision`
  - `codesentinel.incremental`
  - `codesentinel.baseline`
  - `codesentinel.provenance`
- SARIF results include:
  - stable identities in `partialFingerprints`
  - CodeSentinel fields in `result.properties`
  - CWE/OWASP mappings in `result.properties` and `run.taxonomies`/`result.taxa`
- Coverage and policy status are also emitted as `toolExecutionNotifications` for CI/code-scanning consumers.

## 12) Secret Analyzer Stage Contract

- Secret scanning is a first-class auxiliary analyzer stage (`aux:secrets`) controlled by:
  - `-SecretScan` / `CODESENTINEL_SECRET_SCAN`
  - `-SecretEntropyThreshold`
  - `-SecretMinTokenLength`
  - `-SecretMaxFileBytes`
- Detection model v1 is deterministic and local-first:
  - strong patterns (`pattern`)
  - contextual assignment patterns (`contextual_pattern`)
  - context + entropy heuristics (`entropy`)
- Secret findings use the canonical finding model and include:
  - `category = "secrets"`
  - `secret_type`
  - `validation_state`
  - `detector_class`
  - `metadata.secret.*` (including `detector_contract_version`)
- Stage diagnostics are emitted in `diagnostics.analyzer_stages[]` with:
  - `stage = "secrets"`
  - `contract_version = "secrets.v1"`
  - deterministic `detector_hits`
- Incremental trust invalidation includes secret-scan config fields in scan-index analysis signatures.

## 13) Dependency Analyzer Stage Contract

- Dependency scanning is a first-class stage (`aux:deps`) controlled by:
  - `-DependencyScan` / `CODESENTINEL_DEPENDENCY_SCAN`
  - `-DependencyAdvisoryFile`
  - `-DependencyPolicyFile`
  - `-DependencyMaxFileBytes`
- Current deterministic parsers/signals:
  - npm: `package.json`, `package-lock.json`
  - Python: `requirements.txt`
  - Go: `go.mod` (+ `go.sum` presence checks)
- Current risk classes:
  - `untrusted_source`
  - `unpinned_version`
  - `lockfile_missing`
  - `lock_missing_integrity`
  - `insecure_registry`
  - `replace_directive`
  - `policy_violation`
  - `vulnerable_dependency` (from local advisory bundle)
- Dependency findings use canonical schema fields:
  - `category = "dependency"`
  - `dependency_package`
  - `dependency_version`
  - `dependency_ecosystem`
  - `dependency_risk`
  - `metadata.dependency.*` (`detector_contract_version = "deps.v1"`)
- Stage diagnostics are emitted in `diagnostics.analyzer_stages[]` with:
  - `stage = "dependencies"`
  - `contract_version = "deps.v1"`
  - parsed manifest/lockfile counters
  - deterministic `detector_hits`
  - policy/advisory load status and match counts
- Incremental trust invalidation includes dependency-stage config and advisory/policy file hashes in scan-index analysis signatures.

## 14) Unified Confidence Scoring v1

- Canonical findings now use unified confidence scoring model `ucs.v1`.
- Confidence remains orthogonal to severity.
- Canonical confidence fields:
  - `raw_confidence`
  - `confidence` (normalized final score)
  - `confidence_level` (`high|medium|low`)
  - `confidence_model_version`
  - `confidence_reason`
  - `confidence_rationale` (structured adjustments/signals)
- Policy thresholds can use:
  - numeric `min_confidence`
  - categorical `min_confidence_level`
- SARIF result properties include:
  - `codesentinel.raw_confidence`
  - `codesentinel.confidence`
  - `codesentinel.confidence_level`
  - `codesentinel.confidence_model_version`
  - `codesentinel.confidence_rationale`

## 15) Policy Pack Finding Overlays

- `-PolicyFile` can now define deterministic finding overlays in addition to threshold gates.
- Supported overlay fields:
  - `enabled_categories` (allow-list for known categories)
  - `disabled_categories`
  - `severity_overrides`:
    - exact rule id keys (e.g. `deps.unpinned.version`)
    - category keys (`category:dependency`)
  - `rule_overrides` per rule id:
    - `enabled` (`true|false`)
    - `severity`
    - `confidence_override`
    - `confidence_offset`
    - `reason`
    - `id`
- Overlay application is deterministic and runs after normalization/dedup and before baseline/policy evaluation.
- Overlay diagnostics are emitted in `diagnostics.policy_pack`.
- Applied policy-pack identity is emitted in `metadata.policy_pack`.

