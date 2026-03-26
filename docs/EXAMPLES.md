# Example Artifacts

The package includes sample artifacts produced during wrapper smoke validation:

- `sample-report.json`: sample normalized input report with one finding
- `sample-baseline.json`: baseline generated from `sample-report.json`
- `reports/scan.json`: sample runtime-failure report from blocked `CodeSentinel.exe` execution environment
- `codesentinel.rules.lock.json`: sample ruleset pin file (`rules-pin`)

These files can be reused as templates for automation integration and contract testing.

Additional fixture folder:

- `test-fixtures/aux-scan/`:
  - `app.py` (hardcoded credential example)
  - `package.json` (unpinned and git dependency examples)
  - `requirements.txt` (unpinned and VCS dependency examples)
- `test-fixtures/secret-scan/`:
  - `high_signal.py` (strong token patterns)
  - `entropy_assignment.py` (context + entropy heuristic)
  - `private_key.txt` (private key block detection)
  - `placeholder_values.py` (placeholder suppression checks)
  - `tests/mock_secret.py` (test-like path demotion behavior)
- `test-fixtures/dependency-scan/`:
  - `package.json` + `requirements.txt` + `go.mod` (manifest risk signals)
  - `dependency-policy.json` (blocked package + lockfile policy)
  - `dependency-advisories.json` (local advisory bundle matching)
- `test-fixtures/scope-selection-ci/`:
  - deterministic scope contract fixture for include/exclude/default excludes/.gitignore interactions
  - includes representative folders: `.codesentinel`, `build`, `dist`, `node_modules`, `src`, `included`, `vendor`
- `test-fixtures/portfolio-batch/`:
  - `manifest.json` for deterministic multi-project `batch-scan`
  - references `secret-scan` and `dependency-scan` fixtures with per-project config overrides

SARIF golden assertion fixtures:

- `test-fixtures/sarif-golden/default.expected.json`
- `test-fixtures/sarif-golden/blocked-authoritative.expected.json`
- `test-fixtures/sarif-golden/incremental-untrusted.expected.json`

Secret-stage golden assertion fixtures:

- `test-fixtures/secret-golden/canonical-full.expected.json`
- `test-fixtures/secret-golden/canonical-baseline-suppressed.expected.json`
- `test-fixtures/secret-golden/canonical-incremental-trusted.expected.json`
- `test-fixtures/secret-golden/canonical-incremental-baseline-trusted.expected.json`
- `test-fixtures/secret-golden/canonical-incremental-config-mismatch.expected.json`
- `test-fixtures/secret-golden/sarif-full.expected.json`
- `test-fixtures/secret-golden/sarif-incremental-trusted.expected.json`
- `test-fixtures/secret-golden/sarif-baseline-suppressed.expected.json`

Dependency-stage golden assertion fixtures:

- `test-fixtures/dependency-golden/canonical-full.expected.json`
- `test-fixtures/dependency-golden/canonical-baseline-suppressed.expected.json`
- `test-fixtures/dependency-golden/canonical-incremental-trusted.expected.json`
- `test-fixtures/dependency-golden/canonical-incremental-baseline-trusted.expected.json`
- `test-fixtures/dependency-golden/canonical-incremental-config-mismatch.expected.json`
- `test-fixtures/dependency-golden/sarif-full.expected.json`
- `test-fixtures/dependency-golden/sarif-baseline-suppressed.expected.json`

Unified confidence golden assertion fixtures:

- `test-fixtures/confidence-golden/canonical-secret-full.expected.json`
- `test-fixtures/confidence-golden/canonical-dependency-full.expected.json`
- `test-fixtures/confidence-golden/policy-confidence-level-fail.expected.json`
- `test-fixtures/confidence-golden/policy-confidence-level-pass.expected.json`
- `test-fixtures/confidence-golden/sarif-confidence.expected.json`

Policy-pack overlay golden assertion fixtures:

- `test-fixtures/policy-pack-golden/canonical-overrides.expected.json`
- `test-fixtures/policy-pack-golden/sarif-overrides.expected.json`

Scope selection contract golden assertion fixtures:

- `test-fixtures/scope-golden/default-scope.expected.json`
- `test-fixtures/scope-golden/include-exclude-scope.expected.json`
- `test-fixtures/scope-golden/no-default-excludes.expected.json`
- `test-fixtures/scope-golden/gitignore-off.expected.json`
- `test-fixtures/scope-golden/incremental-filtered-scope.expected.json`
- `test-fixtures/scope-golden/incremental-scope-config-mismatch.expected.json`

Portfolio batch golden assertion fixtures:

- `test-fixtures/portfolio-golden/portfolio-batch.expected.json`
- `test-fixtures/portfolio-golden/portfolio-batch-invalid.expected.json`

Stage finalization verification:

- `.\tools\verify-stage3-finalization.ps1`
  - runs command/spec validation
  - validates schema compatibility for generated reports
  - validates golden assertions for scope, secret, dependency, policy-pack, confidence, SARIF, and portfolio flows
  - validates normalized determinism for canonical JSON, SARIF, and batch outputs
