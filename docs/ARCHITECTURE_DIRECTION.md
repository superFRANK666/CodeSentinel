# High-Level Product Architecture Direction

## Platform Layers

1. CLI Frontend
- Command parsing and interactive flow
- Config source merge and validation

2. Analyzer Abstraction
- Uniform interface for local/AI/language analyzers
- Capability declaration (`syntax`, `rule`, `semantic`, `taint`)

3. Language Adapter Layer
- Per-language parser + semantic modules
- Framework/ecosystem rule packs

4. Normalization Layer
- Canonical finding schema
- Severity and confidence normalization
- Error envelope normalization

5. Reporting Layer
- Console, JSON, SARIF, Markdown, HTML, XML outputs
- Provenance and diagnostics embedding

6. Rulepack and Policy Layer
- Versioned rulepacks
- Profile-based policy overlays
- Ruleset pinning/lock support

7. Offline and Trust Layer
- Signed bundles for rules/dependency intel
- Provenance manifests with binary hash/run metadata

## Analyzer Fallback Model

- `local-only`: deterministic local scan.
- `ai-only`: AI scan; strict dependency requirement.
- `hybrid`: AI first, local fallback by policy.
- `fail-open` vs `fail-closed` behavior controlled by config.

## Observability Model

- Structured diagnostics for dependencies, analyzer attempts, and degradations.
- Run correlation via `provenance.run_id`.
- Deterministic exit code contract for CI/CD gating.
