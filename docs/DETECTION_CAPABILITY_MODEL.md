# Detection Capability Model

## Core Taxonomy

- CWE mapping
- OWASP mapping
- Cross-language categories:
  - `injection`
  - `crypto`
  - `authz/authn`
  - `secrets`
  - `deserialization`
  - `filesystem`
  - `network`
  - `dependency`
  - `misconfiguration`

## Analysis Layers

1. Syntax/rule-based checks (fast, broad)
2. Semantic/type-aware checks (higher precision)
3. Taint/dataflow checks (high-value classes)
4. AI-assisted enrichment (explain/remediation/prioritization)

## Confidence and Severity

- Severity: `critical`, `high`, `medium`, `low`, `info`
- Confidence: numeric `0.0..1.0`
- Policy evaluation uses severity + confidence thresholds.

## False-Positive Control

- Baseline suppression (`baseline-create`, `-BaselineFile`)
- Policy thresholds (`-FailOn`, `-MinConfidence`)
- Rulepack pinning (`rules-pin`, lock file)

## Fallback Behavior

- `ai-only`: requires API key and AI availability
- `local-only`: deterministic local analyzer path
- `hybrid`: AI first, local fallback
- `fail-open` vs `fail-closed` controls degradation behavior
