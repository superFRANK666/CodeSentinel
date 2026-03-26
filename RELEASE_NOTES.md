# CodeSentinel v2.0.0

A major release bringing production-grade security analysis capabilities with CI/CD-first design.

## Highlights

- **Secret Scanning** — First-class secret detection with pattern, entropy, and context heuristics. Includes detector metadata for triage workflows.
- **Dependency Risk Analysis** — Manifest and lockfile scanning with policy and advisory support for supply chain security.
- **SARIF 2.1.0 Output** — Full SARIF support with policy and baseline metadata, ready for GitHub Code Scanning and other CI platforms.
- **Incremental Scanning** — File-hash based diff scanning with persistent cache index. Only re-analyze changed files for faster CI runs.
- **Policy Engine v2** — Deterministic `pass|fail|blocked` outcomes with configurable scopes, built-in CI profiles (`ci_pr_fast`, `ci_pr_strict`, `ci_main_strict`), and policy pack overlays.
- **Unified Confidence Scoring (UCS v1)** — Structured confidence rationale with normalized levels for precise policy gating and false-positive reduction.
- **Portfolio Scanning** — Manifest-driven batch analysis across multiple projects with aggregate CI decision contracts.
- **Baseline Suppression** — Evolved baseline format with stable finding identity (`finding_id` + `fingerprint_version=v2`) for reliable dedup and suppression.

## What's New

### Analysis
- First-class secret scanning stage (`-Enable secrets`)
- First-class dependency risk stage (`-Enable deps`)
- Unified Confidence Scoring v1 with structured rationale
- Stable finding identity with `finding_id`, `fingerprint_version=v2`, `dedup_key`

### CI/CD Integration
- SARIF 2.1.0 adapter with full metadata
- Deterministic exit code contract (0/10/11/12/20/30/40/50/60)
- Policy Decision Contract v2 with `pass|fail|blocked`
- Built-in policy profiles for common CI scenarios
- Partial scan semantics with dedicated exit code `12`

### Workflow
- Incremental/diff scan with persistent file-hash cache
- Baseline suppression with incremental status tracking
- Policy pack finding overlays (rule/category suppression, severity overrides)
- Portfolio/batch scanning with aggregate decisions
- Scope contract v1.1 with decision-trace diagnostics

### Infrastructure
- Machine-readable error envelopes with codes, hints, doc URLs
- Provenance metadata in every report (run ID, binary hash, ruleset version)
- Comprehensive JSON schemas for all data contracts
- Golden assertion test fixtures for deterministic verification

## Supported Languages

| Tier | Languages | Status |
|------|-----------|--------|
| Baseline | Python, JavaScript, TypeScript | Verified |
| Tier 1 | Java, C#, Go | Planned |
| Tier 2 | PHP, Ruby, Rust, Kotlin, Swift | Planned |
| Tier 3 | PowerShell, Shell/Bash, SQL | Planned |

## System Requirements

- Windows 10/11 (64-bit)
- PowerShell 5.1+
- Optional: Node.js + ESLint, OpenAI API key

## Getting Started

```powershell
.\codesentinel.cmd spec-version
.\codesentinel.cmd scan . -Format json -Output report.json
.\codesentinel.cmd scan . -Enable secrets,deps -Format sarif -Output report.sarif
```

See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions.

## SHA256

```
05B0605BDF4AB812F3400953FF13D279D8B8DB785DAF53F43B1B8270CE72EBE4  CodeSentinel.exe
```

---

**Full Changelog:** [CHANGELOG.md](CHANGELOG.md)
