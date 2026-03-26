# CodeSentinel v2.0.0

**Windows-first code security analysis CLI** — deterministic, CI-ready, with optional AI-assisted analysis.

CodeSentinel scans your codebase for security vulnerabilities, hardcoded secrets, and dependency risks. It outputs normalized, machine-readable reports in multiple formats with deterministic exit codes designed for CI/CD integration.

## Features

- **Multi-language analysis** — Python, JavaScript, TypeScript (baseline); extensible language adapter architecture
- **Dual-mode analysis** — Local deterministic analyzer + optional AI-assisted analysis (OpenAI API)
- **Secret scanning** — Pattern + entropy + context heuristics with structured detector metadata
- **Dependency risk analysis** — Manifest/lockfile risk signals with policy and advisory support
- **Multiple output formats** — JSON, SARIF 2.1.0, Markdown, HTML, XML, Console
- **Incremental scanning** — File-hash based diff scanning with persistent cache index
- **Policy engine** — Configurable severity/confidence thresholds, category gating, built-in CI profiles
- **Baseline suppression** — Suppress known findings with fingerprint-based baselines
- **Portfolio scanning** — Manifest-driven batch scanning across multiple projects
- **Deterministic exit codes** — Machine-readable CI gate outcomes (`0`=pass, `10`=findings, `11`=policy breach, `12`=partial)

## Quick Start

```powershell
# Verify installation
.\codesentinel.cmd spec-version

# Run environment diagnostics
.\codesentinel.cmd doctor -Format json

# Scan current directory
.\codesentinel.cmd scan . -Format json -Output report.json

# Scan with secret + dependency detection
.\codesentinel.cmd scan . -Enable secrets,deps -Format json -Output report.json

# SARIF output for CI integration
.\codesentinel.cmd scan . -Format sarif -Output report.sarif

# Validate configuration
.\codesentinel.cmd config-validate
```

## Installation

1. Download and extract the release archive
2. Open PowerShell and navigate to the extracted directory
3. Run `.\codesentinel.cmd spec-version` to verify

For AI-assisted analysis, copy `.env.example` to `.env` and add your OpenAI API key.

See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions.

## Architecture

```
codesentinel.cmd          CLI launcher (batch)
  └─ codesentinel.ps1     Contracted wrapper CLI (PowerShell)
       └─ CodeSentinel.exe  Core analysis binary
```

The wrapper enforces all CLI contracts (exit codes, output schemas, scope filtering, policy evaluation) on top of the core binary. This layered design ensures deterministic, CI-safe behavior.

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan [target]` | Run security analysis on target path |
| `doctor` | Check environment dependencies |
| `config-validate` | Validate configuration files |
| `spec-version` | Print specification version |
| `rules-list` | List available rule packs |
| `rules-pin` | Pin ruleset version |
| `baseline-create` | Generate baseline from scan report |
| `batch-scan` | Run portfolio scan from manifest |

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Console | `-Format console` | Human-readable terminal output |
| JSON | `-Format json` | Normalized machine-readable report |
| SARIF | `-Format sarif` | GitHub/CI code scanning integration |
| Markdown | `-Format markdown` | Documentation and PR comments |
| HTML | `-Format html` | Standalone report pages |
| XML | `-Format xml` | Legacy tool integration |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — no findings or policy pass |
| `10` | Findings present |
| `11` | Policy breach — CI gate failure |
| `12` | Partial results — scan incomplete |
| `20` | Usage error |
| `30` | Configuration error |
| `40` | Runtime error |
| `50` | Dependency error |
| `60` | Internal error |

## Configuration

Configuration follows strict precedence: **CLI args > Environment variables > Config file > Defaults**

```powershell
# Analyzer modes
-AnalyzerMode local-only    # No API key needed
-AnalyzerMode ai-only       # Requires OPENAI_API_KEY
-AnalyzerMode hybrid        # Best of both (default)

# Fallback policies
-FallbackPolicy fail-open   # Continue on analyzer failure
-FallbackPolicy fail-closed # Abort on analyzer failure

# Scope filtering
-Include "src/**,lib/**"
-Exclude "**/*.test.*"
-RespectGitIgnore
-NoDefaultExcludes
```

See [docs/CLI_SPEC_v1.md](docs/CLI_SPEC_v1.md) for the complete specification.

## CI/CD Integration

CodeSentinel is designed for CI pipelines with deterministic exit codes and SARIF output:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    .\codesentinel.cmd scan . -Format sarif -Output results.sarif -FallbackPolicy fail-open
  continue-on-error: false

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Documentation

| Document | Description |
|----------|-------------|
| [CLI Specification](docs/CLI_SPEC_v1.md) | Complete command and option reference |
| [Architecture Direction](docs/ARCHITECTURE_DIRECTION.md) | Platform layer design |
| [Detection Capability Model](docs/DETECTION_CAPABILITY_MODEL.md) | Analysis layers and false-positive control |
| [Language Coverage Plan](docs/LANGUAGE_COVERAGE_PLAN.md) | Multi-language expansion roadmap |
| [Implementation Status](docs/IMPLEMENTATION_STATUS.md) | Current vs. planned capabilities |
| [Roadmap](docs/ROADMAP.md) | Phase-based development plan |
| [Examples](docs/EXAMPLES.md) | Test fixtures and golden assertions |
| [Changelog](CHANGELOG.md) | Release history |

## Schemas

Machine-readable JSON schemas for all data contracts are in the `schemas/` directory:

- `report.schema.json` — Normalized scan report
- `config.schema.json` — Configuration validation
- `error.schema.json` — Error envelope
- `policy.schema.json` — Policy pack definition
- `baseline.schema.json` — Baseline fingerprint storage
- `scan-index.schema.json` — Incremental scan cache
- `batch-manifest.schema.json` — Portfolio manifest
- `portfolio-report.schema.json` — Batch scan aggregation

## System Requirements

- Windows 10/11 (64-bit)
- PowerShell 5.1+ (included with Windows)
- Optional: Node.js + ESLint (for enhanced JavaScript analysis)
- Optional: OpenAI API key (for AI-assisted analysis)

## License

[MIT](LICENSE)

## Support

- [GitHub Issues](https://github.com/superFRANK666/CodeSentinel/issues)
- [Documentation](https://github.com/superFRANK666/CodeSentinel)
