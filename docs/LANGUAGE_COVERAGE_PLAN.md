# Language Coverage Expansion Plan

This document operationalizes the tiered language strategy for CodeSentinel.

## Current Verified Baseline

- Python
- JavaScript
- TypeScript

## Tier 1 (highest priority)

- Python, JavaScript, TypeScript, Java, C#, Go, PHP, C/C++, Rust, Kotlin, SQL, PowerShell, Shell/Bash

Minimum coverage target:

- syntax checks + rule-based checks + semantic checks
- targeted taint/dataflow for injection, command execution, path traversal, auth flaws
- dependency and secret scanning integration

## Tier 2 (important secondary)

- Swift, Ruby, Scala, Dart, Lua, Objective-C, Groovy, VB.NET

Minimum coverage target:

- syntax checks + rule-based checks
- selective semantic checks for top frameworks

## Tier 3 (ecosystem expansion)

- R, Perl, MATLAB, Assembly

Minimum coverage target:

- syntax and hygiene checks
- secrets and high-confidence hotspot rules

## Cross-Language Consistency Rules

- All analyzers emit findings in the same normalized schema (`schemas/report.schema.json`).
- Shared severity taxonomy: `critical/high/medium/low/info`.
- Shared confidence scale: `0.0` to `1.0`.
- Shared taxonomy mapping: CWE + OWASP categories.
