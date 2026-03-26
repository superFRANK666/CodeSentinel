# Unified Confidence Golden Fixtures

These files define deterministic assertions for Unified Confidence Scoring v1 (`ucs.v1`).

## Suggested generation commands

```powershell
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\confidence-secret-full.json
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\confidence-deps-full.json

.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn high -MinConfidence 0.7 -MinConfidenceLevel high -Format json -Output reports\confidence-policy-level-high.json
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -MinConfidenceLevel high -ExitZeroOnFindings -Format json -Output reports\confidence-policy-pass.json

.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format sarif -Output reports\confidence-deps-full.sarif
```

