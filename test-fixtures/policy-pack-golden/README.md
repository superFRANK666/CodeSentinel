# Policy Pack Golden Fixtures

Deterministic assertions for policy-file finding overlays (rule/category suppression and severity/confidence overrides).

## Suggested generation commands

```powershell
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -PolicyFile test-fixtures\policy-pack\overrides.policy.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\policy-pack-overrides.json

.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -PolicyFile test-fixtures\policy-pack\overrides.policy.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format sarif -Output reports\policy-pack-overrides.sarif
```

