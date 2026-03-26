# Dependency Stage Golden Fixtures

These files define deterministic assertions for the first-class dependency analyzer stage.

## Suggested generation commands

```powershell
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\deps-stage-full.json
.\codesentinel.ps1 baseline-create reports\deps-stage-full.json -Output reports\deps-stage.baseline.json
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -BaselineFile reports\deps-stage.baseline.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\deps-baseline-suppressed.json

$cache='reports\deps-inc-flow\scan-index.v1.json'
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\deps-inc-pass1.json
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\deps-inc-pass2.json
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\deps-inc-mismatch.json
.\\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -BaselineFile reports\deps-stage.baseline.json -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\deps-inc-baseline-trusted.json

.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format sarif -Output reports\deps-stage-full.sarif
.\codesentinel.ps1 scan test-fixtures\dependency-scan -DependencyScan -DependencyPolicyFile test-fixtures\dependency-scan\dependency-policy.json -DependencyAdvisoryFile test-fixtures\dependency-scan\dependency-advisories.json -BaselineFile reports\deps-stage.baseline.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format sarif -Output reports\deps-baseline.sarif
```
