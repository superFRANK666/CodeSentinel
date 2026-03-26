# Secret Stage Golden Fixtures

These files define deterministic assertions for the first-class secret analyzer stage.

## Suggested generation commands

```powershell
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\secret-full.json
.\codesentinel.ps1 baseline-create reports\secret-full.json -Output reports\secret-full.baseline.json
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -BaselineFile reports\secret-full.baseline.json -AnalyzerMode local-only -FallbackPolicy fail-open -Format json -Output reports\secret-baseline-scan.json

$cache='reports\secret-inc-trusted-flow\scan-index.v1.json'
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\secret-inc-trusted-flow-pass1.json
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\secret-inc-flow-pass2b.json
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -SecretEntropyThreshold 5.5 -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format json -Output reports\secret-inc-config-mismatch.json

.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -AnalyzerMode local-only -FallbackPolicy fail-open -Format sarif -Output reports\secret-full.sarif
.\codesentinel.ps1 scan test-fixtures\secret-scan -SecretScan -Incremental -CachePath $cache -AnalyzerMode local-only -FallbackPolicy fail-open -FailOn critical -MinConfidence 1 -ExitZeroOnFindings -Format sarif -Output reports\secret-inc-trusted.sarif
```

These fixture assertions are intended for a simple assertion harness that checks key JSON paths and containment predicates.

