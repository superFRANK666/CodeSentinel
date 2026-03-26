# Scope Contract Golden Fixtures

Deterministic assertions for wrapper-level scan scope selection contract v1.1.

Fixture target:

- `test-fixtures/scope-selection-ci/`

Suggested generation commands:

```powershell
.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -NoCacheWrite -Format json -Output reports\scope-ci-default.json

.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -NoCacheWrite -Include src/**,included/** -Exclude src/custom.log -Format json -Output reports\scope-ci-include-exclude.json

.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -NoCacheWrite -NoDefaultExcludes -Format json -Output reports\scope-ci-no-default-excludes.json

$env:CODESENTINEL_RESPECT_GITIGNORE='false'
.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -NoCacheWrite -Format json -Output reports\scope-ci-gitignore-off.json
Remove-Item Env:CODESENTINEL_RESPECT_GITIGNORE

.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -Include src/**,included/** -Exclude src/custom.log -CachePath reports\scope-ci-inc-cache.v1.json -Format json -Output reports\scope-ci-incremental-seed.json

.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -Incremental -Include src/**,included/** -Exclude src/custom.log -CachePath reports\scope-ci-inc-cache.v1.json -Format json -Output reports\scope-ci-incremental-filtered.json

.\codesentinel.ps1 scan test-fixtures\scope-selection-ci -AnalyzerMode local-only -FallbackPolicy fail-open -Incremental -NoDefaultExcludes -Include src/**,included/** -Exclude src/custom.log -CachePath reports\scope-ci-inc-cache.v1.json -Format json -Output reports\scope-ci-mismatch-incremental.json
```
