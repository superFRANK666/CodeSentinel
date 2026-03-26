param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

$wrapper = Join-Path $Root 'codesentinel.ps1'
if (-not (Test-Path -LiteralPath $wrapper)) { throw "codesentinel.ps1 not found at $wrapper" }

$reportsDir = Join-Path $Root 'reports/stage3-finalization'
if (Test-Path -LiteralPath $reportsDir) { Remove-Item -LiteralPath $reportsDir -Recurse -Force }
New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null

function Read-Json([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing JSON file: $path" }
    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 100)
}

function Get-PropValue($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) {
        if ($obj.Contains($name)) { return $obj[$name] }
        if ($obj.ContainsKey($name)) { return $obj[$name] }
        return $null
    }
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-ByPath($obj, [string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $obj }
    $current = $obj
    foreach ($segment in ($path -split '\.')) {
        if ($null -eq $current) { return $null }
        if ($segment -match '^(?<name>[^\[]+)\[(?<idx>\d+)\]$') {
            $name = $Matches['name']
            $idx = [int]$Matches['idx']
            $arr = Get-PropValue $current $name
            if ($null -eq $arr) { return $null }
            $vals = @($arr)
            if ($idx -ge $vals.Count) { return $null }
            $current = $vals[$idx]
        }
        else {
            $current = Get-PropValue $current $segment
        }
    }
    return $current
}

function Is-List($v) {
    return ($v -is [System.Collections.IEnumerable] -and $v -isnot [string])
}

function To-Array($v) {
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { return @($v) }
    if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { $_ }) }
    return @($v)
}

function Compare-Subset($expected, $actual) {
    if ($null -eq $expected) { return $null -eq $actual }
    if ($expected -is [System.Collections.IDictionary] -or $expected -is [pscustomobject]) {
        if ($null -eq $actual) { return $false }
        $props = @()
        if ($expected -is [System.Collections.IDictionary]) {
            $props = @($expected.Keys)
        }
        else {
            $props = @($expected.PSObject.Properties.Name)
        }
        foreach ($k in $props) {
            $ev = Get-PropValue $expected ([string]$k)
            $av = Get-PropValue $actual ([string]$k)
            if (-not (Compare-Subset $ev $av)) { return $false }
        }
        return $true
    }
    if (Is-List $expected) {
        $ea = To-Array $expected
        $aa = To-Array $actual
        if ($ea.Count -ne $aa.Count) { return $false }
        for ($i = 0; $i -lt $ea.Count; $i++) {
            if (-not (Compare-Subset $ea[$i] $aa[$i])) { return $false }
        }
        return $true
    }
    return [string]$expected -ceq [string]$actual
}

function Assert-Contains($expected, $actual) {
    if (Is-List $expected) {
        foreach ($item in @($expected)) {
            if (-not (Assert-Contains $item $actual)) { return $false }
        }
        return $true
    }
    if ($expected -is [System.Collections.IDictionary] -or $expected -is [pscustomobject]) {
        return (Compare-Subset $expected $actual)
    }
    if ($actual -is [System.Collections.IDictionary] -or $actual -is [pscustomobject]) {
        return ($null -ne (Get-PropValue $actual ([string]$expected)))
    }
    if (Is-List $actual) {
        foreach ($candidate in @($actual)) {
            if (([string]$candidate) -ceq ([string]$expected)) { return $true }
        }
        return $false
    }
    return ([string]$actual -like "*$expected*")
}

function Resolve-AssertionValue($doc, [string]$key, [string]$kind) {
    if ($kind -eq 'sarif') {
        $run = @($doc.runs)[0]
        $inv = @($run.invocations)[0]
        $runProps = $run.properties
        switch -Regex ($key) {
            '^sarif_version$' { return $doc.version }
            '^run_count$' { return @($doc.runs).Count }
            '^result_count$' { return @($run.results).Count }
            '^invocation\.' { return Get-ByPath $inv ($key.Substring('invocation.'.Length)) }
            '^policy_decision\.' {
                $pd = Get-PropValue $runProps 'codesentinel.policy_decision'
                return Get-ByPath $pd ($key.Substring('policy_decision.'.Length))
            }
            '^scan_summary\.' {
                $ss = Get-PropValue $runProps 'codesentinel.scan_summary'
                return Get-ByPath $ss ($key.Substring('scan_summary.'.Length))
            }
            '^incremental\.' {
                $inc = Get-PropValue $runProps 'codesentinel.incremental'
                return Get-ByPath $inc ($key.Substring('incremental.'.Length))
            }
            '^baseline\.' {
                $base = Get-PropValue $runProps 'codesentinel.baseline'
                return Get-ByPath $base ($key.Substring('baseline.'.Length))
            }
            '^notification_ids_contains$' {
                return @($inv.toolExecutionNotifications | ForEach-Object { $_.descriptor.id })
            }
            '^taxonomies_contains$' {
                return @($run.taxonomies | ForEach-Object { $_.name })
            }
            '^run_properties_contains$' {
                return @($runProps.PSObject.Properties.Name)
            }
            '^first_result_properties_contains$' {
                $first = @($run.results)[0]
                return @($first.properties.PSObject.Properties.Name)
            }
            default { return Get-ByPath $doc $key }
        }
    }

    if ($kind -eq 'json') {
        switch -Regex ($key) {
            '^secret_stage\.' {
                $stage = @($doc.diagnostics.analyzer_stages | Where-Object { [string]$_.stage -eq 'secrets' })[0]
                return Get-ByPath $stage ($key.Substring('secret_stage.'.Length))
            }
            '^dependency_stage\.' {
                $stage = @($doc.diagnostics.analyzer_stages | Where-Object { [string]$_.stage -eq 'dependencies' })[0]
                return Get-ByPath $stage ($key.Substring('dependency_stage.'.Length))
            }
            '^first_finding_fields_contains$' {
                $first = @($doc.findings)[0]
                if ($null -eq $first) { return @() }
                return @($first.PSObject.Properties.Name)
            }
            default { return Get-ByPath $doc $key }
        }
    }

    if ($kind -eq 'portfolio') {
        return Get-ByPath $doc $key
    }

    return Get-ByPath $doc $key
}

function Run-Wrapper([string[]]$cmdArgs, [int[]]$allowed) {
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add(("& '{0}'" -f $wrapper)) | Out-Null
    foreach ($arg in $cmdArgs) {
        $s = [string]$arg
        if ($s.StartsWith('-')) {
            $parts.Add($s) | Out-Null
        }
        else {
            $escaped = $s.Replace("'", "''")
            $parts.Add("'$escaped'") | Out-Null
        }
    }
    $cmdText = [string]::Join(' ', @($parts))
    Invoke-Expression $cmdText
    $code = $LASTEXITCODE
    if ($allowed -notcontains $code) {
        throw "Unexpected exit code $code for: $($cmdArgs -join ' ')"
    }
}

function Apply-Assertions([string]$expectedPath, [string]$actualPath, [string]$kind) {
    $expectedDoc = Read-Json $expectedPath
    $actualDoc = Read-Json $actualPath
    $assertions = $expectedDoc.assertions
    foreach ($ap in $assertions.PSObject.Properties) {
        $key = [string]$ap.Name
        $expected = $ap.Value
        $containsMode = $false
        $valueKey = $key
        if ($key.EndsWith('_contains')) {
            $containsMode = $true
            if ($key -notin @('notification_ids_contains', 'taxonomies_contains', 'run_properties_contains', 'first_result_properties_contains', 'first_finding_fields_contains')) {
                $valueKey = $key.Substring(0, $key.Length - '_contains'.Length)
            }
        }
        $actual = Resolve-AssertionValue -doc $actualDoc -key $valueKey -kind $kind
        $ok = if ($containsMode) { Assert-Contains $expected $actual } else { Compare-Subset $expected $actual }
        if (-not $ok) {
            $expJson = $expected | ConvertTo-Json -Depth 30 -Compress
            $actJson = $actual | ConvertTo-Json -Depth 30 -Compress
            throw "Assertion failed [$key] expected=$expJson actual=$actJson (file=$actualPath)"
        }
    }
}

function Validate-Schema([string]$jsonPath, [string]$schemaPath) {
    $raw = Get-Content -LiteralPath $jsonPath -Raw
    $ok = $raw | Test-Json -SchemaFile $schemaPath
    if (-not $ok) { throw "Schema validation failed: $jsonPath against $schemaPath" }
}

function Normalize-Volatile($node, [string]$path = '') {
    if ($null -eq $node) { return $null }
    $volatile = @('generated_at', 'run_id', 'timestamp', 'endTimeUtc', 'duration_ms', 'output')
    if ($node -is [System.Collections.IDictionary] -or $node -is [pscustomobject]) {
        $out = [ordered]@{}
        $keys = @()
        if ($node -is [System.Collections.IDictionary]) { $keys = @($node.Keys) } else { $keys = @($node.PSObject.Properties.Name) }
        foreach ($k in ($keys | Sort-Object)) {
            $name = [string]$k
            $childPath = if ([string]::IsNullOrWhiteSpace($path)) { $name } else { "$path.$name" }
            if ($volatile -contains $name) { continue }
            if ($childPath.EndsWith('runAutomationDetails.id')) { continue }
            $out[$name] = Normalize-Volatile (Get-PropValue $node $name) $childPath
        }
        return $out
    }
    if (Is-List $node) {
        return @($node | ForEach-Object { Normalize-Volatile $_ $path })
    }
    return $node
}

function Stable-HashObject($obj) {
    $norm = Normalize-Volatile $obj
    $json = $norm | ConvertTo-Json -Depth 100 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return (-join ($hash | ForEach-Object { $_.ToString('x2') }))
    }
    finally {
        $sha.Dispose()
    }
}

# Core contract checks
Run-Wrapper -cmdArgs @('spec-version') -allowed @(0)
Run-Wrapper -cmdArgs @('config-validate', '-ErrorFormat', 'json') -allowed @(0)

# Schema self-validation
Validate-Schema (Join-Path $Root 'codesentinel.config.json') (Join-Path $Root 'schemas/config.schema.json')
Validate-Schema (Join-Path $Root 'test-fixtures/portfolio-batch/manifest.json') (Join-Path $Root 'schemas/batch-manifest.schema.json')

$reportSchema = Join-Path $Root 'schemas/report.schema.json'
$portfolioSchema = Join-Path $Root 'schemas/portfolio-report.schema.json'

$scopeCache = Join-Path $reportsDir 'scope-cache.v1.json'
$secretBaseline = Join-Path $reportsDir 'secret.baseline.json'
$depBaseline = Join-Path $reportsDir 'dependency.baseline.json'

$scenarios = @(
    @{ name='scope-default'; kind='json'; expected='test-fixtures/scope-golden/default-scope.expected.json'; output='scope-default.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='scope-include-exclude'; kind='json'; expected='test-fixtures/scope-golden/include-exclude-scope.expected.json'; output='scope-include-exclude.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema; env=@{ CODESENTINEL_INCLUDE='src/**,included/**'; CODESENTINEL_EXCLUDE='src/custom.log' } },
    @{ name='scope-no-default'; kind='json'; expected='test-fixtures/scope-golden/no-default-excludes.expected.json'; output='scope-no-default.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-NoDefaultExcludes','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='scope-gitignore-off'; kind='json'; expected='test-fixtures/scope-golden/gitignore-off.expected.json'; output='scope-gitignore-off.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema; env=@{ CODESENTINEL_RESPECT_GITIGNORE='false' } },

    @{ name='scope-incremental-seed'; kind='json'; expected=$null; output='scope-inc-seed.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-CachePath',$scopeCache,'-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema; env=@{ CODESENTINEL_INCLUDE='src/**,included/**'; CODESENTINEL_EXCLUDE='src/custom.log' } },
    @{ name='scope-incremental-filtered'; kind='json'; expected='test-fixtures/scope-golden/incremental-filtered-scope.expected.json'; output='scope-inc-filtered.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-Incremental','-CachePath',$scopeCache,'-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema; env=@{ CODESENTINEL_INCLUDE='src/**,included/**'; CODESENTINEL_EXCLUDE='src/custom.log' } },
    @{ name='scope-incremental-mismatch'; kind='json'; expected='test-fixtures/scope-golden/incremental-scope-config-mismatch.expected.json'; output='scope-inc-mismatch.json'; args=@('scan','test-fixtures/scope-selection-ci','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-Incremental','-NoDefaultExcludes','-CachePath',$scopeCache,'-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema; env=@{ CODESENTINEL_INCLUDE='src/**,included/**'; CODESENTINEL_EXCLUDE='src/custom.log' } },

    @{ name='secret-full'; kind='json'; expected='test-fixtures/secret-golden/canonical-full.expected.json'; output='secret-full.json'; args=@('scan','test-fixtures/secret-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='secret-sarif-full'; kind='sarif'; expected='test-fixtures/secret-golden/sarif-full.expected.json'; output='secret-full.sarif'; args=@('scan','test-fixtures/secret-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-Format','sarif'); allowed=@(0,10,11,12); schema=$null },

    @{ name='dependency-full'; kind='json'; expected='test-fixtures/dependency-golden/canonical-full.expected.json'; output='dependency-full.json'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='dependency-sarif-full'; kind='sarif'; expected='test-fixtures/dependency-golden/sarif-full.expected.json'; output='dependency-full.sarif'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','sarif'); allowed=@(0,10,11,12); schema=$null },

    @{ name='policy-pack-canonical'; kind='json'; expected='test-fixtures/policy-pack-golden/canonical-overrides.expected.json'; output='policy-pack.json'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-PolicyFile','test-fixtures/policy-pack/overrides.policy.json','-NoCacheWrite','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='policy-pack-sarif'; kind='sarif'; expected='test-fixtures/policy-pack-golden/sarif-overrides.expected.json'; output='policy-pack.sarif'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-PolicyFile','test-fixtures/policy-pack/overrides.policy.json','-NoCacheWrite','-Format','sarif'); allowed=@(0,10,11,12); schema=$null },

    @{ name='confidence-fail'; kind='json'; expected='test-fixtures/confidence-golden/policy-confidence-level-fail.expected.json'; output='confidence-fail.json'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-FailOn','high','-MinConfidence','0.7','-MinConfidenceLevel','high','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='confidence-pass'; kind='json'; expected='test-fixtures/confidence-golden/policy-confidence-level-pass.expected.json'; output='confidence-pass.json'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-FailOn','critical','-MinConfidence','1.0','-MinConfidenceLevel','high','-ExitZeroOnFindings','-Format','json'); allowed=@(0,10,11,12); schema=$reportSchema },
    @{ name='confidence-sarif'; kind='sarif'; expected='test-fixtures/confidence-golden/sarif-confidence.expected.json'; output='confidence.sarif'; args=@('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','sarif'); allowed=@(0,10,11,12); schema=$null },

    @{ name='portfolio-batch'; kind='portfolio'; expected='test-fixtures/portfolio-golden/portfolio-batch.expected.json'; output='portfolio-batch.json'; args=@('batch-scan','test-fixtures/portfolio-batch/manifest.json','-Format','json'); allowed=@(11); schema=$portfolioSchema },
    @{ name='portfolio-batch-invalid'; kind='portfolio'; expected='test-fixtures/portfolio-golden/portfolio-batch-invalid.expected.json'; output='portfolio-batch-invalid.json'; args=@('batch-scan','test-fixtures/portfolio-batch/manifest-invalid.json','-Format','json'); allowed=@(30); schema=$portfolioSchema }
)

foreach ($s in $scenarios) {
    $outPath = Join-Path $reportsDir $s.output
    $cmd = @($s.args + @('-Output', $outPath))

    $oldEnv = @{}
    if ($s.ContainsKey('env')) {
        foreach ($ek in $s.env.Keys) {
            $oldEnv[$ek] = [Environment]::GetEnvironmentVariable([string]$ek)
            [Environment]::SetEnvironmentVariable([string]$ek, [string]$s.env[$ek])
        }
    }

    try {
        Run-Wrapper -cmdArgs $cmd -allowed $s.allowed
    }
    finally {
        if ($s.ContainsKey('env')) {
            foreach ($ek in $s.env.Keys) {
                [Environment]::SetEnvironmentVariable([string]$ek, $oldEnv[$ek])
            }
        }
    }

    if ($s.schema) { Validate-Schema -jsonPath $outPath -schemaPath $s.schema }
    if ($s.expected) {
        $expPath = Join-Path $Root $s.expected
        Apply-Assertions -expectedPath $expPath -actualPath $outPath -kind $s.kind
    }
}

# Baseline interaction scenarios
$secretFullPath = Join-Path $reportsDir 'secret-full.json'
Run-Wrapper -cmdArgs @('baseline-create', $secretFullPath, '-Output', $secretBaseline) -allowed @(0)
Run-Wrapper -cmdArgs @('scan','test-fixtures/secret-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-BaselineFile',$secretBaseline,'-Format','json','-Output',(Join-Path $reportsDir 'secret-baseline-suppressed.json')) -allowed @(0,10,11,12)
Validate-Schema (Join-Path $reportsDir 'secret-baseline-suppressed.json') $reportSchema
Apply-Assertions (Join-Path $Root 'test-fixtures/secret-golden/canonical-baseline-suppressed.expected.json') (Join-Path $reportsDir 'secret-baseline-suppressed.json') 'json'

Run-Wrapper -cmdArgs @('scan','test-fixtures/secret-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','secrets','-NoCacheWrite','-BaselineFile',$secretBaseline,'-Format','sarif','-Output',(Join-Path $reportsDir 'secret-baseline-suppressed.sarif')) -allowed @(0,10,11,12)
Apply-Assertions (Join-Path $Root 'test-fixtures/secret-golden/sarif-baseline-suppressed.expected.json') (Join-Path $reportsDir 'secret-baseline-suppressed.sarif') 'sarif'

$depFullPath = Join-Path $reportsDir 'dependency-full.json'
Run-Wrapper -cmdArgs @('baseline-create', $depFullPath, '-Output', $depBaseline) -allowed @(0)
Run-Wrapper -cmdArgs @('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-BaselineFile',$depBaseline,'-Format','json','-Output',(Join-Path $reportsDir 'dependency-baseline-suppressed.json')) -allowed @(0,10,11,12)
Validate-Schema (Join-Path $reportsDir 'dependency-baseline-suppressed.json') $reportSchema
Apply-Assertions (Join-Path $Root 'test-fixtures/dependency-golden/canonical-baseline-suppressed.expected.json') (Join-Path $reportsDir 'dependency-baseline-suppressed.json') 'json'

Run-Wrapper -cmdArgs @('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-BaselineFile',$depBaseline,'-Format','sarif','-Output',(Join-Path $reportsDir 'dependency-baseline-suppressed.sarif')) -allowed @(0,10,11,12)
Apply-Assertions (Join-Path $Root 'test-fixtures/dependency-golden/sarif-baseline-suppressed.expected.json') (Join-Path $reportsDir 'dependency-baseline-suppressed.sarif') 'sarif'

# Determinism checks (normalized)
function Assert-Deterministic([string[]]$cmdA, [string]$pathA, [string[]]$cmdB, [string]$pathB, [string]$kind) {
    Run-Wrapper -cmdArgs $cmdA -allowed @(0,10,11,12)
    Run-Wrapper -cmdArgs $cmdB -allowed @(0,10,11,12)
    $objA = if ($kind -eq 'sarif') { Read-Json $pathA } else { Read-Json $pathA }
    $objB = if ($kind -eq 'sarif') { Read-Json $pathB } else { Read-Json $pathB }
    $normA = Normalize-Volatile $objA
    $normB = Normalize-Volatile $objB
    $jsonA = $normA | ConvertTo-Json -Depth 100
    $jsonB = $normB | ConvertTo-Json -Depth 100
    $hA = Stable-HashObject $objA
    $hB = Stable-HashObject $objB
    if ($hA -ne $hB) {
        Set-Content -LiteralPath ($pathA + '.norm.json') -Value $jsonA -Encoding UTF8
        Set-Content -LiteralPath ($pathB + '.norm.json') -Value $jsonB -Encoding UTF8
        $linesA = $jsonA -split "`r?`n"
        $linesB = $jsonB -split "`r?`n"
        $delta = Compare-Object -ReferenceObject $linesA -DifferenceObject $linesB -SyncWindow 2 | Select-Object -First 8
        $deltaJson = $delta | ConvertTo-Json -Depth 10 -Compress
        throw ("Determinism check failed for {0}: {1} != {2}; delta={3}" -f $kind, $hA, $hB, $deltaJson)
    }
}

$detA = Join-Path $reportsDir 'det-scan-a.json'
$detB = Join-Path $reportsDir 'det-scan-b.json'
$detScanCmdA = @('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','json','-Output',$detA)
$detScanCmdB = @('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','json','-Output',$detB)
Assert-Deterministic -cmdA $detScanCmdA -pathA $detA -cmdB $detScanCmdB -pathB $detB -kind 'json'

$detSarifA = Join-Path $reportsDir 'det-sarif-a.sarif'
$detSarifB = Join-Path $reportsDir 'det-sarif-b.sarif'
$detSarifCmdA = @('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','sarif','-Output',$detSarifA)
$detSarifCmdB = @('scan','test-fixtures/dependency-scan','-AnalyzerMode','local-only','-FallbackPolicy','fail-open','-Enable','deps','-DependencyPolicyFile','test-fixtures/dependency-scan/dependency-policy.json','-DependencyAdvisoryFile','test-fixtures/dependency-scan/dependency-advisories.json','-NoCacheWrite','-Format','sarif','-Output',$detSarifB)
Assert-Deterministic -cmdA $detSarifCmdA -pathA $detSarifA -cmdB $detSarifCmdB -pathB $detSarifB -kind 'sarif'

$detBatchA = Join-Path $reportsDir 'det-batch-a.json'
$detBatchB = Join-Path $reportsDir 'det-batch-b.json'
Run-Wrapper -cmdArgs @('batch-scan','test-fixtures/portfolio-batch/manifest.json','-Format','json','-Output',$detBatchA) -allowed @(11)
Run-Wrapper -cmdArgs @('batch-scan','test-fixtures/portfolio-batch/manifest.json','-Format','json','-Output',$detBatchB) -allowed @(11)
$bhA = Stable-HashObject (Read-Json $detBatchA)
$bhB = Stable-HashObject (Read-Json $detBatchB)
if ($bhA -ne $bhB) { throw "Determinism check failed for batch-scan: $bhA != $bhB" }

Write-Output "Stage 3 finalization verification complete. Reports: $reportsDir"
