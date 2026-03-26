#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("scan", "doctor", "config-validate", "spec-version", "rules-list", "rules-pin", "baseline-create", "batch-scan")]
    [string]$Command = "scan",
    [Parameter(Position = 1)]
    [string]$Target = ".",
    [string]$BatchManifest = "codesentinel.batch.json",
    [string]$ConfigFile = "codesentinel.config.json",
    [string]$PolicyFile,
    [string]$BaselineFile,
    [switch]$DumpEffectiveConfig,
    [ValidateSet("local-only", "ai-only", "hybrid")]
    [string]$AnalyzerMode,
    [ValidateSet("fail-open", "fail-closed")]
    [string]$FallbackPolicy,
    [ValidateSet("critical", "high", "medium", "low", "info")]
    [string]$MinSeverity,
    [ValidateSet("console", "json", "markdown", "html", "xml", "sarif")]
    [string]$Format,
    [ValidateSet("text", "json")]
    [string]$ErrorFormat,
    [string]$Output,
    [switch]$Stdout,
    [switch]$Progress,
    [switch]$Incremental,
    [string]$DiffFrom,
    [string]$CachePath,
    [switch]$NoCacheWrite,
    [ValidateSet("all_findings", "incremental_delta", "net_new_vs_baseline")]
    [string]$PolicyScope,
    [switch]$BaselineRequired,
    [switch]$RequireAuthoritative,
    [switch]$RequireTrustedIncremental,
    [ValidateSet("dev_local", "ci_pr_fast", "ci_pr_strict", "ci_main_strict")]
    [string]$PolicyProfile,
    [switch]$ExitZeroOnFindings,
    [string]$FailOn,
    [double]$MinConfidence = -1,
    [ValidateSet("low", "medium", "high")]
    [string]$MinConfidenceLevel,
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$RespectGitIgnore,
    [switch]$NoRespectGitIgnore,
    [switch]$NoDefaultExcludes,
    [string[]]$Enable,
    [switch]$SecretScan,
    [double]$SecretEntropyThreshold = -1,
    [int]$SecretMinTokenLength = -1,
    [int]$SecretMaxFileBytes = -1,
    [switch]$DependencyScan,
    [string]$DependencyAdvisoryFile,
    [string]$DependencyPolicyFile,
    [int]$DependencyMaxFileBytes = -1,
    [string]$RulesetVersion = "core-1.0.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Script:InputBound = @{} + $PSBoundParameters

$SpecVersion = "2.0.0"
$ReportVersion = "2.0.0"
$WrapperVersion = "2.0.0"
$SeverityOrder = @{ critical = 5; high = 4; medium = 3; low = 2; info = 1 }
$ConfidenceLevelOrder = @{ low = 1; medium = 2; high = 3 }
$ExitCodes = @{ Success = 0; FindingsPresent = 10; PolicyBreach = 11; PartialResults = 12; UsageError = 20; ConfigError = 30; RuntimeError = 40; DependencyError = 50; InternalError = 60 }
$BinarySupportedExt = @(".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
$TextScanExt = @(".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".cs", ".go", ".php", ".rb", ".rs", ".kt", ".swift", ".ps1", ".psm1", ".sh", ".bash", ".zsh", ".sql", ".yaml", ".yml", ".json", ".env", ".ini", ".toml", ".xml", ".config", ".txt", ".md")
$DefaultExcludePatterns = @("**/node_modules/**", "**/.git/**", ".codesentinel/**", "**/.codesentinel/**", "**/dist/**", "**/build/**", "**/bin/**", "**/obj/**")
$FingerprintVersion = "v2"
$ConfidenceModelVersion = "ucs.v1"

function New-Err([string]$Code, [string]$Message, [object]$Details = $null, [string]$Hint = "") {
    [ordered]@{ code = $Code; message = $Message; details = $Details; hint = $Hint; doc_url = "docs/CLI_SPEC_v1.md" }
}
function Exit-Err([hashtable]$Err, [int]$Code, [string]$Fmt) {
    if ($Fmt -eq "json") { $Err | ConvertTo-Json -Depth 20 | Write-Output } else { Write-Error ("[{0}] {1}" -f $Err.code, $Err.message); if ($Err.hint) { Write-Error ("Hint: {0}" -f $Err.hint) } }
    exit $Code
}
function Sha([string]$Path) { if (Test-Path -LiteralPath $Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash } else { $null } }
function Load-Json([string]$Path) { if (-not (Test-Path -LiteralPath $Path)) { return $null }; $raw = Get-Content -LiteralPath $Path -Raw; if ([string]::IsNullOrWhiteSpace($raw)) { return $null }; $raw | ConvertFrom-Json -Depth 100 }
function To-Hash($Obj) {
    $h = @{}
    if ($null -eq $Obj) { return $h }
    if ($Obj -is [System.Collections.IDictionary]) {
        foreach ($k in $Obj.Keys) { $h[[string]$k] = $Obj[$k] }
        return $h
    }
    $Obj.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }
    $h
}
function Merge([hashtable]$A, [hashtable]$B) { foreach ($k in $B.Keys) { $A[$k] = $B[$k] }; $A }
function Sev([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return "medium" }
    $x = $s.ToLowerInvariant()
    if ($SeverityOrder.ContainsKey($x)) { return $x }
    if ($x -in @("warn", "warning")) { return "medium" }
    if ($x -eq "error") { return "high" }
    if ($x -eq "fatal") { return "critical" }
    "medium"
}

function Clamp-ConfidenceScore([double]$value) {
    if ($value -lt 0) { return 0.0 }
    if ($value -gt 1) { return 1.0 }
    return [math]::Round($value, 3)
}

function Confidence-LevelFromScore([double]$score) {
    if ($score -ge 0.8) { return "high" }
    if ($score -ge 0.6) { return "medium" }
    return "low"
}

function Resolve-UnifiedConfidence([double]$sourceConfidence, [string]$origin, [string]$severity, [string]$category, [string]$secretType, [string]$validationState, [string]$detectorClass, [string]$dependencyRisk, [bool]$hasEvidence, [bool]$hasLocation) {
    $raw = Clamp-ConfidenceScore $sourceConfidence
    $score = $raw
    $adjustments = New-Object System.Collections.Generic.List[object]
    $signals = New-Object System.Collections.Generic.List[string]

    if ($origin.StartsWith("primary:local")) {
        $score += 0.05
        $adjustments.Add(@{ code = "origin_primary_local"; delta = 0.05; reason = "Local primary analyzer signal" }) | Out-Null
        $signals.Add("origin:primary_local") | Out-Null
    }
    elseif ($origin.StartsWith("primary:ai")) {
        $score -= 0.05
        $adjustments.Add(@{ code = "origin_primary_ai"; delta = -0.05; reason = "AI primary analyzer signal" }) | Out-Null
        $signals.Add("origin:primary_ai") | Out-Null
    }
    elseif ($origin.StartsWith("aux:")) {
        $score -= 0.02
        $adjustments.Add(@{ code = "origin_auxiliary"; delta = -0.02; reason = "Auxiliary analyzer signal" }) | Out-Null
        $signals.Add("origin:auxiliary") | Out-Null
    }

    switch ($detectorClass) {
        "pattern" {
            $score += 0.08
            $adjustments.Add(@{ code = "detector_pattern"; delta = 0.08; reason = "Strong pattern detector" }) | Out-Null
            $signals.Add("detector:pattern") | Out-Null
        }
        "contextual_pattern" {
            $score -= 0.03
            $adjustments.Add(@{ code = "detector_contextual_pattern"; delta = -0.03; reason = "Contextual heuristic detector" }) | Out-Null
            $signals.Add("detector:contextual_pattern") | Out-Null
        }
        "entropy" {
            $score -= 0.06
            $adjustments.Add(@{ code = "detector_entropy"; delta = -0.06; reason = "Entropy-based heuristic detector" }) | Out-Null
            $signals.Add("detector:entropy") | Out-Null
        }
        "policy" {
            $score += 0.1
            $adjustments.Add(@{ code = "detector_policy"; delta = 0.1; reason = "Explicit policy detector" }) | Out-Null
            $signals.Add("detector:policy") | Out-Null
        }
        "advisory_match" {
            $score += 0.08
            $adjustments.Add(@{ code = "detector_advisory_match"; delta = 0.08; reason = "Advisory range match detector" }) | Out-Null
            $signals.Add("detector:advisory_match") | Out-Null
        }
        "lockfile_validation" {
            $score += 0.04
            $adjustments.Add(@{ code = "detector_lockfile_validation"; delta = 0.04; reason = "Lockfile validation detector" }) | Out-Null
            $signals.Add("detector:lockfile_validation") | Out-Null
        }
    }

    if ($validationState -eq "pattern_strong" -or $validationState -eq "private_key_block" -or $validationState -eq "policy_blocked" -or $validationState -eq "advisory_matched") {
        $score += 0.05
        $adjustments.Add(@{ code = "validation_strong"; delta = 0.05; reason = "Strong validation state" }) | Out-Null
        $signals.Add("validation:strong") | Out-Null
    }
    elseif ($validationState -eq "entropy_contextual_test_like") {
        $score -= 0.08
        $adjustments.Add(@{ code = "validation_test_like"; delta = -0.08; reason = "Test-like contextual signal" }) | Out-Null
        $signals.Add("validation:test_like") | Out-Null
    }

    switch ($dependencyRisk) {
        "vulnerable_dependency" {
            $score += 0.08
            $adjustments.Add(@{ code = "risk_vulnerable_dependency"; delta = 0.08; reason = "Dependency advisory matched" }) | Out-Null
            $signals.Add("risk:vulnerable_dependency") | Out-Null
        }
        "policy_violation" {
            $score += 0.1
            $adjustments.Add(@{ code = "risk_policy_violation"; delta = 0.1; reason = "Policy-defined violation" }) | Out-Null
            $signals.Add("risk:policy_violation") | Out-Null
        }
        "untrusted_source" {
            $score += 0.03
            $adjustments.Add(@{ code = "risk_untrusted_source"; delta = 0.03; reason = "Untrusted source signal" }) | Out-Null
            $signals.Add("risk:untrusted_source") | Out-Null
        }
        "unpinned_version" {
            $score -= 0.02
            $adjustments.Add(@{ code = "risk_unpinned_version"; delta = -0.02; reason = "Broad policy heuristic signal" }) | Out-Null
            $signals.Add("risk:unpinned_version") | Out-Null
        }
    }

    if ($hasEvidence) {
        $score += 0.02
        $adjustments.Add(@{ code = "evidence_present"; delta = 0.02; reason = "Concrete evidence present" }) | Out-Null
    }
    else {
        $score -= 0.03
        $adjustments.Add(@{ code = "evidence_missing"; delta = -0.03; reason = "Evidence missing" }) | Out-Null
    }

    if (-not $hasLocation) {
        $score -= 0.05
        $adjustments.Add(@{ code = "location_missing"; delta = -0.05; reason = "Precise location missing" }) | Out-Null
    }

    if ($severity -in @("critical", "high")) {
        $score += 0.01
        $adjustments.Add(@{ code = "severity_high_or_critical"; delta = 0.01; reason = "High-impact class often has stronger signatures" }) | Out-Null
    }

    $final = Clamp-ConfidenceScore $score
    $level = Confidence-LevelFromScore $final
    $reason = [string]::Join(",", @($adjustments | Select-Object -First 3 | ForEach-Object { [string]$_.code }))
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "confidence_model_default" }

    return @{
        model_version = $ConfidenceModelVersion
        raw_confidence = $raw
        confidence = $final
        confidence_level = $level
        confidence_reason = $reason
        confidence_rationale = @{
            model = $ConfidenceModelVersion
            base_score = $raw
            adjustments = @($adjustments | ForEach-Object { $_ })
            signals = @($signals | ForEach-Object { $_ })
            final_score = $final
            level = $level
        }
    }
}

function Stable-Hash([string]$s) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })) } finally { $sha.Dispose() }
}

function Stable-ShortId([string]$hashHex) {
    if ([string]::IsNullOrWhiteSpace($hashHex)) { return $null }
    $take = [Math]::Min(16, $hashHex.Length)
    return ("csf_{0}" -f $hashHex.Substring(0, $take))
}

function Default-Config {
    [ordered]@{
        spec_version = $SpecVersion
        report_schema_version = $ReportVersion
        analyzer_mode = "hybrid"
        fallback_policy = "fail-open"
        min_severity = "low"
        format = "console"
        output = $null
        stdout = $false
        progress = $false
        incremental = $false
        diff_from = $null
        cache_path = $null
        no_cache_write = $false
        policy_scope = "all_findings"
        baseline_required = $false
        require_authoritative = $false
        require_trusted_incremental = $false
        policy_profile = $null
        error_format = "text"
        exit_zero_on_findings = $false
        fail_on = "high"
        min_confidence = 0.0
        min_confidence_level = $null
        include = @()
        exclude = @()
        respect_gitignore = $true
        use_default_excludes = $true
        enable = @()
        secret_scan_enabled = $false
        secret_entropy_threshold = 4.5
        secret_min_token_length = 20
        secret_max_file_bytes = 1048576
        dependency_scan_enabled = $false
        dependency_advisory_file = $null
        dependency_policy_file = $null
        dependency_max_file_bytes = 2097152
        policy_file = $null
        baseline_file = $null
        ruleset_version = "core-1.0.0"
    }
}

function Env-Config {
    $m = @{
        CODESENTINEL_ANALYZER_MODE = "analyzer_mode"; CODESENTINEL_FALLBACK_POLICY = "fallback_policy"; CODESENTINEL_MIN_SEVERITY = "min_severity"
        CODESENTINEL_FORMAT = "format"; CODESENTINEL_OUTPUT = "output"; CODESENTINEL_ERROR_FORMAT = "error_format"
        CODESENTINEL_FAIL_ON = "fail_on"; CODESENTINEL_MIN_CONFIDENCE = "min_confidence"; CODESENTINEL_MIN_CONFIDENCE_LEVEL = "min_confidence_level"; CODESENTINEL_EXIT_ZERO_ON_FINDINGS = "exit_zero_on_findings"
        CODESENTINEL_PROGRESS = "progress"; CODESENTINEL_RULESET_VERSION = "ruleset_version"; CODESENTINEL_ENABLE = "enable"
        CODESENTINEL_INCLUDE = "include"; CODESENTINEL_EXCLUDE = "exclude"; CODESENTINEL_RESPECT_GITIGNORE = "respect_gitignore"; CODESENTINEL_NO_DEFAULT_EXCLUDES = "use_default_excludes"
        CODESENTINEL_INCREMENTAL = "incremental"; CODESENTINEL_DIFF_FROM = "diff_from"; CODESENTINEL_CACHE_PATH = "cache_path"; CODESENTINEL_NO_CACHE_WRITE = "no_cache_write"
        CODESENTINEL_POLICY_SCOPE = "policy_scope"; CODESENTINEL_BASELINE_REQUIRED = "baseline_required"; CODESENTINEL_REQUIRE_AUTHORITATIVE = "require_authoritative"; CODESENTINEL_REQUIRE_TRUSTED_INCREMENTAL = "require_trusted_incremental"; CODESENTINEL_POLICY_PROFILE = "policy_profile"; CODESENTINEL_POLICY_FILE = "policy_file"; CODESENTINEL_BASELINE_FILE = "baseline_file"
        CODESENTINEL_SECRET_SCAN = "secret_scan_enabled"; CODESENTINEL_SECRET_ENTROPY_THRESHOLD = "secret_entropy_threshold"; CODESENTINEL_SECRET_MIN_TOKEN_LENGTH = "secret_min_token_length"; CODESENTINEL_SECRET_MAX_FILE_BYTES = "secret_max_file_bytes"
        CODESENTINEL_DEPENDENCY_SCAN = "dependency_scan_enabled"; CODESENTINEL_DEPENDENCY_ADVISORY_FILE = "dependency_advisory_file"; CODESENTINEL_DEPENDENCY_POLICY_FILE = "dependency_policy_file"; CODESENTINEL_DEPENDENCY_MAX_FILE_BYTES = "dependency_max_file_bytes"
    }
    $h = @{}
    foreach ($k in $m.Keys) {
        $v = [Environment]::GetEnvironmentVariable($k)
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            $target = $m[$k]
            switch ($target) {
                "enable" { $h[$target] = @($v -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                "include" { $h[$target] = @($v -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                "exclude" { $h[$target] = @($v -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                "respect_gitignore" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "use_default_excludes" { $h[$target] = -not ($v -match "^(?i:true|1|yes|on)$") }
                "incremental" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "no_cache_write" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "baseline_required" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "require_authoritative" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "require_trusted_incremental" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "secret_scan_enabled" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "secret_entropy_threshold" { $h[$target] = [double]$v }
                "secret_min_token_length" { $h[$target] = [int]$v }
                "secret_max_file_bytes" { $h[$target] = [int]$v }
                "dependency_scan_enabled" { $h[$target] = ($v -match "^(?i:true|1|yes|on)$") }
                "dependency_max_file_bytes" { $h[$target] = [int]$v }
                default { $h[$target] = $v }
            }
        }
    }
    $h
}

function Cli-Config {
    $h = @{}
    if ($Script:InputBound.ContainsKey("AnalyzerMode")) { $h["analyzer_mode"] = $AnalyzerMode }
    if ($Script:InputBound.ContainsKey("FallbackPolicy")) { $h["fallback_policy"] = $FallbackPolicy }
    if ($Script:InputBound.ContainsKey("MinSeverity")) { $h["min_severity"] = $MinSeverity }
    if ($Script:InputBound.ContainsKey("Format")) { $h["format"] = $Format }
    if ($Script:InputBound.ContainsKey("Output")) { $h["output"] = $Output }
    if ($Script:InputBound.ContainsKey("ErrorFormat")) { $h["error_format"] = $ErrorFormat }
    if ($Script:InputBound.ContainsKey("ExitZeroOnFindings")) { $h["exit_zero_on_findings"] = [bool]$ExitZeroOnFindings }
    if ($Script:InputBound.ContainsKey("FailOn")) { $h["fail_on"] = $FailOn }
    if ($Script:InputBound.ContainsKey("MinConfidence")) { $h["min_confidence"] = $MinConfidence }
    if ($Script:InputBound.ContainsKey("MinConfidenceLevel")) { $h["min_confidence_level"] = $MinConfidenceLevel }
    if ($Script:InputBound.ContainsKey("Include")) { $h["include"] = $Include }
    if ($Script:InputBound.ContainsKey("Exclude")) { $h["exclude"] = $Exclude }
    if ($Script:InputBound.ContainsKey("RespectGitIgnore")) { $h["respect_gitignore"] = [bool]$RespectGitIgnore }
    if ($Script:InputBound.ContainsKey("NoRespectGitIgnore")) { $h["respect_gitignore"] = $false }
    if ($Script:InputBound.ContainsKey("NoDefaultExcludes")) { $h["use_default_excludes"] = $false }
    if ($Script:InputBound.ContainsKey("Enable")) { $h["enable"] = $Enable }
    if ($Script:InputBound.ContainsKey("SecretScan")) { $h["secret_scan_enabled"] = [bool]$SecretScan }
    if ($Script:InputBound.ContainsKey("SecretEntropyThreshold")) { $h["secret_entropy_threshold"] = [double]$SecretEntropyThreshold }
    if ($Script:InputBound.ContainsKey("SecretMinTokenLength")) { $h["secret_min_token_length"] = [int]$SecretMinTokenLength }
    if ($Script:InputBound.ContainsKey("SecretMaxFileBytes")) { $h["secret_max_file_bytes"] = [int]$SecretMaxFileBytes }
    if ($Script:InputBound.ContainsKey("DependencyScan")) { $h["dependency_scan_enabled"] = [bool]$DependencyScan }
    if ($Script:InputBound.ContainsKey("DependencyAdvisoryFile")) { $h["dependency_advisory_file"] = $DependencyAdvisoryFile }
    if ($Script:InputBound.ContainsKey("DependencyPolicyFile")) { $h["dependency_policy_file"] = $DependencyPolicyFile }
    if ($Script:InputBound.ContainsKey("DependencyMaxFileBytes")) { $h["dependency_max_file_bytes"] = [int]$DependencyMaxFileBytes }
    if ($Script:InputBound.ContainsKey("Progress")) { $h["progress"] = [bool]$Progress }
    if ($Script:InputBound.ContainsKey("Incremental")) { $h["incremental"] = [bool]$Incremental }
    if ($Script:InputBound.ContainsKey("DiffFrom")) { $h["diff_from"] = $DiffFrom }
    if ($Script:InputBound.ContainsKey("CachePath")) { $h["cache_path"] = $CachePath }
    if ($Script:InputBound.ContainsKey("NoCacheWrite")) { $h["no_cache_write"] = [bool]$NoCacheWrite }
    if ($Script:InputBound.ContainsKey("PolicyScope")) { $h["policy_scope"] = $PolicyScope }
    if ($Script:InputBound.ContainsKey("BaselineRequired")) { $h["baseline_required"] = [bool]$BaselineRequired }
    if ($Script:InputBound.ContainsKey("RequireAuthoritative")) { $h["require_authoritative"] = [bool]$RequireAuthoritative }
    if ($Script:InputBound.ContainsKey("RequireTrustedIncremental")) { $h["require_trusted_incremental"] = [bool]$RequireTrustedIncremental }
    if ($Script:InputBound.ContainsKey("PolicyProfile")) { $h["policy_profile"] = $PolicyProfile }
    if ($Script:InputBound.ContainsKey("Stdout")) { $h["stdout"] = [bool]$Stdout }
    if ($Script:InputBound.ContainsKey("PolicyFile")) { $h["policy_file"] = $PolicyFile }
    if ($Script:InputBound.ContainsKey("BaselineFile")) { $h["baseline_file"] = $BaselineFile }
    if ($Script:InputBound.ContainsKey("RulesetVersion")) { $h["ruleset_version"] = $RulesetVersion }
    $h
}

function Effective-Config {
    $cfg = Default-Config
    $cfg = Merge $cfg (To-Hash (Load-Json $ConfigFile))
    $cfg = Merge $cfg (Env-Config)
    $cfg = Merge $cfg (Cli-Config)
    if ($cfg.min_confidence -is [string]) { $cfg.min_confidence = [double]$cfg.min_confidence }
    if ($cfg.incremental -is [string]) { $cfg.incremental = ($cfg.incremental -match "^(?i:true|1|yes|on)$") }
    if ($cfg.no_cache_write -is [string]) { $cfg.no_cache_write = ($cfg.no_cache_write -match "^(?i:true|1|yes|on)$") }
    if ($cfg.baseline_required -is [string]) { $cfg.baseline_required = ($cfg.baseline_required -match "^(?i:true|1|yes|on)$") }
    if ($cfg.require_authoritative -is [string]) { $cfg.require_authoritative = ($cfg.require_authoritative -match "^(?i:true|1|yes|on)$") }
    if ($cfg.require_trusted_incremental -is [string]) { $cfg.require_trusted_incremental = ($cfg.require_trusted_incremental -match "^(?i:true|1|yes|on)$") }
    if ($cfg.secret_scan_enabled -is [string]) { $cfg.secret_scan_enabled = ($cfg.secret_scan_enabled -match "^(?i:true|1|yes|on)$") }
    if ($cfg.secret_entropy_threshold -is [string]) { $cfg.secret_entropy_threshold = [double]$cfg.secret_entropy_threshold }
    if ($cfg.secret_min_token_length -is [string]) { $cfg.secret_min_token_length = [int]$cfg.secret_min_token_length }
    if ($cfg.secret_max_file_bytes -is [string]) { $cfg.secret_max_file_bytes = [int]$cfg.secret_max_file_bytes }
    if ($cfg.dependency_scan_enabled -is [string]) { $cfg.dependency_scan_enabled = ($cfg.dependency_scan_enabled -match "^(?i:true|1|yes|on)$") }
    if ($cfg.dependency_max_file_bytes -is [string]) { $cfg.dependency_max_file_bytes = [int]$cfg.dependency_max_file_bytes }
    if ($cfg.min_confidence_level -is [string] -and [string]::IsNullOrWhiteSpace([string]$cfg.min_confidence_level)) { $cfg.min_confidence_level = $null }
    if ($cfg.include -is [string]) { $cfg.include = @($cfg.include -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($cfg.exclude -is [string]) { $cfg.exclude = @($cfg.exclude -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($cfg.respect_gitignore -is [string]) { $cfg.respect_gitignore = ($cfg.respect_gitignore -match "^(?i:true|1|yes|on)$") }
    if ($cfg.use_default_excludes -is [string]) { $cfg.use_default_excludes = ($cfg.use_default_excludes -match "^(?i:true|1|yes|on)$") }
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.diff_from)) { $cfg.incremental = $true }
    $cfg
}

function Get-PolicyProfilePreset([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    switch ($name.ToLowerInvariant()) {
        "dev_local" {
            return @{
                policy_scope = "all_findings"
                baseline_required = $false
                require_authoritative = $false
                require_trusted_incremental = $false
                fail_on = "critical"
                min_confidence = 0.9
                min_confidence_level = "high"
                exit_zero_on_findings = $true
            }
        }
        "ci_pr_fast" {
            return @{
                policy_scope = "incremental_delta"
                baseline_required = $false
                require_authoritative = $false
                require_trusted_incremental = $true
                fail_on = "high"
                min_confidence = 0.7
                min_confidence_level = "medium"
                exit_zero_on_findings = $true
            }
        }
        "ci_pr_strict" {
            return @{
                policy_scope = "net_new_vs_baseline"
                baseline_required = $true
                require_authoritative = $true
                require_trusted_incremental = $true
                fail_on = "medium"
                min_confidence = 0.6
                min_confidence_level = "medium"
                exit_zero_on_findings = $true
            }
        }
        "ci_main_strict" {
            return @{
                policy_scope = "all_findings"
                baseline_required = $false
                require_authoritative = $true
                require_trusted_incremental = $false
                fail_on = "medium"
                min_confidence = 0.6
                min_confidence_level = "medium"
                exit_zero_on_findings = $true
            }
        }
        default { return $null }
    }
}

function Apply-PolicyConfig([hashtable]$cfg) {
    if ($cfg.policy_profile) {
        $preset = Get-PolicyProfilePreset -name ([string]$cfg.policy_profile)
        if ($null -eq $preset) {
            $cfg["policy_load_error"] = "unknown policy_profile: $($cfg.policy_profile)"
            return $cfg
        }
        foreach ($k in $preset.Keys) { $cfg[$k] = $preset[$k] }
        $cfg["applied_policy_profile"] = [string]$cfg.policy_profile
    }
    if (-not $cfg.policy_file) { return $cfg }
    if (-not (Test-Path -LiteralPath $cfg.policy_file)) {
        $cfg["policy_load_error"] = "policy_file not found: $($cfg.policy_file)"
        return $cfg
    }
    $p = Load-Json $cfg.policy_file
    if ($null -eq $p) {
        $cfg["policy_load_error"] = "policy_file could not be parsed: $($cfg.policy_file)"
        return $cfg
    }
    $pFailOn = Read-Prop $p "fail_on"
    if ($null -ne $pFailOn -and -not [string]::IsNullOrWhiteSpace([string]$pFailOn)) { $cfg.fail_on = [string]$pFailOn }
    $pMinConfidence = Read-Prop $p "min_confidence"
    if ($null -ne $pMinConfidence) { $cfg.min_confidence = [double]$pMinConfidence }
    $pMinConfidenceLevel = Read-Prop $p "min_confidence_level"
    if ($null -ne $pMinConfidenceLevel -and -not [string]::IsNullOrWhiteSpace([string]$pMinConfidenceLevel)) { $cfg.min_confidence_level = [string]$pMinConfidenceLevel }
    $pPolicyScope = Read-Prop $p "policy_scope"
    if ($null -ne $pPolicyScope -and -not [string]::IsNullOrWhiteSpace([string]$pPolicyScope)) { $cfg.policy_scope = [string]$pPolicyScope }
    $pBaselineRequired = Read-Prop $p "baseline_required"
    if ($null -ne $pBaselineRequired) { $cfg.baseline_required = [bool]$pBaselineRequired }
    $pRequireAuthoritative = Read-Prop $p "require_authoritative"
    if ($null -ne $pRequireAuthoritative) { $cfg.require_authoritative = [bool]$pRequireAuthoritative }
    $pRequireTrustedIncremental = Read-Prop $p "require_trusted_incremental"
    if ($null -ne $pRequireTrustedIncremental) { $cfg.require_trusted_incremental = [bool]$pRequireTrustedIncremental }
    $pExitZeroOnFindings = Read-Prop $p "exit_zero_on_findings"
    if ($null -ne $pExitZeroOnFindings) { $cfg.exit_zero_on_findings = [bool]$pExitZeroOnFindings }
    $pPolicyId = Read-Prop $p "policy_id"
    if ($null -ne $pPolicyId -and -not [string]::IsNullOrWhiteSpace([string]$pPolicyId)) { $cfg["policy_id"] = [string]$pPolicyId }
    $pName = Read-Prop $p "name"
    if ($null -ne $pName -and -not [string]::IsNullOrWhiteSpace([string]$pName)) { $cfg["policy_name"] = [string]$pName }
    $pPolicyPackVersion = Read-Prop $p "policy_pack_version"
    if ($null -ne $pPolicyPackVersion -and -not [string]::IsNullOrWhiteSpace([string]$pPolicyPackVersion)) { $cfg["policy_pack_version"] = [string]$pPolicyPackVersion }
    $enabledCategories = New-Object System.Collections.Generic.List[string]
    foreach ($c in @((Read-Prop $p "enabled_categories"))) {
        $cv = ([string]$c).ToLowerInvariant().Trim()
        if (-not [string]::IsNullOrWhiteSpace($cv)) { $enabledCategories.Add($cv) | Out-Null }
    }
    $disabledCategories = New-Object System.Collections.Generic.List[string]
    foreach ($c in @((Read-Prop $p "disabled_categories"))) {
        $cv = ([string]$c).ToLowerInvariant().Trim()
        if (-not [string]::IsNullOrWhiteSpace($cv)) { $disabledCategories.Add($cv) | Out-Null }
    }
    if ($enabledCategories.Count -gt 0) { $cfg["policy_enabled_categories"] = @($enabledCategories | Sort-Object -Unique) }
    if ($disabledCategories.Count -gt 0) { $cfg["policy_disabled_categories"] = @($disabledCategories | Sort-Object -Unique) }
    $sevOverrides = @{}
    $rawSevOverrides = Read-Prop $p "severity_overrides"
    if ($rawSevOverrides) {
        foreach ($prop in $rawSevOverrides.PSObject.Properties) {
            $k = ([string]$prop.Name).ToLowerInvariant().Trim()
            $v = Sev ([string]$prop.Value)
            if (-not [string]::IsNullOrWhiteSpace($k)) { $sevOverrides[$k] = $v }
        }
    }
    if ($sevOverrides.Count -gt 0) { $cfg["policy_severity_overrides"] = $sevOverrides }
    $ruleOverrides = @{}
    $rawRuleOverrides = Read-Prop $p "rule_overrides"
    if ($rawRuleOverrides) {
        foreach ($prop in $rawRuleOverrides.PSObject.Properties) {
            $rk = ([string]$prop.Name).ToLowerInvariant().Trim()
            if ([string]::IsNullOrWhiteSpace($rk)) { continue }
            $rv = $prop.Value
            $oh = @{}
            if ($rv -is [bool]) {
                $oh["enabled"] = [bool]$rv
            }
            elseif ($rv -is [string]) {
                $oh["severity"] = Sev ([string]$rv)
            }
            elseif ($rv) {
                $vEnabled = Read-Prop $rv "enabled"
                if ($null -ne $vEnabled) { $oh["enabled"] = [bool]$vEnabled }
                $vSeverity = Read-Prop $rv "severity"
                if ($null -ne $vSeverity -and -not [string]::IsNullOrWhiteSpace([string]$vSeverity)) { $oh["severity"] = Sev ([string]$vSeverity) }
                $vConfOverride = Read-Prop $rv "confidence_override"
                if ($null -ne $vConfOverride) { $oh["confidence_override"] = [double]$vConfOverride }
                $vConfOffset = Read-Prop $rv "confidence_offset"
                if ($null -ne $vConfOffset) { $oh["confidence_offset"] = [double]$vConfOffset }
                $vReason = Read-Prop $rv "reason"
                if ($null -ne $vReason -and -not [string]::IsNullOrWhiteSpace([string]$vReason)) { $oh["reason"] = [string]$vReason }
                $vOverrideId = Read-Prop $rv "id"
                if ($null -ne $vOverrideId -and -not [string]::IsNullOrWhiteSpace([string]$vOverrideId)) { $oh["id"] = [string]$vOverrideId }
            }
            $ruleOverrides[$rk] = $oh
        }
    }
    if ($ruleOverrides.Count -gt 0) { $cfg["policy_rule_overrides"] = $ruleOverrides }
    $cfg
}

function Validate-Config([hashtable]$cfg) {
    $errs = New-Object System.Collections.Generic.List[object]
    if ($Script:InputBound.ContainsKey("RespectGitIgnore") -and $Script:InputBound.ContainsKey("NoRespectGitIgnore")) {
        $errs.Add((New-Err "CONFIG_CONFLICT_GITIGNORE_SWITCHES" "Specify either RespectGitIgnore or NoRespectGitIgnore, not both.")) | Out-Null
    }
    if ($cfg.ContainsKey("policy_load_error")) { $errs.Add((New-Err "CONFIG_INVALID_POLICY_FILE" "Policy file could not be loaded." @{ value = $cfg.policy_file; error = $cfg["policy_load_error"] })) }
    if ($cfg.analyzer_mode -notin @("local-only", "ai-only", "hybrid")) { $errs.Add((New-Err "CONFIG_INVALID_ANALYZER_MODE" "Invalid analyzer_mode." @{ value = $cfg.analyzer_mode })) }
    if ($cfg.fallback_policy -notin @("fail-open", "fail-closed")) { $errs.Add((New-Err "CONFIG_INVALID_FALLBACK_POLICY" "Invalid fallback_policy." @{ value = $cfg.fallback_policy })) }
    if (-not $SeverityOrder.ContainsKey((Sev $cfg.min_severity))) { $errs.Add((New-Err "CONFIG_INVALID_MIN_SEVERITY" "Invalid min_severity." @{ value = $cfg.min_severity })) }
    if (-not $SeverityOrder.ContainsKey((Sev $cfg.fail_on))) { $errs.Add((New-Err "CONFIG_INVALID_FAIL_ON" "Invalid fail_on." @{ value = $cfg.fail_on })) }
    if ($cfg.format -notin @("console", "json", "markdown", "html", "xml", "sarif")) { $errs.Add((New-Err "CONFIG_INVALID_FORMAT" "Invalid format." @{ value = $cfg.format })) }
    if ($cfg.error_format -notin @("text", "json")) { $errs.Add((New-Err "CONFIG_INVALID_ERROR_FORMAT" "Invalid error_format." @{ value = $cfg.error_format })) }
    if (($cfg.min_confidence -isnot [double]) -or $cfg.min_confidence -lt 0 -or $cfg.min_confidence -gt 1) { $errs.Add((New-Err "CONFIG_INVALID_MIN_CONFIDENCE" "min_confidence must be 0..1." @{ value = $cfg.min_confidence })) }
    if ($null -ne $cfg.min_confidence_level -and [string]$cfg.min_confidence_level -notin @("low", "medium", "high")) { $errs.Add((New-Err "CONFIG_INVALID_MIN_CONFIDENCE_LEVEL" "min_confidence_level must be low|medium|high." @{ value = $cfg.min_confidence_level })) }
    if ($cfg.include -isnot [System.Collections.IEnumerable] -or $cfg.include -is [string]) { $errs.Add((New-Err "CONFIG_INVALID_INCLUDE" "include must be an array of glob patterns." @{ value = $cfg.include })) }
    else {
        foreach ($p in @($cfg.include)) {
            if ($p -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_INCLUDE_PATTERN" "Each include pattern must be a string." @{ value = $p })) }
        }
    }
    if ($cfg.exclude -isnot [System.Collections.IEnumerable] -or $cfg.exclude -is [string]) { $errs.Add((New-Err "CONFIG_INVALID_EXCLUDE" "exclude must be an array of glob patterns." @{ value = $cfg.exclude })) }
    else {
        foreach ($p in @($cfg.exclude)) {
            if ($p -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_EXCLUDE_PATTERN" "Each exclude pattern must be a string." @{ value = $p })) }
        }
    }
    if ($cfg.respect_gitignore -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_RESPECT_GITIGNORE" "respect_gitignore must be boolean." @{ value = $cfg.respect_gitignore })) }
    if ($cfg.use_default_excludes -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_USE_DEFAULT_EXCLUDES" "use_default_excludes must be boolean." @{ value = $cfg.use_default_excludes })) }
    if ($cfg.incremental -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_INCREMENTAL" "incremental must be boolean." @{ value = $cfg.incremental })) }
    if ($cfg.no_cache_write -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_NO_CACHE_WRITE" "no_cache_write must be boolean." @{ value = $cfg.no_cache_write })) }
    if ($cfg.policy_scope -notin @("all_findings", "incremental_delta", "net_new_vs_baseline")) { $errs.Add((New-Err "CONFIG_INVALID_POLICY_SCOPE" "Invalid policy_scope." @{ value = $cfg.policy_scope })) }
    if ($cfg.baseline_required -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_BASELINE_REQUIRED" "baseline_required must be boolean." @{ value = $cfg.baseline_required })) }
    if ($cfg.require_authoritative -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_REQUIRE_AUTHORITATIVE" "require_authoritative must be boolean." @{ value = $cfg.require_authoritative })) }
    if ($cfg.require_trusted_incremental -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_REQUIRE_TRUSTED_INCREMENTAL" "require_trusted_incremental must be boolean." @{ value = $cfg.require_trusted_incremental })) }
    if ($cfg.secret_scan_enabled -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_SECRET_SCAN_ENABLED" "secret_scan_enabled must be boolean." @{ value = $cfg.secret_scan_enabled })) }
    if (($cfg.secret_entropy_threshold -isnot [double]) -or $cfg.secret_entropy_threshold -lt 3.0 -or $cfg.secret_entropy_threshold -gt 8.0) { $errs.Add((New-Err "CONFIG_INVALID_SECRET_ENTROPY_THRESHOLD" "secret_entropy_threshold must be 3.0..8.0." @{ value = $cfg.secret_entropy_threshold })) }
    $secretMinLenOk = $true; $secretMinLen = 0
    try { $secretMinLen = [int]$cfg.secret_min_token_length } catch { $secretMinLenOk = $false }
    if (-not $secretMinLenOk -or $secretMinLen -lt 8 -or $secretMinLen -gt 256) { $errs.Add((New-Err "CONFIG_INVALID_SECRET_MIN_TOKEN_LENGTH" "secret_min_token_length must be 8..256." @{ value = $cfg.secret_min_token_length })) }
    $secretMaxBytesOk = $true; $secretMaxBytes = 0
    try { $secretMaxBytes = [int]$cfg.secret_max_file_bytes } catch { $secretMaxBytesOk = $false }
    if (-not $secretMaxBytesOk -or $secretMaxBytes -lt 4096 -or $secretMaxBytes -gt 10485760) { $errs.Add((New-Err "CONFIG_INVALID_SECRET_MAX_FILE_BYTES" "secret_max_file_bytes must be 4096..10485760." @{ value = $cfg.secret_max_file_bytes })) }
    if ($cfg.dependency_scan_enabled -isnot [bool]) { $errs.Add((New-Err "CONFIG_INVALID_DEPENDENCY_SCAN_ENABLED" "dependency_scan_enabled must be boolean." @{ value = $cfg.dependency_scan_enabled })) }
    $dependencyMaxBytesOk = $true; $dependencyMaxBytes = 0
    try { $dependencyMaxBytes = [int]$cfg.dependency_max_file_bytes } catch { $dependencyMaxBytesOk = $false }
    if (-not $dependencyMaxBytesOk -or $dependencyMaxBytes -lt 4096 -or $dependencyMaxBytes -gt 20971520) { $errs.Add((New-Err "CONFIG_INVALID_DEPENDENCY_MAX_FILE_BYTES" "dependency_max_file_bytes must be 4096..20971520." @{ value = $cfg.dependency_max_file_bytes })) }
    if ($null -ne $cfg.policy_file -and $cfg.policy_file -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_POLICY_FILE_PATH" "policy_file must be a string path." @{ value = $cfg.policy_file })) }
    if ($null -ne $cfg.baseline_file -and $cfg.baseline_file -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_BASELINE_FILE_PATH" "baseline_file must be a string path." @{ value = $cfg.baseline_file })) }
    if ($null -ne $cfg.dependency_advisory_file -and $cfg.dependency_advisory_file -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_DEPENDENCY_ADVISORY_FILE" "dependency_advisory_file must be a string path." @{ value = $cfg.dependency_advisory_file })) }
    if ($null -ne $cfg.dependency_policy_file -and $cfg.dependency_policy_file -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_DEPENDENCY_POLICY_FILE" "dependency_policy_file must be a string path." @{ value = $cfg.dependency_policy_file })) }
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.dependency_advisory_file) -and -not (Test-Path -LiteralPath $cfg.dependency_advisory_file)) { $errs.Add((New-Err "CONFIG_DEPENDENCY_ADVISORY_FILE_NOT_FOUND" "dependency_advisory_file not found." @{ value = $cfg.dependency_advisory_file })) }
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.dependency_policy_file) -and -not (Test-Path -LiteralPath $cfg.dependency_policy_file)) { $errs.Add((New-Err "CONFIG_DEPENDENCY_POLICY_FILE_NOT_FOUND" "dependency_policy_file not found." @{ value = $cfg.dependency_policy_file })) }
    if ($null -ne $cfg.policy_profile -and -not [string]::IsNullOrWhiteSpace([string]$cfg.policy_profile)) {
        $profilePreset = Get-PolicyProfilePreset -name ([string]$cfg.policy_profile)
        if ($null -eq $profilePreset) { $errs.Add((New-Err "CONFIG_INVALID_POLICY_PROFILE" "Invalid policy_profile." @{ value = $cfg.policy_profile })) }
    }
    if ($null -ne $cfg.diff_from -and $cfg.diff_from -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_DIFF_FROM" "diff_from must be a string path." @{ value = $cfg.diff_from })) }
    if ($null -ne $cfg.cache_path -and $cfg.cache_path -isnot [string]) { $errs.Add((New-Err "CONFIG_INVALID_CACHE_PATH" "cache_path must be a string path." @{ value = $cfg.cache_path })) }
    if ($cfg.analyzer_mode -eq "ai-only" -and [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("OPENAI_API_KEY"))) { $errs.Add((New-Err "CONFIG_MISSING_OPENAI_API_KEY" "OPENAI_API_KEY is required for ai-only.")) }
    $allowedEnable = @("secrets", "deps", "all")
    foreach ($e in @($cfg.enable)) {
        $v = ([string]$e).ToLowerInvariant()
        if ($allowedEnable -notcontains $v) { $errs.Add((New-Err "CONFIG_INVALID_ENABLE_FEATURE" "Unsupported enable feature." @{ value = $e; allowed = $allowedEnable })) }
    }
    $errs
}

function Get-Dependencies {
    $exe = Join-Path $PSScriptRoot "CodeSentinel.exe"
    $node = Get-Command node -ErrorAction SilentlyContinue
    $eslint = Get-Command eslint -ErrorAction SilentlyContinue
    $key = [Environment]::GetEnvironmentVariable("OPENAI_API_KEY")
    @(
        [ordered]@{ component = "CodeSentinel.exe"; status = $(if (Test-Path -LiteralPath $exe) { "ok" } else { "missing" }); detail = $exe },
        [ordered]@{ component = "node"; status = $(if ($node) { "ok" } else { "missing" }); detail = $(if ($node) { $node.Source } else { "not found" }) },
        [ordered]@{ component = "eslint"; status = $(if ($eslint) { "ok" } else { "missing" }); detail = $(if ($eslint) { $eslint.Source } else { "not found" }) },
        [ordered]@{ component = "OPENAI_API_KEY"; status = $(if ([string]::IsNullOrWhiteSpace($key)) { "missing" } else { "ok" }); detail = $(if ([string]::IsNullOrWhiteSpace($key)) { "not set" } else { "set" }) }
    )
}

function Doctor([hashtable]$cfg) {
    $deps = @(Get-Dependencies)
    $exe = Join-Path $PSScriptRoot "CodeSentinel.exe"
    $obj = [ordered]@{ spec_version = $SpecVersion; generated_at = (Get-Date).ToString("o"); dependencies = $deps }
    if ($cfg.format -eq "json") { $obj | ConvertTo-Json -Depth 20 | Write-Output } else { $deps | Format-Table -AutoSize | Out-String | Write-Output }
    if (-not (Test-Path -LiteralPath $exe)) { exit $ExitCodes.DependencyError }
    exit $ExitCodes.Success
}

function Finding-Fingerprint($f) {
    $fp = Read-Prop $f "fingerprint"
    if (-not [string]::IsNullOrWhiteSpace([string]$fp)) { return [string]$fp }
    $rule = [string](Read-Prop $f "rule_id")
    $title = [string](Read-Prop $f "title")
    $sev = [string](Sev ([string](Read-Prop $f "severity")))
    $loc = Read-Prop $f "location"
    $file = $null
    $line = 1
    $col = 1
    if ($loc) {
        $file = Read-Prop $loc "file"
        $lineVal = Read-Prop $loc "line"
        $colVal = Read-Prop $loc "column"
        if ($lineVal) { $line = [int]$lineVal }
        if ($colVal) { $col = [int]$colVal }
    }
    if (-not $file) { $file = Read-Prop $f "file" }
    $normFile = ([string]$file).Replace("\", "/").ToLowerInvariant()
    $seed = [string]::Join("|", @($rule, $normFile, $line, $col, $sev, $title))
    return (Stable-Hash $seed)
}

function Read-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) {
        if ($obj.Contains($name)) { return $obj[$name] }
    }
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Normalize-Finding($f, [int]$i, [string]$origin = "unknown") {
    $srcAnalyzer = [string](Read-Prop $f "analyzer")
    if ($origin -eq "unknown" -and -not [string]::IsNullOrWhiteSpace($srcAnalyzer)) { $origin = $srcAnalyzer }
    $rule = if (Read-Prop $f "rule_id") { Read-Prop $f "rule_id" } elseif (Read-Prop $f "rule") { Read-Prop $f "rule" } else { "generic.rule" }
    $title = if (Read-Prop $f "title") { Read-Prop $f "title" } elseif (Read-Prop $f "message") { Read-Prop $f "message" } else { "Security finding" }
    $sev = Sev (Read-Prop $f "severity")
    $conf = 0.5; try { $v = Read-Prop $f "confidence"; if ($null -ne $v) { $conf = [double]$v } } catch { $conf = 0.5 }
    $locFile = if (Read-Prop $f "file") { Read-Prop $f "file" } elseif (Read-Prop $f "path") { Read-Prop $f "path" } elseif (Read-Prop $f "filename") { Read-Prop $f "filename" } else { $null }
    $line = 1; $lineVal = Read-Prop $f "line"; if ($lineVal) { $line = [int]$lineVal }
    $col = 1; $colVal = Read-Prop $f "column"; if ($colVal) { $col = [int]$colVal }
    $locObj = Read-Prop $f "location"
    if ($locObj) {
        if (-not $locFile) { $locFile = Read-Prop $locObj "file" }
        if (-not $lineVal) {
            $lineFromLoc = Read-Prop $locObj "line"
            if ($lineFromLoc) { $line = [int]$lineFromLoc }
        }
        if (-not $colVal) {
            $colFromLoc = Read-Prop $locObj "column"
            if ($colFromLoc) { $col = [int]$colFromLoc }
        }
    }
    $langVal = Read-Prop $f "language"
    if ([string]::IsNullOrWhiteSpace([string]$langVal)) { $langVal = $null }
    $cweVal = Read-Prop $f "cwe"
    $owaspVal = Read-Prop $f "owasp"
    $cweList = @()
    foreach ($c in @($cweVal)) { if ($null -ne $c -and -not [string]::IsNullOrWhiteSpace([string]$c)) { $cweList += [string]$c } }
    $owaspList = @()
    foreach ($o in @($owaspVal)) { if ($null -ne $o -and -not [string]::IsNullOrWhiteSpace([string]$o)) { $owaspList += [string]$o } }
    $evidenceVal = [string](Read-Prop $f "evidence")
    $locNorm = ([string]$locFile).Replace("\", "/").ToLowerInvariant()
    $existingId = [string](Read-Prop $f "finding_id")
    $existingFp = [string](Read-Prop $f "fingerprint")
    $identitySeed = [string]::Join("|", @(
            "fpv=$FingerprintVersion",
            "rule=$rule",
            "lang=$langVal",
            "file=$locNorm",
            "line=$line",
            "col=$col",
            "sev=$sev",
            "title=$title",
            "evh=$(Stable-Hash $evidenceVal)",
            "origin=$origin"
        ))
    $fingerprint = if (-not [string]::IsNullOrWhiteSpace($existingFp)) { $existingFp } else { Stable-Hash $identitySeed }
    $stableId = if (-not [string]::IsNullOrWhiteSpace($existingId)) { $existingId } else { Stable-ShortId $fingerprint }
    $dedupSeed = [string]::Join("|", @("rule=$rule", "file=$locNorm", "line=$line", "col=$col", "title=$title"))
    $dedupKey = Stable-Hash $dedupSeed
    $metadataVal = Read-Prop $f "metadata"
    $categoryVal = [string](Read-Prop $metadataVal "category")
    if ([string]::IsNullOrWhiteSpace($categoryVal)) { $categoryVal = [string](Read-Prop $f "category") }
    if ([string]::IsNullOrWhiteSpace($categoryVal)) { $categoryVal = $null }
    $secretMeta = Read-Prop $metadataVal "secret"
    $secretType = [string](Read-Prop $secretMeta "type")
    if ([string]::IsNullOrWhiteSpace($secretType)) { $secretType = [string](Read-Prop $f "secret_type") }
    if ([string]::IsNullOrWhiteSpace($secretType)) { $secretType = $null }
    $validationState = [string](Read-Prop $secretMeta "validation_state")
    if ([string]::IsNullOrWhiteSpace($validationState)) { $validationState = [string](Read-Prop $f "validation_state") }
    if ([string]::IsNullOrWhiteSpace($validationState)) { $validationState = $null }
    $detectorClass = [string](Read-Prop $secretMeta "detector_class")
    if ([string]::IsNullOrWhiteSpace($detectorClass)) { $detectorClass = [string](Read-Prop $f "detector_class") }
    if ([string]::IsNullOrWhiteSpace($detectorClass)) { $detectorClass = $null }
    $depMeta = Read-Prop $metadataVal "dependency"
    $dependencyPackage = [string](Read-Prop $depMeta "package")
    if ([string]::IsNullOrWhiteSpace($dependencyPackage)) { $dependencyPackage = [string](Read-Prop $f "dependency_package") }
    if ([string]::IsNullOrWhiteSpace($dependencyPackage)) { $dependencyPackage = $null }
    $dependencyVersion = [string](Read-Prop $depMeta "version")
    if ([string]::IsNullOrWhiteSpace($dependencyVersion)) { $dependencyVersion = [string](Read-Prop $f "dependency_version") }
    if ([string]::IsNullOrWhiteSpace($dependencyVersion)) { $dependencyVersion = $null }
    $dependencyEcosystem = [string](Read-Prop $depMeta "ecosystem")
    if ([string]::IsNullOrWhiteSpace($dependencyEcosystem)) { $dependencyEcosystem = [string](Read-Prop $f "dependency_ecosystem") }
    if ([string]::IsNullOrWhiteSpace($dependencyEcosystem)) { $dependencyEcosystem = $null }
    $dependencyRisk = [string](Read-Prop $depMeta "risk")
    if ([string]::IsNullOrWhiteSpace($dependencyRisk)) { $dependencyRisk = [string](Read-Prop $f "dependency_risk") }
    if ([string]::IsNullOrWhiteSpace($dependencyRisk)) { $dependencyRisk = $null }
    $hasEvidence = (-not [string]::IsNullOrWhiteSpace($evidenceVal))
    $hasLocation = (-not [string]::IsNullOrWhiteSpace([string]$locFile))
    $ucs = Resolve-UnifiedConfidence -sourceConfidence $conf -origin $origin -severity $sev -category $categoryVal -secretType $secretType -validationState $validationState -detectorClass $detectorClass -dependencyRisk $dependencyRisk -hasEvidence $hasEvidence -hasLocation $hasLocation
    [ordered]@{
        id = $stableId
        finding_id = $stableId
        fingerprint = $fingerprint
        fingerprint_version = $FingerprintVersion
        dedup_key = $dedupKey
        origin = [ordered]@{ analyzer = $origin; primary = $origin.StartsWith("primary"); auxiliary = $origin.StartsWith("aux") }
        id_index = ("F{0:d6}" -f $i)
        rule_id = [string]$rule
        title = [string]$title
        severity = $sev
        normalized_severity = $sev
        raw_confidence = [double](Read-Prop $ucs "raw_confidence")
        confidence = [double](Read-Prop $ucs "confidence")
        confidence_level = [string](Read-Prop $ucs "confidence_level")
        confidence_model_version = [string](Read-Prop $ucs "model_version")
        confidence_reason = [string](Read-Prop $ucs "confidence_reason")
        confidence_rationale = (Read-Prop $ucs "confidence_rationale")
        language = $langVal
        category = $categoryVal
        secret_type = $secretType
        validation_state = $validationState
        detector_class = $detectorClass
        dependency_package = $dependencyPackage
        dependency_version = $dependencyVersion
        dependency_ecosystem = $dependencyEcosystem
        dependency_risk = $dependencyRisk
        metadata = $metadataVal
        cwe = $cweList
        owasp = $owaspList
        location = [ordered]@{ file = $locFile; line = $line; column = $col }
        evidence = (Read-Prop $f "evidence")
        remediation = (Read-Prop $f "remediation")
        raw = $f
    }
}

function Dedup-Findings([object[]]$findings) {
    $map = @{}
    foreach ($f in @($findings)) {
        $key = [string](Read-Prop $f "dedup_key")
        if ([string]::IsNullOrWhiteSpace($key)) { $key = [string](Finding-Fingerprint $f) }
        if (-not $map.ContainsKey($key)) { $map[$key] = $f; continue }
        $existing = $map[$key]
        $existingConf = [double](Read-Prop $existing "confidence")
        $newConf = [double](Read-Prop $f "confidence")
        $existingSev = $SeverityOrder[(Sev ([string](Read-Prop $existing "severity")))]
        $newSev = $SeverityOrder[(Sev ([string](Read-Prop $f "severity")))]
        if ($newSev -gt $existingSev -or ($newSev -eq $existingSev -and $newConf -gt $existingConf)) { $map[$key] = $f }
    }
    return @($map.Values)
}

function Sort-Findings([object[]]$findings) {
    return @($findings | Sort-Object `
            @{ Expression = { -1 * $SeverityOrder[(Sev ([string](Read-Prop $_ "severity")))] } }, `
            @{ Expression = { [string](Read-Prop (Read-Prop $_ "location") "file") } }, `
            @{ Expression = { [int](Read-Prop (Read-Prop $_ "location") "line") } }, `
            @{ Expression = { [int](Read-Prop (Read-Prop $_ "location") "column") } }, `
            @{ Expression = { [string](Read-Prop $_ "rule_id") } }, `
            @{ Expression = { [string](Read-Prop $_ "fingerprint") } })
}

function Parse-RawFindings([string]$JsonPath) {
    $obj = Load-Json $JsonPath
    if ($null -eq $obj) { return @() }
    if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) { return @($obj) }
    if ($obj.findings) { return @($obj.findings) }
    if ($obj.issues) { return @($obj.issues) }
    @()
}

function Feature-Enabled([hashtable]$cfg, [string]$name) {
    if (-not $cfg.enable) { return $false }
    $vals = @($cfg.enable | ForEach-Object { ([string]$_).ToLowerInvariant() })
    return ($vals -contains "all" -or $vals -contains $name.ToLowerInvariant())
}

function RelPath([string]$root, [string]$full) {
    [System.IO.Path]::GetRelativePath($root, $full).Replace("\", "/")
}

function Normalize-Pattern([string]$pattern) {
    if ([string]::IsNullOrWhiteSpace($pattern)) { return $null }
    $p = $pattern.Trim().Replace("\", "/")
    if ($p.StartsWith("./")) { $p = $p.Substring(2) }
    if ($p.StartsWith("/")) { $p = $p.Substring(1) }
    if ($p.EndsWith("/")) { $p = $p + "**" }
    return $p
}

function Normalize-PatternList([object[]]$patterns) {
    $vals = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($patterns)) {
        $n = Normalize-Pattern ([string]$p)
        if (-not [string]::IsNullOrWhiteSpace($n)) { $vals.Add($n) | Out-Null }
    }
    return @($vals | Sort-Object -Unique)
}

function Get-GitIgnorePatterns([string]$root) {
    $path = Join-Path $root ".gitignore"
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    $lines = Get-Content -LiteralPath $path -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        $t = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($t.StartsWith("#")) { continue }
        if ($t.StartsWith("!")) { continue }
        $p = Normalize-Pattern $t
        if (-not $p) { continue }
        if ($p -notmatch "[\*\?\[]") {
            if ($p.Contains("/")) { $p = "$p*" } else { $p = "**/$p*" }
        }
        $out.Add($p) | Out-Null
    }
    @($out | Sort-Object -Unique | ForEach-Object { $_ })
}

function Build-PatternSpecs([string[]]$patterns, [string]$source) {
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($patterns | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace([string]$p)) { continue }
        $items.Add([ordered]@{
                pattern = [string]$p
                source = [string]$source
            }) | Out-Null
    }
    return @($items | ForEach-Object { $_ })
}

function Get-PatternVariants([string]$pattern) {
    if ([string]::IsNullOrWhiteSpace($pattern)) { return @() }
    $vals = New-Object System.Collections.Generic.List[string]
    $vals.Add($pattern) | Out-Null
    if ($pattern.StartsWith("**/")) {
        $trimmed = $pattern.Substring(3)
        if (-not [string]::IsNullOrWhiteSpace($trimmed)) { $vals.Add($trimmed) | Out-Null }
    }
    return @($vals | Sort-Object -Unique)
}

function Resolve-EffectiveScopeRules([hashtable]$cfg) {
    $include = Normalize-PatternList @($cfg.include)
    $userExclude = Normalize-PatternList @($cfg.exclude)
    $defaultExclude = if ([bool]$cfg.use_default_excludes) { Normalize-PatternList @($DefaultExcludePatterns) } else { @() }
    $effectiveExclude = @(@($userExclude) + @($defaultExclude) | Sort-Object -Unique)
    $excludeSpecs = @(
        @(Build-PatternSpecs -patterns $userExclude -source "user")
        @(Build-PatternSpecs -patterns $defaultExclude -source "default")
    )
    return [ordered]@{
        include_patterns = @($include)
        user_exclude_patterns = @($userExclude)
        default_exclude_patterns = @($defaultExclude)
        effective_exclude_patterns = @($effectiveExclude)
        exclude_specs = @($excludeSpecs | ForEach-Object { $_ })
        use_default_excludes = [bool]$cfg.use_default_excludes
        respect_gitignore = [bool]$cfg.respect_gitignore
    }
}

function Match-FirstPattern([string]$rel, [object[]]$patternSpecs) {
    foreach ($spec in @($patternSpecs)) {
        $p = [string](Read-Prop $spec "pattern")
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        foreach ($variant in @(Get-PatternVariants -pattern $p)) {
            if ($rel -like $variant) { return $spec }
        }
    }
    return $null
}

function Match-Any([string]$rel, [string[]]$patterns) {
    return ($null -ne (Match-FirstPattern -rel $rel -patternSpecs @(Build-PatternSpecs -patterns (Normalize-PatternList @($patterns)) -source "generic")))
}

function Language-FromPath([string]$path) {
    $ext = ([System.IO.Path]::GetExtension($path) ?? "").ToLowerInvariant()
    switch ($ext) {
        ".py" { "python" }
        ".js" { "javascript" }
        ".jsx" { "javascript" }
        ".mjs" { "javascript" }
        ".cjs" { "javascript" }
        ".ts" { "typescript" }
        ".tsx" { "typescript" }
        ".java" { "java" }
        ".cs" { "csharp" }
        ".go" { "go" }
        ".php" { "php" }
        ".rb" { "ruby" }
        ".rs" { "rust" }
        ".kt" { "kotlin" }
        ".swift" { "swift" }
        ".ps1" { "powershell" }
        ".sh" { "shell" }
        ".sql" { "sql" }
        default { $null }
    }
}

function Get-ScopedFiles([string]$targetPath, [hashtable]$cfg) {
    $resolved = (Resolve-Path -LiteralPath $targetPath).Path
    $isDir = Test-Path -LiteralPath $resolved -PathType Container
    $root = if ($isDir) { $resolved } else { Split-Path -Parent $resolved }
    $all = @()
    if ($isDir) {
        $all = @(Get-ChildItem -LiteralPath $resolved -Recurse -File -ErrorAction SilentlyContinue)
    }
    else {
        $all = @((Get-Item -LiteralPath $resolved -ErrorAction Stop))
    }
    $rules = Resolve-EffectiveScopeRules -cfg $cfg
    $include = @($rules.include_patterns)
    $excludeSpecs = @($rules.exclude_specs)
    $excludeEffective = @($rules.effective_exclude_patterns)
    $gitIgnore = @()
    $gitIgnoreApplied = $false
    $gitIgnoreFile = $null
    if ($isDir -and [bool]$rules.respect_gitignore) {
        $gitIgnoreApplied = $true
        $gitIgnoreFile = Join-Path $root ".gitignore"
        $gitIgnore = @(Get-GitIgnorePatterns $root)
    }
    $gitIgnoreSpecs = @(Build-PatternSpecs -patterns $gitIgnore -source "gitignore")
    $orderedFiles = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($all)) {
        $rel = RelPath $root $f.FullName
        $orderedFiles.Add([ordered]@{ file = $f; rel = $rel }) | Out-Null
    }
    $orderedFilesArray = @($orderedFiles | Sort-Object rel)
    $selected = New-Object System.Collections.Generic.List[object]
    $excludedByInclude = 0
    $excludedByExclude = 0
    $excludedByDefaultExclude = 0
    $excludedByUserExclude = 0
    $excludedByGitIgnore = 0
    $sampleLimit = 25
    $selectedSample = New-Object System.Collections.Generic.List[string]
    $excludedByIncludeSample = New-Object System.Collections.Generic.List[string]
    $excludedByExcludeSample = New-Object System.Collections.Generic.List[object]
    $excludedByGitignoreSample = New-Object System.Collections.Generic.List[object]
    foreach ($of in $orderedFilesArray) {
        $f = $of.file
        $rel = [string]$of.rel
        $incOk = if ($include.Count -eq 0) { $true } else { Match-Any -rel $rel -patterns $include }
        if (-not $incOk) { $excludedByInclude++; continue }
        $excludeMatch = Match-FirstPattern -rel $rel -patternSpecs $excludeSpecs
        $gitIgnoreMatch = $null
        $isExcluded = $false
        if ($excludeMatch) {
            $isExcluded = $true
            $excludedByExclude++
            $src = [string](Read-Prop $excludeMatch "source")
            if ($src -eq "default") { $excludedByDefaultExclude++ } else { $excludedByUserExclude++ }
            if ($excludedByExcludeSample.Count -lt $sampleLimit) {
                $excludedByExcludeSample.Add([ordered]@{
                        rel_path = $rel
                        pattern = [string](Read-Prop $excludeMatch "pattern")
                        source = $src
                    }) | Out-Null
            }
        }
        elseif ($gitIgnoreSpecs.Count -gt 0) {
            $gitIgnoreMatch = Match-FirstPattern -rel $rel -patternSpecs $gitIgnoreSpecs
            if ($gitIgnoreMatch) {
                $isExcluded = $true
                $excludedByGitIgnore++
                if ($excludedByGitignoreSample.Count -lt $sampleLimit) {
                    $excludedByGitignoreSample.Add([ordered]@{
                            rel_path = $rel
                            pattern = [string](Read-Prop $gitIgnoreMatch "pattern")
                        }) | Out-Null
                }
            }
        }
        if ($isExcluded) { continue }
        if ($selectedSample.Count -lt $sampleLimit) { $selectedSample.Add($rel) | Out-Null }
        $selected.Add([ordered]@{
                full_path = $f.FullName
                rel_path  = $rel
                extension = ($f.Extension ?? "").ToLowerInvariant()
                language  = Language-FromPath $f.FullName
                size      = [int64]$f.Length
            }) | Out-Null
    }
    if ($excludedByInclude -gt 0) {
        foreach ($of in $orderedFilesArray) {
            if ($excludedByIncludeSample.Count -ge $sampleLimit) { break }
            $rel = [string]$of.rel
            $incOk = if ($include.Count -eq 0) { $true } else { Match-Any -rel $rel -patterns $include }
            if (-not $incOk) { $excludedByIncludeSample.Add($rel) | Out-Null }
        }
    }
    $selectedArray = @($selected | ForEach-Object { $_ } | Sort-Object rel_path)
    $selectedDigestSeed = [string]::Join("`n", @($selectedArray | ForEach-Object { $_.rel_path }))
    $selectedDigest = Stable-Hash $selectedDigestSeed
    $langCounts = @{}
    foreach ($sf in $selectedArray) {
        $lang = if ($sf.language) { [string]$sf.language } else { "unknown" }
        if (-not $langCounts.ContainsKey($lang)) { $langCounts[$lang] = 0 }
        $langCounts[$lang]++
    }
    $res = @{}
    $res["root"] = $root
    $res["is_directory"] = $isDir
    $res["selection_contract_version"] = "1.1"
    $res["selection_order"] = @("include", "exclude", "gitignore")
    $res["total_files"] = $all.Count
    $res["selected_files"] = $selectedArray
    $res["selected_count"] = $selectedArray.Count
    $res["excluded_count"] = ($excludedByInclude + $excludedByExclude + $excludedByGitIgnore)
    $res["excluded_by_include"] = $excludedByInclude
    $res["excluded_by_exclude"] = $excludedByExclude
    $res["excluded_by_default_exclude"] = $excludedByDefaultExclude
    $res["excluded_by_user_exclude"] = $excludedByUserExclude
    $res["excluded_by_gitignore"] = $excludedByGitIgnore
    $res["include_patterns"] = @($rules.include_patterns)
    $res["user_exclude_patterns"] = @($rules.user_exclude_patterns)
    $res["default_exclude_patterns"] = @($rules.default_exclude_patterns)
    $res["effective_exclude_patterns"] = @($excludeEffective)
    $res["use_default_excludes"] = [bool]$rules.use_default_excludes
    $res["respect_gitignore"] = [bool]$rules.respect_gitignore
    $res["gitignore_applied"] = $gitIgnoreApplied
    $res["gitignore_file"] = if ($gitIgnoreApplied -and (Test-Path -LiteralPath $gitIgnoreFile)) { $gitIgnoreFile } else { $null }
    $res["gitignore_patterns"] = @($gitIgnore)
    $res["gitignore_count"] = $gitIgnore.Count
    $res["selected_digest"] = $selectedDigest
    $res["selected_by_language"] = $langCounts
    $res["decision_sample_limit"] = $sampleLimit
    $res["selected_sample"] = @($selectedSample | ForEach-Object { $_ })
    $res["excluded_by_include_sample"] = @($excludedByIncludeSample | ForEach-Object { $_ })
    $res["excluded_by_exclude_sample"] = @($excludedByExcludeSample | ForEach-Object { $_ })
    $res["excluded_by_gitignore_sample"] = @($excludedByGitignoreSample | ForEach-Object { $_ })
    return $res
}

function Build-ScopeDiagnostics([hashtable]$scope, [hashtable]$analysisScope, [hashtable]$cfg) {
    return @{
        root = $scope.root
        total_files = $scope.total_files
        selected_files = $scope.selected_count
        analyzed_files = $analysisScope.selected_count
        excluded_files = $scope.excluded_count
        excluded_by_include = $scope.excluded_by_include
        excluded_by_exclude = $scope.excluded_by_exclude
        excluded_by_default_exclude = $scope.excluded_by_default_exclude
        excluded_by_user_exclude = $scope.excluded_by_user_exclude
        excluded_by_gitignore = $scope.excluded_by_gitignore
        gitignore_patterns = $scope.gitignore_count
        selected_digest = $scope.selected_digest
        selected_by_language = $scope.selected_by_language
        selection_contract_version = $scope.selection_contract_version
        selection_order = @($scope.selection_order)
        include = @($scope.include_patterns)
        exclude = @($scope.effective_exclude_patterns)
        include_patterns = @($scope.include_patterns)
        exclude_patterns = @{
            use_default_excludes = [bool]$scope.use_default_excludes
            default = @($scope.default_exclude_patterns)
            user = @($scope.user_exclude_patterns)
            effective = @($scope.effective_exclude_patterns)
        }
        respect_gitignore = [bool]$scope.respect_gitignore
        gitignore = @{
            enabled = [bool]$scope.respect_gitignore
            applied = [bool]$scope.gitignore_applied
            file = $scope.gitignore_file
            patterns_count = $scope.gitignore_count
            patterns = @($scope.gitignore_patterns)
        }
        decision_trace = @{
            sample_limit = $scope.decision_sample_limit
            selected = @($scope.selected_sample)
            excluded_by_include = @($scope.excluded_by_include_sample)
            excluded_by_exclude = @($scope.excluded_by_exclude_sample)
            excluded_by_gitignore = @($scope.excluded_by_gitignore_sample)
        }
        note = "Wrapper scope filtering is applied before analyzer execution."
    }
}

function Get-BinaryFiles([object[]]$files) {
    @($files | Where-Object { $BinarySupportedExt -contains $_.extension })
}

function Stage-ScopedFiles([string]$root, [object[]]$files) {
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("codesentinel-stage-{0}" -f [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($f in $files) {
        $dest = Join-Path $stage $f.rel_path
        $destDir = Split-Path -Parent $dest
        if ($destDir -and -not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Copy-Item -LiteralPath $f.full_path -Destination $dest -Force
    }
    $stage
}

function Build-RawFinding([string]$ruleId, [string]$title, [string]$severity, [double]$confidence, [string]$file, [int]$line, [int]$col, [string]$lang, [string[]]$cwe, [string[]]$owasp, [string]$evidence, [string]$remediation, [string]$analyzer = "aux:unknown", [hashtable]$Metadata = $null) {
    [ordered]@{
        rule_id = $ruleId
        title = $title
        severity = $severity
        confidence = $confidence
        file = $file
        line = $line
        column = $col
        language = $lang
        cwe = @($cwe)
        owasp = @($owasp)
        evidence = $evidence
        remediation = $remediation
        analyzer = $analyzer
        metadata = $Metadata
    }
}

function Is-SecretScanEnabled([hashtable]$cfg) {
    if ([bool]$cfg.secret_scan_enabled) { return $true }
    return (Feature-Enabled -cfg $cfg -name "secrets")
}

function Demote-Severity([string]$sev) {
    switch (Sev $sev) {
        "critical" { "high" }
        "high" { "medium" }
        "medium" { "low" }
        "low" { "low" }
        default { "info" }
    }
}

function Get-PathSecretContext([string]$relPath) {
    $p = ([string]$relPath).Replace("\", "/").ToLowerInvariant()
    if ($p -match "(^|/)(test|tests|spec|specs|fixture|fixtures|sample|samples|example|examples|mock|mocks)(/|$)") { return "test_like" }
    "default"
}

function Is-PlaceholderSecret([string]$token) {
    if ([string]::IsNullOrWhiteSpace($token)) { return $true }
    $x = $token.Trim().ToLowerInvariant()
    if ($x -in @("changeme", "change_me", "example", "example123", "dummy", "placeholder", "your-api-key-here", "token", "password", "secret", "none", "null", "nil")) { return $true }
    if ($x -match "^(x{8,}|0{8,}|1{8,}|a{8,}|abc(?:123)?|test(?:123)?|password(?:123)?|secret(?:123)?)$") { return $true }
    if ($x -match "^(localhost|127\.0\.0\.1|http://|https://)") { return $true }
    return $false
}

function Mask-SecretEvidence([string]$token) {
    if ([string]::IsNullOrWhiteSpace($token)) { return "[redacted]" }
    $t = $token.Trim()
    if ($t.Length -le 8) { return "[redacted]" }
    if ($t.Length -le 16) { return ("{0}...{1}" -f $t.Substring(0, 2), $t.Substring($t.Length - 2, 2)) }
    return ("{0}...{1}" -f $t.Substring(0, 4), $t.Substring($t.Length - 3, 3))
}

function Get-ShannonEntropy([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return 0.0 }
    $freq = @{}
    foreach ($ch in $s.ToCharArray()) {
        $k = [string]$ch
        if (-not $freq.ContainsKey($k)) { $freq[$k] = 0 }
        $freq[$k]++
    }
    $len = [double]$s.Length
    $ent = 0.0
    foreach ($k in $freq.Keys) {
        $p = ([double]$freq[$k]) / $len
        $ent += (-1.0 * $p * [Math]::Log($p, 2.0))
    }
    return [math]::Round($ent, 3)
}

function New-SecretMetadata([string]$type, [string]$detectorClass, [string]$validationState, [double]$entropy, [string]$pathContext, [string]$detectorId, [string]$candidateKind) {
    return [ordered]@{
        category = "secrets"
        secret = [ordered]@{
            detector_contract_version = "secrets.v1"
            type = $type
            detector_class = $detectorClass
            validation_state = $validationState
            entropy = [math]::Round($entropy, 3)
            path_context = $pathContext
            detector_id = $detectorId
            candidate_kind = $candidateKind
        }
    }
}

function Invoke-SecretAnalyzerStage([hashtable]$scope, [hashtable]$cfg) {
    $stageStart = Get-Date
    $out = New-Object System.Collections.Generic.List[object]
    $detectorHits = @{}
    $filesConsidered = 0
    $filesScanned = 0
    $skippedLarge = 0
    $skippedUnsupported = 0
    $entropyCandidates = 0
    $entropyHits = 0
    $readFailures = 0

    $keywordRegex = '(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|auth(?:orization)?|bearer|private[_-]?key|client[_-]?secret|access[_-]?key)\b'
    $quotedTokenRegex = '["'']([A-Za-z0-9+/_=.-]{8,})["'']'
    $privateKeyRegex = "-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) PRIVATE KEY-----"
    $lineRules = @(
        @{ id = "secret.aws.access_key"; title = "Possible AWS access key hardcoded"; severity = "high"; conf = 0.97; regex = "\b(AKIA|ASIA)[0-9A-Z]{16}\b"; type = "aws_access_key"; cls = "pattern"; state = "pattern_strong"; cwe = @("CWE-798"); owasp = @("A07:2021") },
        @{ id = "secret.openai.api_key"; title = "Possible OpenAI API key hardcoded"; severity = "high"; conf = 0.95; regex = "\bsk-[A-Za-z0-9]{20,}\b"; type = "openai_api_key"; cls = "pattern"; state = "pattern_strong"; cwe = @("CWE-798"); owasp = @("A07:2021") },
        @{ id = "secret.github.token"; title = "Possible GitHub token hardcoded"; severity = "high"; conf = 0.96; regex = "\bgh[pousr]_[A-Za-z0-9]{30,}\b"; type = "github_token"; cls = "pattern"; state = "pattern_strong"; cwe = @("CWE-798"); owasp = @("A07:2021") },
        @{ id = "secret.stripe.live_key"; title = "Possible Stripe live key hardcoded"; severity = "high"; conf = 0.94; regex = "\bsk_live_[A-Za-z0-9]{16,}\b"; type = "stripe_live_key"; cls = "pattern"; state = "pattern_strong"; cwe = @("CWE-798"); owasp = @("A07:2021") },
        @{ id = "secret.jwt.token"; title = "Possible JWT token hardcoded"; severity = "medium"; conf = 0.82; regex = "\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"; type = "jwt"; cls = "pattern"; state = "pattern_contextual"; cwe = @("CWE-798"); owasp = @("A07:2021") },
        @{ id = "secret.generic.assignment"; title = "Possible hardcoded credential assignment"; severity = "medium"; conf = 0.76; regex = '(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|client[_-]?secret)\b\s*[:=]\s*["''][^"'']{8,}["'']'; type = "credential_assignment"; cls = "contextual_pattern"; state = "pattern_contextual"; cwe = @("CWE-798"); owasp = @("A07:2021") }
    )

    foreach ($f in @($scope.selected_files)) {
        $filesConsidered++
        if ($TextScanExt -notcontains $f.extension) { $skippedUnsupported++; continue }
        if ([int64]$f.size -gt [int64]$cfg.secret_max_file_bytes) { $skippedLarge++; continue }

        $raw = $null
        try { $raw = Get-Content -LiteralPath $f.full_path -Raw -ErrorAction Stop } catch { $readFailures++; continue }
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        if ($raw.IndexOf([char]0) -ge 0) { continue }
        $filesScanned++
        $pathContext = Get-PathSecretContext -relPath ([string]$f.rel_path)

        $lines = [regex]::Split($raw, "`r`n|`n|`r")
        $lineNo = 0
        foreach ($line in $lines) {
            $lineNo++
            foreach ($rule in $lineRules) {
                $matches = [regex]::Matches($line, $rule.regex)
                foreach ($m in $matches) {
                    $token = [string]$m.Value
                    if ([string]$rule.id -eq "secret.generic.assignment") {
                        $q = [regex]::Match($token, '["'']([^"'']+)["'']')
                        if ($q.Success -and $q.Groups.Count -gt 1) { $token = [string]$q.Groups[1].Value }
                    }
                    if (Is-PlaceholderSecret $token) { continue }
                    $sev = [string]$rule.severity
                    $conf = [double]$rule.conf
                    if ($pathContext -eq "test_like" -and $rule.state -ne "pattern_strong") {
                        $sev = Demote-Severity $sev
                        $conf = [math]::Max(0.55, $conf - 0.2)
                    }
                    $meta = New-SecretMetadata -type ([string]$rule.type) -detectorClass ([string]$rule.cls) -validationState ([string]$rule.state) -entropy (Get-ShannonEntropy $token) -pathContext $pathContext -detectorId ([string]$rule.id) -candidateKind "line_pattern"
                    $out.Add((Build-RawFinding -ruleId $rule.id -title $rule.title -severity $sev -confidence ([double]$conf) -file $f.rel_path -line $lineNo -col ($m.Index + 1) -lang $f.language -cwe $rule.cwe -owasp $rule.owasp -evidence (Mask-SecretEvidence $token) -remediation "Move the secret to environment variables or a secret manager and rotate exposed credentials." -analyzer "aux:secrets" -Metadata $meta)) | Out-Null
                    if (-not $detectorHits.ContainsKey([string]$rule.id)) { $detectorHits[[string]$rule.id] = 0 }
                    $detectorHits[[string]$rule.id]++
                }
            }

            $hasSecretContext = ([regex]::IsMatch($line, $keywordRegex))
            if (-not $hasSecretContext) { continue }
            $qmatches = [regex]::Matches($line, $quotedTokenRegex)
            foreach ($qm in $qmatches) {
                if ($qm.Groups.Count -lt 2) { continue }
                $token = [string]$qm.Groups[1].Value
                if ([string]::IsNullOrWhiteSpace($token)) { continue }
                $entropyCandidates++
                if ($token.Length -lt [int]$cfg.secret_min_token_length) { continue }
                if ($token.Length -gt 256) { continue }
                if (Is-PlaceholderSecret $token) { continue }
                if ($token -match "^[A-Za-z]+://") { continue }
                $entropy = Get-ShannonEntropy $token
                if ($entropy -lt [double]$cfg.secret_entropy_threshold) { continue }
                $entropyHits++
                $sev = "medium"
                $conf = 0.74
                $state = "entropy_contextual"
                if ($entropy -ge ([double]$cfg.secret_entropy_threshold + 0.6)) { $sev = "high"; $conf = 0.82; $state = "entropy_contextual_strong" }
                if ($pathContext -eq "test_like") {
                    $sev = Demote-Severity $sev
                    $conf = [math]::Max(0.5, $conf - 0.15)
                    $state = "entropy_contextual_test_like"
                }
                $meta = New-SecretMetadata -type "generic_high_entropy_secret" -detectorClass "entropy" -validationState $state -entropy $entropy -pathContext $pathContext -detectorId "secret.high_entropy.assignment" -candidateKind "quoted_entropy"
                $out.Add((Build-RawFinding -ruleId "secret.high_entropy.assignment" -title "Possible hardcoded high-entropy secret in assignment context" -severity $sev -confidence ([double]$conf) -file $f.rel_path -line $lineNo -col ($qm.Groups[1].Index + 1) -lang $f.language -cwe @("CWE-798") -owasp @("A07:2021") -evidence (Mask-SecretEvidence $token) -remediation "Replace hardcoded values with references to secure secret storage." -analyzer "aux:secrets" -Metadata $meta)) | Out-Null
                if (-not $detectorHits.ContainsKey("secret.high_entropy.assignment")) { $detectorHits["secret.high_entropy.assignment"] = 0 }
                $detectorHits["secret.high_entropy.assignment"]++
            }
        }

        $keyMatch = [regex]::Match($raw, $privateKeyRegex)
        if ($keyMatch.Success) {
            $before = $raw.Substring(0, $keyMatch.Index)
            $keyLine = ([regex]::Matches($before, "`n").Count + 1)
            $meta = New-SecretMetadata -type "private_key_material" -detectorClass "pattern" -validationState "private_key_block" -entropy 0.0 -pathContext $pathContext -detectorId "secret.private_key.block" -candidateKind "block_pattern"
            $out.Add((Build-RawFinding -ruleId "secret.private_key.block" -title "Possible private key material in source" -severity "critical" -confidence 0.99 -file $f.rel_path -line $keyLine -col 1 -lang $f.language -cwe @("CWE-798") -owasp @("A07:2021") -evidence "Private key block header detected" -remediation "Remove key material from source and rotate exposed credentials immediately." -analyzer "aux:secrets" -Metadata $meta)) | Out-Null
            if (-not $detectorHits.ContainsKey("secret.private_key.block")) { $detectorHits["secret.private_key.block"] = 0 }
            $detectorHits["secret.private_key.block"]++
        }
    }

    $orderedDetectorHits = [ordered]@{}
    foreach ($k in @($detectorHits.Keys | Sort-Object)) {
        $orderedDetectorHits[[string]$k] = [int]$detectorHits[$k]
    }
    $elapsed = [int]((Get-Date) - $stageStart).TotalMilliseconds
    $findingsArray = @($out.ToArray())
    return @{
        findings = $findingsArray
        diagnostics = @{
            stage = "secrets"
            analyzer = "aux:secrets"
            contract_version = "secrets.v1"
            status = "completed"
            files_considered = $filesConsidered
            files_scanned = $filesScanned
            skipped_large_files = $skippedLarge
            skipped_unsupported_files = $skippedUnsupported
            read_failures = $readFailures
            entropy_candidates = $entropyCandidates
            entropy_hits = $entropyHits
            findings_total = $findingsArray.Count
            detector_hits = $orderedDetectorHits
            config = @{
                entropy_threshold = [double]$cfg.secret_entropy_threshold
                min_token_length = [int]$cfg.secret_min_token_length
                max_file_bytes = [int]$cfg.secret_max_file_bytes
            }
            duration_ms = $elapsed
        }
    }
}

function Add-DepFinding([System.Collections.Generic.List[object]]$out, [string]$ruleId, [string]$title, [string]$severity, [double]$confidence, [string]$file, [int]$line, [string]$evidence, [string]$remediation) {
    $out.Add((Build-RawFinding -ruleId $ruleId -title $title -severity $severity -confidence $confidence -file $file -line $line -col 1 -lang $null -cwe @("CWE-1104") -owasp @("A06:2021") -evidence $evidence -remediation $remediation -analyzer "aux:deps")) | Out-Null
}

function Invoke-DependencyScan([hashtable]$scope) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($scope.selected_files)) {
        $name = [System.IO.Path]::GetFileName($f.rel_path).ToLowerInvariant()
        if ($name -eq "package.json") {
            $obj = Load-Json $f.full_path
            if ($null -eq $obj) { continue }
            foreach ($secName in @("dependencies", "devDependencies")) {
                $sec = Read-Prop $obj $secName
                if ($null -eq $sec) { continue }
                foreach ($p in $sec.PSObject.Properties) {
                    $ver = [string]$p.Value
                    if ($ver -match "^(git\+|https?://|github:|file:)") {
                        Add-DepFinding -out $out -ruleId "deps.untrusted.source" -title "Dependency uses non-registry source" -severity "high" -confidence 0.8 -file $f.rel_path -line 1 -evidence ("{0}: {1}" -f $p.Name, $ver) -remediation "Use trusted registries and pin immutable versions."
                    }
                    elseif ($ver -match "^\s*(\^|~|>|<|=|latest|\*|x|X)") {
                        Add-DepFinding -out $out -ruleId "deps.unpinned.version" -title "Dependency version is not pinned" -severity "medium" -confidence 0.72 -file $f.rel_path -line 1 -evidence ("{0}: {1}" -f $p.Name, $ver) -remediation "Pin dependency to an explicit version and update through controlled workflows."
                    }
                }
            }
        }
        elseif ($name -eq "requirements.txt") {
            $lines = Get-Content -LiteralPath $f.full_path -ErrorAction SilentlyContinue
            $ln = 0
            foreach ($line in $lines) {
                $ln++
                $t = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
                if ($t -match "^(-e\s+)?(git\+|https?://)") {
                    Add-DepFinding -out $out -ruleId "deps.untrusted.source" -title "Dependency uses direct URL or VCS source" -severity "high" -confidence 0.78 -file $f.rel_path -line $ln -evidence $t -remediation "Use vetted package indexes with pinned versions/hashes."
                }
                elseif ($t -notmatch "==") {
                    Add-DepFinding -out $out -ruleId "deps.unpinned.version" -title "Python dependency is not strictly pinned" -severity "medium" -confidence 0.7 -file $f.rel_path -line $ln -evidence $t -remediation "Use exact version pinning (and hashes where possible)."
                }
            }
        }
    }
    @($out | ForEach-Object { $_ })
}

function Is-DependencyScanEnabled([hashtable]$cfg) {
    if ([bool]$cfg.dependency_scan_enabled) { return $true }
    return (Feature-Enabled -cfg $cfg -name "deps")
}

function New-DependencyMetadata([string]$ecosystem, [string]$package, [string]$version, [string]$risk, [string]$sourceType, [string]$manifestFile, [bool]$isLockfile, [string]$detectorId, [string]$detectorClass, [string]$validationState, [string]$policyId = $null, [string]$advisoryId = $null) {
    return [ordered]@{
        category = "dependency"
        dependency = [ordered]@{
            detector_contract_version = "deps.v1"
            ecosystem = $ecosystem
            package = $package
            version = $version
            risk = $risk
            source_type = $sourceType
            manifest_file = $manifestFile
            is_lockfile = $isLockfile
            detector_id = $detectorId
            detector_class = $detectorClass
            validation_state = $validationState
            policy_id = $policyId
            advisory_id = $advisoryId
        }
    }
}

function Add-DepStageFinding([System.Collections.Generic.List[object]]$out, [hashtable]$detectorHits, [string]$ruleId, [string]$title, [string]$severity, [double]$confidence, [string]$file, [int]$line, [string]$lang, [string]$evidence, [string]$remediation, [hashtable]$metadata, [string[]]$cwe = @("CWE-1104"), [string[]]$owasp = @("A06:2021")) {
    $out.Add((Build-RawFinding -ruleId $ruleId -title $title -severity $severity -confidence $confidence -file $file -line $line -col 1 -lang $lang -cwe $cwe -owasp $owasp -evidence $evidence -remediation $remediation -analyzer "aux:deps" -Metadata $metadata)) | Out-Null
    if (-not $detectorHits.ContainsKey([string]$ruleId)) { $detectorHits[[string]$ruleId] = 0 }
    $detectorHits[[string]$ruleId]++
}

function Parse-VersionTuple([string]$version) {
    if ([string]::IsNullOrWhiteSpace($version)) { return $null }
    $v = $version.Trim()
    if ($v.StartsWith("v")) { $v = $v.Substring(1) }
    $v = ($v -replace "^[=~^<>! ]+", "")
    $m = [regex]::Match($v, "^\d+(?:\.\d+){0,3}")
    if (-not $m.Success) { return $null }
    $parts = @($m.Value.Split("."))
    $nums = New-Object System.Collections.Generic.List[int]
    foreach ($p in $parts) {
        $x = 0
        if (-not [int]::TryParse($p, [ref]$x)) { return $null }
        $nums.Add($x) | Out-Null
    }
    while ($nums.Count -lt 4) { $nums.Add(0) | Out-Null }
    return @($nums | Select-Object -First 4)
}

function Compare-VersionTuple([int[]]$a, [int[]]$b) {
    if ($null -eq $a -or $null -eq $b) { return $null }
    $n = [Math]::Min($a.Length, $b.Length)
    for ($i = 0; $i -lt $n; $i++) {
        if ($a[$i] -gt $b[$i]) { return 1 }
        if ($a[$i] -lt $b[$i]) { return -1 }
    }
    return 0
}

function Test-VersionConstraint([string]$installedVersion, [string]$constraint) {
    if ([string]::IsNullOrWhiteSpace($installedVersion) -or [string]::IsNullOrWhiteSpace($constraint)) { return $false }
    $iv = Parse-VersionTuple $installedVersion
    if ($null -eq $iv) { return $false }
    $c = $constraint.Trim()
    $op = "=="
    $rhs = $c
    if ($c -match "^(<=|>=|==|=|<|>)[ ]*(.+)$") {
        $op = [string]$Matches[1]
        $rhs = [string]$Matches[2]
    }
    $rv = Parse-VersionTuple $rhs
    if ($null -eq $rv) { return $false }
    $cmp = Compare-VersionTuple -a $iv -b $rv
    switch ($op) {
        "<" { return ($cmp -lt 0) }
        "<=" { return ($cmp -le 0) }
        ">" { return ($cmp -gt 0) }
        ">=" { return ($cmp -ge 0) }
        "=" { return ($cmp -eq 0) }
        "==" { return ($cmp -eq 0) }
        default { return $false }
    }
}

function Test-AffectedRange([string]$installedVersion, [string]$affected) {
    if ([string]::IsNullOrWhiteSpace($affected)) { return $false }
    $parts = @($affected.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $false }
    foreach ($p in $parts) {
        if (-not (Test-VersionConstraint -installedVersion $installedVersion -constraint $p)) { return $false }
    }
    return $true
}

function Is-ExactVersionSpec([string]$spec) {
    if ([string]::IsNullOrWhiteSpace($spec)) { return $false }
    return ($spec.Trim() -match "^v?\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9\.-]+)?$")
}

function Read-DependencyPolicy([hashtable]$cfg) {
    $diag = [ordered]@{
        status = "not_configured"
        source = $null
        blocked_rules = 0
        require_lockfile = @{ npm = $true; go = $true; pypi = $false }
    }
    $blocked = @{}
    $path = [string]$cfg.dependency_policy_file
    if ([string]::IsNullOrWhiteSpace($path)) {
        return @{ blocked = $blocked; require_lockfile = $diag.require_lockfile; diagnostics = $diag }
    }
    $diag.source = Resolve-AbsolutePath -path $path -baseDir (Get-Location).Path
    if (-not (Test-Path -LiteralPath $diag.source)) {
        $diag.status = "missing"
        return @{ blocked = $blocked; require_lockfile = $diag.require_lockfile; diagnostics = $diag }
    }
    $obj = Load-Json $diag.source
    if ($null -eq $obj) {
        $diag.status = "parse_error"
        return @{ blocked = $blocked; require_lockfile = $diag.require_lockfile; diagnostics = $diag }
    }
    $diag.status = "loaded"
    $req = Read-Prop $obj "require_lockfile"
    if ($req) {
        foreach ($eco in @("npm", "go", "pypi")) {
            $v = Read-Prop $req $eco
            if ($null -ne $v) { $diag.require_lockfile[$eco] = [bool]$v }
        }
    }
    foreach ($item in @(Read-Prop $obj "blocked_packages")) {
        $eco = ([string](Read-Prop $item "ecosystem")).ToLowerInvariant()
        $name = ([string](Read-Prop $item "name")).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($eco) -or [string]::IsNullOrWhiteSpace($name)) { continue }
        $blocked["{0}|{1}" -f $eco, $name] = [ordered]@{
            ecosystem = $eco
            name = $name
            severity = (Sev ([string](Read-Prop $item "severity")))
            reason = [string](Read-Prop $item "reason")
            policy_id = [string](Read-Prop $item "policy_id")
        }
    }
    $diag.blocked_rules = $blocked.Count
    return @{ blocked = $blocked; require_lockfile = $diag.require_lockfile; diagnostics = $diag }
}

function Read-DependencyAdvisories([hashtable]$cfg) {
    $diag = [ordered]@{
        status = "not_configured"
        source = $null
        advisories_total = 0
        matched = 0
    }
    $items = New-Object System.Collections.Generic.List[object]
    $path = [string]$cfg.dependency_advisory_file
    if ([string]::IsNullOrWhiteSpace($path)) {
        return @{ advisories = @(); diagnostics = $diag }
    }
    $diag.source = Resolve-AbsolutePath -path $path -baseDir (Get-Location).Path
    if (-not (Test-Path -LiteralPath $diag.source)) {
        $diag.status = "missing"
        return @{ advisories = @(); diagnostics = $diag }
    }
    $obj = Load-Json $diag.source
    if ($null -eq $obj) {
        $diag.status = "parse_error"
        return @{ advisories = @(); diagnostics = $diag }
    }
    $diag.status = "loaded"
    foreach ($a in @(Read-Prop $obj "advisories")) {
        $eco = ([string](Read-Prop $a "ecosystem")).ToLowerInvariant()
        $pkg = ([string](Read-Prop $a "package")).ToLowerInvariant()
        $affected = [string](Read-Prop $a "affected")
        if ([string]::IsNullOrWhiteSpace($eco) -or [string]::IsNullOrWhiteSpace($pkg) -or [string]::IsNullOrWhiteSpace($affected)) { continue }
        $items.Add([ordered]@{
                id = [string](Read-Prop $a "id")
                ecosystem = $eco
                package = $pkg
                affected = $affected
                severity = (Sev ([string](Read-Prop $a "severity")))
                title = [string](Read-Prop $a "title")
                cwe = @((Read-Prop $a "cwe"))
                owasp = @((Read-Prop $a "owasp"))
            }) | Out-Null
    }
    $diag.advisories_total = $items.Count
    return @{ advisories = @($items | Sort-Object ecosystem, package, id); diagnostics = $diag }
}

function Evaluate-DependencyPolicy([hashtable]$policy, [System.Collections.Generic.List[object]]$findingsOut, [hashtable]$detectorHits, [string]$ecosystem, [string]$package, [string]$version, [string]$file, [int]$line, [string]$lang, [bool]$isLockfile) {
    $blocked = Read-Prop $policy "blocked"
    if ($null -eq $blocked) { return }
    $key = "{0}|{1}" -f $ecosystem.ToLowerInvariant(), $package.ToLowerInvariant()
    if (-not $blocked.ContainsKey($key)) { return }
    $rule = $blocked[$key]
    $sev = [string](Read-Prop $rule "severity")
    if ([string]::IsNullOrWhiteSpace($sev)) { $sev = "high" }
    $reason = [string](Read-Prop $rule "reason")
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "Package blocked by dependency policy." }
    $policyId = [string](Read-Prop $rule "policy_id")
    $meta = New-DependencyMetadata -ecosystem $ecosystem -package $package -version $version -risk "policy_violation" -sourceType "registry_or_declared" -manifestFile $file -isLockfile $isLockfile -detectorId "deps.policy.blocked_package" -detectorClass "policy" -validationState "policy_blocked" -policyId $policyId
    Add-DepStageFinding -out $findingsOut -detectorHits $detectorHits -ruleId "deps.policy.blocked_package" -title "Dependency blocked by policy" -severity $sev -confidence 0.99 -file $file -line $line -lang $lang -evidence ("{0}@{1}" -f $package, $version) -remediation "Remove or replace the blocked dependency according to organizational policy." -metadata $meta
}

function Evaluate-DependencyAdvisories([object[]]$advisories, [System.Collections.Generic.List[object]]$findingsOut, [hashtable]$detectorHits, [string]$ecosystem, [string]$package, [string]$version, [string]$file, [int]$line, [string]$lang, [bool]$isLockfile, [ref]$matchedCounter) {
    if ([string]::IsNullOrWhiteSpace($version)) { return }
    foreach ($a in @($advisories)) {
        if ([string](Read-Prop $a "ecosystem") -ne $ecosystem.ToLowerInvariant()) { continue }
        if ([string](Read-Prop $a "package") -ne $package.ToLowerInvariant()) { continue }
        $affected = [string](Read-Prop $a "affected")
        if (-not (Test-AffectedRange -installedVersion $version -affected $affected)) { continue }
        $sev = [string](Read-Prop $a "severity")
        if ([string]::IsNullOrWhiteSpace($sev)) { $sev = "high" }
        $title = [string](Read-Prop $a "title")
        if ([string]::IsNullOrWhiteSpace($title)) { $title = "Dependency matches advisory range" }
        $advisoryId = [string](Read-Prop $a "id")
        $meta = New-DependencyMetadata -ecosystem $ecosystem -package $package -version $version -risk "vulnerable_dependency" -sourceType "registry_or_declared" -manifestFile $file -isLockfile $isLockfile -detectorId "deps.vulnerable.package" -detectorClass "advisory_match" -validationState "advisory_matched" -advisoryId $advisoryId
        $cwe = @((Read-Prop $a "cwe"))
        if ($cwe.Count -eq 0) { $cwe = @("CWE-1104") }
        $owasp = @((Read-Prop $a "owasp"))
        if ($owasp.Count -eq 0) { $owasp = @("A06:2021") }
        Add-DepStageFinding -out $findingsOut -detectorHits $detectorHits -ruleId "deps.vulnerable.package" -title $title -severity $sev -confidence 0.93 -file $file -line $line -lang $lang -evidence ("{0}@{1} affected by {2}" -f $package, $version, $affected) -remediation "Upgrade to a version outside the affected range and verify transitive dependency resolution." -metadata $meta -cwe $cwe -owasp $owasp
        $matchedCounter.Value = [int]$matchedCounter.Value + 1
    }
}

function Invoke-DependencyAnalyzerStage([hashtable]$scope, [hashtable]$cfg) {
    $stageStart = Get-Date
    $out = New-Object System.Collections.Generic.List[object]
    $detectorHits = @{}
    $filesConsidered = 0
    $manifestsParsed = 0
    $lockfilesParsed = 0
    $packagesEvaluated = 0
    $readFailures = 0
    $skippedLarge = 0
    $advisoryMatches = 0

    $policy = Read-DependencyPolicy -cfg $cfg
    $advisoryBundle = Read-DependencyAdvisories -cfg $cfg
    $advisories = @($advisoryBundle.advisories)
    $matchRef = [ref]$advisoryMatches

    foreach ($f in @($scope.selected_files | Sort-Object rel_path)) {
        $filesConsidered++
        if ([int64]$f.size -gt [int64]$cfg.dependency_max_file_bytes) { $skippedLarge++; continue }
        $name = ([System.IO.Path]::GetFileName([string]$f.rel_path)).ToLowerInvariant()

        if ($name -eq "package.json") {
            $raw = $null
            try { $raw = Get-Content -LiteralPath $f.full_path -Raw -ErrorAction Stop } catch { $readFailures++; $raw = $null }
            $obj = Load-Json $f.full_path
            if ($null -eq $obj) { continue }
            $manifestsParsed++
            $depCount = 0
            foreach ($secName in @("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")) {
                $sec = Read-Prop $obj $secName
                if ($null -eq $sec) { continue }
                foreach ($p in @($sec.PSObject.Properties | Sort-Object Name)) {
                    $depCount++
                    $packagesEvaluated++
                    $pkg = [string]$p.Name
                    $spec = [string]$p.Value
                    $line = if ($raw) { [Math]::Max(1, ([regex]::Matches($raw.Substring(0, [Math]::Max(0, $raw.IndexOf('"' + $pkg + '"'))), "`n").Count + 1)) } else { 1 }

                    if ($spec -match "^(?i)(git\+|https?://|github:|git://)") {
                        $meta = New-DependencyMetadata -ecosystem "npm" -package $pkg -version $spec -risk "untrusted_source" -sourceType "remote_vcs_or_url" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.untrusted.source" -detectorClass "pattern" -validationState "source_non_registry"
                        Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.untrusted.source" -title "Dependency uses non-registry source" -severity "high" -confidence 0.86 -file $f.rel_path -line $line -lang "javascript" -evidence ("{0}: {1}" -f $pkg, $spec) -remediation "Use trusted registry sources and immutable version references." -metadata $meta
                    }
                    elseif ($spec -match "^(?i)(file:|link:|workspace:)") {
                        $meta = New-DependencyMetadata -ecosystem "npm" -package $pkg -version $spec -risk "path_source" -sourceType "local_path_or_workspace" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.path.source" -detectorClass "pattern" -validationState "path_based_source"
                        Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.path.source" -title "Dependency uses local path/workspace source" -severity "medium" -confidence 0.7 -file $f.rel_path -line $line -lang "javascript" -evidence ("{0}: {1}" -f $pkg, $spec) -remediation "Use reviewed, immutable dependency sources for CI and production builds." -metadata $meta
                    }

                    $isExact = Is-ExactVersionSpec $spec
                    if (-not $isExact) {
                        $meta = New-DependencyMetadata -ecosystem "npm" -package $pkg -version $spec -risk "unpinned_version" -sourceType "registry_or_declared" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.unpinned.version" -detectorClass "semver_policy" -validationState "not_exact_pin"
                        Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.unpinned.version" -title "Dependency version is not pinned" -severity "medium" -confidence 0.74 -file $f.rel_path -line $line -lang "javascript" -evidence ("{0}: {1}" -f $pkg, $spec) -remediation "Pin to an explicit version and update through controlled dependency management." -metadata $meta
                    }

                    Evaluate-DependencyPolicy -policy $policy -findingsOut $out -detectorHits $detectorHits -ecosystem "npm" -package $pkg -version $spec -file $f.rel_path -line $line -lang "javascript" -isLockfile $false
                    if ($isExact) {
                        Evaluate-DependencyAdvisories -advisories $advisories -findingsOut $out -detectorHits $detectorHits -ecosystem "npm" -package $pkg -version $spec -file $f.rel_path -line $line -lang "javascript" -isLockfile $false -matchedCounter $matchRef
                    }
                }
            }
            $requireLock = [bool](Read-Prop (Read-Prop $policy "require_lockfile") "npm")
            if ($requireLock -and $depCount -gt 0) {
                $dir = Split-Path -Parent ([string]$f.rel_path)
                $dirPrefix = if ([string]::IsNullOrWhiteSpace($dir)) { "" } else { ($dir.Replace("\", "/") + "/") }
                $hasLock = $false
                foreach ($sf in @($scope.selected_files)) {
                    $rp = [string]$sf.rel_path
                    if ($rp -eq ($dirPrefix + "package-lock.json") -or $rp -eq ($dirPrefix + "npm-shrinkwrap.json") -or $rp -eq ($dirPrefix + "yarn.lock") -or $rp -eq ($dirPrefix + "pnpm-lock.yaml")) { $hasLock = $true; break }
                }
                if (-not $hasLock) {
                    $meta = New-DependencyMetadata -ecosystem "npm" -package "<project>" -version $null -risk "lockfile_missing" -sourceType "manifest_only" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.lockfile.missing" -detectorClass "project_hygiene" -validationState "lockfile_required_missing"
                    Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.lockfile.missing" -title "Lockfile missing for npm project" -severity "medium" -confidence 0.86 -file $f.rel_path -line 1 -lang "javascript" -evidence "package.json present with dependencies but no lockfile found in project directory." -remediation "Commit and maintain a lockfile to ensure deterministic dependency resolution." -metadata $meta
                }
            }
        }
        elseif ($name -eq "package-lock.json") {
            $obj = Load-Json $f.full_path
            if ($null -eq $obj) { $readFailures++; continue }
            $lockfilesParsed++
            $packages = Read-Prop $obj "packages"
            if ($packages) {
                foreach ($kv in @($packages.PSObject.Properties | Sort-Object Name)) {
                    $pkgPath = [string]$kv.Name
                    if ([string]::IsNullOrWhiteSpace($pkgPath) -or $pkgPath -notmatch "node_modules/") { continue }
                    $pkgName = ($pkgPath -split "node_modules/")[-1]
                    if ([string]::IsNullOrWhiteSpace($pkgName)) { continue }
                    $entry = $kv.Value
                    $ver = [string](Read-Prop $entry "version")
                    $resolved = [string](Read-Prop $entry "resolved")
                    $integrity = [string](Read-Prop $entry "integrity")
                    $packagesEvaluated++
                    if (-not [string]::IsNullOrWhiteSpace($resolved) -and $resolved -match "^(?i)(http://|git\+|github:|git://)") {
                        $meta = New-DependencyMetadata -ecosystem "npm" -package $pkgName -version $ver -risk "untrusted_source" -sourceType "lock_resolved" -manifestFile $f.rel_path -isLockfile $true -detectorId "deps.untrusted.source" -detectorClass "lockfile_validation" -validationState "lock_source_non_registry"
                        Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.untrusted.source" -title "Lockfile resolves dependency from non-trusted source" -severity "high" -confidence 0.9 -file $f.rel_path -line 1 -lang "javascript" -evidence ("{0}@{1} -> {2}" -f $pkgName, $ver, $resolved) -remediation "Use trusted registries and HTTPS lockfile sources." -metadata $meta
                    }
                    if ([string]::IsNullOrWhiteSpace($integrity)) {
                        $meta = New-DependencyMetadata -ecosystem "npm" -package $pkgName -version $ver -risk "lock_missing_integrity" -sourceType "lock_resolved" -manifestFile $f.rel_path -isLockfile $true -detectorId "deps.lock.missing_integrity" -detectorClass "lockfile_validation" -validationState "integrity_missing"
                        Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.lock.missing_integrity" -title "Lockfile entry missing integrity hash" -severity "medium" -confidence 0.82 -file $f.rel_path -line 1 -lang "javascript" -evidence ("{0}@{1}" -f $pkgName, $ver) -remediation "Regenerate lockfile with integrity metadata and integrity verification." -metadata $meta
                    }
                    Evaluate-DependencyPolicy -policy $policy -findingsOut $out -detectorHits $detectorHits -ecosystem "npm" -package $pkgName -version $ver -file $f.rel_path -line 1 -lang "javascript" -isLockfile $true
                    Evaluate-DependencyAdvisories -advisories $advisories -findingsOut $out -detectorHits $detectorHits -ecosystem "npm" -package $pkgName -version $ver -file $f.rel_path -line 1 -lang "javascript" -isLockfile $true -matchedCounter $matchRef
                }
            }
        }
        elseif ($name -eq "requirements.txt") {
            $lines = Get-Content -LiteralPath $f.full_path -ErrorAction SilentlyContinue
            if ($null -eq $lines) { $readFailures++; continue }
            $manifestsParsed++
            $ln = 0
            foreach ($line in $lines) {
                $ln++
                $t = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
                if ($t -match "^(?i)--(extra-)?index-url\s+http://") {
                    $meta = New-DependencyMetadata -ecosystem "pypi" -package "<index>" -version $null -risk "insecure_registry" -sourceType "index_url" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.index.insecure_url" -detectorClass "pattern" -validationState "http_index_url"
                    Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.index.insecure_url" -title "Dependency index uses insecure HTTP URL" -severity "high" -confidence 0.91 -file $f.rel_path -line $ln -lang "python" -evidence $t -remediation "Use HTTPS package indexes and trusted repositories only." -metadata $meta -cwe @("CWE-319") -owasp @("A02:2021")
                    continue
                }
                if ($t -match "^(-e\s+)?(git\+|https?://)") {
                    $meta = New-DependencyMetadata -ecosystem "pypi" -package "<direct>" -version $null -risk "untrusted_source" -sourceType "direct_url_or_vcs" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.untrusted.source" -detectorClass "pattern" -validationState "source_non_registry"
                    Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.untrusted.source" -title "Dependency uses direct URL or VCS source" -severity "high" -confidence 0.8 -file $f.rel_path -line $ln -lang "python" -evidence $t -remediation "Use vetted package indexes and immutable pinned versions." -metadata $meta
                    continue
                }
                $m = [regex]::Match($t, "^([A-Za-z0-9_.-]+)\s*([=!~<>]{1,2})?\s*([A-Za-z0-9\.\-+]+)?")
                if (-not $m.Success) { continue }
                $pkg = [string]$m.Groups[1].Value
                $op = [string]$m.Groups[2].Value
                $ver = [string]$m.Groups[3].Value
                $packagesEvaluated++
                if ([string]::IsNullOrWhiteSpace($op) -or $op -ne "==") {
                    $meta = New-DependencyMetadata -ecosystem "pypi" -package $pkg -version $t -risk "unpinned_version" -sourceType "manifest_spec" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.unpinned.version" -detectorClass "version_policy" -validationState "not_exact_pin"
                    Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.unpinned.version" -title "Python dependency is not strictly pinned" -severity "medium" -confidence 0.72 -file $f.rel_path -line $ln -lang "python" -evidence $t -remediation "Use exact version pins (and hashes where possible) for deterministic installs." -metadata $meta
                }
                Evaluate-DependencyPolicy -policy $policy -findingsOut $out -detectorHits $detectorHits -ecosystem "pypi" -package $pkg -version $ver -file $f.rel_path -line $ln -lang "python" -isLockfile $false
                if ($op -eq "==" -and -not [string]::IsNullOrWhiteSpace($ver)) {
                    Evaluate-DependencyAdvisories -advisories $advisories -findingsOut $out -detectorHits $detectorHits -ecosystem "pypi" -package $pkg -version $ver -file $f.rel_path -line $ln -lang "python" -isLockfile $false -matchedCounter $matchRef
                }
            }
        }
        elseif ($name -eq "go.mod") {
            $lines = Get-Content -LiteralPath $f.full_path -ErrorAction SilentlyContinue
            if ($null -eq $lines) { $readFailures++; continue }
            $manifestsParsed++
            $hasRequire = $false
            $ln = 0
            foreach ($line in $lines) {
                $ln++
                $t = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("//")) { continue }
                if ($t -match "^replace\s+.+=>\s+(\.\./|\.\/|/|https?://|git\+)") {
                    $meta = New-DependencyMetadata -ecosystem "go" -package "<replace>" -version $null -risk "replace_directive" -sourceType "replace_directive" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.replace.directive" -detectorClass "manifest_policy" -validationState "replace_detected"
                    Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.replace.directive" -title "go.mod replace directive detected" -severity "medium" -confidence 0.8 -file $f.rel_path -line $ln -lang "go" -evidence $t -remediation "Review replace directives to ensure they are intentional and safe for CI/production builds." -metadata $meta
                    continue
                }
                $m = [regex]::Match($t, "^(?:require\s+)?([^\s]+)\s+v?([0-9][^\s]*)$")
                if (-not $m.Success) { continue }
                $hasRequire = $true
                $packagesEvaluated++
                $pkg = [string]$m.Groups[1].Value
                $ver = [string]$m.Groups[2].Value
                Evaluate-DependencyPolicy -policy $policy -findingsOut $out -detectorHits $detectorHits -ecosystem "go" -package $pkg -version $ver -file $f.rel_path -line $ln -lang "go" -isLockfile $false
                Evaluate-DependencyAdvisories -advisories $advisories -findingsOut $out -detectorHits $detectorHits -ecosystem "go" -package $pkg -version $ver -file $f.rel_path -line $ln -lang "go" -isLockfile $false -matchedCounter $matchRef
            }
            $requireLock = [bool](Read-Prop (Read-Prop $policy "require_lockfile") "go")
            if ($requireLock -and $hasRequire) {
                $dir = Split-Path -Parent ([string]$f.rel_path)
                $dirPrefix = if ([string]::IsNullOrWhiteSpace($dir)) { "" } else { ($dir.Replace("\", "/") + "/") }
                $hasSum = $false
                foreach ($sf in @($scope.selected_files)) {
                    if ([string]$sf.rel_path -eq ($dirPrefix + "go.sum")) { $hasSum = $true; break }
                }
                if (-not $hasSum) {
                    $meta = New-DependencyMetadata -ecosystem "go" -package "<project>" -version $null -risk "lockfile_missing" -sourceType "manifest_only" -manifestFile $f.rel_path -isLockfile $false -detectorId "deps.lockfile.missing" -detectorClass "project_hygiene" -validationState "sumfile_missing"
                    Add-DepStageFinding -out $out -detectorHits $detectorHits -ruleId "deps.lockfile.missing" -title "go.sum missing for go.mod project" -severity "medium" -confidence 0.85 -file $f.rel_path -line 1 -lang "go" -evidence "go.mod has require entries but go.sum is missing." -remediation "Generate and commit go.sum to lock dependency checksums." -metadata $meta
                }
            }
        }
        elseif ($name -eq "go.sum") {
            $lockfilesParsed++
        }
    }

    $orderedDetectorHits = [ordered]@{}
    foreach ($k in @($detectorHits.Keys | Sort-Object)) { $orderedDetectorHits[[string]$k] = [int]$detectorHits[$k] }
    $advisoryDiag = [ordered]@{} + (Read-Prop $advisoryBundle "diagnostics")
    $advisoryDiag["matched"] = [int]$advisoryMatches
    $elapsed = [int]((Get-Date) - $stageStart).TotalMilliseconds
    $findingsArray = @($out.ToArray())
    return @{
        findings = $findingsArray
        diagnostics = @{
            stage = "dependencies"
            analyzer = "aux:deps"
            contract_version = "deps.v1"
            status = "completed"
            files_considered = $filesConsidered
            manifests_parsed = $manifestsParsed
            lockfiles_parsed = $lockfilesParsed
            packages_evaluated = $packagesEvaluated
            skipped_large_files = $skippedLarge
            read_failures = $readFailures
            findings_total = $findingsArray.Count
            detector_hits = $orderedDetectorHits
            policy = (Read-Prop $policy "diagnostics")
            advisory_bundle = $advisoryDiag
            config = @{
                max_file_bytes = [int]$cfg.dependency_max_file_bytes
                advisory_file = (Read-Prop $cfg "dependency_advisory_file")
                policy_file = (Read-Prop $cfg "dependency_policy_file")
            }
            duration_ms = $elapsed
        }
    }
}

function To-SarifLevel([string]$severity) {
    switch (Sev $severity) {
        "critical" { return "error" }
        "high" { return "error" }
        "medium" { return "warning" }
        "low" { return "note" }
        default { return "none" }
    }
}

function To-DirFileUri([string]$dirPath) {
    if ([string]::IsNullOrWhiteSpace($dirPath)) { return $null }
    try {
        $abs = Resolve-AbsolutePath -path $dirPath -baseDir (Get-Location).Path
        if (-not $abs.EndsWith([System.IO.Path]::DirectorySeparatorChar)) { $abs = $abs + [System.IO.Path]::DirectorySeparatorChar }
        return ([System.Uri]$abs).AbsoluteUri
    }
    catch { return $null }
}

function To-PathSet([object[]]$paths) {
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($p in @($paths)) {
        $k = Path-Key ([string]$p)
        if (-not [string]::IsNullOrWhiteSpace($k)) { [void]$set.Add($k) }
    }
    return ,$set
}

function Add-Notification([System.Collections.Generic.List[object]]$out, [string]$level, [string]$id, [string]$text, [object]$props = $null) {
    $n = [ordered]@{
        level = $level
        descriptor = @{ id = $id }
        message = @{ text = $text }
    }
    if ($null -ne $props) { $n["properties"] = $props }
    $out.Add($n) | Out-Null
}

function Build-Sarif($report) {
    $findings = @(Read-Prop $report "findings")
    $scanSummary = Read-Prop $report "scan_summary"
    $metadata = Read-Prop $report "metadata"
    $diagnostics = Read-Prop $report "diagnostics"
    $policyDecision = Read-Prop $report "policy_decision"
    $provenance = Read-Prop $report "provenance"
    $scopeDiag = Read-Prop $diagnostics "scope"
    $incDiag = Read-Prop $diagnostics "incremental"
    $baselineDiag = Read-Prop $diagnostics "baseline"
    $policyPackDiag = Read-Prop $diagnostics "policy_pack"
    $incFileSets = Read-Prop $incDiag "file_sets"

    $scopeRoot = [string](Read-Prop $scopeDiag "root")
    $srcRootUri = To-DirFileUri $scopeRoot
    $originalUriBaseIds = $null
    if (-not [string]::IsNullOrWhiteSpace($srcRootUri)) {
        $originalUriBaseIds = [ordered]@{ SRCROOT = @{ uri = $srcRootUri; description = @{ text = "CodeSentinel scoped source root" } } }
    }

    $changedSet = To-PathSet @(Read-Prop $incFileSets "changed")
    $newSet = To-PathSet @(Read-Prop $incFileSets "new")
    $analyzedSet = To-PathSet @(Read-Prop $incFileSets "analyzed")
    $unchangedSet = To-PathSet @(Read-Prop $incFileSets "unchanged")

    $ruleAgg = @{}
    $cweTaxaSet = New-Object System.Collections.Generic.HashSet[string]
    $owaspTaxaSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($f in @($findings)) {
        $rid = [string](Read-Prop $f "rule_id")
        if ([string]::IsNullOrWhiteSpace($rid)) { continue }
        if (-not $ruleAgg.ContainsKey($rid)) {
            $ruleAgg[$rid] = @{
                title = [string](Read-Prop $f "title")
                severity = (Sev ([string](Read-Prop $f "severity")))
                cwe = New-Object System.Collections.Generic.HashSet[string]
                owasp = New-Object System.Collections.Generic.HashSet[string]
            }
        }
        $agg = $ruleAgg[$rid]
        $curSev = (Sev ([string](Read-Prop $f "severity")))
        if ($SeverityOrder[$curSev] -gt $SeverityOrder[$agg.severity]) { $agg.severity = $curSev }
        foreach ($c in @(Read-Prop $f "cwe")) {
            $cv = [string]$c
            if (-not [string]::IsNullOrWhiteSpace($cv)) { [void]$agg.cwe.Add($cv); [void]$cweTaxaSet.Add($cv) }
        }
        foreach ($o in @(Read-Prop $f "owasp")) {
            $ov = [string]$o
            if (-not [string]::IsNullOrWhiteSpace($ov)) { [void]$agg.owasp.Add($ov); [void]$owaspTaxaSet.Add($ov) }
        }
    }

    $rules = New-Object System.Collections.Generic.List[object]
    $ruleIndex = @{}
    $ri = 0
    foreach ($rid in @($ruleAgg.Keys | Sort-Object)) {
        $agg = $ruleAgg[$rid]
        $tags = New-Object System.Collections.Generic.List[string]
        $tags.Add("security") | Out-Null
        $tags.Add(("severity:{0}" -f [string]$agg.severity)) | Out-Null
        foreach ($c in @($agg.cwe | ForEach-Object { [string]$_ } | Sort-Object)) { $tags.Add(("cwe:{0}" -f $c)) | Out-Null }
        foreach ($o in @($agg.owasp | ForEach-Object { [string]$_ } | Sort-Object)) { $tags.Add(("owasp:{0}" -f $o)) | Out-Null }
        $rules.Add([ordered]@{
                id = $rid
                name = $rid
                shortDescription = @{ text = [string]$agg.title }
                fullDescription = @{ text = [string]$agg.title }
                defaultConfiguration = @{ level = (To-SarifLevel ([string]$agg.severity)) }
                properties = @{ tags = @($tags | ForEach-Object { $_ }) }
            }) | Out-Null
        $ruleIndex[$rid] = $ri
        $ri++
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Sort-Findings @($findings))) {
        $rid = [string](Read-Prop $f "rule_id")
        $loc = Read-Prop $f "location"
        $file = [string](Read-Prop $loc "file")
        $line = Read-Prop $loc "line"
        $col = Read-Prop $loc "column"
        if (-not $line) { $line = 1 }
        if (-not $col) { $col = 1 }
        $pathKey = Path-Key $file
        $uri = ($file ?? "").Replace("\", "/")
        $uriBaseId = $null
        if (-not [string]::IsNullOrWhiteSpace($file)) {
            if ($originalUriBaseIds -and -not [System.IO.Path]::IsPathRooted($file)) {
                $uriBaseId = "SRCROOT"
            }
            elseif ($originalUriBaseIds -and [System.IO.Path]::IsPathRooted($file) -and -not [string]::IsNullOrWhiteSpace($scopeRoot)) {
                try {
                    $rel = [System.IO.Path]::GetRelativePath($scopeRoot, $file).Replace("\", "/")
                    if (-not $rel.StartsWith("..")) { $uri = $rel; $uriBaseId = "SRCROOT" }
                }
                catch {}
            }
        }

        $fileClass = "scoped"
        if ($newSet.Contains($pathKey)) { $fileClass = "new" }
        elseif ($changedSet.Contains($pathKey)) { $fileClass = "changed" }
        elseif ($analyzedSet.Contains($pathKey)) { $fileClass = "analyzed" }
        elseif ($unchangedSet.Contains($pathKey)) { $fileClass = "unchanged" }

        $cweArr = @()
        foreach ($c in @(Read-Prop $f "cwe")) { if (-not [string]::IsNullOrWhiteSpace([string]$c)) { $cweArr += [string]$c } }
        $owaspArr = @()
        foreach ($o in @(Read-Prop $f "owasp")) { if (-not [string]::IsNullOrWhiteSpace([string]$o)) { $owaspArr += [string]$o } }

        $resProps = [ordered]@{
            "codesentinel.finding_id" = [string](Read-Prop $f "finding_id")
            "codesentinel.fingerprint" = [string](Read-Prop $f "fingerprint")
            "codesentinel.fingerprint_version" = [string](Read-Prop $f "fingerprint_version")
            "codesentinel.dedup_key" = [string](Read-Prop $f "dedup_key")
            "codesentinel.severity" = (Sev ([string](Read-Prop $f "severity")))
            "codesentinel.confidence" = [double](Read-Prop $f "confidence")
            "codesentinel.raw_confidence" = [double](Read-Prop $f "raw_confidence")
            "codesentinel.confidence_level" = (Read-Prop $f "confidence_level")
            "codesentinel.confidence_model_version" = (Read-Prop $f "confidence_model_version")
            "codesentinel.confidence_rationale" = (Read-Prop $f "confidence_rationale")
            "codesentinel.language" = (Read-Prop $f "language")
            "codesentinel.category" = (Read-Prop $f "category")
            "codesentinel.secret_type" = (Read-Prop $f "secret_type")
            "codesentinel.validation_state" = (Read-Prop $f "validation_state")
            "codesentinel.detector_class" = (Read-Prop $f "detector_class")
            "codesentinel.dependency_package" = (Read-Prop $f "dependency_package")
            "codesentinel.dependency_version" = (Read-Prop $f "dependency_version")
            "codesentinel.dependency_ecosystem" = (Read-Prop $f "dependency_ecosystem")
            "codesentinel.dependency_risk" = (Read-Prop $f "dependency_risk")
            "codesentinel.cwe" = @($cweArr)
            "codesentinel.owasp" = @($owaspArr)
            "codesentinel.origin" = (Read-Prop $f "origin")
            "codesentinel.file_class" = $fileClass
            "codesentinel.scan_mode" = [string](Read-Prop $scanSummary "scan_mode")
            "codesentinel.policy_scope" = [string](Read-Prop $policyDecision "scope_effective")
        }
        $evidence = Read-Prop $f "evidence"
        if ($null -ne $evidence -and -not [string]::IsNullOrWhiteSpace([string]$evidence)) { $resProps["codesentinel.evidence"] = [string]$evidence }
        $remediation = Read-Prop $f "remediation"
        if ($null -ne $remediation -and -not [string]::IsNullOrWhiteSpace([string]$remediation)) { $resProps["codesentinel.remediation"] = [string]$remediation }

        $locObj = [ordered]@{
            physicalLocation = @{
                artifactLocation = @{}
                region = @{
                    startLine = [int]$line
                    startColumn = [int]$col
                }
            }
        }
        $locObj.physicalLocation.artifactLocation["uri"] = $uri
        if ($uriBaseId) { $locObj.physicalLocation.artifactLocation["uriBaseId"] = $uriBaseId }

        $result = [ordered]@{
            ruleId = $rid
            level = (To-SarifLevel ([string](Read-Prop $f "severity")))
            kind = "fail"
            message = @{ text = [string](Read-Prop $f "title") }
            partialFingerprints = @{
                primaryLocationLineHash = [string](Read-Prop $f "fingerprint")
                codesentinelFindingId = [string](Read-Prop $f "finding_id")
            }
            properties = $resProps
            locations = @($locObj)
        }
        $taxaRefs = New-Object System.Collections.Generic.List[object]
        foreach ($c in @($cweArr | Sort-Object -Unique)) {
            $taxaRefs.Add(@{ id = [string]$c; toolComponent = @{ name = "CWE" } }) | Out-Null
        }
        foreach ($o in @($owaspArr | Sort-Object -Unique)) {
            $taxaRefs.Add(@{ id = [string]$o; toolComponent = @{ name = "OWASP" } }) | Out-Null
        }
        if ($taxaRefs.Count -gt 0) { $result["taxa"] = @($taxaRefs | ForEach-Object { $_ }) }
        if ($ruleIndex.ContainsKey($rid)) { $result["ruleIndex"] = [int]$ruleIndex[$rid] }
        if ($baselineDiag -and [string](Read-Prop $baselineDiag "status") -eq "loaded") { $result["baselineState"] = "new" }
        $results.Add($result) | Out-Null
    }

    $notifications = New-Object System.Collections.Generic.List[object]
    $decision = [string](Read-Prop $policyDecision "decision")
    $decisionKind = [string](Read-Prop $policyDecision "decision_kind")
    if ($decision -eq "blocked") {
        Add-Notification -out $notifications -level "error" -id "codesentinel.policy.blocked" -text "Policy decision blocked due to coverage/trust requirements." -props @{ reason_codes = @(Read-Prop $policyDecision "reason_codes") }
    }
    elseif ($decision -eq "fail") {
        Add-Notification -out $notifications -level "warning" -id "codesentinel.policy.fail" -text "Policy decision failed." -props @{ decision_kind = $decisionKind; reason_codes = @(Read-Prop $policyDecision "reason_codes") }
    }
    else {
        Add-Notification -out $notifications -level "note" -id "codesentinel.policy.pass" -text "Policy decision passed." -props @{ reason_codes = @(Read-Prop $policyDecision "reason_codes") }
    }
    foreach ($lim in @(Read-Prop $scanSummary "coverage_limitations")) {
        Add-Notification -out $notifications -level "warning" -id "codesentinel.coverage.limitation" -text ("Coverage limitation: {0}" -f [string]$lim)
    }
    foreach ($e in @(Read-Prop $report "errors")) {
        $code = [string](Read-Prop $e "code")
        $msg = [string](Read-Prop $e "message")
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "CodeSentinel error." }
        if ([string]::IsNullOrWhiteSpace($code)) { $code = "codesentinel.error" }
        Add-Notification -out $notifications -level "error" -id $code -text $msg -props @{ details = (Read-Prop $e "details"); hint = (Read-Prop $e "hint") }
    }

    $invocationExit = [int](Read-Prop $policyDecision "exit_code")
    $executionSuccessful = ([string](Read-Prop $scanSummary "status") -eq "completed")
    $invocation = [ordered]@{
        executionSuccessful = $executionSuccessful
        endTimeUtc = [string](Read-Prop $report "generated_at")
        exitCode = $invocationExit
        properties = @{
            "codesentinel.scan_status" = [string](Read-Prop $scanSummary "status")
            "codesentinel.completeness" = [string](Read-Prop $scanSummary "completeness")
            "codesentinel.policy_decision" = $policyDecision
            "codesentinel.incremental" = $incDiag
            "codesentinel.baseline" = $baselineDiag
        }
        toolExecutionNotifications = @($notifications | ForEach-Object { $_ })
    }

    $runProps = [ordered]@{
        "codesentinel.spec_version" = [string](Read-Prop $report "spec_version")
        "codesentinel.report_version" = [string](Read-Prop $report "report_version")
        "codesentinel.confidence_model_version" = [string](Read-Prop $metadata "confidence_model_version")
        "codesentinel.scan_summary" = $scanSummary
        "codesentinel.policy_decision" = $policyDecision
        "codesentinel.policy_pack" = $policyPackDiag
        "codesentinel.analyzer_stages" = (Read-Prop $diagnostics "analyzer_stages")
        "codesentinel.incremental" = $incDiag
        "codesentinel.baseline" = $baselineDiag
        "codesentinel.provenance" = $provenance
        "codesentinel.target" = [string](Read-Prop $metadata "target")
    }

    $driver = [ordered]@{
        name = "CodeSentinel"
        version = $WrapperVersion
        semanticVersion = $WrapperVersion
        informationUri = "https://codesentinel.local"
        rules = @($rules | ForEach-Object { $_ })
    }

    $run = [ordered]@{
        tool = @{ driver = $driver }
        invocations = @($invocation)
        results = @($results | ForEach-Object { $_ })
        properties = $runProps
        runAutomationDetails = @{
            id = [string](Read-Prop $provenance "run_id")
            description = @{ text = "CodeSentinel wrapper scan run" }
        }
    }
    if ($originalUriBaseIds) { $run["originalUriBaseIds"] = $originalUriBaseIds }
    $taxonomies = New-Object System.Collections.Generic.List[object]
    if ($cweTaxaSet.Count -gt 0) {
        $taxa = New-Object System.Collections.Generic.List[object]
        foreach ($c in @($cweTaxaSet | ForEach-Object { [string]$_ } | Sort-Object)) {
            $taxa.Add(@{ id = $c; name = $c; shortDescription = @{ text = $c } }) | Out-Null
        }
        $taxonomies.Add([ordered]@{
                name = "CWE"
                organization = "MITRE"
                shortDescription = @{ text = "Common Weakness Enumeration taxonomy mapped from CodeSentinel findings." }
                taxa = @($taxa | ForEach-Object { $_ })
            }) | Out-Null
    }
    if ($owaspTaxaSet.Count -gt 0) {
        $taxa = New-Object System.Collections.Generic.List[object]
        foreach ($o in @($owaspTaxaSet | ForEach-Object { [string]$_ } | Sort-Object)) {
            $taxa.Add(@{ id = $o; name = $o; shortDescription = @{ text = $o } }) | Out-Null
        }
        $taxonomies.Add([ordered]@{
                name = "OWASP"
                organization = "OWASP Foundation"
                shortDescription = @{ text = "OWASP taxonomy mapped from CodeSentinel findings." }
                taxa = @($taxa | ForEach-Object { $_ })
            }) | Out-Null
    }
    if ($taxonomies.Count -gt 0) { $run["taxonomies"] = @($taxonomies | ForEach-Object { $_ }) }

    [ordered]@{
        '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
        version = "2.1.0"
        runs = @($run)
    }
}

function Write-Report($report, [hashtable]$cfg) {
    if ($cfg.format -eq "console") { Write-Output ("Scan status: {0}" -f $report.scan_summary.status); Write-Output ("Findings total: {0}" -f $report.scan_summary.findings_total); Write-Output ("Policy breach: {0}" -f $report.scan_summary.policy.breach); return }
    $payload = switch ($cfg.format) {
        "json" { $report | ConvertTo-Json -Depth 100 }
        "sarif" { (Build-Sarif $report) | ConvertTo-Json -Depth 100 }
        "markdown" { ($report | ConvertTo-Json -Depth 100) }
        "html" { "<pre>$($report | ConvertTo-Json -Depth 100)</pre>" }
        "xml" { "<codesentinel_report><![CDATA[$($report | ConvertTo-Json -Depth 100)]]></codesentinel_report>" }
    }
    if ($cfg.output) { $dir = Split-Path -Parent $cfg.output; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; Set-Content -LiteralPath $cfg.output -Value $payload -Encoding UTF8 }
    if ($cfg.stdout -or -not $cfg.output) { Write-Output $payload }
}

function To-BatchBool($value, [bool]$defaultValue = $false) {
    if ($null -eq $value) { return $defaultValue }
    if ($value -is [bool]) { return [bool]$value }
    $s = [string]$value
    if ([string]::IsNullOrWhiteSpace($s)) { return $defaultValue }
    return ($s -match "^(?i:true|1|yes|on)$")
}

function To-BatchArray($value) {
    if ($null -eq $value) { return @() }
    if ($value -is [string]) { return @($value -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) { return @($value | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
    return @([string]$value)
}

function Sanitize-FileToken([string]$value, [string]$fallback = "project") {
    if ([string]::IsNullOrWhiteSpace($value)) { return $fallback }
    $x = ([string]$value).Trim()
    $x = $x -replace "[^A-Za-z0-9._-]", "_"
    if ([string]::IsNullOrWhiteSpace($x)) { return $fallback }
    return $x
}

function Resolve-BatchManifestPath() {
    if ($Script:InputBound.ContainsKey("BatchManifest") -and -not [string]::IsNullOrWhiteSpace([string]$BatchManifest)) {
        return Resolve-AbsolutePath -path ([string]$BatchManifest) -baseDir (Get-Location).Path
    }
    if ($Script:InputBound.ContainsKey("Target") -and -not [string]::IsNullOrWhiteSpace([string]$Target) -and [string]$Target -ne ".") {
        return Resolve-AbsolutePath -path ([string]$Target) -baseDir (Get-Location).Path
    }
    return Resolve-AbsolutePath -path ([string]$BatchManifest) -baseDir (Get-Location).Path
}

function Merge-BatchProjectConfig([hashtable]$baseCfg, $projectConfig, [string]$manifestDir) {
    $cfg = @{} + $baseCfg
    $pc = To-Hash $projectConfig
    $boolKeys = @("incremental", "no_cache_write", "baseline_required", "require_authoritative", "require_trusted_incremental", "secret_scan_enabled", "dependency_scan_enabled", "respect_gitignore", "use_default_excludes", "exit_zero_on_findings")
    $stringKeys = @("analyzer_mode", "fallback_policy", "min_severity", "format", "error_format", "policy_scope", "policy_profile", "fail_on", "min_confidence_level", "ruleset_version")
    $numberKeys = @("min_confidence", "secret_entropy_threshold", "secret_min_token_length", "secret_max_file_bytes", "dependency_max_file_bytes")
    $arrayKeys = @("include", "exclude", "enable")
    $pathKeys = @("diff_from", "cache_path", "policy_file", "baseline_file", "dependency_advisory_file", "dependency_policy_file", "output")

    foreach ($k in $boolKeys) {
        if ($pc.ContainsKey($k)) { $cfg[$k] = To-BatchBool -value $pc[$k] -defaultValue ([bool]$cfg[$k]) }
    }
    foreach ($k in $stringKeys) {
        if ($pc.ContainsKey($k)) {
            $v = [string]$pc[$k]
            if (-not [string]::IsNullOrWhiteSpace($v)) { $cfg[$k] = $v }
        }
    }
    foreach ($k in $numberKeys) {
        if ($pc.ContainsKey($k)) {
            if ($k -eq "min_confidence" -or $k -eq "secret_entropy_threshold") { $cfg[$k] = [double]$pc[$k] } else { $cfg[$k] = [int]$pc[$k] }
        }
    }
    foreach ($k in $arrayKeys) {
        if ($pc.ContainsKey($k)) { $cfg[$k] = @(To-BatchArray $pc[$k]) }
    }
    foreach ($k in $pathKeys) {
        if ($pc.ContainsKey($k)) {
            $v = [string]$pc[$k]
            if ([string]::IsNullOrWhiteSpace($v)) { $cfg[$k] = $null }
            else { $cfg[$k] = Resolve-AbsolutePath -path $v -baseDir $manifestDir }
        }
    }
    return $cfg
}

function Invoke-BatchProjectScan([string]$projectId, [string]$targetPath, [hashtable]$projectCfg, [string]$projectOutputPath) {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("codesentinel-batch-{0}" -f [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $tmpCfg = Join-Path $tmpDir "project.config.json"
    $cfgToWrite = @{} + $projectCfg
    $cfgToWrite["format"] = "json"
    $cfgToWrite["error_format"] = "json"
    $cfgToWrite["output"] = $null
    $cfgToWrite | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $tmpCfg -Encoding UTF8
    Ensure-ParentDirectory -filePath $projectOutputPath

    $self = if (-not [string]::IsNullOrWhiteSpace([string]$PSCommandPath)) { $PSCommandPath } else { Join-Path $PSScriptRoot "codesentinel.ps1" }
    $invokeParams = @{
        Command = "scan"
        Target = $targetPath
        ConfigFile = $tmpCfg
        Format = "json"
        Output = $projectOutputPath
        ErrorFormat = "json"
    }
    $stdout = @()
    $exitCode = $ExitCodes.RuntimeError
    try {
        $stdout = @(& $self @invokeParams 2>&1)
        $exitCode = [int]$LASTEXITCODE
    }
    catch {
        $stdout = @($_.Exception.Message)
        $exitCode = $ExitCodes.InternalError
    }

    $reportObj = $null
    $status = "report_missing"
    $errorObj = $null
    if (Test-Path -LiteralPath $projectOutputPath) {
        $reportObj = Load-Json $projectOutputPath
        if ($null -ne $reportObj) { $status = "completed" }
        else {
            $status = "report_parse_error"
            $errorObj = New-Err "BATCH_PROJECT_REPORT_PARSE_ERROR" "Project report could not be parsed." @{ project_id = $projectId; report_path = $projectOutputPath }
        }
    }
    else {
        $status = "report_missing"
        $errorObj = New-Err "BATCH_PROJECT_REPORT_MISSING" "Project report was not produced." @{ project_id = $projectId; report_path = $projectOutputPath; exit_code = $exitCode; stdout = [string]::Join("`n", @($stdout)) }
    }

    if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    return @{
        project_id = $projectId
        target = $targetPath
        output_path = $projectOutputPath
        status = $status
        exit_code = [int]$exitCode
        report = $reportObj
        error = $errorObj
    }
}

function Build-PortfolioDecision([object[]]$projectRuns) {
    $anyExecError = $false
    $invalidConfig = 0
    $blocked = 0
    $failed = 0
    $failedPolicy = 0
    $failedFindings = 0
    foreach ($p in @($projectRuns)) {
        $status = [string](Read-Prop $p "status")
        if ($status -eq "invalid_project") { $invalidConfig++; continue }
        if ($status -ne "completed") { $anyExecError = $true; continue }
        $pd = Read-Prop $p "policy_decision"
        $d = [string](Read-Prop $pd "decision")
        $k = [string](Read-Prop $pd "decision_kind")
        switch ($d) {
            "blocked" { $blocked++ }
            "fail" {
                $failed++
                if ($k -eq "policy_breach") { $failedPolicy++ } else { $failedFindings++ }
            }
        }
    }
    $decision = "pass"
    $decisionKind = "no_breach"
    $exitCode = $ExitCodes.Success
    $reasonCodes = New-Object System.Collections.Generic.List[string]
    if ($invalidConfig -gt 0) {
        $decision = "blocked"
        $decisionKind = "config_error"
        $exitCode = $ExitCodes.ConfigError
        $reasonCodes.Add("project_config_invalid") | Out-Null
    }
    elseif ($anyExecError) {
        $decision = "blocked"
        $decisionKind = "execution_error"
        $exitCode = $ExitCodes.RuntimeError
        $reasonCodes.Add("project_execution_error") | Out-Null
    }
    elseif ($blocked -gt 0) {
        $decision = "blocked"
        $decisionKind = "coverage_blocked"
        $exitCode = $ExitCodes.PartialResults
        $reasonCodes.Add("project_policy_blocked") | Out-Null
    }
    elseif ($failed -gt 0) {
        $decision = "fail"
        if ($failedPolicy -gt 0) {
            $decisionKind = "policy_breach"
            $exitCode = $ExitCodes.PolicyBreach
            $reasonCodes.Add("project_policy_fail") | Out-Null
        }
        else {
            $decisionKind = "findings_present"
            $exitCode = $ExitCodes.FindingsPresent
            $reasonCodes.Add("project_findings_present") | Out-Null
        }
    }
    else {
        $reasonCodes.Add("pass") | Out-Null
    }
    return @{
        decision = $decision
        decision_kind = $decisionKind
        reason_codes = @($reasonCodes | ForEach-Object { $_ })
        exit_code = [int]$exitCode
        summary = @{
            invalid_config_projects = [int]$invalidConfig
            blocked_projects = [int]$blocked
            failed_projects = [int]$failed
            failed_policy_projects = [int]$failedPolicy
            failed_findings_projects = [int]$failedFindings
            execution_error = [bool]$anyExecError
        }
    }
}

function Write-PortfolioReport($report, [hashtable]$cfg) {
    if ($cfg.format -eq "sarif") { Exit-Err (New-Err "BATCH_UNSUPPORTED_FORMAT" "batch-scan does not support sarif output. Use json for portfolio artifacts." @{ format = $cfg.format }) $ExitCodes.UsageError $cfg.error_format }
    if ($cfg.format -eq "console") {
        $sum = Read-Prop $report "portfolio_summary"
        Write-Output ("Portfolio decision: {0}" -f [string](Read-Prop $sum "decision"))
        Write-Output ("Projects total: {0}" -f [int](Read-Prop $sum "projects_total"))
        Write-Output ("Projects scanned: {0}" -f [int](Read-Prop $sum "projects_scanned"))
        Write-Output ("Projects failed: {0}" -f [int](Read-Prop $sum "projects_failed"))
        Write-Output ("Projects blocked: {0}" -f [int](Read-Prop $sum "projects_blocked"))
        return
    }
    $payload = switch ($cfg.format) {
        "json" { $report | ConvertTo-Json -Depth 100 }
        "markdown" { ($report | ConvertTo-Json -Depth 100) }
        "html" { "<pre>$($report | ConvertTo-Json -Depth 100)</pre>" }
        "xml" { "<codesentinel_portfolio_report><![CDATA[$($report | ConvertTo-Json -Depth 100)]]></codesentinel_portfolio_report>" }
        default { $report | ConvertTo-Json -Depth 100 }
    }
    if ($cfg.output) { Ensure-ParentDirectory -filePath $cfg.output; Set-Content -LiteralPath $cfg.output -Value $payload -Encoding UTF8 }
    if ($cfg.stdout -or -not $cfg.output) { Write-Output $payload }
}

function Batch-Scan([hashtable]$cfg) {
    $manifestPath = Resolve-BatchManifestPath
    if (-not (Test-Path -LiteralPath $manifestPath)) { Exit-Err (New-Err "BATCH_MANIFEST_NOT_FOUND" "Batch manifest not found." @{ manifest = $manifestPath }) $ExitCodes.UsageError $cfg.error_format }
    $manifest = Load-Json $manifestPath
    if ($null -eq $manifest) { Exit-Err (New-Err "BATCH_MANIFEST_PARSE_ERROR" "Batch manifest could not be parsed." @{ manifest = $manifestPath }) $ExitCodes.ConfigError $cfg.error_format }
    $schema = [string](Read-Prop $manifest "schema")
    if (-not [string]::IsNullOrWhiteSpace($schema) -and $schema -ne "batch-manifest.v1") { Exit-Err (New-Err "BATCH_MANIFEST_SCHEMA_UNSUPPORTED" "Unsupported batch manifest schema." @{ schema = $schema; expected = "batch-manifest.v1" }) $ExitCodes.ConfigError $cfg.error_format }
    $manifestDir = Split-Path -Parent $manifestPath
    $projects = @(Read-Prop $manifest "projects")
    if ($projects.Count -eq 0) { Exit-Err (New-Err "BATCH_MANIFEST_NO_PROJECTS" "Batch manifest must define at least one project." @{ manifest = $manifestPath }) $ExitCodes.ConfigError $cfg.error_format }
    $outputDirRaw = [string](Read-Prop $manifest "output_dir")
    $outputDir = if (-not [string]::IsNullOrWhiteSpace($outputDirRaw)) { Resolve-AbsolutePath -path $outputDirRaw -baseDir $manifestDir } else { Join-Path $manifestDir ".codesentinel\\batch-reports" }
    if (-not (Test-Path -LiteralPath $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

    $runItems = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    $seenIds = New-Object System.Collections.Generic.HashSet[string]
    $index = 1
    foreach ($p in @($projects)) {
        $enabled = To-BatchBool -value (Read-Prop $p "enabled") -defaultValue $true
        $projectId = [string](Read-Prop $p "id")
        if ([string]::IsNullOrWhiteSpace($projectId)) { $projectId = ("project-{0}" -f $index) }
        if (-not $seenIds.Add($projectId)) {
            $errors.Add((New-Err "BATCH_PROJECT_ID_DUPLICATE" "Project id must be unique in batch manifest." @{ project_id = $projectId })) | Out-Null
            $runItems.Add([ordered]@{
                    project_id = $projectId
                    target = [string](Read-Prop $p "target")
                    status = "invalid_project"
                    exit_code = $ExitCodes.ConfigError
                    scan_summary = $null
                    policy_decision = $null
                    report_path = $null
                }) | Out-Null
            $index++
            continue
        }
        $targetRaw = [string](Read-Prop $p "target")
        if (-not $enabled) {
            $runItems.Add([ordered]@{
                    project_id = $projectId
                    target = $targetRaw
                    status = "skipped"
                    exit_code = $ExitCodes.Success
                    scan_summary = $null
                    policy_decision = $null
                    report_path = $null
                }) | Out-Null
            $index++
            continue
        }
        if ([string]::IsNullOrWhiteSpace($targetRaw)) {
            $errors.Add((New-Err "BATCH_PROJECT_TARGET_MISSING" "Project target is required in batch manifest." @{ project_id = $projectId })) | Out-Null
            $runItems.Add([ordered]@{
                    project_id = $projectId
                    target = $null
                    status = "invalid_project"
                    exit_code = $ExitCodes.ConfigError
                    scan_summary = $null
                    policy_decision = $null
                    report_path = $null
                }) | Out-Null
            $index++
            continue
        }
        $targetAbs = Resolve-AbsolutePath -path $targetRaw -baseDir $manifestDir
        if (-not (Test-Path -LiteralPath $targetAbs)) {
            $errors.Add((New-Err "BATCH_PROJECT_TARGET_NOT_FOUND" "Project target does not exist." @{ project_id = $projectId; target = $targetAbs })) | Out-Null
            $runItems.Add([ordered]@{
                    project_id = $projectId
                    target = $targetAbs
                    status = "invalid_project"
                    exit_code = $ExitCodes.UsageError
                    scan_summary = $null
                    policy_decision = $null
                    report_path = $null
                }) | Out-Null
            $index++
            continue
        }
        $projCfg = Merge-BatchProjectConfig -baseCfg $cfg -projectConfig (Read-Prop $p "config") -manifestDir $manifestDir
        $projCfg = Apply-PolicyConfig $projCfg
        $projVerr = @(Validate-Config $projCfg)
        if ($projVerr.Count -gt 0) {
            $errors.Add((New-Err "BATCH_PROJECT_CONFIG_INVALID" "Project config validation failed." @{ project_id = $projectId; errors = @($projVerr) })) | Out-Null
            $runItems.Add([ordered]@{
                    project_id = $projectId
                    target = $targetAbs
                    status = "invalid_project"
                    exit_code = $ExitCodes.ConfigError
                    scan_summary = $null
                    policy_decision = $null
                    report_path = $null
                }) | Out-Null
            $index++
            continue
        }
        $token = Sanitize-FileToken -value $projectId -fallback ("project-{0}" -f $index)
        $projectReportPath = Join-Path $outputDir ("{0:D3}-{1}.json" -f $index, $token)
        $scanRun = Invoke-BatchProjectScan -projectId $projectId -targetPath $targetAbs -projectCfg $projCfg -projectOutputPath $projectReportPath
        if ($scanRun.error) { $errors.Add($scanRun.error) | Out-Null }
        $reportObj = Read-Prop $scanRun "report"
        $scanSummary = if ($reportObj) { Read-Prop $reportObj "scan_summary" } else { $null }
        $policyDecision = if ($reportObj) { Read-Prop $reportObj "policy_decision" } else { $null }
        $runItems.Add([ordered]@{
                project_id = $projectId
                target = $targetAbs
                status = [string](Read-Prop $scanRun "status")
                exit_code = [int](Read-Prop $scanRun "exit_code")
                scan_summary = $scanSummary
                policy_decision = $policyDecision
                report_path = $projectReportPath
            }) | Out-Null
        $index++
    }

    $decision = Build-PortfolioDecision -projectRuns @($runItems | ForEach-Object { $_ })
    $projectsTotal = [int]$runItems.Count
    $projectsScanned = @($runItems | Where-Object { $_.status -eq "completed" }).Count
    $projectsFailed = @($runItems | Where-Object { $_.policy_decision -and [string](Read-Prop $_.policy_decision "decision") -eq "fail" }).Count
    $projectsBlocked = @($runItems | Where-Object { $_.policy_decision -and [string](Read-Prop $_.policy_decision "decision") -eq "blocked" }).Count
    $projectsSkipped = @($runItems | Where-Object { $_.status -eq "skipped" }).Count
    $projectsError = @($runItems | Where-Object { $_.status -ne "completed" -and $_.status -ne "skipped" }).Count
    $projectsInvalid = @($runItems | Where-Object { $_.status -eq "invalid_project" }).Count
    $projectsWithFindings = @($runItems | Where-Object { $_.scan_summary -and [int](Read-Prop $_.scan_summary "findings_total") -gt 0 }).Count
    $manifestHash = Sha $manifestPath
    $projectStatusCounts = @{
        completed = @($runItems | Where-Object { $_.status -eq "completed" }).Count
        skipped = @($runItems | Where-Object { $_.status -eq "skipped" }).Count
        invalid_project = @($runItems | Where-Object { $_.status -eq "invalid_project" }).Count
        report_missing = @($runItems | Where-Object { $_.status -eq "report_missing" }).Count
        report_parse_error = @($runItems | Where-Object { $_.status -eq "report_parse_error" }).Count
    }
    $report = [ordered]@{
        report_type = "portfolio"
        portfolio_report_version = "1.0"
        spec_version = $SpecVersion
        generated_at = (Get-Date).ToString("o")
        metadata = @{
            tool = @{ name = "CodeSentinel Wrapper"; version = $WrapperVersion }
            manifest = $manifestPath
            output_directory = $outputDir
            analyzer_mode = [string]$cfg.analyzer_mode
            fallback_policy = [string]$cfg.fallback_policy
        }
        portfolio_summary = @{
            decision = [string](Read-Prop $decision "decision")
            decision_kind = [string](Read-Prop $decision "decision_kind")
            reason_codes = @((Read-Prop $decision "reason_codes"))
            projects_total = [int]$projectsTotal
            projects_scanned = [int]$projectsScanned
            projects_skipped = [int]$projectsSkipped
            projects_errors = [int]$projectsError
            projects_invalid = [int]$projectsInvalid
            projects_failed = [int]$projectsFailed
            projects_blocked = [int]$projectsBlocked
            projects_with_findings = [int]$projectsWithFindings
            exit_code = [int](Read-Prop $decision "exit_code")
            decision_summary = (Read-Prop $decision "summary")
        }
        diagnostics = @{
            orchestration_contract_version = "batch.v1"
            manifest = @{
                path = $manifestPath
                schema = if ([string]::IsNullOrWhiteSpace($schema)) { "batch-manifest.v1" } else { $schema }
                sha256 = $manifestHash
                output_directory = $outputDir
            }
            project_order = @($runItems | ForEach-Object { [string]$_.project_id })
            project_status_counts = $projectStatusCounts
        }
        projects = @($runItems | ForEach-Object { $_ })
        errors = @($errors | ForEach-Object { $_ })
    }
    Write-PortfolioReport -report $report -cfg $cfg
    exit ([int](Read-Prop $decision "exit_code"))
}

function Resolve-AbsolutePath([string]$path, [string]$baseDir = $null) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    if ([System.IO.Path]::IsPathRooted($path)) { return [System.IO.Path]::GetFullPath($path) }
    $base = if ($baseDir) { $baseDir } else { (Get-Location).Path }
    return [System.IO.Path]::GetFullPath((Join-Path $base $path))
}

function Path-Key([string]$relPath) {
    if ([string]::IsNullOrWhiteSpace($relPath)) { return "" }
    $p = ([string]$relPath).Replace("\", "/")
    while ($p.StartsWith("./")) { $p = $p.Substring(2) }
    if ($p.StartsWith("/")) { $p = $p.Substring(1) }
    return $p.ToLowerInvariant()
}

function Get-DefaultCachePath([string]$scopeRoot) {
    return (Join-Path $scopeRoot ".codesentinel\cache\scan-index.v1.json")
}

function Ensure-ParentDirectory([string]$filePath) {
    $dir = Split-Path -Parent $filePath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Get-ConfigSignature([hashtable]$cfg) {
    $depAdvisoryPath = $null
    $depAdvisoryHash = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.dependency_advisory_file)) {
        $depAdvisoryPath = Resolve-AbsolutePath -path ([string]$cfg.dependency_advisory_file) -baseDir (Get-Location).Path
        if (Test-Path -LiteralPath $depAdvisoryPath) { $depAdvisoryHash = Sha $depAdvisoryPath }
    }
    $depPolicyPath = $null
    $depPolicyHash = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.dependency_policy_file)) {
        $depPolicyPath = Resolve-AbsolutePath -path ([string]$cfg.dependency_policy_file) -baseDir (Get-Location).Path
        if (Test-Path -LiteralPath $depPolicyPath) { $depPolicyHash = Sha $depPolicyPath }
    }
    $scopeRules = Resolve-EffectiveScopeRules -cfg $cfg
    $sigObj = [ordered]@{
        schema = "config-signature.v1"
        analyzer_mode = [string]$cfg.analyzer_mode
        fallback_policy = [string]$cfg.fallback_policy
        min_severity = (Sev ([string]$cfg.min_severity))
        ruleset_version = [string]$cfg.ruleset_version
        include = @($scopeRules.include_patterns)
        exclude = @($scopeRules.effective_exclude_patterns)
        user_exclude = @($scopeRules.user_exclude_patterns)
        default_exclude = @($scopeRules.default_exclude_patterns)
        use_default_excludes = [bool]$scopeRules.use_default_excludes
        respect_gitignore = [bool]$cfg.respect_gitignore
        enable = @(@($cfg.enable | ForEach-Object { ([string]$_).ToLowerInvariant() }) | Sort-Object -Unique)
        secret_scan_enabled = [bool]$cfg.secret_scan_enabled
        secret_entropy_threshold = [double]$cfg.secret_entropy_threshold
        secret_min_token_length = [int]$cfg.secret_min_token_length
        secret_max_file_bytes = [int]$cfg.secret_max_file_bytes
        dependency_scan_enabled = [bool]$cfg.dependency_scan_enabled
        dependency_max_file_bytes = [int]$cfg.dependency_max_file_bytes
        dependency_advisory_file = $depAdvisoryPath
        dependency_advisory_sha256 = [string]$depAdvisoryHash
        dependency_policy_file = $depPolicyPath
        dependency_policy_sha256 = [string]$depPolicyHash
    }
    return (Stable-Hash ($sigObj | ConvertTo-Json -Depth 20 -Compress))
}

function Get-CapabilitySignature([object[]]$deps) {
    $parts = @($deps | Sort-Object component | ForEach-Object { "{0}:{1}:{2}" -f [string]$_.component, [string]$_.status, [string]$_.detail })
    return (Stable-Hash ([string]::Join("|", $parts)))
}

function Build-AnalysisSignature([hashtable]$cfg, [object[]]$deps, [string]$binarySha) {
    $sig = [ordered]@{
        schema = "analysis-signature.v1"
        wrapper_version = $WrapperVersion
        binary_sha256 = [string]$binarySha
        fingerprint_version = $FingerprintVersion
        config_signature = (Get-ConfigSignature $cfg)
        capability_signature = (Get-CapabilitySignature $deps)
        ruleset_version = [string]$cfg.ruleset_version
    }
    return (Stable-Hash ($sig | ConvertTo-Json -Depth 20 -Compress))
}

function To-PathMap($obj) {
    $h = @{}
    if ($null -eq $obj) { return $h }
    if ($obj -is [System.Collections.IDictionary]) {
        foreach ($k in $obj.Keys) {
            $h[(Path-Key ([string]$k))] = $obj[$k]
        }
        return $h
    }
    foreach ($p in $obj.PSObject.Properties) {
        $h[(Path-Key ([string]$p.Name))] = $p.Value
    }
    return $h
}

function Build-CurrentFileIndex([hashtable]$scope) {
    $filesByKey = @{}
    $selectedByKey = @{}
    $hashErrors = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($scope.selected_files | Sort-Object rel_path)) {
        $key = Path-Key ([string]$f.rel_path)
        $mtime = $null
        try { $mtime = (Get-Item -LiteralPath $f.full_path -ErrorAction Stop).LastWriteTimeUtc.ToString("o") } catch { $mtime = $null }
        $sha = $null
        try { $sha = Sha $f.full_path } catch { $sha = $null }
        if ([string]::IsNullOrWhiteSpace([string]$sha)) { $hashErrors.Add([string]$f.rel_path) | Out-Null }
        $filesByKey[$key] = [ordered]@{
            rel_path = [string]$f.rel_path
            sha256 = [string]$sha
            size = [int64]$f.size
            mtime_utc = $mtime
            language = (Read-Prop $f "language")
            extension = (Read-Prop $f "extension")
        }
        $selectedByKey[$key] = $f
    }
    return @{
        files = $filesByKey
        selected_by_key = $selectedByKey
        hash_errors = @($hashErrors | ForEach-Object { $_ })
    }
}

function Resolve-IncrementalPlan([hashtable]$cfg, [hashtable]$scope, [object[]]$deps, [string]$binarySha) {
    $requested = [bool]$cfg.incremental
    $cwd = (Get-Location).Path
    $cachePath = if ($cfg.cache_path) { Resolve-AbsolutePath -path ([string]$cfg.cache_path) -baseDir $cwd } else { Get-DefaultCachePath $scope.root }
    $baseIndexPath = if (-not [string]::IsNullOrWhiteSpace([string]$cfg.diff_from)) { Resolve-AbsolutePath -path ([string]$cfg.diff_from) -baseDir $cwd } else { $cachePath }
    $current = Build-CurrentFileIndex -scope $scope
    $currentFiles = $current.files
    $selectedByKey = $current.selected_by_key
    $hashErrors = @($current.hash_errors)
    $analysisSig = Build-AnalysisSignature -cfg $cfg -deps $deps -binarySha $binarySha
    $configSig = Get-ConfigSignature -cfg $cfg
    $capSig = Get-CapabilitySignature -deps $deps

    $reasons = New-Object System.Collections.Generic.List[string]
    $newKeys = New-Object System.Collections.Generic.List[string]
    $changedKeys = New-Object System.Collections.Generic.List[string]
    $unchangedKeys = New-Object System.Collections.Generic.List[string]
    $deletedKeys = New-Object System.Collections.Generic.List[string]
    $base = $null
    $scanMode = "full"
    $trusted = $false
    $fallbackToFull = $false

    if ($requested) {
        if (-not (Test-Path -LiteralPath $baseIndexPath)) {
            $reasons.Add("base_index_missing") | Out-Null
        }
        else {
            $base = Load-Json $baseIndexPath
            if ($null -eq $base) {
                $reasons.Add("base_index_parse_error") | Out-Null
            }
            else {
                if ([string](Read-Prop $base "schema") -ne "scan-index.v1") { $reasons.Add("base_index_schema_mismatch") | Out-Null }
                $baseRoot = [string](Read-Prop $base "target_root")
                if (-not [string]::IsNullOrWhiteSpace($baseRoot)) {
                    $normBaseRoot = Resolve-AbsolutePath -path $baseRoot -baseDir $scope.root
                    $normCurRoot = Resolve-AbsolutePath -path $scope.root -baseDir $scope.root
                    if ($normBaseRoot -ne $normCurRoot) { $reasons.Add("base_index_target_root_mismatch") | Out-Null }
                }
                $baseSig = [string](Read-Prop $base "analysis_signature")
                if ([string]::IsNullOrWhiteSpace($baseSig)) { $reasons.Add("base_index_missing_analysis_signature") | Out-Null }
                elseif ($baseSig -ne $analysisSig) { $reasons.Add("analysis_signature_mismatch") | Out-Null }
                $baseCompleteness = [string](Read-Prop $base "source_completeness")
                if ($baseCompleteness -eq "failed") { $reasons.Add("base_index_from_failed_scan") | Out-Null }
                $baseContract = [string](Read-Prop $base "selection_contract_version")
                if (-not [string]::IsNullOrWhiteSpace($baseContract) -and $baseContract -ne [string]$scope.selection_contract_version) { $reasons.Add("selection_contract_mismatch") | Out-Null }
            }
        }
        if ($hashErrors.Count -gt 0) { $reasons.Add("current_file_hash_unavailable") | Out-Null }
        if ($reasons.Count -eq 0) {
            $trusted = $true
            $scanMode = "incremental"
        }
        else {
            $fallbackToFull = $true
        }
    }

    $baseFiles = @{}
    if ($base) { $baseFiles = To-PathMap (Read-Prop $base "files") }
    if ($trusted) {
        $currentKeys = @($currentFiles.Keys | Sort-Object)
        $baseKeys = @($baseFiles.Keys | Sort-Object)
        foreach ($k in $currentKeys) {
            if (-not $baseFiles.ContainsKey($k)) {
                $newKeys.Add($k) | Out-Null
                continue
            }
            $curSha = [string](Read-Prop $currentFiles[$k] "sha256")
            $baseSha = [string](Read-Prop $baseFiles[$k] "sha256")
            if (-not [string]::IsNullOrWhiteSpace($curSha) -and $curSha -eq $baseSha) { $unchangedKeys.Add($k) | Out-Null } else { $changedKeys.Add($k) | Out-Null }
        }
        foreach ($k in $baseKeys) {
            if (-not $currentFiles.ContainsKey($k)) { $deletedKeys.Add($k) | Out-Null }
        }
    }

    $analyzedKeys = @()
    if ($trusted) {
        $analyzedKeys = @(@($newKeys | ForEach-Object { $_ }) + @($changedKeys | ForEach-Object { $_ }) | Sort-Object -Unique)
    }
    else {
        $analyzedKeys = @($currentFiles.Keys | Sort-Object)
    }

    $analyzedFiles = New-Object System.Collections.Generic.List[object]
    $analyzedRelPaths = New-Object System.Collections.Generic.List[string]
    foreach ($k in $analyzedKeys) {
        if ($selectedByKey.ContainsKey($k)) {
            $f = $selectedByKey[$k]
            $analyzedFiles.Add($f) | Out-Null
            $analyzedRelPaths.Add([string]$f.rel_path) | Out-Null
        }
    }

    $newRelPaths = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($newKeys | ForEach-Object { $_ } | Sort-Object)) {
        $m = $currentFiles[$k]
        $newRelPaths.Add([string](Read-Prop $m "rel_path")) | Out-Null
    }
    $changedRelPaths = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($changedKeys | ForEach-Object { $_ } | Sort-Object)) {
        $m = $currentFiles[$k]
        $changedRelPaths.Add([string](Read-Prop $m "rel_path")) | Out-Null
    }
    $unchangedRelPaths = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($unchangedKeys | ForEach-Object { $_ } | Sort-Object)) {
        $m = $currentFiles[$k]
        $unchangedRelPaths.Add([string](Read-Prop $m "rel_path")) | Out-Null
    }
    $deletedRelPaths = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($deletedKeys | ForEach-Object { $_ } | Sort-Object)) {
        $m = if ($baseFiles.ContainsKey($k)) { $baseFiles[$k] } else { $null }
        $rp = if ($m) { [string](Read-Prop $m "rel_path") } else { $k }
        if ([string]::IsNullOrWhiteSpace($rp)) { $rp = $k }
        $deletedRelPaths.Add($rp) | Out-Null
    }

    $coverageLimitations = New-Object System.Collections.Generic.List[string]
    if ($scanMode -eq "incremental") {
        if ($unchangedRelPaths.Count -gt 0) { $coverageLimitations.Add("unchanged_files_not_reanalyzed") | Out-Null }
        if ($deletedRelPaths.Count -gt 0) { $coverageLimitations.Add("deleted_files_not_reanalyzed") | Out-Null }
        if ($analyzedFiles.Count -eq 0) { $coverageLimitations.Add("no_changed_or_new_files") | Out-Null }
    }
    if ($fallbackToFull) { $coverageLimitations.Add("incremental_untrusted_fallback_to_full") | Out-Null }

    return @{
        requested = $requested
        scan_mode = $scanMode
        trusted = $trusted
        fallback_to_full = $fallbackToFull
        reasons = @($reasons | ForEach-Object { $_ } | Sort-Object -Unique)
        cache_path = $cachePath
        base_index_path = $baseIndexPath
        file_change_summary = @{
            total_scoped = [int]$scope.selected_count
            analyzed = [int]$analyzedFiles.Count
            new = [int]$newRelPaths.Count
            changed = [int]$changedRelPaths.Count
            unchanged = [int]$unchangedRelPaths.Count
            deleted = [int]$deletedRelPaths.Count
        }
        analyzed_files = @($analyzedFiles | ForEach-Object { $_ })
        analyzed_rel_paths = @($analyzedRelPaths | ForEach-Object { $_ })
        analyzed_keys = @($analyzedKeys)
        new_rel_paths = @($newRelPaths | ForEach-Object { $_ })
        changed_rel_paths = @($changedRelPaths | ForEach-Object { $_ })
        unchanged_rel_paths = @($unchangedRelPaths | ForEach-Object { $_ })
        deleted_rel_paths = @($deletedRelPaths | ForEach-Object { $_ })
        unchanged_keys = @($unchangedKeys | ForEach-Object { $_ })
        deleted_keys = @($deletedKeys | ForEach-Object { $_ })
        coverage_limitations = @($coverageLimitations | ForEach-Object { $_ })
        hash_errors = @($hashErrors)
        current_files = $currentFiles
        analysis_signature = $analysisSig
        config_signature = $configSig
        capability_signature = $capSig
    }
}

function Write-ScanCache([string]$path, [hashtable]$scope, [hashtable]$cfg, [hashtable]$plan, [string]$binarySha, [string]$sourceCompleteness, [bool]$sourceAuthoritative) {
    $orderedFiles = [ordered]@{}
    foreach ($k in @($plan.current_files.Keys | Sort-Object)) {
        $orderedFiles[$k] = $plan.current_files[$k]
    }
    $obj = [ordered]@{
        schema = "scan-index.v1"
        spec_version = $SpecVersion
        generated_at = (Get-Date).ToString("o")
        target_root = $scope.root
        scope_digest = $scope.selected_digest
        selection_contract_version = [string]$scope.selection_contract_version
        analysis_signature = [string]$plan.analysis_signature
        config_signature = [string]$plan.config_signature
        capability_signature = [string]$plan.capability_signature
        wrapper_version = $WrapperVersion
        ruleset_version = [string]$cfg.ruleset_version
        binary_sha256 = [string]$binarySha
        source_completeness = [string]$sourceCompleteness
        source_is_authoritative = [bool]$sourceAuthoritative
        files = $orderedFiles
        summary = @{
            file_count = [int]$scope.selected_count
            language_counts = $scope.selected_by_language
        }
    }
    Ensure-ParentDirectory -filePath $path
    $obj | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Soft-MatchKey([string]$ruleId, [string]$file, [int]$line, [string]$title) {
    $normTitle = [string]$title
    if ($null -eq $normTitle) { $normTitle = "" }
    $normTitle = $normTitle.ToLowerInvariant()
    $seed = [string]::Join("|", @(
            "rule=$([string]$ruleId)",
            "file=$(Path-Key $file)",
            "line=$line",
            "title=$normTitle"
        ))
    return (Stable-Hash $seed)
}

function Apply-BaselineSuppression([object[]]$findings, $baselineObj, [bool]$allowSoftMatch) {
    $fpSet = New-Object System.Collections.Generic.HashSet[string]
    $idSet = New-Object System.Collections.Generic.HashSet[string]
    $softSet = New-Object System.Collections.Generic.HashSet[string]
    $entries = New-Object System.Collections.Generic.List[object]
    $matchedFp = New-Object System.Collections.Generic.HashSet[string]
    $matchedId = New-Object System.Collections.Generic.HashSet[string]
    $matchedSoft = New-Object System.Collections.Generic.HashSet[string]
    $suppressedByFp = 0
    $suppressedById = 0
    $suppressedBySoft = 0

    if ($baselineObj -and $baselineObj.entries) {
        foreach ($e in @($baselineObj.entries)) {
            $efp = [string](Read-Prop $e "fingerprint")
            $eid = [string](Read-Prop $e "finding_id")
            if (-not [string]::IsNullOrWhiteSpace($efp)) { [void]$fpSet.Add($efp) }
            if (-not [string]::IsNullOrWhiteSpace($eid)) { [void]$idSet.Add($eid) }
            $loc = Read-Prop $e "location"
            $file = $null
            $line = 1
            if ($loc) {
                $file = [string](Read-Prop $loc "file")
                $lineVal = Read-Prop $loc "line"
                if ($lineVal) { $line = [int]$lineVal }
            }
            $rule = [string](Read-Prop $e "rule_id")
            $title = [string](Read-Prop $e "title")
            $soft = $null
            if (-not [string]::IsNullOrWhiteSpace($rule) -and -not [string]::IsNullOrWhiteSpace($file)) {
                $soft = Soft-MatchKey -ruleId $rule -file $file -line $line -title $title
                if ($allowSoftMatch) { [void]$softSet.Add($soft) }
            }
            $entries.Add([ordered]@{
                    fingerprint = $efp
                    finding_id = $eid
                    rule_id = $rule
                    title = $title
                    file = $file
                    file_key = (Path-Key $file)
                    line = $line
                    soft_key = $soft
                }) | Out-Null
        }
    }
    if ($baselineObj -and $baselineObj.fingerprints) {
        foreach ($fp in @($baselineObj.fingerprints)) {
            $v = [string]$fp
            if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$fpSet.Add($v) }
        }
    }

    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($findings)) {
        $fp = [string](Finding-Fingerprint $f)
        $fid = [string](Read-Prop $f "finding_id")
        $matched = $false
        if (-not [string]::IsNullOrWhiteSpace($fp) -and $fpSet.Contains($fp)) {
            $matched = $true
            $suppressedByFp++
            [void]$matchedFp.Add($fp)
        }
        elseif (-not [string]::IsNullOrWhiteSpace($fid) -and $idSet.Contains($fid)) {
            $matched = $true
            $suppressedById++
            [void]$matchedId.Add($fid)
        }
        elseif ($allowSoftMatch) {
            $loc = Read-Prop $f "location"
            $file = [string](Read-Prop $loc "file")
            $line = 1
            $lineVal = Read-Prop $loc "line"
            if ($lineVal) { $line = [int]$lineVal }
            $rule = [string](Read-Prop $f "rule_id")
            $title = [string](Read-Prop $f "title")
            if (-not [string]::IsNullOrWhiteSpace($rule) -and -not [string]::IsNullOrWhiteSpace($file)) {
                $sk = Soft-MatchKey -ruleId $rule -file $file -line $line -title $title
                if ($softSet.Contains($sk)) {
                    $matched = $true
                    $suppressedBySoft++
                    [void]$matchedSoft.Add($sk)
                }
            }
        }
        if (-not $matched) { $keep.Add($f) | Out-Null }
    }

    return @{
        findings = @($keep | ForEach-Object { $_ })
        suppressed_total = ($suppressedByFp + $suppressedById + $suppressedBySoft)
        suppressed_by = @{
            fingerprint = $suppressedByFp
            finding_id = $suppressedById
            soft_match = $suppressedBySoft
        }
        entries = @($entries | ForEach-Object { $_ })
        matched_fingerprints = @($matchedFp | ForEach-Object { $_ })
        matched_finding_ids = @($matchedId | ForEach-Object { $_ })
        matched_soft_keys = @($matchedSoft | ForEach-Object { $_ })
        soft_match_enabled = $allowSoftMatch
    }
}

function Get-BaselineIncrementalStatus([hashtable]$baselineResult, [hashtable]$incrementalPlan) {
    $entries = @($baselineResult.entries)
    if ($entries.Count -eq 0) {
        return @{
            status = "unknown_no_entries"
            reevaluated_entries = 0
            resolved_candidates = 0
            still_present = 0
            not_reevaluated = 0
            resolved_by_deleted_file = 0
            out_of_scope = 0
        }
    }

    $analyzed = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in @($incrementalPlan.analyzed_keys)) { if ($k) { [void]$analyzed.Add([string]$k) } }
    $unchanged = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in @($incrementalPlan.unchanged_keys)) { if ($k) { [void]$unchanged.Add([string]$k) } }
    $deleted = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in @($incrementalPlan.deleted_keys)) { if ($k) { [void]$deleted.Add([string]$k) } }
    $matchedFp = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in @($baselineResult.matched_fingerprints)) { if ($x) { [void]$matchedFp.Add([string]$x) } }
    $matchedId = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in @($baselineResult.matched_finding_ids)) { if ($x) { [void]$matchedId.Add([string]$x) } }
    $matchedSoft = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in @($baselineResult.matched_soft_keys)) { if ($x) { [void]$matchedSoft.Add([string]$x) } }

    $reevaluated = 0
    $resolvedCandidates = 0
    $stillPresent = 0
    $notReevaluated = 0
    $resolvedDeleted = 0
    $outOfScope = 0

    foreach ($e in $entries) {
        $k = [string](Read-Prop $e "file_key")
        if ([string]::IsNullOrWhiteSpace($k)) { $outOfScope++; continue }
        if ($analyzed.Contains($k)) {
            $reevaluated++
            $isPresent = $false
            $efp = [string](Read-Prop $e "fingerprint")
            $eid = [string](Read-Prop $e "finding_id")
            $esk = [string](Read-Prop $e "soft_key")
            if (-not [string]::IsNullOrWhiteSpace($efp) -and $matchedFp.Contains($efp)) { $isPresent = $true }
            elseif (-not [string]::IsNullOrWhiteSpace($eid) -and $matchedId.Contains($eid)) { $isPresent = $true }
            elseif ($baselineResult.soft_match_enabled -and -not [string]::IsNullOrWhiteSpace($esk) -and $matchedSoft.Contains($esk)) { $isPresent = $true }
            if ($isPresent) { $stillPresent++ } else { $resolvedCandidates++ }
        }
        elseif ($unchanged.Contains($k)) {
            $notReevaluated++
        }
        elseif ($deleted.Contains($k)) {
            $resolvedDeleted++
        }
        else {
            $outOfScope++
        }
    }

    return @{
        status = "estimated"
        reevaluated_entries = $reevaluated
        resolved_candidates = $resolvedCandidates
        still_present = $stillPresent
        not_reevaluated = $notReevaluated
        resolved_by_deleted_file = $resolvedDeleted
        out_of_scope = $outOfScope
    }
}

function Apply-FindingPolicyPack([object[]]$findings, [hashtable]$cfg) {
    $enabledCategories = @()
    if ($cfg.ContainsKey("policy_enabled_categories")) { $enabledCategories = @($cfg["policy_enabled_categories"]) }
    $disabledCategories = @()
    if ($cfg.ContainsKey("policy_disabled_categories")) { $disabledCategories = @($cfg["policy_disabled_categories"]) }
    $severityOverrides = @{}
    if ($cfg.ContainsKey("policy_severity_overrides")) { $severityOverrides = $cfg["policy_severity_overrides"] }
    $ruleOverrides = @{}
    if ($cfg.ContainsKey("policy_rule_overrides")) { $ruleOverrides = $cfg["policy_rule_overrides"] }

    $active = ($enabledCategories.Count -gt 0 -or $disabledCategories.Count -gt 0 -or $severityOverrides.Count -gt 0 -or $ruleOverrides.Count -gt 0)
    if (-not $active) {
        return @{
            findings = @($findings)
            diagnostics = @{
                status = "not_configured"
                findings_in = @($findings).Count
                findings_out = @($findings).Count
                suppressed_total = 0
                suppressed_by_category = @{}
                suppressed_by_rule = @{}
                overrides_applied = 0
                severity_overrides_applied = 0
                confidence_overrides_applied = 0
            }
        }
    }

    $enabledSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($c in @($enabledCategories)) { if (-not [string]::IsNullOrWhiteSpace([string]$c)) { [void]$enabledSet.Add(([string]$c).ToLowerInvariant()) } }
    $disabledSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($c in @($disabledCategories)) { if (-not [string]::IsNullOrWhiteSpace([string]$c)) { [void]$disabledSet.Add(([string]$c).ToLowerInvariant()) } }

    $keep = New-Object System.Collections.Generic.List[object]
    $suppressedByCategory = @{}
    $suppressedByRule = @{}
    $suppressedTotal = 0
    $overridesApplied = 0
    $sevOverridesApplied = 0
    $confOverridesApplied = 0

    foreach ($f in @($findings)) {
        $copy = To-Hash $f
        $ruleId = [string](Read-Prop $copy "rule_id")
        $ruleIdKey = $ruleId.ToLowerInvariant()
        $category = [string](Read-Prop $copy "category")
        if ([string]::IsNullOrWhiteSpace($category)) {
            if ($ruleIdKey.StartsWith("secret.")) { $category = "secrets" }
            elseif ($ruleIdKey.StartsWith("deps.")) { $category = "dependency" }
        }
        $categoryKey = if ([string]::IsNullOrWhiteSpace($category)) { "" } else { $category.ToLowerInvariant() }

        $suppressed = $false
        if ($enabledSet.Count -gt 0) {
            if (-not [string]::IsNullOrWhiteSpace($categoryKey) -and -not $enabledSet.Contains($categoryKey)) {
                $suppressed = $true
                if (-not $suppressedByCategory.ContainsKey($categoryKey)) { $suppressedByCategory[$categoryKey] = 0 }
                $suppressedByCategory[$categoryKey]++
            }
        }
        if (-not $suppressed -and $disabledSet.Contains($categoryKey)) {
            $suppressed = $true
            if (-not $suppressedByCategory.ContainsKey($categoryKey)) { $suppressedByCategory[$categoryKey] = 0 }
            $suppressedByCategory[$categoryKey]++
        }

        $ruleOverride = $null
        if ($ruleOverrides.ContainsKey($ruleIdKey)) { $ruleOverride = $ruleOverrides[$ruleIdKey] }
        if (-not $suppressed -and $ruleOverride) {
            $enabledOverride = Read-Prop $ruleOverride "enabled"
            if ($null -ne $enabledOverride -and -not [bool]$enabledOverride) {
                $suppressed = $true
                if (-not $suppressedByRule.ContainsKey($ruleId)) { $suppressedByRule[$ruleId] = 0 }
                $suppressedByRule[$ruleId]++
            }
        }
        if ($suppressed) { $suppressedTotal++; continue }

        $newSeverity = $null
        $sevFromRule = $null
        if ($ruleOverride) { $sevFromRule = Read-Prop $ruleOverride "severity" }
        if ($sevFromRule) { $newSeverity = Sev ([string]$sevFromRule) }
        elseif ($severityOverrides.ContainsKey($ruleIdKey)) { $newSeverity = Sev ([string]$severityOverrides[$ruleIdKey]) }
        elseif (-not [string]::IsNullOrWhiteSpace($categoryKey) -and $severityOverrides.ContainsKey(("category:{0}" -f $categoryKey))) { $newSeverity = Sev ([string]$severityOverrides[("category:{0}" -f $categoryKey)]) }
        if (-not [string]::IsNullOrWhiteSpace($newSeverity)) {
            $copy["severity"] = $newSeverity
            $copy["normalized_severity"] = $newSeverity
            $overridesApplied++
            $sevOverridesApplied++
        }

        $origConfidence = [double](Read-Prop $copy "confidence")
        $confOverride = $null
        if ($ruleOverride) { $confOverride = Read-Prop $ruleOverride "confidence_override" }
        $confOffset = $null
        if ($ruleOverride) { $confOffset = Read-Prop $ruleOverride "confidence_offset" }
        $newConfidence = $origConfidence
        $confidenceChanged = $false
        if ($null -ne $confOverride) {
            $newConfidence = Clamp-ConfidenceScore ([double]$confOverride)
            $confidenceChanged = $true
        }
        if ($null -ne $confOffset) {
            $newConfidence = Clamp-ConfidenceScore ($newConfidence + [double]$confOffset)
            $confidenceChanged = $true
        }
        if ($confidenceChanged) {
            $copy["confidence"] = $newConfidence
            $copy["confidence_level"] = Confidence-LevelFromScore $newConfidence
            $reason = [string](Read-Prop $copy "confidence_reason")
            if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "policy_pack_override" } else { $reason = ("{0},policy_pack_override" -f $reason) }
            $copy["confidence_reason"] = $reason
            $rat = To-Hash (Read-Prop $copy "confidence_rationale")
            $rat["policy_pack_adjustment"] = @{
                original_confidence = $origConfidence
                final_confidence = $newConfidence
                rule_id = $ruleId
                override_id = (Read-Prop $ruleOverride "id")
                reason = (Read-Prop $ruleOverride "reason")
            }
            $copy["confidence_rationale"] = $rat
            $overridesApplied++
            $confOverridesApplied++
        }

        if ($ruleOverride) {
            $meta = To-Hash (Read-Prop $copy "metadata")
            if ($meta.Count -eq 0) { $meta = @{} }
            $meta["policy_override"] = @{
                rule_id = $ruleId
                id = (Read-Prop $ruleOverride "id")
                reason = (Read-Prop $ruleOverride "reason")
            }
            $copy["metadata"] = $meta
        }

        $keep.Add($copy) | Out-Null
    }

    $keptFindings = @($keep.ToArray())
    return @{
        findings = $keptFindings
        diagnostics = @{
            status = "applied"
            findings_in = @($findings).Count
            findings_out = $keptFindings.Count
            suppressed_total = $suppressedTotal
            suppressed_by_category = $suppressedByCategory
            suppressed_by_rule = $suppressedByRule
            overrides_applied = $overridesApplied
            severity_overrides_applied = $sevOverridesApplied
            confidence_overrides_applied = $confOverridesApplied
            enabled_categories = @($enabledSet | ForEach-Object { $_ } | Sort-Object)
            disabled_categories = @($disabledSet | ForEach-Object { $_ } | Sort-Object)
        }
    }
}

function Finding-PathKey($f) {
    $loc = Read-Prop $f "location"
    if ($null -eq $loc) { return "" }
    $file = [string](Read-Prop $loc "file")
    return (Path-Key $file)
}

function Select-PolicyInputSet([object[]]$allFindings, [object[]]$netNewFindings, [hashtable]$cfg, [string]$scanMode, [hashtable]$incrementalPlan, [bool]$baselineAvailable) {
    $requested = [string]$cfg.policy_scope
    $effective = $requested
    $selectionReasons = New-Object System.Collections.Generic.List[string]
    $selected = @()

    switch ($requested) {
        "all_findings" {
            $selected = @($allFindings)
        }
        "incremental_delta" {
            if ($scanMode -eq "incremental" -and [bool]$incrementalPlan.trusted) {
                $selected = @($allFindings)
            }
            elseif ([bool]$cfg.require_trusted_incremental) {
                $selected = @()
                $selectionReasons.Add("incremental_delta_unavailable") | Out-Null
            }
            else {
                $effective = "all_findings"
                $selected = @($allFindings)
                $selectionReasons.Add("incremental_delta_fallback_all_findings") | Out-Null
            }
        }
        "net_new_vs_baseline" {
            if ($baselineAvailable) {
                $selected = @($netNewFindings)
            }
            elseif ([bool]$cfg.baseline_required) {
                $selected = @()
                $selectionReasons.Add("baseline_missing_required_for_scope") | Out-Null
            }
            else {
                $effective = "all_findings"
                $selected = @($allFindings)
                $selectionReasons.Add("baseline_missing_fallback_all_findings") | Out-Null
            }
        }
        default {
            $effective = "all_findings"
            $selected = @($allFindings)
            $selectionReasons.Add("policy_scope_invalid_fallback_all_findings") | Out-Null
        }
    }

    return @{
        scope_requested = $requested
        scope_effective = $effective
        selection_reasons = @($selectionReasons | ForEach-Object { $_ })
        findings = @(Sort-Findings $selected)
        input_findings_total = @($allFindings).Count
        evaluated_findings_total = @($selected).Count
    }
}

function Build-PolicyDecision([hashtable]$cfg, [hashtable]$coverageState, [hashtable]$policyInput, [int]$totalFindings) {
    $reasonCodes = New-Object System.Collections.Generic.List[string]
    $steps = New-Object System.Collections.Generic.List[object]
    $blockedReasons = New-Object System.Collections.Generic.List[string]

    $steps.Add([ordered]@{
            stage = "input_selection"
            scope_requested = $policyInput.scope_requested
            scope_effective = $policyInput.scope_effective
            input_findings_total = [int]$policyInput.input_findings_total
            evaluated_findings_total = [int]$policyInput.evaluated_findings_total
            selection_reasons = @($policyInput.selection_reasons)
        }) | Out-Null

    if ([bool]$cfg.require_authoritative -and -not [bool]$coverageState.is_authoritative) { $blockedReasons.Add("coverage_authoritative_required") | Out-Null }
    if ([bool]$cfg.require_trusted_incremental -and [bool]$coverageState.incremental_requested -and -not [bool]$coverageState.incremental_trusted) { $blockedReasons.Add("coverage_incremental_trust_required") | Out-Null }
    if ([bool]$cfg.baseline_required -and [string]$cfg.policy_scope -eq "net_new_vs_baseline" -and -not [bool]$coverageState.baseline_available) { $blockedReasons.Add("baseline_required_missing") | Out-Null }
    foreach ($sr in @($policyInput.selection_reasons)) {
        if ($sr -eq "incremental_delta_unavailable" -or $sr -eq "baseline_missing_required_for_scope") { $blockedReasons.Add([string]$sr) | Out-Null }
    }
    $steps.Add([ordered]@{
            stage = "coverage_validation"
            is_authoritative = [bool]$coverageState.is_authoritative
            completeness = [string]$coverageState.completeness
            incremental_requested = [bool]$coverageState.incremental_requested
            incremental_trusted = [bool]$coverageState.incremental_trusted
            baseline_available = [bool]$coverageState.baseline_available
            blocked_conditions = @($blockedReasons | ForEach-Object { $_ })
        }) | Out-Null

    $decision = "pass"
    $exitCode = $ExitCodes.Success
    $decisionKind = "pass"
    $breachFindings = @()
    if ($blockedReasons.Count -gt 0) {
        $decision = "blocked"
        foreach ($r in @($blockedReasons | ForEach-Object { $_ })) { $reasonCodes.Add([string]$r) | Out-Null }
        $exitCode = $ExitCodes.PartialResults
        $decisionKind = "coverage_blocked"
    }
    else {
        $thr = $SeverityOrder[(Sev $cfg.fail_on)]
        $minConfLevel = $null
        $minConfLevelRank = 0
        if ($null -ne $cfg.min_confidence_level -and -not [string]::IsNullOrWhiteSpace([string]$cfg.min_confidence_level)) {
            $minConfLevel = ([string]$cfg.min_confidence_level).ToLowerInvariant()
            if ($ConfidenceLevelOrder.ContainsKey($minConfLevel)) { $minConfLevelRank = [int]$ConfidenceLevelOrder[$minConfLevel] }
        }
        foreach ($f in @($policyInput.findings)) {
            $sevRank = $SeverityOrder[(Sev ([string](Read-Prop $f "severity")))]
            $conf = [double](Read-Prop $f "confidence")
            $confLevel = [string](Read-Prop $f "confidence_level")
            if ([string]::IsNullOrWhiteSpace($confLevel)) { $confLevel = Confidence-LevelFromScore $conf }
            $confLevelRank = if ($ConfidenceLevelOrder.ContainsKey($confLevel)) { [int]$ConfidenceLevelOrder[$confLevel] } else { 0 }
            $confLevelOk = if ($minConfLevelRank -gt 0) { $confLevelRank -ge $minConfLevelRank } else { $true }
            if ($sevRank -ge $thr -and $conf -ge [double]$cfg.min_confidence -and $confLevelOk) { $breachFindings += $f }
        }
        if (@($breachFindings).Count -gt 0) {
            $decision = "fail"
            $decisionKind = "policy_breach"
            $reasonCodes.Add("threshold_breach") | Out-Null
            $exitCode = $ExitCodes.PolicyBreach
        }
        elseif (@($policyInput.findings).Count -gt 0 -and -not [bool]$cfg.exit_zero_on_findings) {
            $decision = "fail"
            $decisionKind = "legacy_findings_present"
            $reasonCodes.Add("legacy_findings_present") | Out-Null
            $exitCode = $ExitCodes.FindingsPresent
        }
        else {
            $decision = "pass"
            $decisionKind = "no_breach"
            $reasonCodes.Add("pass") | Out-Null
            $exitCode = $ExitCodes.Success
        }
    }

    $maxSev = $null
    $maxConf = 0.0
    if (@($breachFindings).Count -gt 0) {
        $maxRank = -1
        foreach ($f in @($breachFindings)) {
            $sev = Sev ([string](Read-Prop $f "severity"))
            $rank = $SeverityOrder[$sev]
            if ($rank -gt $maxRank) { $maxRank = $rank; $maxSev = $sev }
            $conf = [double](Read-Prop $f "confidence")
            if ($conf -gt $maxConf) { $maxConf = $conf }
        }
    }
    $steps.Add([ordered]@{
            stage = "policy_evaluation"
            fail_on = [string]$cfg.fail_on
            min_confidence = [double]$cfg.min_confidence
            min_confidence_level = (Read-Prop $cfg "min_confidence_level")
            breach_count = @($breachFindings).Count
            decision = $decision
            decision_kind = $decisionKind
        }) | Out-Null

    return @{
        contract_version = "2.0"
        decision = $decision
        decision_kind = $decisionKind
        reason_code = [string]$reasonCodes[0]
        reason_codes = @($reasonCodes | ForEach-Object { $_ })
        scope_requested = $policyInput.scope_requested
        scope_effective = $policyInput.scope_effective
        input_findings_total = [int]$policyInput.input_findings_total
        evaluated_findings_total = [int]$policyInput.evaluated_findings_total
        threshold = @{
            fail_on = [string]$cfg.fail_on
            min_confidence = [double]$cfg.min_confidence
            min_confidence_level = (Read-Prop $cfg "min_confidence_level")
            exit_zero_on_findings = [bool]$cfg.exit_zero_on_findings
        }
        breach_summary = @{
            breach_count = @($breachFindings).Count
            max_severity = $maxSev
            max_confidence = [math]::Round($maxConf, 3)
            sample_finding_ids = @(@($breachFindings | ForEach-Object { [string](Read-Prop $_ "finding_id") }) | Select-Object -First 5)
        }
        coverage = @{
            completeness = [string]$coverageState.completeness
            is_authoritative = [bool]$coverageState.is_authoritative
            incremental_requested = [bool]$coverageState.incremental_requested
            incremental_trusted = [bool]$coverageState.incremental_trusted
            baseline_available = [bool]$coverageState.baseline_available
            blocked_conditions = @($blockedReasons | ForEach-Object { $_ })
        }
        profile = @{
            requested = [string]$cfg.policy_profile
            applied = [string](Read-Prop $cfg "applied_policy_profile")
        }
        precedence = @("input_selection", "coverage_validation", "policy_evaluation")
        reasoning = @($steps | ForEach-Object { $_ })
        exit_code = [int]$exitCode
        total_findings_in_report = [int]$totalFindings
    }
}

function Scan([hashtable]$cfg) {
    $exe = Join-Path $PSScriptRoot "CodeSentinel.exe"
    if (-not (Test-Path -LiteralPath $exe)) { Exit-Err (New-Err "DEPENDENCY_MISSING_EXE" "CodeSentinel.exe not found." @{ expected_path = $exe }) $ExitCodes.DependencyError $cfg.error_format }
    if (-not (Test-Path -LiteralPath $Target)) { Exit-Err (New-Err "USAGE_TARGET_NOT_FOUND" "Target path does not exist." @{ target = $Target }) $ExitCodes.UsageError $cfg.error_format }

    $scope = Get-ScopedFiles -targetPath $Target -cfg $cfg
    $resolvedTarget = (Resolve-Path -LiteralPath $Target).Path
    $deps = @(Get-Dependencies)
    $binarySha = (Sha $exe)
    $incrementalPlan = Resolve-IncrementalPlan -cfg $cfg -scope $scope -deps $deps -binarySha $binarySha
    $scanMode = [string]$incrementalPlan.scan_mode
    $analysisScope = @{} + $scope
    $analysisScope["selected_files"] = @($incrementalPlan.analyzed_files | ForEach-Object { $_ })
    $analysisScope["selected_count"] = @($analysisScope.selected_files).Count

    $attempts = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    $degradations = New-Object System.Collections.Generic.List[object]
    $enabledFeatures = New-Object System.Collections.Generic.List[string]
    $analyzerStages = New-Object System.Collections.Generic.List[object]
    $order = switch ($cfg.analyzer_mode) { "local-only" { @("local") }; "ai-only" { @("ai") }; default { @("local", "ai") } }
    $authoritativeAnalyzer = if ($cfg.analyzer_mode -eq "ai-only") { "ai" } else { "local" }
    $localOk = $false
    $aiOk = $false
    $primaryOk = $false
    $findings = @()
    $stagePath = $null
    $scanInput = $resolvedTarget
    $primaryEligibleCount = 0

    if ($analysisScope.is_directory) {
        $binaryFiles = @(Get-BinaryFiles $analysisScope.selected_files)
        $primaryEligibleCount = $binaryFiles.Count
        if ($binaryFiles.Count -eq 0) {
            $attempts.Add(@{ analyzer = "primary"; status = "skipped"; reason = "no_supported_source_files_after_scope_filter" }) | Out-Null
            if ($scanMode -eq "full") { $degradations.Add("primary_analyzer_skipped_no_supported_files") | Out-Null }
            $primaryOk = $true
        }
        else {
            $stagePath = Stage-ScopedFiles -root $analysisScope.root -files $binaryFiles
            $scanInput = $stagePath
        }
    }
    else {
        $binaryFiles = @(Get-BinaryFiles $analysisScope.selected_files)
        $primaryEligibleCount = $binaryFiles.Count
        if ($primaryEligibleCount -eq 0) {
            $attempts.Add(@{ analyzer = "primary"; status = "skipped"; reason = "target_file_not_supported_by_primary_analyzer" }) | Out-Null
            if ($scanMode -eq "full") { $degradations.Add("primary_analyzer_skipped_no_supported_files") | Out-Null }
            $primaryOk = $true
        }
    }

    try {
        if (-not $primaryOk) {
            foreach ($a in $order) {
                if ($a -eq "ai" -and [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("OPENAI_API_KEY"))) {
                    $attempts.Add(@{ analyzer = "ai"; status = "skipped"; reason = "OPENAI_API_KEY missing" }) | Out-Null
                    $degradations.Add("ai_unavailable_openai_key_missing") | Out-Null
                    if ($cfg.fallback_policy -eq "fail-closed" -or $cfg.analyzer_mode -eq "ai-only") {
                        $errors.Add((New-Err "DEPENDENCY_MISSING_OPENAI_API_KEY" "AI analyzer requested but OPENAI_API_KEY is missing.")) | Out-Null
                        break
                    }
                    else { continue }
                }

                $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("codesentinel-raw-{0}.json" -f [guid]::NewGuid().ToString("N"))
                $args = @("$scanInput", "--analyzer", $a, "--format", "json", "--output", $tmp, "--severity", $cfg.min_severity)
                if ($cfg.progress) { $args += "--progress" }
                try {
                    $run = & $exe @args 2>&1
                    $code = $LASTEXITCODE
                    if ($code -eq 0) {
                        $raw = Parse-RawFindings $tmp
                        $i = 1
                        $norm = @()
                        foreach ($rf in $raw) { $norm += (Normalize-Finding $rf $i ("primary:{0}" -f $a)); $i++ }
                        if ($a -eq "local") { $localOk = $true }
                        if ($a -eq "ai") { $aiOk = $true }
                        $findings = $norm
                        $primaryOk = $true
                        $attempts.Add(@{ analyzer = $a; status = "ok"; exit_code = $code }) | Out-Null
                        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
                        break
                    }
                    else {
                        $attempts.Add(@{ analyzer = $a; status = "failed"; exit_code = $code }) | Out-Null
                        $errors.Add((New-Err "ANALYZER_RUNTIME_FAILURE" "Analyzer run failed." @{ analyzer = $a; exit_code = $code; stderr = [string]::Join("`n", @($run)) })) | Out-Null
                        if ($cfg.fallback_policy -eq "fail-closed") { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }; break }
                    }
                }
                catch {
                    $attempts.Add(@{ analyzer = $a; status = "failed"; exit_code = $null }) | Out-Null
                    $errors.Add((New-Err "ANALYZER_EXECUTION_EXCEPTION" "Failed to execute analyzer process." @{ analyzer = $a; exception = $_.Exception.Message })) | Out-Null
                    if ($cfg.fallback_policy -eq "fail-closed") { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }; break }
                }
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    finally {
        if ($stagePath -and (Test-Path -LiteralPath $stagePath)) { Remove-Item -LiteralPath $stagePath -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $extraRaw = @()
    if (Is-SecretScanEnabled -cfg $cfg) {
        $enabledFeatures.Add("secrets") | Out-Null
        $secretStage = Invoke-SecretAnalyzerStage -scope $analysisScope -cfg $cfg
        $extraRaw += @($secretStage.findings)
        if ($secretStage.diagnostics) { $analyzerStages.Add($secretStage.diagnostics) | Out-Null }
    }
    else {
        $analyzerStages.Add(@{ stage = "secrets"; analyzer = "aux:secrets"; status = "skipped"; reason = "disabled" }) | Out-Null
    }
    if (Is-DependencyScanEnabled -cfg $cfg) {
        $enabledFeatures.Add("deps") | Out-Null
        $depStage = Invoke-DependencyAnalyzerStage -scope $analysisScope -cfg $cfg
        $extraRaw += @($depStage.findings)
        if ($depStage.diagnostics) { $analyzerStages.Add($depStage.diagnostics) | Out-Null }
    }
    else {
        $analyzerStages.Add(@{ stage = "dependencies"; analyzer = "aux:deps"; status = "skipped"; reason = "disabled" }) | Out-Null
    }
    if ($extraRaw.Count -gt 0) {
        $idx = $findings.Count + 1
        foreach ($x in $extraRaw) {
            $findings += @(Normalize-Finding $x $idx)
            $idx++
        }
    }

    $findings = @(Dedup-Findings $findings)
    $findings = @(Sort-Findings $findings)
    $policyPackApply = Apply-FindingPolicyPack -findings $findings -cfg $cfg
    $findings = @(Sort-Findings @($policyPackApply.findings))
    $allFindings = @($findings)
    $policyPackDiag = $policyPackApply.diagnostics

    if (-not $primaryOk -and $cfg.fallback_policy -eq "fail-open" -and $findings.Count -gt 0) {
        $degradations.Add("primary_analyzer_failed_auxiliary_findings_used") | Out-Null
        $primaryOk = $true
    }

    $authoritativeOk = if ($authoritativeAnalyzer -eq "ai") { $aiOk } else { $localOk }
    $authoritativeSatisfiedByDelta = ($scanMode -eq "incremental" -and $primaryEligibleCount -eq 0)
    $completeness = "failed"
    $completenessReasons = New-Object System.Collections.Generic.List[string]
    if ($authoritativeOk -or $authoritativeSatisfiedByDelta) {
        $completeness = "full"
    }
    elseif ($primaryEligibleCount -eq 0 -and $analysisScope.selected_count -gt 0) {
        $completeness = "partial"
        if ($scanMode -eq "incremental") { $completenessReasons.Add("no_primary_eligible_files_in_incremental_delta") | Out-Null } else { $completenessReasons.Add("no_primary_eligible_files_in_scope") | Out-Null }
    }
    elseif ($primaryOk -and $findings.Count -gt 0) {
        $completeness = "partial"
        $completenessReasons.Add("authoritative_analyzer_unavailable_or_failed") | Out-Null
    }
    if ($degradations.Count -gt 0) {
        foreach ($d in @($degradations | ForEach-Object { $_ })) {
            if (-not $completenessReasons.Contains([string]$d)) { $completenessReasons.Add([string]$d) | Out-Null }
        }
    }
    $coverageLimitations = New-Object System.Collections.Generic.List[string]
    foreach ($l in @($incrementalPlan.coverage_limitations)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$l) -and -not $coverageLimitations.Contains([string]$l)) { $coverageLimitations.Add([string]$l) | Out-Null }
    }
    if ($scanMode -eq "incremental" -and $completeness -ne "full" -and -not $coverageLimitations.Contains("incremental_authoritative_coverage_incomplete")) {
        $coverageLimitations.Add("incremental_authoritative_coverage_incomplete") | Out-Null
    }

    $incrementalDiagnostics = @{
        requested = [bool]$cfg.incremental
        scan_mode = $scanMode
        trusted = [bool]$incrementalPlan.trusted
        fallback_to_full = [bool]$incrementalPlan.fallback_to_full
        reasons = @($incrementalPlan.reasons)
        base_index = $incrementalPlan.base_index_path
        cache_path = $incrementalPlan.cache_path
        file_change_summary = $incrementalPlan.file_change_summary
        coverage_limitations = @($coverageLimitations | ForEach-Object { $_ })
        hash_errors = @($incrementalPlan.hash_errors)
        cache_write = @{
            attempted = $false
            written = $false
            path = $incrementalPlan.cache_path
            reason = "scan_failed"
        }
        file_sets = @{
            analyzed = @($incrementalPlan.analyzed_rel_paths)
            new = @($incrementalPlan.new_rel_paths)
            changed = @($incrementalPlan.changed_rel_paths)
            unchanged = @($incrementalPlan.unchanged_rel_paths)
            deleted = @($incrementalPlan.deleted_rel_paths)
        }
    }

    if (-not $primaryOk) {
        $attemptArray = @($attempts | ForEach-Object { $_ })
        $degradationArray = @($degradations | ForEach-Object { $_ })
        $errorArray = @($errors | ForEach-Object { $_ })
        $enabledArray = @($enabledFeatures | ForEach-Object { $_ })
        $stageArray = @($analyzerStages | ForEach-Object { $_ })
        $failedConfCounts = @{ high = 0; medium = 0; low = 0 }
        foreach ($ff in @($allFindings)) {
            $lvl = [string](Read-Prop $ff "confidence_level")
            if ([string]::IsNullOrWhiteSpace($lvl)) { $lvl = Confidence-LevelFromScore ([double](Read-Prop $ff "confidence")) }
            if (-not $failedConfCounts.ContainsKey($lvl)) { $failedConfCounts[$lvl] = 0 }
            $failedConfCounts[$lvl]++
        }
        $r = @{}
        $r["report_version"] = $ReportVersion
        $r["spec_version"] = $SpecVersion
        $r["generated_at"] = (Get-Date).ToString("o")
        $r["metadata"] = @{
            tool = @{ name = "CodeSentinel Wrapper"; version = $WrapperVersion }
            target = $resolvedTarget
            confidence_model_version = $ConfidenceModelVersion
            enabled_auxiliary_analyzers = $enabledArray
        }
        $r["scan_summary"] = @{
            status = "failed"
            scan_mode = $scanMode
            completeness = "failed"
            completeness_reasons = @($completenessReasons | ForEach-Object { $_ })
            file_change_summary = $incrementalPlan.file_change_summary
            coverage_limitations = @($coverageLimitations | ForEach-Object { $_ })
            findings_total = $allFindings.Count
            confidence_counts = $failedConfCounts
            exit_reason = "runtime_error"
            policy = @{
                breach = $false
                fail_on = $cfg.fail_on
                min_confidence = $cfg.min_confidence
                min_confidence_level = (Read-Prop $cfg "min_confidence_level")
                is_authoritative = $false
                scope = [string]$cfg.policy_scope
                decision = "blocked"
                input_findings_total = $allFindings.Count
                evaluated_findings_total = 0
            }
        }
        $r["diagnostics"] = @{
            dependencies = @($deps)
            analyzer_attempts = $attemptArray
            analyzer_stages = $stageArray
            policy_pack = $policyPackDiag
            degradations = $degradationArray
            incremental = $incrementalDiagnostics
            scope = (Build-ScopeDiagnostics -scope $scope -analysisScope $analysisScope -cfg $cfg)
        }
        $r["effective_config"] = $cfg
        $r["provenance"] = @{ run_id = [guid]::NewGuid().ToString(); timestamp = (Get-Date).ToString("o"); binary_sha256 = $binarySha; ruleset_version = $cfg.ruleset_version; confidence_model_version = $ConfidenceModelVersion }
        $r["policy_decision"] = @{
            contract_version = "2.0"
            decision = "blocked"
            decision_kind = "runtime_error"
            reason_code = "scan_runtime_error"
            reason_codes = @("scan_runtime_error")
            scope_requested = [string]$cfg.policy_scope
            scope_effective = [string]$cfg.policy_scope
            input_findings_total = $allFindings.Count
            evaluated_findings_total = 0
            threshold = @{ fail_on = [string]$cfg.fail_on; min_confidence = [double]$cfg.min_confidence; min_confidence_level = (Read-Prop $cfg "min_confidence_level"); exit_zero_on_findings = [bool]$cfg.exit_zero_on_findings }
            breach_summary = @{ breach_count = 0; max_severity = $null; max_confidence = 0.0; sample_finding_ids = @() }
            coverage = @{
                completeness = "failed"
                is_authoritative = $false
                incremental_requested = [bool]$cfg.incremental
                incremental_trusted = [bool]$incrementalPlan.trusted
                baseline_available = $false
                blocked_conditions = @("scan_runtime_error")
            }
            profile = @{ requested = [string]$cfg.policy_profile; applied = [string](Read-Prop $cfg "applied_policy_profile") }
            precedence = @("input_selection", "coverage_validation", "policy_evaluation")
            reasoning = @(
                @{ stage = "input_selection"; status = "unavailable" },
                @{ stage = "coverage_validation"; status = "blocked"; blocked_conditions = @("scan_runtime_error") },
                @{ stage = "policy_evaluation"; status = "skipped" }
            )
            exit_code = $ExitCodes.RuntimeError
            total_findings_in_report = $allFindings.Count
        }
        $r["findings"] = @($allFindings)
        $r["errors"] = $errorArray
        Write-Report $r $cfg
        exit $ExitCodes.RuntimeError
    }

    $baselineDiag = $null
    $baselineAvailable = $false
    $netNewFindings = @($allFindings)
    if ($cfg.baseline_file -and (Test-Path -LiteralPath $cfg.baseline_file)) {
        $b = Load-Json $cfg.baseline_file
        if ($null -eq $b) {
            $errors.Add((New-Err "BASELINE_PARSE_ERROR" "Baseline file could not be parsed." @{ baseline_file = $cfg.baseline_file })) | Out-Null
            $baselineDiag = @{
                source = (Resolve-AbsolutePath -path $cfg.baseline_file -baseDir (Get-Location).Path)
                status = "parse_error"
            }
        }
        else {
            $baselineAvailable = $true
            $baseFpVer = [string](Read-Prop $b "fingerprint_version")
            $allowSoft = (-not [string]::IsNullOrWhiteSpace($baseFpVer) -and $baseFpVer -ne $FingerprintVersion)
            $baselineApply = Apply-BaselineSuppression -findings $allFindings -baselineObj $b -allowSoftMatch $allowSoft
            $netNewFindings = @(Sort-Findings @($baselineApply.findings))
            $baselineDiag = @{
                source = (Resolve-AbsolutePath -path $cfg.baseline_file -baseDir (Get-Location).Path)
                status = "loaded"
                fingerprint_version = $baseFpVer
                soft_match_enabled = [bool]$baselineApply.soft_match_enabled
                suppressed = [int]$baselineApply.suppressed_total
                suppressed_by = $baselineApply.suppressed_by
                entries_total = @($baselineApply.entries).Count
            }
            if ($scanMode -eq "incremental" -and [bool]$incrementalPlan.trusted) {
                $baselineDiag["incremental_status"] = Get-BaselineIncrementalStatus -baselineResult $baselineApply -incrementalPlan $incrementalPlan
            }
        }
    }
    elseif ($cfg.baseline_file) {
        $baselineDiag = @{
            source = (Resolve-AbsolutePath -path $cfg.baseline_file -baseDir (Get-Location).Path)
            status = "missing"
        }
    }

    $findings = @($netNewFindings)
    $policyAllFindings = @($findings)
    $sevCounts = @{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
    foreach ($f in $findings) { $sevCounts[(Sev $f.severity)]++ }

    $confCounts = @{ high = 0; medium = 0; low = 0 }
    foreach ($f in $findings) {
        $lvl = [string](Read-Prop $f "confidence_level")
        if ([string]::IsNullOrWhiteSpace($lvl)) { $lvl = Confidence-LevelFromScore ([double](Read-Prop $f "confidence")) }
        if (-not $confCounts.ContainsKey($lvl)) { $confCounts[$lvl] = 0 }
        $confCounts[$lvl]++
    }

    $coverageState = @{
        completeness = $completeness
        is_authoritative = ($completeness -eq "full")
        incremental_requested = [bool]$cfg.incremental
        incremental_trusted = [bool]$incrementalPlan.trusted
        baseline_available = [bool]$baselineAvailable
    }
    $policyInput = Select-PolicyInputSet -allFindings $policyAllFindings -netNewFindings $netNewFindings -cfg $cfg -scanMode $scanMode -incrementalPlan $incrementalPlan -baselineAvailable $baselineAvailable
    $policyDecision = Build-PolicyDecision -cfg $cfg -coverageState $coverageState -policyInput $policyInput -totalFindings $findings.Count
    $code = [int]$policyDecision.exit_code
    $reason = switch ([string]$policyDecision.decision_kind) {
        "policy_breach" { "policy_breach" }
        "legacy_findings_present" { "findings_present" }
        "coverage_blocked" { "policy_blocked" }
        default { "success" }
    }

    $attemptArray = @($attempts | ForEach-Object { $_ })
    $degradationArray = @($degradations | ForEach-Object { $_ })
    $errorArray = @($errors | ForEach-Object { $_ })
    $enabledArray = @($enabledFeatures | ForEach-Object { $_ })
    $stageArray = @($analyzerStages | ForEach-Object { $_ })
    $report = @{}
    $report["report_version"] = $ReportVersion
    $report["spec_version"] = $SpecVersion
    $report["generated_at"] = (Get-Date).ToString("o")
    $appliedPolicy = $null
    if ($cfg.ContainsKey("policy_id")) { $appliedPolicy = $cfg["policy_id"] }
    $report["metadata"] = @{ tool = @{ name = "CodeSentinel Wrapper"; version = $WrapperVersion }; target = $resolvedTarget; analyzer_mode = $cfg.analyzer_mode; fallback_policy = $cfg.fallback_policy; format = $cfg.format; scan_mode = $scanMode; confidence_model_version = $ConfidenceModelVersion; supported_languages = @("python", "javascript", "typescript"); applied_policy = $appliedPolicy; policy_profile = [string](Read-Prop $cfg "applied_policy_profile"); policy_pack = @{ id = (Read-Prop $cfg "policy_id"); name = (Read-Prop $cfg "policy_name"); version = (Read-Prop $cfg "policy_pack_version") }; enabled_auxiliary_analyzers = $enabledArray }
    $report["scan_summary"] = @{
        status = "completed"
        scan_mode = $scanMode
        completeness = $completeness
        completeness_reasons = @($completenessReasons | ForEach-Object { $_ })
        file_change_summary = $incrementalPlan.file_change_summary
        coverage_limitations = @($coverageLimitations | ForEach-Object { $_ })
        findings_total = $findings.Count
        severity_counts = $sevCounts
        confidence_counts = $confCounts
        exit_reason = $reason
        policy = @{
            decision = $policyDecision.decision
            decision_kind = $policyDecision.decision_kind
            breach = ($policyDecision.decision_kind -eq "policy_breach")
            fail_on = $cfg.fail_on
            min_confidence = [double]$cfg.min_confidence
            min_confidence_level = (Read-Prop $cfg "min_confidence_level")
            is_authoritative = ($completeness -eq "full")
            scope = $policyDecision.scope_effective
            scope_requested = $policyDecision.scope_requested
            input_findings_total = $policyDecision.input_findings_total
            evaluated_findings_total = $policyDecision.evaluated_findings_total
            reason_codes = @($policyDecision.reason_codes)
        }
    }
    $cacheWrite = @{
        attempted = $false
        written = $false
        path = $incrementalPlan.cache_path
        reason = $null
    }
    if ([bool]$cfg.no_cache_write) {
        $cacheWrite.reason = "disabled_by_config"
    }
    else {
        try {
            Write-ScanCache -path $incrementalPlan.cache_path -scope $scope -cfg $cfg -plan $incrementalPlan -binarySha $binarySha -sourceCompleteness $completeness -sourceAuthoritative ($completeness -eq "full")
            $cacheWrite.attempted = $true
            $cacheWrite.written = $true
            $cacheWrite.reason = "ok"
        }
        catch {
            $cacheWrite.attempted = $true
            $cacheWrite.written = $false
            $cacheWrite.reason = "cache_write_failed"
            $errors.Add((New-Err "CACHE_WRITE_FAILED" "Failed to persist scan cache index." @{ cache_path = $incrementalPlan.cache_path; exception = $_.Exception.Message })) | Out-Null
        }
    }
    $incrementalDiagnostics["cache_write"] = $cacheWrite
    $report["diagnostics"] = @{
        dependencies = @($deps)
        analyzer_attempts = $attemptArray
        analyzer_stages = $stageArray
        policy_pack = $policyPackDiag
        degradations = $degradationArray
        incremental = $incrementalDiagnostics
        baseline = $baselineDiag
        scope = (Build-ScopeDiagnostics -scope $scope -analysisScope $analysisScope -cfg $cfg)
    }
    $report["effective_config"] = $cfg
    $report["provenance"] = @{ run_id = [guid]::NewGuid().ToString(); timestamp = (Get-Date).ToString("o"); binary_sha256 = $binarySha; ruleset_version = $cfg.ruleset_version; confidence_model_version = $ConfidenceModelVersion; analyzer_versions = @{ local = "unknown"; ai = "unknown" } }
    $report["policy_decision"] = $policyDecision
    $report["findings"] = @($findings)
    $report["errors"] = $errorArray
    Write-Report $report $cfg
    exit $code
}

function Rules-List {
    $path = Join-Path $PSScriptRoot "rulepacks\\index.json"
    if (-not (Test-Path -LiteralPath $path)) { Exit-Err (New-Err "RULES_INDEX_NOT_FOUND" "rulepacks/index.json not found." @{ path = $path }) $ExitCodes.ConfigError "json" }
    Get-Content -LiteralPath $path -Raw | Write-Output
    exit $ExitCodes.Success
}
function Rules-Pin([hashtable]$cfg) {
    $lock = [ordered]@{ spec_version = $SpecVersion; pinned_at = (Get-Date).ToString("o"); ruleset_version = $cfg.ruleset_version }
    $path = Join-Path $PSScriptRoot "codesentinel.rules.lock.json"
    $lock | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Output ("Pinned ruleset_version={0} to {1}" -f $cfg.ruleset_version, $path)
    exit $ExitCodes.Success
}
function Baseline-Create([string]$Source, [string]$Out) {
    if (-not (Test-Path -LiteralPath $Source)) { Exit-Err (New-Err "BASELINE_SOURCE_REPORT_NOT_FOUND" "Provide a valid JSON report path via Target." @{ target = $Source }) $ExitCodes.UsageError "json" }
    $obj = Load-Json $Source; $findings = @(); if ($obj -and $obj.findings) { $findings = @($obj.findings) }
    $fps = New-Object System.Collections.Generic.List[string]; $i = 1
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($f in $findings) {
        $existingFp = [string](Read-Prop $f "fingerprint")
        $existingId = [string](Read-Prop $f "finding_id")
        $n = if (-not [string]::IsNullOrWhiteSpace($existingFp) -or -not [string]::IsNullOrWhiteSpace($existingId)) { $f } else { Normalize-Finding $f $i }
        $fp = [string]$existingFp
        if ([string]::IsNullOrWhiteSpace($fp)) { $fp = [string](Finding-Fingerprint $n) }
        $fid = [string]$existingId
        if ([string]::IsNullOrWhiteSpace($fid)) { $fid = [string](Read-Prop $n "finding_id") }
        $loc = Read-Prop $n "location"
        $fpv = [string](Read-Prop $n "fingerprint_version")
        if ([string]::IsNullOrWhiteSpace($fpv)) { $fpv = $FingerprintVersion }
        $fps.Add($fp)
        $entries.Add([ordered]@{
                finding_id = $fid
                fingerprint = $fp
                fingerprint_version = $fpv
                rule_id = [string](Read-Prop $n "rule_id")
                title = [string](Read-Prop $n "title")
                language = (Read-Prop $n "language")
                location = $loc
            }) | Out-Null
        $i++
    }
    $base = [ordered]@{
        spec_version = $SpecVersion
        generated_at = (Get-Date).ToString("o")
        source_report = (Resolve-Path -LiteralPath $Source).Path
        fingerprint_version = $FingerprintVersion
        entries = @($entries | ForEach-Object { $_ })
        fingerprints = @($fps | Sort-Object -Unique)
    }
    $dest = if ($Out) { $Out } else { Join-Path $PSScriptRoot "codesentinel.baseline.json" }
    $base | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $dest -Encoding UTF8
    Write-Output ("Baseline written: {0}" -f $dest)
    exit $ExitCodes.Success
}

try {
    if ($Command -eq "spec-version") { Write-Output $SpecVersion; exit $ExitCodes.Success }
    $cfg = Effective-Config
    $cfg = Apply-PolicyConfig $cfg
    $verr = @(Validate-Config $cfg)
    if ($Command -eq "config-validate") { [ordered]@{ spec_version = $SpecVersion; valid = ($verr.Count -eq 0); errors = @($verr); effective_config = $cfg } | ConvertTo-Json -Depth 100 | Write-Output; if ($verr.Count -gt 0) { exit $ExitCodes.ConfigError } else { exit $ExitCodes.Success } }
    if ($verr.Count -gt 0) { Exit-Err (New-Err "CONFIG_VALIDATION_FAILED" "Configuration validation failed." @{ errors = @($verr) }) $ExitCodes.ConfigError $cfg.error_format }
    if ($DumpEffectiveConfig) { $cfg | ConvertTo-Json -Depth 100 | Write-Output; if ($Command -eq "scan") { exit $ExitCodes.Success } }

    switch ($Command) {
        "scan" { Scan $cfg }
        "batch-scan" { Batch-Scan $cfg }
        "doctor" { Doctor $cfg }
        "rules-list" { Rules-List }
        "rules-pin" { Rules-Pin $cfg }
        "baseline-create" { Baseline-Create $Target $cfg.output }
        default { Exit-Err (New-Err "USAGE_INVALID_COMMAND" "Unsupported command." @{ command = $Command }) $ExitCodes.UsageError $cfg.error_format }
    }
}
catch {
    $fmt = if ($PSBoundParameters.ContainsKey("ErrorFormat")) { $ErrorFormat } else { "text" }
    Exit-Err (New-Err "INTERNAL_UNHANDLED_EXCEPTION" "Unhandled exception in wrapper." @{ exception = $_.Exception.Message; stack = $_.ScriptStackTrace }) $ExitCodes.InternalError $fmt
}
