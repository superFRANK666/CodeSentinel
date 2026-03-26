# Next Evolution Steps (Concrete Design)

## 1) Incremental / Diff Scanning (v1)

### 1.1 Scan Cache Model

`./.codesentinel/cache/scan-index.v1.json`

```json
{
  "schema": "scan-index.v1",
  "target_root": "C:/repo",
  "scope_digest": "sha256",
  "files": {
    "src/app.py": {
      "sha256": "abc...",
      "size": 1234,
      "mtime_utc": "2026-03-25T10:00:00Z",
      "language": "python"
    }
  }
}
```

### 1.2 Diff Selection Rules

- `new`: file exists now, absent in cache
- `changed`: hash differs
- `deleted`: in cache, absent now
- `unchanged`: same hash

CLI concept:

- `scan <target> -Incremental`
- `scan <target> -DiffFrom <path-to-scan-index.v1.json>`

Execution:

- Build scoped file list first (same filtering contract).
- Hash scoped files.
- Analyze `new + changed`.
- Keep `deleted` in scan summary (`removed_files`), no findings.

### 1.3 Incremental Report Fields

Add to report:

```json
{
  "scan_mode": "incremental",
  "incremental": {
    "base_index": ".codesentinel/cache/scan-index.v1.json",
    "new_files": 2,
    "changed_files": 5,
    "deleted_files": 1,
    "unchanged_files": 100
  }
}
```

## 2) Baseline Matching Evolution

Current baseline already supports:

- `entries[]` with `finding_id` + `fingerprint`
- compatibility with legacy `fingerprints[]`

Next matching strategy:

1. exact fingerprint match
2. exact finding_id match
3. fallback soft match (`rule_id + file + line + title`) only when fingerprint version differs

Add suppression diagnostics:

```json
{
  "baseline": {
    "source": "baseline.json",
    "suppressed": 12,
    "suppressed_by": {
      "fingerprint": 10,
      "finding_id": 2,
      "soft_match": 0
    }
  }
}
```

## 3) Batch / Portfolio Scanning (later stage)

### 3.1 Manifest

`portfolio.manifest.json`

```json
{
  "schema": "portfolio.manifest.v1",
  "projects": [
    { "name": "svc-a", "path": "C:/code/svc-a", "policy": "policies/default.policy.json" },
    { "name": "svc-b", "path": "C:/code/svc-b", "policy": "policies/strict.policy.json" }
  ]
}
```

### 3.2 Batch Output

```json
{
  "schema": "portfolio.report.v1",
  "projects": [
    { "name": "svc-a", "exit_code": 11, "findings_total": 23, "completeness": "full" }
  ],
  "summary": {
    "projects_total": 2,
    "policy_breach": 1,
    "partial_results": 0
  }
}
```
