# CodeSentinel v2.0.0 — Installation Guide

## Package Contents

- `CodeSentinel.exe` — Core analysis binary (Windows x86-64)
- `codesentinel.ps1` — Contracted wrapper CLI (recommended entry point)
- `codesentinel.cmd` — Wrapper launcher (works from CMD and PowerShell)
- `quick_start.bat` — Interactive quick-start script
- `.env.example` — Environment variable configuration template
- `codesentinel.config.json` — Default configuration
- `checksums.txt` — SHA256 checksums for integrity verification
- `docs/` — CLI specification, architecture, and roadmap documentation
- `schemas/` — Machine-readable JSON schema definitions
- `policies/` — Default policy pack
- `rulepacks/` — Rule pack index

## System Requirements

- Windows 10 or Windows 11 (64-bit)
- PowerShell 5.1+ (included with Windows)
- Optional: Node.js + ESLint (for enhanced JavaScript/TypeScript analysis)
- Optional: OpenAI API key (for AI-assisted analysis mode)

## Quick Start

### Method 1: Wrapper CLI (Recommended)

1. **Extract the release archive** to your preferred directory
2. **Open PowerShell** and navigate to the extracted directory
3. **Verify installation:**

```powershell
.\codesentinel.cmd spec-version
.\codesentinel.cmd doctor -Format json
.\codesentinel.cmd config-validate
```

4. **Run your first scan:**

```powershell
.\codesentinel.cmd scan . -Format json -Output report.json
```

### Method 2: Quick Start Script

1. **Double-click `quick_start.bat`**
2. **Choose a quick action** or press Enter for the native interactive menu
3. **Or pass arguments directly:** `quick_start.bat scan . -Format json -Output report.json`

## Configuration

### OpenAI API Setup (Optional)

Required only for AI-assisted analysis (`-AnalyzerMode ai-only` or `hybrid`):

1. **Copy the configuration template:**
   ```cmd
   copy .env.example .env
   ```

2. **Edit `.env`** and add your API key:
   ```
   OPENAI_API_KEY=sk-your-key-here
   ```

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_MODEL` | `gpt-4o-mini` | AI model for analysis |
| `REQUEST_TIMEOUT` | `60` | API timeout in seconds |
| `MAX_RETRIES` | `3` | Retry count on API failure |
| `LOG_LEVEL` | `INFO` | Log verbosity (DEBUG/INFO/WARNING/ERROR) |

Analyzer mode is controlled via the CLI: `-AnalyzerMode local-only|ai-only|hybrid`

## Usage

### Command-Line Mode (Wrapper CLI)

```powershell
# Basic scan with JSON report
.\codesentinel.cmd scan C:\project\src -Format json -Output report.json

# SARIF output for CI integration
.\codesentinel.cmd scan C:\project\src -Format sarif -Output report.sarif

# Local-only analysis (no API key needed)
.\codesentinel.cmd scan C:\project\src -AnalyzerMode local-only

# AI-only analysis (requires API key)
.\codesentinel.cmd scan C:\project\src -AnalyzerMode ai-only

# Enable secret + dependency scanning
.\codesentinel.cmd scan C:\project\src -Enable secrets,deps -Format json -Output report.json

# Environment diagnostics
.\codesentinel.cmd doctor -Format json
```

### Interactive Mode

Run `CodeSentinel.exe` directly for the native text-based interactive menu.

## Integrity Verification

Verify the binary before first use:

```powershell
Get-FileHash .\CodeSentinel.exe -Algorithm SHA256
```

Compare the output against the SHA256 value in `checksums.txt`.

## Troubleshooting

**Program won't start**
- Ensure Windows 10/11 64-bit
- Check if antivirus or system policy is blocking execution
- Only run as administrator if accessing restricted directories

**Dependency issues**
- Run `.\codesentinel.cmd doctor -Format json` to diagnose
- Check status of `CodeSentinel.exe`, `node`, `eslint`, `OPENAI_API_KEY`

**AI analysis not working**
- Verify API key in `.env` file
- Check network connectivity
- Use `-AnalyzerMode local-only` as fallback

**Slow analysis**
- Use `-AnalyzerMode local-only` for faster local scans
- Narrow scan scope with `-Include` and `-Exclude` flags
- Use `-Incremental` for subsequent scans

## Support

- **Issues:** [github.com/superFRANK666/CodeSentinel/issues](https://github.com/superFRANK666/CodeSentinel/issues)
- **Documentation:** [github.com/superFRANK666/CodeSentinel](https://github.com/superFRANK666/CodeSentinel)
- **CLI Reference:** `docs/CLI_SPEC_v2.md`

