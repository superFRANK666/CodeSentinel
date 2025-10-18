# Getting Started Guide

Welcome to CodeSentinel! This guide will help you get started with security analysis of your codebase.

## Installation

### From Source

```bash
git clone https://github.com/your-org/codesentinel.git
cd codesentinel
pip install -e .
```

### Using Docker

```bash
docker pull codesentinel:latest
docker run -v $(pwd):/data codesentinel analyze /data
```

## Quick Start

### Basic Command Line Usage

```bash
# Analyze a single file
codesentinel analyze app.py

# Analyze entire directory
codesentinel analyze src/ --output reports/

# Specify severity level
codesentinel analyze src/ --severity medium

# Generate HTML report
codesentinel analyze src/ --format html --output reports/
```

### Python API Usage

```python
import asyncio
from pathlib import Path
from src.application.local_analyzer import LocalAnalyzer
from src.core.interfaces import AnalyzerConfig, SeverityLevel

async def analyze_code():
    # Configure analyzer
    config = AnalyzerConfig(
        severity_threshold=SeverityLevel.MEDIUM,
        max_file_size=10 * 1024 * 1024,  # 10MB
        concurrent_limit=5
    )

    # Initialize analyzer
    analyzer = LocalAnalyzer(config)

    # Analyze single file
    result = await analyzer.analyze_file(
        Path("app.py"),
        severity_filter=SeverityLevel.MEDIUM
    )

    # Display results
    print(f"Security Score: {result.security_score}/100")
    print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")

    for vuln in result.vulnerabilities:
        print(f"\n{vuln.type} ({vuln.severity.value})")
        print(f"Line {vuln.line}: {vuln.description}")
        print(f"Fix: {vuln.remediation}")

# Run analysis
if __name__ == "__main__":
    asyncio.run(analyze_code())
```

## Configuration

### Configuration File

Create a `config.yaml` file:

```yaml
analyzer:
  severity_threshold: "medium"
  max_file_size: 10485760  # 10MB
  concurrent_limit: 5
  cache_enabled: true
  cache_ttl: 3600

report:
  formats: ["console", "markdown"]
  output_dir: "./reports"
  include_code_snippets: true
  include_remediation: true

security:
  enable_privacy_check: true
  allowed_file_extensions: [".py", ".js", ".ts"]
```

### Environment Variables

```bash
export OPENAI_API_KEY="your-api-key-here"
export CODESENTINAL_CONFIG="config.yaml"
export LOG_LEVEL="INFO"
```

## Supported Languages

- **Python** (.py) - Full support with taint analysis
- **JavaScript** (.js) - ESLint integration
- **TypeScript** (.ts, .tsx) - ESLint integration
- **JSX** (.jsx) - ESLint integration

## Example Analysis

### Python Security Analysis

```python
# vulnerable_app.py
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user/<int:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    user = cursor.fetchone()
    return f"User: {user}"

@app.route('/search')
def search():
    term = request.args.get('q', '')

    # XSS vulnerability
    return f"<h1>Search Results for: {term}</h1>"

if __name__ == '__main__':
    app.run(debug=True)
```

**Analysis Results:**

```
Security Score: 35/100
Vulnerabilities Found: 3

SQL_INJECTION (HIGH)
Line 13: Direct string concatenation in SQL query
Fix: Use parameterized queries instead of string formatting

XSS (MEDIUM)
Line 22: Direct output of user input without sanitization
Fix: Sanitize user input before displaying

DEBUG_MODE (LOW)
Line 26: Running Flask in debug mode in production
Fix: Disable debug mode in production environments
```

### JavaScript Security Analysis

```javascript
// vulnerable.js
const express = require('express');
const fs = require('fs');

const app = express();

app.get('/read-file', (req, res) => {
    const filename = req.query.file;

    // Path Traversal vulnerability
    const content = fs.readFileSync(filename, 'utf8');
    res.send(content);
});

app.get('/eval', (req, res) => {
    const code = req.query.code;

    // Code Injection vulnerability
    const result = eval(code);
    res.json({ result });
});

app.listen(3000);
```

**Analysis Results:**

```
Security Score: 25/100
Vulnerabilities Found: 2

PATH_TRAVERSAL (HIGH)
Line 7: User input used directly in file system operations
Fix: Validate and sanitize file paths, use allowlist

CODE_INJECTION (CRITICAL)
Line 14: Use of eval() with user input
Fix: Avoid eval(), use safer alternatives
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install CodeSentinel
        run: pip install codesentinel

      - name: Run Security Analysis
        run: |
          codesentinel analyze src/ \
            --format sarif \
            --output security-results.sarif \
            --severity medium

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: security-results.sarif
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Security Analysis') {
            steps {
                sh 'pip install codesentinel'
                sh 'codesentinel analyze src/ --format json --output security-report.json'

                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'index.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

## Advanced Usage

### AI-Powered Analysis

```python
from src.application.ai_analyzer import AIAnalyzer
import os

async def ai_analysis():
    config = AnalyzerConfig(
        ai_model="gpt-4o-mini",
        severity_threshold=SeverityLevel.LOW
    )

    api_key = os.getenv("OPENAI_API_KEY")
    analyzer = AIAnalyzer(config, api_key)

    result = await analyzer.analyze_file(
        Path("complex_logic.py"),
        SeverityLevel.LOW
    )

    # AI provides more detailed analysis and explanations
    for vuln in result.vulnerabilities:
        print(f"AI Analysis: {vuln.description}")
        print(f"Context: {vuln.code_snippet}")
```

### Custom Rules

```python
from src.core.interfaces import IVulnerabilityDetector

class CustomSecurityRules(IVulnerabilityDetector):
    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        vulnerabilities = []

        # Custom rule: Check for hardcoded passwords
        if 'password = ' in content.lower():
            vulnerabilities.append(Vulnerability(
                type="HARDCODED_PASSWORD",
                severity=SeverityLevel.HIGH,
                line=self._find_line_number(content, 'password = '),
                description="Hardcoded password detected",
                remediation="Use environment variables or secure credential storage",
                code_snippet=self._extract_line(content, 'password = ')
            ))

        return vulnerabilities

# Register custom detector
analyzer.register_detector(CustomSecurityRules())
```

## Next Steps

1. **Explore the API Reference** - Read detailed documentation about all interfaces and components
2. **Try Advanced Usage** - Learn about AI-powered analysis and custom plugins
3. **Integrate with CI/CD** - Set up automated security scanning in your pipeline
4. **Contribute** - Help improve CodeSentinel by reporting issues or contributing code

## Support

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/codesentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/codesentinel/discussions)
- **Email**: security@yourorg.com