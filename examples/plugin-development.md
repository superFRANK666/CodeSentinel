# Plugin Development Guide

This guide will help you create custom plugins for CodeSentinel to extend its functionality.

## Plugin Architecture

CodeSentinel supports two main types of plugins:

1. **Vulnerability Detectors** - Find specific types of security vulnerabilities
2. **Report Generators** - Create custom report formats

All plugins implement the interfaces defined in `src/core/interfaces.py`.

## Creating a Vulnerability Detector Plugin

### Basic Structure

```python
from src.core.interfaces import IVulnerabilityDetector, Vulnerability, SeverityLevel
from pathlib import Path
from typing import List, Dict, Any

class CustomVulnerabilityDetector(IVulnerabilityDetector):
    """Custom vulnerability detector plugin"""

    def __init__(self):
        self.name = "Custom Detector"
        self.version = "1.0.0"
        self.description = "Detects custom security vulnerabilities"

    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        """
        Detect vulnerabilities in the given content.

        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        # Your detection logic here
        if self._contains_vulnerability(content):
            vuln = Vulnerability(
                type="CUSTOM_VULNERABILITY",
                severity=SeverityLevel.MEDIUM,
                line=1,  # Line number where vulnerability was found
                description="Custom vulnerability detected",
                remediation="Fix the custom vulnerability",
                code_snippet=content.split('\n')[0],  # First line as example
                confidence=0.8
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def get_detector_info(self) -> Dict[str, Any]:
        """
        Get information about this detector.

        Returns:
            Dictionary containing detector metadata
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_languages": ["python"],
            "vulnerability_types": ["CUSTOM_VULNERABILITY"]
        }

    def _contains_vulnerability(self, content: str) -> bool:
        """Helper method to detect specific vulnerability pattern"""
        # Implement your detection logic here
        return "vulnerable_pattern" in content
```

### Advanced Example: API Key Leakage Detector

```python
import re
import base64
from src.core.interfaces import IVulnerabilityDetector, Vulnerability, SeverityLevel
from pathlib import Path
from typing import List, Dict, Any

class APIKeyLeakageDetector(IVulnerabilityDetector):
    """Detects potential API key leaks in code"""

    def __init__(self):
        self.name = "API Key Leakage Detector"
        self.version = "1.0.0"
        self.description = "Detects hardcoded API keys and sensitive credentials"

        # Regex patterns for various API key formats
        self.api_patterns = {
            "AWS_ACCESS_KEY": r'AKIA[0-9A-Z]{16}',
            "AWS_SECRET_KEY": r'[0-9a-zA-Z/+=]{40}',
            "GCP_API_KEY": r'AIza[0-9A-Za-z_-]{35}',
            "GITHUB_TOKEN": r'ghp_[0-9a-zA-Z]{36}',
            "SLACK_TOKEN": r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
            "Generic_API_Key": r'api[_-]?key\s*[:=]\s*["\'][0-9a-zA-Z_-]{16,}["\']',
            "Generic_Secret": r'secret\s*[:=]\s*["\'][0-9a-zA-Z_-]{16,}["\']',
            "Private_Key": r'-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----'
        }

    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        vulnerabilities = []

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            # Skip comments and documentation strings
            if self._is_comment_or_docstring(line):
                continue

            for pattern_name, pattern in self.api_patterns.items():
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Additional validation to reduce false positives
                    if self._is_likely_api_key(match.group(), pattern_name):
                        vulnerability = Vulnerability(
                            type="HARDCODED_API_KEY",
                            severity=SeverityLevel.CRITICAL,
                            line=line_num,
                            description=f"Potential {pattern_name} detected in code",
                            remediation="Remove hardcoded credentials and use environment variables or secure credential management",
                            code_snippet=line.strip(),
                            confidence=self._calculate_confidence(match.group(), pattern_name),
                            cwe_id=self._get_cwe_id(pattern_name),
                            owasp_category="A02:2021 - Cryptographic Failures"
                        )
                        vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_comment_or_docstring(self, line: str) -> bool:
        """Check if line is a comment or docstring"""
        stripped = line.strip()
        return (
            stripped.startswith('#') or
            stripped.startswith('//') or
            stripped.startswith('/*') or
            stripped.startswith('*') or
            stripped.startswith('"""') or
            stripped.startswith("'''")
        )

    def _is_likely_api_key(self, match: str, pattern_name: str) -> bool:
        """Additional validation to reduce false positives"""

        # Skip obvious examples or placeholders
        if any(placeholder in match.lower() for placeholder in [
            'example', 'test', 'demo', 'sample', 'fake', 'xxx', 'yyy', 'zzz'
        ]):
            return False

        # Skip short matches for generic patterns
        if pattern_name in ["Generic_API_Key", "Generic_Secret"] and len(match) < 30:
            return False

        # Additional pattern-specific validation
        if pattern_name == "Generic_API_Key":
            # Look for actual key patterns after the API key identifier
            key_part = re.search(r'["\']([^"\']{16,})["\']', match)
            if key_part:
                key = key_part.group(1)
                # Check if key has sufficient entropy (looks like a real key)
                return self._has_sufficient_entropy(key)

        return True

    def _has_sufficient_entropy(self, key: str) -> bool:
        """Check if a key has sufficient entropy to be real"""
        # Simple entropy calculation
        unique_chars = len(set(key))
        if unique_chars < len(key) * 0.3:  # Less than 30% unique characters
            return False

        # Check for common patterns
        if any(pattern in key.lower() for pattern in ['secret', 'key', 'token']):
            return len(key) > 20

        return True

    def _calculate_confidence(self, match: str, pattern_name: str) -> float:
        """Calculate confidence score for the detection"""
        base_confidence = 0.7

        # Increase confidence for specific, well-defined patterns
        if pattern_name in ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN"]:
            base_confidence = 0.95
        elif pattern_name in ["GCP_API_KEY", "SLACK_TOKEN"]:
            base_confidence = 0.9
        elif pattern_name == "Private_Key":
            base_confidence = 0.85

        # Reduce confidence for generic patterns
        if pattern_name in ["Generic_API_Key", "Generic_Secret"]:
            base_confidence = 0.6

        # Adjust based on context
        if "example" in match.lower() or "test" in match.lower():
            base_confidence *= 0.3

        return min(base_confidence, 1.0)

    def _get_cwe_id(self, pattern_name: str) -> str:
        """Get appropriate CWE ID for the pattern"""
        cwe_mapping = {
            "AWS_ACCESS_KEY": "CWE-798",
            "AWS_SECRET_KEY": "CWE-798",
            "GCP_API_KEY": "CWE-798",
            "GITHUB_TOKEN": "CWE-798",
            "SLACK_TOKEN": "CWE-798",
            "Generic_API_Key": "CWE-798",
            "Generic_Secret": "CWE-798",
            "Private_Key": "CWE-200"
        }
        return cwe_mapping.get(pattern_name, "CWE-798")

    def get_detector_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_languages": ["python", "javascript", "typescript", "java", "go"],
            "vulnerability_types": ["HARDCODED_API_KEY"],
            "detection_patterns": list(self.api_patterns.keys()),
            "false_positive_rate": "Low to Medium"
        }
```

### AST-based Detector Example

```python
import ast
from src.core.interfaces import IVulnerabilityDetector, Vulnerability, SeverityLevel
from pathlib import Path
from typing import List, Dict, Any

class SQLInjectionDetector(IVulnerabilityDetector):
    """Detects SQL injection vulnerabilities using AST analysis"""

    def __init__(self):
        self.name = "SQL Injection Detector"
        self.version = "1.0.0"
        self.description = "Detects potential SQL injection vulnerabilities"

        # Known SQL database modules
        self.sql_modules = {
            'sqlite3', 'psycopg2', 'mysql', 'pymysql', 'cx_Oracle',
            'pyodbc', 'sqlalchemy', 'django.db', 'flask_sqlalchemy'
        }

        # Vulnerable SQL execution methods
        self.vulnerable_methods = {
            'execute', 'executemany', 'cursor', 'query', 'raw'
        }

    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        vulnerabilities = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Can't parse file, skip analysis
            return vulnerabilities

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                vulnerabilities.extend(self._analyze_call(node, content))
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                vulnerabilities.extend(self._analyze_string_concat(node, content))

        return vulnerabilities

    def _analyze_call(self, node: ast.Call, content: str) -> List[Vulnerability]:
        """Analyze function calls for SQL injection patterns"""
        vulnerabilities = []

        # Check if this is a database call
        if self._is_database_call(node):
            # Check if arguments contain user input
            for arg in node.args:
                if self._contains_user_input(arg):
                    vulnerability = Vulnerability(
                        type="SQL_INJECTION",
                        severity=SeverityLevel.HIGH,
                        line=node.lineno,
                        description="Potential SQL injection in database query",
                        remediation="Use parameterized queries or ORM methods instead of string concatenation",
                        code_snippet=ast.get_source_segment(content, node),
                        confidence=0.8,
                        cwe_id="CWE-89",
                        owasp_category="A03:2021 - Injection"
                    )
                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _analyze_string_concat(self, node: ast.BinOp, content: str) -> List[Vulnerability]:
        """Analyze string concatenation in SQL contexts"""
        vulnerabilities = []

        # Check if this concatenation is part of a SQL query
        if self._is_in_sql_context(node):
            vulnerability = Vulnerability(
                type="SQL_INJECTION",
                severity=SeverityLevel.MEDIUM,
                line=node.lineno,
                description="String concatenation in SQL query context",
                remediation="Use parameterized queries or proper string formatting",
                code_snippet=ast.get_source_segment(content, node),
                confidence=0.7,
                cwe_id="CWE-89",
                owasp_category="A03:2021 - Injection"
            )
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_database_call(self, node: ast.Call) -> bool:
        """Check if the function call is a database operation"""
        if isinstance(node.func, ast.Attribute):
            # Check for methods like cursor.execute(), conn.query(), etc.
            if node.func.attr in self.vulnerable_methods:
                return True

        if isinstance(node.func, ast.Name):
            # Check for direct function calls
            if node.func.id in self.vulnerable_methods:
                return True

        return False

    def _contains_user_input(self, node: ast.AST) -> bool:
        """Check if AST node contains user input"""
        if isinstance(node, ast.Name):
            # Common sources of user input
            user_input_sources = {
                'request', 'input', 'raw_input', 'sys.argv', 'os.environ',
                'forms', 'args', 'query', 'params', 'data'
            }
            return node.id in user_input_sources

        elif isinstance(node, ast.Attribute):
            # Check for request.args, request.form, etc.
            if isinstance(node.value, ast.Name):
                if node.value.id == 'request':
                    return node.attr in {'args', 'form', 'json', 'data', 'get', 'post'}

        return False

    def _is_in_sql_context(self, node: ast.BinOp) -> bool:
        """Check if string concatenation is in SQL context"""
        # This is a simplified check - in practice you'd need more sophisticated
        # analysis to determine if we're in a SQL context
        return any(keyword in ast.dump(node).lower() for keyword in ['sql', 'query', 'select'])

    def get_detector_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_languages": ["python"],
            "vulnerability_types": ["SQL_INJECTION"],
            "detection_method": "AST analysis",
            "accuracy": "High"
        }
```

## Creating a Report Generator Plugin

### Basic Report Generator

```python
from src.core.interfaces import IReportGenerator
from typing import Dict, Any, Optional
from pathlib import Path
import json

class JSONReportGenerator(IReportGenerator):
    """Generate JSON reports"""

    def __init__(self, indent: int = 2):
        self.indent = indent

    def generate_report(self, results: Dict[str, Any], output_path: Optional[str] = None) -> None:
        """Generate JSON report from analysis results"""

        # Process results into desired format
        report_data = self._format_results(results)

        # Determine output file
        if output_path:
            output_file = Path(output_path)
        else:
            output_file = Path("security-report.json")

        # Write report
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=self.indent, default=str)

    def _format_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format results into JSON structure"""
        return {
            "scan_summary": results.get("summary", {}),
            "files_analyzed": results.get("total_files", 0),
            "vulnerabilities": self._extract_vulnerabilities(results),
            "recommendations": self._extract_recommendations(results),
            "scan_metadata": {
                "timestamp": results.get("timestamp"),
                "analyzer_version": results.get("analyzer_version", "1.0.0"),
                "scan_duration": results.get("scan_duration")
            }
        }

    def _extract_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all vulnerabilities from results"""
        vulnerabilities = []

        for file_result in results.get("files", []):
            for vuln in file_result.get("vulnerabilities", []):
                vulnerabilities.append({
                    "type": vuln.get("type"),
                    "severity": vuln.get("severity"),
                    "file_path": file_result.get("file_path"),
                    "line": vuln.get("line"),
                    "description": vuln.get("description"),
                    "remediation": vuln.get("remediation"),
                    "confidence": vuln.get("confidence"),
                    "cwe_id": vuln.get("cwe_id"),
                    "owasp_category": vuln.get("owasp_category")
                })

        return vulnerabilities

    def _extract_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Extract recommendations from results"""
        recommendations = set()

        for file_result in results.get("files", []):
            recommendations.update(file_result.get("recommendations", []))

        return list(recommendations)
```

### Advanced HTML Report Generator

```python
from src.core.interfaces import IReportGenerator
from typing import Dict, Any, Optional
from pathlib import Path
from jinja2 import Template
import base64

class HTMLReportGenerator(IReportGenerator):
    """Generate interactive HTML reports"""

    def __init__(self, template_path: Optional[str] = None):
        self.template_path = template_path
        self.template = self._load_template()

    def generate_report(self, results: Dict[str, Any], output_path: Optional[str] = None) -> None:
        """Generate HTML report"""

        # Prepare data for template
        template_data = self._prepare_template_data(results)

        # Render template
        html_content = self.template.render(**template_data)

        # Write to file
        output_file = Path(output_path) if output_path else Path("security-report.html")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _load_template(self) -> Template:
        """Load HTML template"""
        if self.template_path and Path(self.template_path).exists():
            with open(self.template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        else:
            # Use default template
            template_content = self._get_default_template()

        return Template(template_content)

    def _prepare_template_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template"""

        # Calculate statistics
        total_vulnerabilities = sum(
            len(file_result.get("vulnerabilities", []))
            for file_result in results.get("files", [])
        )

        severity_counts = self._count_by_severity(results)

        # Group vulnerabilities by type
        vulnerabilities_by_type = self._group_by_type(results)

        return {
            "title": "Security Analysis Report",
            "scan_summary": results.get("summary", {}),
            "total_files": results.get("total_files", 0),
            "total_vulnerabilities": total_vulnerabilities,
            "severity_counts": severity_counts,
            "vulnerabilities_by_type": vulnerabilities_by_type,
            "files": results.get("files", []),
            "scan_metadata": {
                "timestamp": results.get("timestamp"),
                "analyzer_version": results.get("analyzer_version", "1.0.0"),
                "scan_duration": results.get("scan_duration")
            }
        }

    def _count_by_severity(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for file_result in results.get("files", []):
            for vuln in file_result.get("vulnerabilities", []):
                severity = vuln.get("severity", "low").lower()
                if severity in counts:
                    counts[severity] += 1

        return counts

    def _group_by_type(self, results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by type"""
        grouped = {}

        for file_result in results.get("files", []):
            for vuln in file_result.get("vulnerabilities", []):
                vuln_type = vuln.get("type", "Unknown")
                if vuln_type not in grouped:
                    grouped[vuln_type] = []

                grouped[vuln_type].append({
                    **vuln,
                    "file_path": file_result.get("file_path")
                })

        return grouped

    def _get_default_template(self) -> str:
        """Get default HTML template"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
        .severity-critical { background: #f8d7da; color: #721c24; }
        .severity-high { background: #f5c6cb; color: #721c24; }
        .severity-medium { background: #fff3cd; color: #856404; }
        .severity-low { background: #d1ecf1; color: #0c5460; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .vulnerability-title { font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }
        .code-snippet { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; margin: 10px 0; }
        .remediation { background: #d4edda; padding: 10px; border-radius: 3px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Generated on: {{ scan_metadata.timestamp }}</p>
        <p>Analyzer Version: {{ scan_metadata.analyzer_version }}</p>
        {% if scan_metadata.scan_duration %}
        <p>Scan Duration: {{ "%.2f"|format(scan_metadata.scan_duration) }} seconds</p>
        {% endif %}
    </div>

    <div class="summary">
        <div class="metric">
            <h3>{{ total_files }}</h3>
            <p>Files Analyzed</p>
        </div>
        <div class="metric">
            <h3>{{ total_vulnerabilities }}</h3>
            <p>Total Vulnerabilities</p>
        </div>
        <div class="metric severity-critical">
            <h3>{{ severity_counts.critical }}</h3>
            <p>Critical</p>
        </div>
        <div class="metric severity-high">
            <h3>{{ severity_counts.high }}</h3>
            <p>High</p>
        </div>
        <div class="metric severity-medium">
            <h3>{{ severity_counts.medium }}</h3>
            <p>Medium</p>
        </div>
        <div class="metric severity-low">
            <h3>{{ severity_counts.low }}</h3>
            <p>Low</p>
        </div>
    </div>

    {% if vulnerabilities_by_type %}
    <h2>Vulnerabilities by Type</h2>
    {% for vuln_type, vulns in vulnerabilities_by_type.items() %}
    <h3>{{ vuln_type }} ({{ vulns|length }})</h3>
    {% for vuln in vulns %}
    <div class="vulnerability">
        <div class="vulnerability-title">
            {{ vuln.type }} - {{ vuln.severity.title() }}
            <span style="float: right; font-size: 0.8em; color: #666;">
                {{ vuln.file_path }}:{{ vuln.line }}
            </span>
        </div>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if vuln.code_snippet %}
        <div class="code-snippet">{{ vuln.code_snippet }}</div>
        {% endif %}
        {% if vuln.remediation %}
        <div class="remediation">
            <strong>Remediation:</strong> {{ vuln.remediation }}
        </div>
        {% endif %}
        <p style="font-size: 0.9em; color: #666;">
            Confidence: {{ "%.1f"|format(vuln.confidence * 100) }}%
            {% if vuln.cwe_id %} | CWE: {{ vuln.cwe_id }}{% endif %}
            {% if vuln.owasp_category %} | {{ vuln.owasp_category }}{% endif %}
        </p>
    </div>
    {% endfor %}
    {% endfor %}
    {% endif %}

    <h2>File Details</h2>
    <table>
        <tr>
            <th>File</th>
            <th>Security Score</th>
            <th>Vulnerabilities</th>
            <th>Status</th>
        </tr>
        {% for file in files %}
        <tr>
            <td>{{ file.file_path }}</td>
            <td>{{ file.security_score }}/100</td>
            <td>{{ file.vulnerabilities|length }}</td>
            <td>{{ file.analysis_status }}</td>
        </tr>
        {% endfor %}
    </table>

</body>
</html>
        '''
```

## Plugin Registration and Loading

### Plugin Registration

```python
from src.infrastructure.plugin_manager import PluginManager
from pathlib import Path

def register_plugins():
    """Register custom plugins with CodeSentinel"""

    plugin_manager = PluginManager()

    # Register vulnerability detector
    api_key_detector = APIKeyLeakageDetector()
    plugin_manager.register_plugin(api_key_detector)

    sql_injection_detector = SQLInjectionDetector()
    plugin_manager.register_plugin(sql_injection_detector)

    # Register report generator
    html_generator = HTMLReportGenerator()
    plugin_manager.register_plugin(html_generator)

    return plugin_manager
```

### Plugin Configuration

```yaml
# config/plugins.yaml
plugins:
  directory: "./plugins"
  auto_load: true

  vulnerability_detectors:
    - name: "APIKeyLeakageDetector"
      enabled: true
      config:
        confidence_threshold: 0.7
        exclude_patterns:
          - "*.test.js"
          - "*_test.py"

    - name: "SQLInjectionDetector"
      enabled: true
      config:
        check_string_concatenation: true
        exclude_safe_methods: true

  report_generators:
    - name: "HTMLReportGenerator"
      enabled: true
      config:
        template_path: "./templates/custom-report.html"
        include_charts: true

    - name: "JSONReportGenerator"
      enabled: true
      config:
        indent: 4
        include_metadata: true
```

### Testing Your Plugin

```python
import pytest
from src.core.interfaces import Vulnerability, SeverityLevel
from pathlib import Path

class TestAPIKeyLeakageDetector:
    def test_api_key_detection(self):
        """Test API key detection functionality"""
        detector = APIKeyLeakageDetector()

        # Test code with API key
        code_with_key = """
import requests

def make_request():
    api_key = "AIzaSyABC123xyz456"  # This should be detected
    headers = {"Authorization": f"Bearer {api_key}"}
    return requests.get("https://api.example.com", headers=headers)
"""

        vulnerabilities = detector.detect_vulnerabilities(code_with_key, Path("test.py"))

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].type == "HARDCODED_API_KEY"
        assert vulnerabilities[0].severity == SeverityLevel.CRITICAL

    def test_false_positive_filtering(self):
        """Test that examples and test data are not flagged"""
        detector = APIKeyLeakageDetector()

        # Test code with example key
        code_with_example = """
def example_usage():
    api_key = "AIzaSyEXAMPLE_KEY_HERE"  # This should not be detected
    # This is just an example
"""

        vulnerabilities = detector.detect_vulnerabilities(code_with_example, Path("test.py"))

        # Should not detect the example key
        assert len(vulnerabilities) == 0

    def test_detector_info(self):
        """Test detector metadata"""
        detector = APIKeyLeakageDetector()
        info = detector.get_detector_info()

        assert info["name"] == "API Key Leakage Detector"
        assert "HARDCODED_API_KEY" in info["vulnerability_types"]
        assert isinstance(info["supported_languages"], list)
```

## Best Practices for Plugin Development

1. **Performance**: Optimize your detectors for performance, especially when processing large files
2. **False Positives**: Implement validation logic to minimize false positives
3. **Documentation**: Provide clear documentation for your plugin functionality
4. **Testing**: Write comprehensive tests for your plugins
5. **Error Handling**: Implement robust error handling for edge cases
6. **Configuration**: Make your plugins configurable through parameters
7. **Standards**: Follow the defined interfaces and patterns consistently

## Publishing Your Plugin

1. **Package Structure**: Follow Python package structure
2. **Setup.py**: Create proper setup.py with metadata
3. **Documentation**: Include README and documentation
4. **Testing**: Include tests and CI/CD configuration
5. **PyPI**: Publish to PyPI for easy installation

Example setup.py:

```python
from setuptools import setup, find_packages

setup(
    name="codesentinel-custom-detectors",
    version="1.0.0",
    description="Custom vulnerability detectors for CodeSentinel",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=["codesentinel>=1.0.0"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.8",
)
```

This guide provides a comprehensive foundation for creating custom plugins that extend CodeSentinel's capabilities to meet your specific security analysis needs.