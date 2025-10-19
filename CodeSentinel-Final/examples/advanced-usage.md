# Advanced Usage Guide

This guide covers advanced features and configurations for power users of CodeSentinel.

## AI-Powered Analysis

### Setting up AI Analysis

```python
from src.application.ai_analyzer import AIAnalyzer
from src.application.hybrid_analyzer import HybridAnalyzer
from src.core.interfaces import AnalyzerConfig, SeverityLevel
import os

async def setup_ai_analysis():
    # Configure for AI analysis
    config = AnalyzerConfig(
        ai_model="gpt-4o-mini",
        api_timeout=120,
        max_retries=3,
        severity_threshold=SeverityLevel.LOW
    )

    # Initialize AI analyzer
    api_key = os.getenv("OPENAI_API_KEY")
    ai_analyzer = AIAnalyzer(config, api_key)

    # Or use hybrid analysis (local + AI)
    hybrid_analyzer = HybridAnalyzer(config, api_key)

    return ai_analyzer, hybrid_analyzer
```

### AI Prompt Customization

```python
from src.application.ai_analyzer import PromptManager

# Custom AI prompts for specific vulnerability types
custom_prompts = {
    "sql_injection": """
    Analyze this Python code for SQL injection vulnerabilities.
    Focus on:
    1. String concatenation in SQL queries
    2. Unsanitized user input
    3. Dynamic query construction
    4. ORM misuse

    Provide specific line numbers and remediation advice.
    """,

    "business_logic": """
    Look for business logic vulnerabilities in this code:
    1. Authorization bypasses
    2. Race conditions
    3. Logic flaws in workflows
    4. Improper validation sequences
    """
}

prompt_manager = PromptManager(custom_prompts)
```

### Batch AI Analysis

```python
async def batch_ai_analysis(file_paths: List[Path]):
    config = AnalyzerConfig(
        ai_model="gpt-4o-mini",
        concurrent_limit=3,  # Limit concurrent AI calls
        api_timeout=120
    )

    analyzer = AIAnalyzer(config, os.getenv("OPENAI_API_KEY"))

    # Process files in batches to avoid rate limits
    batch_size = 5
    all_results = []

    for i in range(0, len(file_paths), batch_size):
        batch = file_paths[i:i + batch_size]
        batch_results = await analyzer.analyze_batch(batch, SeverityLevel.MEDIUM)
        all_results.extend(batch_results)

        # Optional: Add delay between batches
        if i + batch_size < len(file_paths):
            await asyncio.sleep(1)

    return all_results
```

## Custom Plugin Development

### Creating a Custom Detector

```python
from src.core.interfaces import IVulnerabilityDetector, Vulnerability, SeverityLevel
from pathlib import Path
import ast
import re

class CustomSecurityDetector(IVulnerabilityDetector):
    """Custom detector for specific security patterns"""

    def __init__(self):
        self.name = "Custom Security Detector"
        self.version = "1.0.0"

    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        vulnerabilities = []

        # Detect hardcoded secrets
        vulnerabilities.extend(self._detect_secrets(content, file_path))

        # Detect insecure random number generation
        vulnerabilities.extend(self._detect_weak_random(content, file_path))

        # Detect improper error handling
        vulnerabilities.extend(self._detect_error_leakage(content, file_path))

        return vulnerabilities

    def _detect_secrets(self, content: str, file_path: Path) -> List[Vulnerability]:
        """Detect hardcoded secrets and credentials"""
        vulnerabilities = []

        # Patterns for common secrets
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "HARDCODED_PASSWORD"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "HARDCODED_API_KEY"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "HARDCODED_SECRET"),
            (r'token\s*=\s*["\'][^"\']+["\']', "HARDCODED_TOKEN"),
        ]

        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern, vuln_type in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        type=vuln_type,
                        severity=SeverityLevel.HIGH,
                        line=line_num,
                        description=f"Hardcoded {vuln_type.split('_')[1].lower()} detected",
                        remediation="Use environment variables or secure credential storage",
                        code_snippet=line.strip(),
                        confidence=0.9
                    ))

        return vulnerabilities

    def _detect_weak_random(self, content: str, file_path: Path) -> List[Vulnerability]:
        """Detect weak random number generation"""
        vulnerabilities = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if (isinstance(node.func, ast.Attribute) and
                        isinstance(node.func.value, ast.Name) and
                        node.func.value.id == 'random' and
                        node.func.attr == 'random'):

                        vulnerabilities.append(Vulnerability(
                            type="WEAK_RANDOMNESS",
                            severity=SeverityLevel.MEDIUM,
                            line=node.lineno,
                            description="Use of cryptographically weak random number generator",
                            remediation="Use secrets module or os.urandom() for cryptographic purposes",
                            code_snippet=ast.get_source_segment(content, node),
                            confidence=0.8
                        ))
        except SyntaxError:
            pass  # Skip if code can't be parsed

        return vulnerabilities

    def _detect_error_leakage(self, content: str, file_path: Path) -> List[Vulnerability]:
        """Detect potential information leakage in error handling"""
        vulnerabilities = []

        # Look for broad exception handling
        if re.search(r'except.*Exception.*as.*e:', content):
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                if re.search(r'except.*Exception.*as.*e:', line):
                    # Check if exception is logged or exposed
                    next_lines = lines[line_num:line_num + 3]
                    for next_line in next_lines:
                        if 'print(' in next_line and 'e' in next_line:
                            vulnerabilities.append(Vulnerability(
                                type="INFORMATION_DISCLOSURE",
                                severity=SeverityLevel.LOW,
                                line=line_num,
                                description="Potential information disclosure through exception printing",
                                remediation="Log exceptions securely and avoid exposing internal details",
                                code_snippet=line.strip(),
                                confidence=0.7
                            ))
                            break

        return vulnerabilities

    def get_detector_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "supported_languages": ["python"],
            "detection_types": [
                "HARDCODED_PASSWORD",
                "HARDCODED_API_KEY",
                "HARDCODED_SECRET",
                "WEAK_RANDOMNESS",
                "INFORMATION_DISCLOSURE"
            ]
        }
```

### Creating a Custom Report Generator

```python
from src.core.interfaces import IReportGenerator
from typing import Dict, Any
import json
from pathlib import Path

class SARIFReportGenerator(IReportGenerator):
    """Generate SARIF (Static Analysis Results Interchange Format) reports"""

    def __init__(self, tool_info: Dict[str, Any]):
        self.tool_info = tool_info

    def generate_report(self, results: Dict[str, Any], output_path: Optional[str] = None) -> None:
        sarif_report = self._convert_to_sarif(results)

        output_file = Path(output_path) if output_path else Path("security-report.sarif")

        with open(output_file, 'w') as f:
            json.dump(sarif_report, f, indent=2)

    def _convert_to_sarif(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert analysis results to SARIF format"""

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_info.get("name", "CodeSentinel"),
                        "version": self.tool_info.get("version", "1.0.0"),
                        "informationUri": "https://github.com/your-org/codesentinel"
                    }
                },
                "results": []
            }]
        }

        # Convert each vulnerability to SARIF result
        for file_result in results.get("files", []):
            file_path = file_result.get("file_path")

            for vuln in file_result.get("vulnerabilities", []):
                sarif_result = {
                    "ruleId": vuln.get("type"),
                    "level": self._severity_to_sarif_level(vuln.get("severity")),
                    "message": {
                        "text": vuln.get("description")
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": vuln.get("line"),
                                "endLine": vuln.get("line")
                            }
                        }
                    }],
                    "properties": {
                        "remediation": vuln.get("remediation"),
                        "confidence": vuln.get("confidence"),
                        "code_snippet": vuln.get("code_snippet")
                    }
                }

                # Add additional properties if available
                if vuln.get("cwe_id"):
                    sarif_result["properties"]["cwe_id"] = vuln["cwe_id"]

                if vuln.get("owasp_category"):
                    sarif_result["properties"]["owasp_category"] = vuln["owasp_category"]

                sarif["runs"][0]["results"].append(sarif_result)

        return sarif

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity level to SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity.lower(), "warning")
```

## Performance Optimization

### Parallel Processing

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List

async def parallel_analysis(file_paths: List[Path], max_workers: int = 10):
    """Analyze files in parallel for better performance"""

    config = AnalyzerConfig(
        concurrent_limit=max_workers,
        cache_enabled=True,
        cache_ttl=3600
    )

    analyzer = LocalAnalyzer(config)

    # Create semaphore to limit concurrent operations
    semaphore = asyncio.Semaphore(max_workers)

    async def analyze_with_semaphore(file_path: Path):
        async with semaphore:
            return await analyzer.analyze_file(file_path, SeverityLevel.MEDIUM)

    # Run analyses in parallel
    tasks = [analyze_with_semaphore(fp) for fp in file_paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    valid_results = [r for r in results if not isinstance(r, Exception)]

    return valid_results
```

### Intelligent Caching

```python
from src.infrastructure.cache_manager import CacheManager
import hashlib

class IntelligentCacheManager(CacheManager):
    """Enhanced cache manager with intelligent invalidation"""

    def __init__(self, cache_dir: str = ".cache", ttl: int = 3600):
        super().__init__(cache_dir, ttl)
        self.dependency_graph: Dict[str, Set[str]] = {}

    def track_dependencies(self, file_path: Path, dependencies: List[Path]):
        """Track file dependencies for intelligent cache invalidation"""
        file_hash = self._calculate_hash(file_path)

        if file_hash not in self.dependency_graph:
            self.dependency_graph[file_hash] = set()

        for dep in dependencies:
            dep_hash = self._calculate_hash(dep)
            self.dependency_graph[file_hash].add(dep_hash)

    def is_cache_valid_with_deps(self, file_path: Path, file_hash: str) -> bool:
        """Check cache validity considering dependencies"""
        if not self.is_cache_valid(file_path, file_hash):
            return False

        # Check if any dependencies have changed
        if file_hash in self.dependency_graph:
            for dep_hash in self.dependency_graph[file_hash]:
                if not self._is_dependency_cache_valid(dep_hash):
                    return False

        return True

    def invalidate_dependent_cache(self, file_path: Path):
        """Invalidate cache for files that depend on this file"""
        file_hash = self._calculate_hash(file_path)

        # Find files that depend on this file
        dependent_files = [
            cached_hash for cached_hash, deps in self.dependency_graph.items()
            if file_hash in deps
        ]

        # Remove cached results for dependent files
        for dep_file_hash in dependent_files:
            cache_file = self.cache_dir / f"{dep_file_hash}.json"
            if cache_file.exists():
                cache_file.unlink()
```

### Memory Optimization

```python
import gc
from typing import Iterator

class MemoryOptimizedAnalyzer:
    """Analyzer optimized for large codebases with memory constraints"""

    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.memory_threshold = 100 * 1024 * 1024  # 100MB

    def analyze_large_codebase(self, root_path: Path) -> Iterator[AnalysisResult]:
        """Analyze large codebase using streaming approach"""

        file_count = 0
        for file_path in self._get_files_generator(root_path):
            result = self._analyze_single_file(file_path)
            yield result

            file_count += 1

            # Periodic cleanup
            if file_count % 100 == 0:
                self._cleanup_memory()

    def _analyze_single_file(self, file_path: Path) -> AnalysisResult:
        """Analyze a single file with minimal memory footprint"""

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Analyze content
            # ... analysis logic ...

            # Immediately cleanup large content
            del content

            return result

        except Exception as e:
            # Handle errors
            pass

    def _cleanup_memory(self):
        """Force garbage collection to free memory"""
        gc.collect()

    def _check_memory_usage(self):
        """Check current memory usage and trigger cleanup if needed"""
        import psutil
        process = psutil.Process()
        memory_usage = process.memory_info().rss

        if memory_usage > self.memory_threshold:
            self._cleanup_memory()
```

## Advanced Configuration

### Multi-Environment Configuration

```yaml
# config/base.yaml
default:
  analyzer:
    severity_threshold: "medium"
    max_file_size: 10485760
    concurrent_limit: 5
    cache_enabled: true
    cache_ttl: 3600

  report:
    formats: ["console", "markdown"]
    output_dir: "./reports"

development:
  analyzer:
    severity_threshold: "low"
    cache_enabled: false  # Disable cache for fresh analysis

  report:
    formats: ["console", "html", "json"]
    include_code_snippets: true

production:
  analyzer:
    severity_threshold: "high"
    concurrent_limit: 10
    cache_ttl: 7200

  security:
    enable_privacy_check: true
    enable_code_sanitization: true

ci_cd:
  analyzer:
    severity_threshold: "medium"
    concurrent_limit: 15
    cache_enabled: true
    cache_ttl: 300  # Short cache for CI/CD

  report:
    formats: ["sarif", "json"]
    output_dir: "./security-reports"
```

### Dynamic Configuration Loading

```python
from src.infrastructure.config_manager import ConfigManager
import os

class DynamicConfigManager(ConfigManager):
    """Configuration manager that supports dynamic reloading"""

    def __init__(self, config_path: Optional[str] = None):
        super().__init__(config_path)
        self._watchers = []
        self._setup_file_watcher()

    def _setup_file_watcher(self):
        """Setup file system watcher for config changes"""
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class ConfigReloadHandler(FileSystemEventHandler):
            def __init__(self, config_manager):
                self.config_manager = config_manager

            def on_modified(self, event):
                if event.src_path.endswith(('yaml', 'yml', 'json')):
                    self.config_manager.reload_config()

        observer = Observer()
        observer.schedule(
            ConfigReloadHandler(self),
            path=str(Path(self.config_path).parent),
            recursive=False
        )
        observer.start()

    def reload_config(self):
        """Reload configuration from file"""
        self._config_cache.clear()
        self.load_config()

    def get_environment_config(self) -> Dict[str, Any]:
        """Get configuration based on current environment"""
        env = os.getenv("CODESENTINEL_ENV", "default")
        return self.get(f"environments.{env}", {})
```

## Monitoring and Observability

### Metrics Collection

```python
from src.infrastructure.monitoring import MonitoringService
import time
from typing import Dict, Any

class AdvancedMonitoringService(MonitoringService):
    """Enhanced monitoring with detailed metrics"""

    def __init__(self, enabled: bool = True):
        super().__init__(enabled)
        self.detailed_metrics = {
            "vulnerability_types": {},
            "file_types": {},
            "analysis_duration": [],
            "memory_usage": [],
            "cache_hit_rate": 0.0
        }

    def track_vulnerability(self, vuln_type: str, severity: str, file_extension: str):
        """Track vulnerability discovery metrics"""
        if vuln_type not in self.detailed_metrics["vulnerability_types"]:
            self.detailed_metrics["vulnerability_types"][vuln_type] = {
                "count": 0,
                "severity_breakdown": {}
            }

        self.detailed_metrics["vulnerability_types"][vuln_type]["count"] += 1

        if severity not in self.detailed_metrics["vulnerability_types"][vuln_type]["severity_breakdown"]:
            self.detailed_metrics["vulnerability_types"][vuln_type]["severity_breakdown"][severity] = 0
        self.detailed_metrics["vulnerability_types"][vuln_type]["severity_breakdown"][severity] += 1

        # Track file types
        if file_extension not in self.detailed_metrics["file_types"]:
            self.detailed_metrics["file_types"][file_extension] = 0
        self.detailed_metrics["file_types"][file_extension] += 1

    def track_analysis_performance(self, duration: float, memory_usage: int):
        """Track performance metrics"""
        self.detailed_metrics["analysis_duration"].append(duration)
        self.detailed_metrics["memory_usage"].append(memory_usage)

        # Keep only last 1000 entries
        if len(self.detailed_metrics["analysis_duration"]) > 1000:
            self.detailed_metrics["analysis_duration"] = self.detailed_metrics["analysis_duration"][-1000:]
            self.detailed_metrics["memory_usage"] = self.detailed_metrics["memory_usage"][-1000:]

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics"""
        durations = self.detailed_metrics["analysis_duration"]
        memory_usage = self.detailed_metrics["memory_usage"]

        return {
            "avg_analysis_time": sum(durations) / len(durations) if durations else 0,
            "max_analysis_time": max(durations) if durations else 0,
            "avg_memory_usage": sum(memory_usage) / len(memory_usage) if memory_usage else 0,
            "max_memory_usage": max(memory_usage) if memory_usage else 0,
            "total_files_analyzed": len(durations),
            "cache_hit_rate": self.detailed_metrics["cache_hit_rate"]
        }

    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        metrics = []

        # Vulnerability counts by type
        for vuln_type, data in self.detailed_metrics["vulnerability_types"].items():
            metrics.append(
                f'codesentinel_vulnerabilities{{type="{vuln_type}"}} {data["count"]}'
            )

        # Performance metrics
        perf_summary = self.get_performance_summary()
        metrics.append(f'codesentinel_analysis_duration_seconds {perf_summary["avg_analysis_time"]}')
        metrics.append(f'codesentinel_memory_usage_bytes {perf_summary["avg_memory_usage"]}')

        return '\n'.join(metrics)
```

### Alerting Integration

```python
class AlertingService:
    """Service for sending alerts based on security findings"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.webhook_url = config.get("webhook_url")
        self.email_config = config.get("email")
        self.slack_config = config.get("slack")

    def send_critical_vulnerability_alert(self, vulnerability: Vulnerability, file_path: str):
        """Send alert for critical vulnerabilities"""

        alert_data = {
            "severity": "critical",
            "vulnerability_type": vulnerability.type,
            "description": vulnerability.description,
            "file_path": file_path,
            "line_number": vulnerability.line,
            "remediation": vulnerability.remediation,
            "timestamp": time.time()
        }

        # Send to multiple channels
        if self.webhook_url:
            self._send_webhook_alert(alert_data)

        if self.email_config:
            self._send_email_alert(alert_data)

        if self.slack_config:
            self._send_slack_alert(alert_data)

    def _send_webhook_alert(self, alert_data: Dict[str, Any]):
        """Send webhook alert"""
        import requests

        try:
            response = requests.post(
                self.webhook_url,
                json=alert_data,
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send webhook alert: {e}")

    def _send_email_alert(self, alert_data: Dict[str, Any]):
        """Send email alert"""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Email implementation here
        pass

    def _send_slack_alert(self, alert_data: Dict[str, Any]):
        """Send Slack alert"""
        import requests

        webhook_url = self.slack_config.get("webhook_url")

        message = {
            "text": f"🚨 Critical Security Vulnerability Detected",
            "attachments": [{
                "color": "danger",
                "fields": [
                    {"title": "Type", "value": alert_data["vulnerability_type"], "short": True},
                    {"title": "File", "value": alert_data["file_path"], "short": True},
                    {"title": "Line", "value": str(alert_data["line_number"]), "short": True},
                    {"title": "Description", "value": alert_data["description"], "short": False},
                    {"title": "Remediation", "value": alert_data["remediation"], "short": False}
                ]
            }]
        }

        try:
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")
```

This advanced usage guide demonstrates how to leverage CodeSentinel's full capabilities for complex security analysis scenarios, custom integrations, and enterprise-scale deployments.