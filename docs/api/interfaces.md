# Core Interfaces

This module defines the core interfaces and data models for the CodeSentinel security analysis system.

## Data Models

### SeverityLevel

Enumeration of vulnerability severity levels.

```python
class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

### Vulnerability

Represents a security vulnerability found in code.

```python
@dataclass
class Vulnerability:
    type: str                          # Type of vulnerability
    severity: SeverityLevel            # Severity level
    line: int                         # Line number where found
    description: str                  # Detailed description
    remediation: str                  # How to fix it
    code_snippet: str                 # Code containing the vulnerability
    confidence: float = 0.8           # Detection confidence (0-1)
    cwe_id: Optional[str] = None      # CWE identifier
    owasp_category: Optional[str] = None  # OWASP category
```

### AnalysisResult

Contains the complete analysis results for a file.

```python
@dataclass
class AnalysisResult:
    file_path: str                    # Path to analyzed file
    file_size: int                    # File size in bytes
    analysis_status: str              # Analysis status
    vulnerabilities: List[Vulnerability]  # List of found vulnerabilities
    security_score: int               # Security score (0-100)
    recommendations: List[str]        # Security recommendations
    analysis_time: float              # Time taken for analysis (seconds)
    pre_analysis_info: Optional[Dict[str, Any]] = None  # Pre-analysis data
```

### ScanSummary

Summary of a complete security scan.

```python
@dataclass
class ScanSummary:
    total_files: int                  # Total files scanned
    scan_time: float                  # Total scan time
    total_vulnerabilities: int        # Total vulnerabilities found
    severity_counts: Dict[str, int]   # Count by severity level
    files_with_issues: int            # Files with vulnerabilities
    analysis_engine: str              # Engine used for analysis
    scan_timestamp: str               # When the scan was performed
```

## Core Interfaces

### ICodeAnalyzer

Main interface for code analysis engines.

```python
class ICodeAnalyzer(Protocol):
    async def analyze_file(
        self,
        file_path: Path,
        severity_filter: SeverityLevel = SeverityLevel.LOW
    ) -> AnalysisResult:
        """Analyze a single file for security vulnerabilities."""

    async def analyze_batch(
        self,
        file_paths: List[Path],
        severity_filter: SeverityLevel = SeverityLevel.LOW
    ) -> List[AnalysisResult]:
        """Analyze multiple files in batch."""

    def get_analyzer_info(self) -> Dict[str, Any]:
        """Get information about the analyzer engine."""
```

### IReportGenerator

Interface for generating security reports.

```python
class IReportGenerator(Protocol):
    def generate_report(
        self,
        results: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> None:
        """Generate a security report from analysis results."""
```

### IVulnerabilityDetector

Interface for vulnerability detection plugins.

```python
class IVulnerabilityDetector(Protocol):
    def detect_vulnerabilities(
        self,
        content: str,
        file_path: Path
    ) -> List[Vulnerability]:
        """Detect vulnerabilities in code content."""

    def get_detector_info(self) -> Dict[str, Any]:
        """Get information about the detector."""
```

## Configuration Models

### AnalyzerConfig

Configuration for code analysis parameters.

```python
@dataclass
class AnalyzerConfig:
    severity_threshold: SeverityLevel = SeverityLevel.LOW
    max_file_size: int = 1024 * 1024     # 1MB
    concurrent_limit: int = 5
    cache_enabled: bool = True
    cache_ttl: int = 3600               # 1 hour
    ai_model: str = "gpt-4o-mini"
    api_timeout: int = 60
    max_retries: int = 3
    base_url: Optional[str] = None
```

### ReportConfig

Configuration for report generation.

```python
@dataclass
class ReportConfig:
    formats: List[str] = field(default_factory=lambda: ["console", "markdown"])
    output_dir: str = "./reports"
    include_code_snippets: bool = True
    include_remediation: bool = True
    max_vulnerabilities: int = 1000
```

### SecurityConfig

Configuration for security settings.

```python
@dataclass
class SecurityConfig:
    enable_privacy_check: bool = True
    enable_code_sanitization: bool = False
    allowed_file_extensions: List[str] = field(default_factory=lambda: [".py"])
    blocked_patterns: List[str] = field(default_factory=lambda: ["*.pyc", "__pycache__", "*.so", "*.dll"])
```

## Usage Examples

### Basic Analysis

```python
from pathlib import Path
from src.core.interfaces import ICodeAnalyzer, SeverityLevel

# Initialize analyzer
analyzer: ICodeAnalyzer = ConcreteAnalyzer()

# Analyze single file
result = await analyzer.analyze_file(
    Path("example.py"),
    severity_filter=SeverityLevel.MEDIUM
)

print(f"Security score: {result.security_score}")
print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
```

### Batch Analysis

```python
# Analyze multiple files
files = [Path("app.py"), Path("utils.py"), Path("models.py")]
results = await analyzer.analyze_batch(files, SeverityLevel.LOW)

for result in results:
    print(f"{result.file_path}: {result.security_score}")
```

### Custom Vulnerability Detector

```python
class CustomDetector:
    def detect_vulnerabilities(self, content: str, file_path: Path) -> List[Vulnerability]:
        vulnerabilities = []
        # Custom detection logic here
        return vulnerabilities

    def get_detector_info(self) -> Dict[str, Any]:
        return {
            "name": "Custom Detector",
            "version": "1.0.0",
            "supported_languages": ["python"]
        }
```