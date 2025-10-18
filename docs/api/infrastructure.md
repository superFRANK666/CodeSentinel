# Infrastructure

This module contains the infrastructure components that support the security analysis system, including configuration management, caching, error handling, and reporting.

## Core Components

### ConfigManager

Manages application configuration with support for multiple sources.

```python
class ConfigManager:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self._config_cache: Dict[str, Any] = {}

    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or environment variables."""

    def save_config(self, config: Dict[str, Any], config_path: str) -> None:
        """Save configuration to file."""

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation support."""

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
```

**Configuration Sources:**
- YAML/JSON configuration files
- Environment variables
- Command-line arguments
- Default values

**Configuration Priority:**
1. Command-line arguments (highest)
2. Environment variables
3. Configuration file
4. Default values (lowest)

### CacheManager

Intelligent caching system for analysis results.

```python
class CacheManager:
    def __init__(self, cache_dir: str = ".cache", ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.ttl = ttl
        self._setup_cache_dir()

    def get_cached_result(self, file_hash: str) -> Optional[AnalysisResult]:
        """Get cached analysis result if valid."""

    def cache_result(self, file_hash: str, result: AnalysisResult) -> None:
        """Cache analysis result with metadata."""

    def is_cache_valid(self, file_path: Path, file_hash: str) -> bool:
        """Check if cached result is still valid."""

    def clear_cache(self) -> None:
        """Clear all cached results."""
```

**Cache Features:**
- File hash-based caching
- TTL (Time To Live) support
- Automatic cache cleanup
- Cache statistics and monitoring

### ProgressReporter

Real-time progress reporting for long-running operations.

```python
class ProgressReporter:
    def __init__(self, show_progress: bool = True):
        self.show_progress = show_progress
        self.progress_bar: Optional[tqdm] = None

    def start_progress(self, total: int, description: str = "") -> None:
        """Initialize progress tracking."""

    def update_progress(self, current: int, message: str = "") -> None:
        """Update progress with optional message."""

    def finish_progress(self) -> None:
        """Complete progress tracking."""
```

**Progress Features:**
- Visual progress bars
- ETA calculation
- Throughput monitoring
- Cancellable operations

### ErrorHandler

Centralized error handling and reporting.

```python
class ErrorHandler:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_stats: Dict[str, int] = {}

    def handle_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle error and return user-friendly information."""

    def get_error_suggestions(self, error_type: str) -> List[str]:
        """Get suggestions for resolving common errors."""

    def log_error(self, error: Exception, context: Dict[str, Any]) -> None:
        """Log error with context information."""
```

**Error Categories:**
- File system errors
- Network errors
- Parsing errors
- Configuration errors
- API errors

## Security Components

### PrivacyManager

Handles code privacy and sensitive data protection.

```python
class PrivacyManager:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.sensitive_patterns = self._load_sensitive_patterns()

    def sanitize_code(self, content: str) -> str:
        """Remove or mask sensitive information from code."""

    def is_sensitive_content(self, content: str) -> bool:
        """Check if content contains sensitive information."""

    def get_privacy_level(self, content: str) -> str:
        """Determine privacy level of content."""
```

**Privacy Features:**
- Sensitive data detection
- Code sanitization
- Privacy level assessment
- Compliance checking

### AuthenticationManager

Manages API authentication and user sessions.

```python
class AuthenticationManager:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session_info: Optional[Dict[str, Any]] = None

    async def authenticate(self, api_key: str) -> bool:
        """Authenticate user with API key."""

    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get current user information."""
```

**Authentication Features:**
- API key validation
- Session management
- Rate limiting
- User analytics

## Plugin System

### PluginManager

Manages loading and execution of plugins.

```python
class PluginManager:
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.detector_plugins: List[IVulnerabilityDetector] = []
        self.reporter_plugins: List[IReportGenerator] = []

    def load_plugins(self, plugin_dir: str) -> None:
        """Load all plugins from directory."""

    def get_detector_plugins(self) -> List[IVulnerabilityDetector]:
        """Get all vulnerability detector plugins."""

    def get_reporter_plugins(self) -> List[IReportGenerator]:
        """Get all report generator plugins."""

    def register_plugin(self, plugin: Any) -> None:
        """Register a plugin instance."""
```

**Plugin Types:**
- Vulnerability detectors
- Report generators
- Data processors
- External analyzers

## Monitoring and Analytics

### MonitoringService

System monitoring and performance tracking.

```python
class MonitoringService:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.metrics: Dict[str, Any] = {}
        self.start_time = time.time()

    def track_analysis(self, file_path: str, duration: float, vulnerabilities: int) -> None:
        """Track analysis metrics."""

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""

    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format."""
```

**Metrics Tracked:**
- Analysis duration
- Files processed
- Vulnerabilities found
- Memory usage
- API calls

## External Integrations

### ExternalAnalyzer

Interface for external analysis services.

```python
class ExternalAnalyzer:
    def __init__(self, service_config: Dict[str, Any]):
        self.config = service_config
        self.client = self._create_client()

    async def analyze_with_external_service(self, code_content: str, file_path: Path) -> List[Vulnerability]:
        """Send code to external service for analysis."""

    def _create_client(self) -> Any:
        """Create HTTP client for external service."""

    def _format_request(self, code: str, file_path: Path) -> Dict[str, Any]:
        """Format request for external service."""
```

**Supported Services:**
- CodeQL
- SonarQube
- Snyk
- GitHub Code Scanning

## Report Generation

### ReportGeneratorFactory

Factory for creating different types of report generators.

```python
class ReportGeneratorFactory:
    @staticmethod
    def create_generator(format: str, config: ReportConfig) -> IReportGenerator:
        """Create report generator for specified format."""

    @staticmethod
    def get_supported_formats() -> List[str]:
        """Get list of supported report formats."""
```

**Supported Formats:**
- Console output
- Markdown
- HTML
- JSON
- PDF
- SARIF (Static Analysis Results Interchange Format)

### TemplateEngine

Template-based report generation.

```python
class TemplateEngine:
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.jinja_env = self._setup_jinja()

    def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render template with context."""

    def create_custom_template(self, template_name: str, content: str) -> None:
        """Create custom template."""
```

**Template Features:**
- Jinja2 templating
- Custom templates
- Template inheritance
- Dynamic content generation

## Configuration Examples

### Basic Configuration

```yaml
# config.yaml
analyzer:
  severity_threshold: "medium"
  max_file_size: 10485760  # 10MB
  concurrent_limit: 5
  cache_enabled: true
  cache_ttl: 3600

report:
  formats: ["console", "markdown", "html"]
  output_dir: "./reports"
  include_code_snippets: true
  include_remediation: true

security:
  enable_privacy_check: true
  enable_code_sanitization: false
  allowed_file_extensions: [".py", ".js", ".ts"]
  blocked_patterns: ["*.pyc", "__pycache__", "*.so"]

monitoring:
  enabled: true
  export_metrics: true
  metrics_format: "json"

plugins:
  plugin_dir: "./plugins"
  auto_load: true
```

### Production Configuration

```yaml
# config.prod.yaml
analyzer:
  severity_threshold: "low"
  max_file_size: 52428800  # 50MB
  concurrent_limit: 10
  ai_model: "gpt-4o-mini"
  api_timeout: 120
  max_retries: 5

security:
  enable_privacy_check: true
  enable_code_sanitization: true
  allowed_file_extensions: [".py", ".js", ".ts", ".java", ".cpp"]

cache:
  cache_dir: "/var/cache/codesentinel"
  ttl: 7200  # 2 hours
  max_size: "1GB"

monitoring:
  enabled: true
  metrics_endpoint: "http://metrics:9090"
  alert_threshold: 100
```

## Usage Examples

### Configuration Management

```python
from src.infrastructure.config_manager import ConfigManager

# Load configuration
config_manager = ConfigManager("config.yaml")
config = config_manager.load_config()

# Access configuration
severity_threshold = config_manager.get("analyzer.severity_threshold", "low")
config_manager.set("analyzer.concurrent_limit", 10)
```

### Caching Results

```python
from src.infrastructure.cache_manager import CacheManager

# Setup cache
cache_manager = CacheManager(cache_dir=".analysis_cache", ttl=3600)

# Cache analysis result
file_hash = hashlib.sha256(content.encode()).hexdigest()
cache_manager.cache_result(file_hash, analysis_result)

# Retrieve cached result
cached_result = cache_manager.get_cached_result(file_hash)
if cached_result and cache_manager.is_cache_valid(file_path, file_hash):
    return cached_result
```

### Error Handling

```python
from src.infrastructure.error_handler import ErrorHandler

error_handler = ErrorHandler()

try:
    result = await analyze_file(file_path)
except Exception as e:
    error_info = error_handler.handle_error(e, {"file": str(file_path)})
    suggestions = error_handler.get_error_suggestions(type(e).__name__)
    print(f"Error: {error_info['message']}")
    print("Suggestions:")
    for suggestion in suggestions:
        print(f"- {suggestion}")
```