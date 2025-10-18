# Analyzers

This module contains the core analyzer implementations for detecting security vulnerabilities in code.

## Base Analyzer

### BaseAnalyzer

Abstract base class for all security analyzers.

```python
class BaseAnalyzer:
    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def analyze_file(
        self,
        file_path: Path,
        severity_filter: SeverityLevel = SeverityLevel.LOW
    ) -> AnalysisResult:
        """Analyze a single file for security vulnerabilities."""

    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed based on configuration."""

    def _calculate_security_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """Calculate security score based on found vulnerabilities."""
```

## Specialized Analyzers

### JavaScriptAnalyzer

Analyzer for JavaScript/TypeScript code using ESLint.

```python
class JavaScriptAnalyzer(BaseAnalyzer):
    def __init__(self, config: AnalyzerConfig):
        super().__init__(config)
        self.eslint_config = self._load_eslint_config()

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Analyze JavaScript/TypeScript files using ESLint."""

    def _run_eslint(self, file_path: Path) -> List[Dict[str, Any]]:
        """Run ESLint on the file and return results."""

    def _parse_eslint_results(self, eslint_results: List[Dict], file_path: Path) -> List[Vulnerability]:
        """Parse ESLint results into Vulnerability objects."""
```

**Supported ESLint Rules:**
- Security-focused rules (no-eval, no-implied-eval, no-new-func)
- Best practices (no-console, debugger, alert)
- Code quality issues (unused-vars, no-unused-vars)

### LargeFileAnalyzer

Analyzer for handling large files that exceed size limits.

```python
class LargeFileAnalyzer(BaseAnalyzer):
    def __init__(self, config: AnalyzerConfig):
        super().__init__(config)
        self.chunk_size = 1024 * 1024  # 1MB chunks

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Analyze large files by processing in chunks."""

    def _analyze_chunk(self, chunk: str, chunk_number: int, file_path: Path) -> List[Vulnerability]:
        """Analyze a chunk of the file."""

    def _get_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Get metadata about the large file."""
```

**Features:**
- Chunked processing for memory efficiency
- Metadata analysis (file type, encoding, structure)
- Pattern matching across chunk boundaries
- Progress reporting for large files

### TaintAnalyzer

Advanced taint analysis for detecting data flow vulnerabilities.

```python
class TaintAnalyzer(BaseAnalyzer):
    def __init__(self, config: AnalyzerConfig):
        super().__init__(config)
        self.taint_sources = self._load_taint_sources()
        self.taint_sinks = self._load_taint_sinks()
        self.sanitizers = self._load_sanitizers()

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Perform taint analysis on the file."""

    def _build_taint_graph(self, ast_tree: AST) -> TaintGraph:
        """Build taint propagation graph from AST."""

    def _trace_data_flow(self, source: TaintNode, sink: TaintNode) -> List[TaintFlow]:
        """Trace data flow from source to sink."""

    def _check_sanitization(self, flow: TaintFlow) -> bool:
        """Check if data flow is properly sanitized."""
```

**Taint Sources:**
- HTTP request parameters
- User input functions
- File reads
- Database queries
- Environment variables

**Taint Sinks:**
- SQL execution
- Command execution
- File operations
- Network operations
- HTML output

## Application Layer Analyzers

### LocalAnalyzer

Local-only analyzer without external dependencies.

```python
class LocalAnalyzer:
    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.base_analyzer = BaseAnalyzer(config)
        self.large_file_analyzer = LargeFileAnalyzer(config)
        self.taint_analyzer = TaintAnalyzer(config)

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Analyze file using local analyzers only."""

    def _select_analyzer(self, file_path: Path, file_size: int) -> BaseAnalyzer:
        """Select appropriate analyzer based on file characteristics."""
```

**Features:**
- No external API dependencies
- Multiple analysis strategies
- Automatic analyzer selection
- Local caching of results

### AIAnalyzer

AI-powered analyzer using language models for advanced detection.

```python
class AIAnalyzer:
    def __init__(self, config: AnalyzerConfig, api_key: str):
        self.config = config
        self.client = OpenAI(api_key=api_key)
        self.prompt_manager = PromptManager()

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Analyze file using AI language models."""

    async def _get_ai_analysis(self, code_content: str, file_path: Path) -> List[Vulnerability]:
        """Get vulnerability analysis from AI model."""

    def _validate_ai_results(self, ai_vulnerabilities: List[Dict]) -> List[Vulnerability]:
        """Validate and filter AI-generated results."""
```

**AI Capabilities:**
- Context-aware vulnerability detection
- Business logic flaw identification
- Complex pattern recognition
- Natural language explanations

### HybridAnalyzer

Combines local and AI analysis for comprehensive coverage.

```python
class HybridAnalyzer:
    def __init__(self, config: AnalyzerConfig, api_key: Optional[str] = None):
        self.config = config
        self.local_analyzer = LocalAnalyzer(config)
        self.ai_analyzer = AIAnalyzer(config, api_key) if api_key else None

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Analyze file using both local and AI methods."""

    def _merge_results(self, local_result: AnalysisResult, ai_result: Optional[AnalysisResult]) -> AnalysisResult:
        """Merge results from different analyzers."""

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
```

**Hybrid Strategy:**
1. Run local analysis first (fast, reliable)
2. Run AI analysis for complex patterns
3. Merge and deduplicate results
4. Prioritize by confidence and severity

### MultiLanguageAnalyzer

Supports multiple programming languages.

```python
class MultiLanguageAnalyzer:
    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.analyzers = {
            '.py': LocalAnalyzer(config),
            '.js': JavaScriptAnalyzer(config),
            '.ts': JavaScriptAnalyzer(config),
            '.jsx': JavaScriptAnalyzer(config),
            '.tsx': JavaScriptAnalyzer(config),
        }

    async def analyze_file(self, file_path: Path, severity_filter: SeverityLevel) -> AnalysisResult:
        """Analyze file based on its language."""

    def _get_language_analyzer(self, file_path: Path) -> Optional[BaseAnalyzer]:
        """Get appropriate analyzer for file language."""
```

**Supported Languages:**
- Python (.py)
- JavaScript (.js)
- TypeScript (.ts, .tsx)
- JSX (.jsx)

## Configuration

### Analyzer Configuration

```python
config = AnalyzerConfig(
    severity_threshold=SeverityLevel.MEDIUM,
    max_file_size=10 * 1024 * 1024,  # 10MB
    concurrent_limit=5,
    cache_enabled=True,
    cache_ttl=3600,
    ai_model="gpt-4o-mini",
    api_timeout=60,
    max_retries=3
)
```

### Rule Configuration

```python
# Custom taint sources
taint_sources = [
    {"function": "input", "module": "builtins"},
    {"function": "request.args.get", "module": "flask"},
    {"function": "query_params", "module": "django.http"},
]

# Custom taint sinks
taint_sinks = [
    {"function": "execute", "module": "sqlite3"},
    {"function": "os.system", "module": "os"},
    {"function": "subprocess.run", "module": "subprocess"},
]
```

## Usage Examples

### Basic Local Analysis

```python
from src.application.local_analyzer import LocalAnalyzer
from src.core.interfaces import AnalyzerConfig, SeverityLevel

# Configure analyzer
config = AnalyzerConfig(severity_threshold=SeverityLevel.MEDIUM)
analyzer = LocalAnalyzer(config)

# Analyze file
result = await analyzer.analyze_file(Path("app.py"), SeverityLevel.MEDIUM)
print(f"Found {len(result.vulnerabilities)} vulnerabilities")
```

### AI-Powered Analysis

```python
from src.application.ai_analyzer import AIAnalyzer
import os

# Configure AI analyzer
config = AnalyzerConfig(ai_model="gpt-4o-mini")
api_key = os.getenv("OPENAI_API_KEY")
analyzer = AIAnalyzer(config, api_key)

# Analyze with AI
result = await analyzer.analyze_file(Path("complex_logic.py"))
for vuln in result.vulnerabilities:
    print(f"{vuln.type}: {vuln.description}")
```

### Hybrid Analysis

```python
from src.application.hybrid_analyzer import HybridAnalyzer

# Use both local and AI analysis
analyzer = HybridAnalyzer(config, api_key)
result = await analyzer.analyze_file(Path("sensitive_app.py"))

# Results include both local and AI findings
print(f"Security score: {result.security_score}")
print(f"Total findings: {len(result.vulnerabilities)}")
```