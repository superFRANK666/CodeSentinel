<p align="right"><a href="README.zh-CN.md">简体中文</a></p>

# CodeSentinel: AI-Powered Multi-Language Code Security Auditor

<div align="center">

![CodeSentinel Logo](https://img.shields.io/badge/CodeSentinel-v1.0.0-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.10+-green?style=for-the-badge&logo=python)](https://python.org)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?style=for-the-badge&logo=javascript)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)](https://docker.com)

**Advanced AI-powered security auditing tool for Python and JavaScript**

CodeSentinel combines local static analysis, AI-powered deep inspection, and industry-standard tools to provide comprehensive vulnerability detection for modern codebases. Built with a clean, enterprise-grade architecture and enhanced developer experience.

</div>

## ✨ Key Features

### 🌍 Multi-Language Support
- **Python**: Full AST analysis, taint analysis, and AI-powered inspection
- **JavaScript**: ESLint integration with comprehensive security rules (including React support)
- **Auto-Detection**: Automatically identifies file types and selects appropriate analyzers
- **Large File Handling**: Specialized analyzer for large codebases with memory optimization

### 🔍 Advanced Analysis Capabilities
- **Hybrid Analysis Engine**: Combines AST/Taint analysis speed with AI deep inspection
- **Multiple Analyzer Modes**: `local`, `ai`, `hybrid`, and `multi_language` modes
- **Intelligent Caching**: SHA-256 based file caching for dramatic performance improvements
- **Incremental Analysis**: Only analyzes changed files, perfect for CI/CD
- **Real-time Vulnerability Detection**: Comprehensive security pattern matching

### 🛡️ Comprehensive Vulnerability Coverage
- **Injection Attacks**: SQL, Command, Code Injection with advanced detection
- **Web Security**: XSS, CSRF, Path Traversal, prototype pollution
- **Crypto Issues**: Weak algorithms, insecure randomness, timing attacks
- **Data Exposure**: Hardcoded secrets, sensitive data leakage patterns
- **JavaScript-specific**: eval() usage, unsafe dynamic code, object injection
- **Modern Threats**: Detection of latest security vulnerabilities and attack vectors

### 🚀 Performance & Usability
- **Intelligent Caching**: SHA-256 based caching dramatically speeds up subsequent scans
- **Parallel Processing**: Concurrent analysis with configurable worker limits
- **Rich Reporting**: Console, Markdown, JSON, HTML, XML formats with detailed vulnerability reports
- **Progress Tracking**: Real-time analysis progress with animated UI and status indicators
- **Enhanced CLI**: Beautiful ASCII art animations, loading screens, and intuitive error messages

### 🔧 Enterprise-Grade Architecture
- **Dependency Injection**: Clean, testable architecture with proper separation of concerns
- **Layered Design**: Application → Core → Infrastructure layers for maintainability
- **Error Handling**: Comprehensive error management with user-friendly messages and debugging support
- **Container Support**: Docker-ready with multi-stage builds and optimized deployment
- **Plugin Architecture**: Easy addition of new analyzers and reporters
- **CI/CD Integration**: GitHub Actions ready with automated testing and deployment

## 📋 Requirements

### Core Dependencies
- **Python 3.10+**: Core analysis engine
- **Node.js 16+ & npm**: Required for JavaScript analysis via ESLint

### Optional Dependencies
- **OpenAI API Key**: For AI-powered deep analysis (`ai` and `hybrid` modes)

### System Requirements
- **RAM**: Minimum 4GB, recommended 8GB+ for large codebases
- **Storage**: 500MB for installation + space for analysis cache
- **OS**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 18.04+)

## 🚀 Installation

### 1. Clone Repository
```bash
git clone https://github.com/superFRANK666/CodeSentinel.git
cd CodeSentinel
```

### 2. Set Up Python Environment
```bash
# Create virtual environment
python -m venv venv

# Activate environment
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Install ESLint (for JavaScript Analysis)
```bash
# Install ESLint globally
npm install -g eslint

# Install security plugin
npm install -g eslint-plugin-security

# Verify installation
eslint --version
```

### 4. Configure Environment
```bash
# Copy environment template
cp docs/.env.example .env

# Edit .env file with your API key
# OPENAI_API_KEY=your-openai-api-key-here
```

### 5. Verify Installation
```bash
# Test Python analysis
python main.py --help

# Test JavaScript analysis (requires a .js file)
echo "console.log('test');" > test.js
python main.py test.js
rm test.js

# Verify the enhanced CLI with animations
python main.py --version
```

## JavaScript Support

CodeSentinel now supports JavaScript code analysis through ESLint integration. The JavaScript analyzer can detect:

- **Code Injection**: Usage of `eval()`, `new Function()`, and other dangerous eval-like constructs
- **XSS Vulnerabilities**: Unsafe use of `innerHTML`, `document.write()`, and `javascript:` URLs
- **Path Traversal**: Unsafe file system access patterns
- **Insecure Randomness**: Usage of predictable random number generators
- **Object Injection**: Prototype pollution and unsafe object property access
- **Timing Attacks**: Non-constant-time operations on sensitive data

### ESLint Configuration

The project includes a comprehensive ESLint configuration (`.eslintrc.json`) with security-focused rules and the `eslint-plugin-security` plugin for enhanced vulnerability detection.

## 💡 Usage Examples

### Basic Usage
```bash
# Analyze single files
python main.py script.py                    # Python file
python main.py app.js                       # JavaScript file

# Analyze directories (auto-detects file types)
python main.py src/                         # Mixed languages
python main.py frontend/                    # JavaScript/TypeScript
python main.py backend/                     # Python
```

### Advanced Usage
```bash
# Use specific analyzers
python main.py src/ --analyzer local        # Fast local analysis
python main.py src/ --analyzer ai           # AI-powered analysis
python main.py src/ --analyzer hybrid       # Combined approach
python main.py src/ --analyzer multi_language  # Default, auto-detect

# Filter by severity
python main.py src/ --severity high         # High severity only
python main.py src/ --severity medium       # Medium and above
python main.py src/ --severity critical     # Critical only

# Generate reports
python main.py src/ --output report.md --format markdown
python main.py src/ --output report.html --format html
python main.py src/ --output results.json --format json
```

### File Type Filtering
```bash
# Analyze specific file types
python main.py . --include "*.py"           # Python only
python main.py . --include "*.js" --include "*.jsx"  # JavaScript + React
python main.py . --include "*.py" --include "*.js"   # Both languages

# Exclude patterns
python main.py src/ --exclude "test_*" --exclude "__pycache__"
python main.js src/ --exclude "*.min.js" --exclude "node_modules"
```

### Performance Options
```bash
# Show progress and verbose output
python main.py src/ --progress --verbose

# Control concurrency
python main.py src/ --workers 8             # 8 parallel workers

# Cache management
python main.py src/ --no-cache              # Disable caching
python main.py --clear-cache                # Clear existing cache

# Privacy options
python main.py src/ --privacy-mode full     # Enhanced privacy for sensitive code
```

### Quick Start Examples
```bash
# Quick security check of your project
python main.py . --severity high --progress

# Full comprehensive analysis with AI
python main.py . --analyzer hybrid --output full_report.html --format html

# CI/CD integration (fail on critical issues)
python main.py src/ --severity critical --quiet
```

## Project Structure

The project is organized into a clean, layered architecture following enterprise best practices:

```
CodeSentinel/
├── 📁 config/                 # Default configuration files
├── 📁 docs/                   # Comprehensive documentation and examples
│   ├── api/                   # API documentation
│   └── README.md              # Additional docs
├── 📁 examples/               # Usage examples and tutorials
├── 📁 src/
│   ├── 📁 application/        # Core application logic
│   │   ├── ai_analyzer.py     # AI-powered analysis
│   │   ├── hybrid_analyzer.py # Hybrid analysis engine
│   │   ├── local_analyzer.py  # Local static analysis
│   │   ├── multi_language_analyzer.py  # Multi-language support
│   │   └── report_generators.py # Report generation
│   ├── 📁 core/               # Core components and interfaces
│   │   ├── analyzers/         # Specialized analyzers
│   │   ├── container.py       # Dependency injection container
│   │   ├── interfaces.py      # Core interfaces and contracts
│   │   └── input_validator.py # Input validation
│   └── 📁 infrastructure/     # Supporting infrastructure
│       ├── ascii_art.py       # Enhanced UI elements
│       ├── auth_manager.py    # Authentication management
│       ├── cache_manager.py   # Intelligent caching system
│       ├── config_manager.py  # Configuration management
│       ├── error_handler.py   # Comprehensive error handling
│       ├── monitoring.py      # System monitoring
│       ├── plugin_manager.py  # Plugin architecture
│       ├── privacy_manager.py # Privacy and security
│       ├── progress_reporter.py # Progress tracking
│       └── ui_manager.py      # User interface management
├── 📁 tests/                  # Test suite (ready for implementation)
├── 📁 .github/                # GitHub Actions workflows
├── 📁 archive/                # Archived files (not in distribution)
├── 📁 release/                # Release artifacts and builds
├── 📁 scripts/                # Development and setup scripts
├── 🐳 Dockerfile              # Multi-stage Docker build
├── 🐳 docker-compose.yml      # Development environment
├── 📄 Makefile                # Development task automation
├── 📄 MANIFEST.in             # Package distribution manifest
├── 📄 pyproject.toml          # Modern Python package configuration
├── 📄 .flake8                 # Code quality configuration
├── 📄 .gitignore              # Git ignore patterns
├── 📄 LICENSE                 # MIT License
├── 📄 main.py                 # Enhanced CLI entry point
├── 📄 requirements.txt        # Python dependencies
├── 📄 requirements-dev.txt    # Development dependencies
├── 📄 .eslintrc.json          # JavaScript analysis configuration
└── 📄 .env                    # Environment variables (you create this)
```

### Architecture Highlights
- **Clean Architecture**: Separation of concerns with clear layer boundaries
- **Dependency Injection**: Testable, maintainable code structure
- **Plugin System**: Extensible analyzer and reporter architecture
- **Enterprise Ready**: Comprehensive error handling, logging, and monitoring
- **Container Support**: Docker-optimized with multi-stage builds

## 🛠️ Configuration

### Environment Variables
Create a `.env` file in the project root:
```bash
# OpenAI API key (required for AI analysis)
OPENAI_API_KEY=your-openai-api-key-here

# Optional: Custom OpenAI base URL
OPENAI_BASE_URL=https://api.openai.com/v1
```

### Custom Analysis Rules
Create a custom `config.json` to override default settings:
```json
{
  "analyzer": {
    "severity_threshold": "medium",
    "max_file_size": 2048,
    "concurrent_limit": 8
  },
  "security": {
    "allowed_file_extensions": [".py", ".js", ".jsx"],
    "blocked_patterns": ["*.min.js", "node_modules"]
  }
}
```

## 🔧 Troubleshooting

### Common Issues

**ESLint not found**
```bash
# Install ESLint globally
npm install -g eslint eslint-plugin-security

# Or locally in your project
npm install eslint eslint-plugin-security
```

**Python module not found**
```bash
# Ensure you're in the project directory with activated venv
cd CodeSentinel
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

**Memory issues with large codebases**
```bash
# Reduce concurrent workers
python main.py src/ --workers 2

# Exclude large directories
python main.py src/ --exclude "node_modules" --exclude ".git"
```

**AI analysis not working**
1. Check your OpenAI API key in `.env` file
2. Verify API key has sufficient credits
3. Check internet connection
4. Try with local analyzer first: `--analyzer local`

### Debug Mode
Enable verbose logging for troubleshooting:
```bash
python main.py src/ --verbose --progress
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

#### Development Setup
```bash
# Clone and install development dependencies
git clone https://github.com/superFRANK666/CodeSentinel.git
cd CodeSentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Run tests (framework ready for implementation)
python -m pytest tests/

# Run code quality checks
flake8 src/
mypy src/
black src/

# Format code automatically
black --line-length 88 src/

# Check for security issues in dependencies
pip-audit
```

### Docker Development
```bash
# Build development image
docker-compose build

# Run analysis with Docker
docker-compose run codesentinel python main.py src/

# Run tests in container
docker-compose run --rm test
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [ESLint](https://eslint.org/) - JavaScript analysis engine with security plugin
- [OpenAI](https://openai.com/) - AI-powered code analysis
- [Python AST](https://docs.python.org/3/library/ast.html) - Abstract Syntax Tree parsing
- The Python security community for inspiration and feedback


---

<div align="center">

**⭐ Star this repository if it helped you!**

[🐛 Report Bug](https://github.com/superFRANK666/CodeSentinel/issues) | [💡 Feature Request](https://github.com/superFRANK666/CodeSentinel/issues/new) | [📖 Documentation](https://github.com/superFRANK666/CodeSentinel/wiki)

[![CodeSentinel](https://img.shields.io/badge/CodeSentinel-AI%20Powered%20Security%20Auditor-blue?style=for-the-badge)](https://github.com/superFRANK666/CodeSentinel)

</div>