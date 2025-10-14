<p align="right"><a href="README.zh-CN.md">简体中文</a></p>

# CodeSentinel: AI-Powered Multi-Language Code Security Auditor

<div align="center">

![CodeSentinel Logo](https://img.shields.io/badge/CodeSentinel-v2.0-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.10+-green?style=for-the-badge&logo=python)](https://python.org)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?style=for-the-badge&logo=javascript)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)

**Advanced AI-powered security auditing tool for Python and JavaScript**

CodeSentinel combines local static analysis, AI-powered deep inspection, and industry-standard tools to provide comprehensive vulnerability detection for modern codebases.

</div>

## ✨ Key Features

### 🌍 Multi-Language Support
- **Python**: Full AST analysis, taint analysis, and AI-powered inspection
- **JavaScript**: ESLint integration with security-focused rules
- **Auto-Detection**: Automatically identifies file types and selects appropriate analyzers

### 🔍 Advanced Analysis Capabilities
- **Hybrid Analysis Engine**: Combines AST/Taint analysis speed with AI deep inspection
- **Multiple Analyzer Modes**: `local`, `ai`, `hybrid`, and `multi_language` modes
- **Real-time Vulnerability Detection**: Comprehensive security pattern matching

### 🛡️ Comprehensive Vulnerability Coverage
- **Injection Attacks**: SQL, Command, Code Injection
- **Web Security**: XSS, CSRF, Path Traversal
- **Crypto Issues**: Weak algorithms, insecure randomness
- **Data Exposure**: Hardcoded secrets, sensitive data leakage
- **JavaScript-specific**: eval() usage, prototype pollution, unsafe dynamic code

### 🚀 Performance & Usability
- **Intelligent Caching**: Dramatically speeds up subsequent scans
- **Parallel Processing**: Concurrent analysis of multiple files
- **Rich Reporting**: Console, Markdown, JSON, HTML, XML formats
- **Progress Tracking**: Real-time analysis progress indication

### 🔧 Extensibility
- **Plugin Architecture**: Easy addition of new analyzers and reporters
- **Configurable Rules**: Customizable security rule sets
- **CI/CD Integration**: Perfect for automated security pipelines

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

The project is organized into a clean, layered architecture:

```
CodeSentinel/
├── config/                # Default configuration files
├── docs/                  # Documentation and examples
├── src/
│   ├── application/       # Core application logic (analyzers, report generators)
│   ├── core/              # Core components (interfaces, container, base classes)
│   └── infrastructure/    # Supporting modules (config, cache, UI, etc.)
├── .gitignore
├── main.py                # Main CLI entry point
├── requirements.txt       # Project dependencies
└── .env                   # Environment variables (you create this)
```

## Configuration

-   **Environment Variables**: The primary way to configure secrets like the OpenAI API key is through the `.env` file in the project root.
-   **JSON Configuration**: Default behaviors (like analyzer settings, report formats, etc.) are defined in `config/default.json`. You can create a custom `config.json` to override these settings.

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

### Development Setup
```bash
# Clone and install development dependencies
git clone https://github.com/superFRANK666/CodeSentinel.git
cd CodeSentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Run tests
python -m pytest tests/

# Run code quality checks
flake8 src/
mypy src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [ESLint](https://eslint.org/) - JavaScript analysis engine
- [OpenAI](https://openai.com/) - AI-powered code analysis
- The Python security community for inspiration and feedback

---

<div align="center">

**⭐ Star this repository if it helped you!**

[🐛 Report Bug](https://github.com/superFRANK666/CodeSentinel/issues) | [💡 Feature Request](https://github.com/superFRANK666/CodeSentinel/issues/new) | [📖 Documentation](https://github.com/superFRANK666/CodeSentinel/wiki)

</div>