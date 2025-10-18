#!/bin/bash
# CodeSentinel Development Setup Script
# This script sets up the development environment for CodeSentinel

set -e  # Exit on any error

echo "🚀 Setting up CodeSentinel development environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.10 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
pre-commit install

# Check Node.js and npm (for JavaScript analysis)
if command -v node &> /dev/null && command -v npm &> /dev/null; then
    echo "✅ Node.js and npm found"
    node_version=$(node --version)
    echo "📌 Node.js version: $node_version"

    # Install ESLint globally
    echo "📥 Installing ESLint globally..."
    npm install -g eslint eslint-plugin-security
else
    echo "⚠️ Node.js and npm not found. JavaScript analysis features will not be available."
    echo "   Install Node.js from https://nodejs.org/ to enable full functionality."
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env 2>/dev/null || cat > .env << EOF
# OpenAI API Key (required for AI analysis)
OPENAI_API_KEY=your-openai-api-key-here

# Optional: Custom OpenAI base URL
OPENAI_BASE_URL=https://api.openai.com/v1

# AI Model (optional, default: gpt-4o-mini)
OPENAI_MODEL=gpt-4o-mini

# Request timeout in seconds (optional, default: 60)
REQUEST_TIMEOUT=60

# Maximum retry attempts (optional, default: 3)
MAX_RETRIES=3

# Log level (optional, values: DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO

# Enable verbose logging (optional, true/false)
VERBOSE_LOGGING=false
EOF
    echo "📝 .env file created. Please edit it to add your OpenAI API key."
fi

# Run tests to verify setup
echo "🧪 Running tests to verify setup..."
if pytest tests/ --tb=short; then
    echo "✅ All tests passed!"
else
    echo "❌ Some tests failed. Please check the output above."
    exit 1
fi

# Run code quality checks
echo "🔍 Running code quality checks..."
echo "Running black..."
black --check src/ tests/ || echo "⚠️ Black formatting issues found. Run 'black src/ tests/' to fix."
echo "Running isort..."
isort --check-only src/ tests/ || echo "⚠️ Import sorting issues found. Run 'isort src/ tests/' to fix."
echo "Running flake8..."
flake8 src/ tests/ || echo "⚠️ Flake8 issues found."
echo "Running mypy..."
mypy src/ || echo "⚠️ MyPy type checking issues found."

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file to add your OpenAI API key"
echo "2. Activate the virtual environment: source venv/bin/activate"
echo "3. Run the tool: python main.py --help"
echo "4. For development guidelines, see CONTRIBUTING.md"
echo ""
echo "Useful commands:"
echo "- Activate venv: source venv/bin/activate"
echo "- Run tests: pytest"
echo "- Format code: black src/ tests/ && isort src/ tests/"
echo "- Type check: mypy src/"
echo "- Lint: flake8 src/ tests/"
echo "- Security check: bandit -r src/"