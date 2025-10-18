@echo off
REM CodeSentinel Development Setup Script (Windows)
REM This script sets up the development environment for CodeSentinel

echo 🚀 Setting up CodeSentinel development environment...

REM Check Python version
python --version > temp_version.txt 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.10 or higher from https://python.org/
    del temp_version.txt
    exit /b 1
)

for /f "tokens=2" %%i in (temp_version.txt) do set python_version=%%i
del temp_version.txt

echo ✅ Python version check passed: %python_version%

REM Create virtual environment
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo ⬆️ Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo 📥 Installing dependencies...
pip install -r requirements.txt
pip install -r requirements-dev.txt

REM Install pre-commit hooks
echo 🪝 Setting up pre-commit hooks...
pre-commit install

REM Check Node.js and npm (for JavaScript analysis)
node --version >temp_node.txt 2>&1
if %errorlevel% equ 0 (
    echo ✅ Node.js and npm found
    for /f "tokens=*" %%i in (temp_node.txt) do set node_version=%%i
    echo 📌 Node.js version: %node_version%
    del temp_node.txt

    REM Install ESLint globally
    echo 📥 Installing ESLint globally...
    npm install -g eslint eslint-plugin-security
) else (
    echo ⚠️ Node.js and npm not found. JavaScript analysis features will not be available.
    echo    Install Node.js from https://nodejs.org/ to enable full functionality.
    del temp_node.txt 2>nul
)

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo 📝 Creating .env file from template...
    if exist ".env.example" (
        copy .env.example .env >nul
    ) else (
        echo # OpenAI API Key (required for AI analysis) > .env
        echo OPENAI_API_KEY=your-openai-api-key-here >> .env
        echo. >> .env
        echo # Optional: Custom OpenAI base URL >> .env
        echo OPENAI_BASE_URL=https://api.openai.com/v1 >> .env
        echo. >> .env
        echo # AI Model (optional, default: gpt-4o-mini) >> .env
        echo OPENAI_MODEL=gpt-4o-mini >> .env
        echo. >> .env
        echo # Request timeout in seconds (optional, default: 60) >> .env
        echo REQUEST_TIMEOUT=60 >> .env
        echo. >> .env
        echo # Maximum retry attempts (optional, default: 3) >> .env
        echo MAX_RETRIES=3 >> .env
        echo. >> .env
        echo # Log level (optional, values: DEBUG, INFO, WARNING, ERROR) >> .env
        echo LOG_LEVEL=INFO >> .env
        echo. >> .env
        echo # Enable verbose logging (optional, true/false) >> .env
        echo VERBOSE_LOGGING=false >> .env
    )
    echo 📝 .env file created. Please edit it to add your OpenAI API key.
)

REM Run tests to verify setup
echo 🧪 Running tests to verify setup...
pytest tests/ --tb=short
if %errorlevel% equ 0 (
    echo ✅ All tests passed!
) else (
    echo ❌ Some tests failed. Please check the output above.
    exit /b 1
)

REM Run code quality checks
echo 🔍 Running code quality checks...
echo Running black...
black --check src/ tests/ || echo ⚠️ Black formatting issues found. Run 'black src/ tests/' to fix.
echo Running isort...
isort --check-only src/ tests/ || echo ⚠️ Import sorting issues found. Run 'isort src/ tests/' to fix.
echo Running flake8...
flake8 src/ tests/ || echo ⚠️ Flake8 issues found.
echo Running mypy...
mypy src/ || echo ⚠️ MyPy type checking issues found.

echo.
echo 🎉 Development environment setup complete!
echo.
echo Next steps:
echo 1. Edit .env file to add your OpenAI API key
echo 2. Activate the virtual environment: venv\Scripts\activate.bat
echo 3. Run the tool: python main.py --help
echo 4. For development guidelines, see CONTRIBUTING.md
echo.
echo Useful commands:
echo - Activate venv: venv\Scripts\activate.bat
echo - Run tests: pytest
echo - Format code: black src/ tests/ ^&^& isort src/ tests/
echo - Type check: mypy src/
echo - Lint: flake8 src/ tests/
echo - Security check: bandit -r src/

pause