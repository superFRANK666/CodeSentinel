# CodeSentinel Makefile
# This Makefile provides common development tasks for CodeSentinel

.PHONY: help install install-dev test lint format type-check security clean build docker run docs setup

# Default target
help: ## Show this help message
	@echo "CodeSentinel Development Commands"
	@echo "================================"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Installation targets
install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install development dependencies
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

setup: ## Set up development environment (runs setup script)
	@if [ -f "scripts/setup.sh" ]; then \
		bash scripts/setup.sh; \
	elif [ -f "scripts/setup.bat" ]; then \
		scripts/setup.bat; \
	else \
		echo "Setup script not found. Please run manual setup."; \
	fi

# Code quality targets
format: ## Format code with black and isort
	black src/ tests/
	isort src/ tests/

lint: ## Run linting checks
	@echo "Running flake8..."
	flake8 src/ tests/
	@echo "Linting complete!"

type-check: ## Run type checking with mypy
	mypy src/

security: ## Run security checks
	@echo "Running bandit security scan..."
	bandit -r src/
	@echo "Running safety check..."
	safety check
	@echo "Security checks complete!"

check-all: format lint type-check security ## Run all code quality checks

# Testing targets
test: ## Run all tests
	pytest

test-cov: ## Run tests with coverage
	pytest --cov=src --cov-report=html --cov-report=term-missing

test-watch: ## Run tests in watch mode
	pytest-watch

test-specific: ## Run specific test file (usage: make test-specific FILE=test_example.py)
	pytest $(FILE)

# Build targets
clean: ## Clean build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@echo "Clean complete!"

build: clean ## Build the package
	python -m build

build-wheel: clean ## Build wheel package only
	python -m build --wheel

build-sdist: clean ## Build source distribution only
	python -m build --sdist

# Docker targets
docker-build: ## Build Docker image
	docker build -t codesentinel:latest .

docker-run: docker-build ## Run CodeSentinel in Docker
	docker run --rm -it -v $(PWD)/src:/app/src codesentinel:latest --help

docker-test: ## Run tests in Docker
	docker build -t codesentinel-test -f Dockerfile.test .
	docker run --rm codesentinel-test

# Documentation targets
docs: ## Generate documentation
	@echo "Documentation generation not yet implemented"
	@echo "See docs/ directory for existing documentation"

docs-serve: ## Serve documentation locally
	@echo "Documentation serving not yet implemented"
	@echo "Use a local web server to serve docs/ directory"

# Development targets
dev: ## Start development mode (watch for changes)
	@echo "Development mode not yet implemented"
	@echo "Use 'make test-watch' for test watching"

pre-commit: format lint type-check ## Run pre-commit checks
	@echo "Pre-commit checks complete!"

# Release targets
version: ## Show current version
	@grep -E '^version = ' pyproject.toml | cut -d'"' -f2

release-patch: ## Bump patch version
	bump2version patch

release-minor: ## Bump minor version
	bump2version minor

release-major: ## Bump major version
	bump2version major

# Utility targets
tree: ## Show project tree structure
	tree -I '__pycache__|*.pyc|.git|venv|env|node_modules|htmlcov|.pytest_cache|.mypy_cache|build|dist|*.egg-info' -a

deps-update: ## Update dependencies
	pip-compile requirements.in
	pip-compile requirements-dev.in
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

deps-check: ## Check for outdated dependencies
	pip list --outdated

# Quick start targets
quick-test: ## Quick test run (without coverage)
	pytest -x --tb=short

quick-lint: ## Quick lint check (errors only)
	flake8 src/ tests/ --select=E9,F63,F7,F82 --show-source --statistics

quick-format: ## Quick format check only
	black --check --diff src/ tests/