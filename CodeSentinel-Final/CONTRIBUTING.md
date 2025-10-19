# Contributing to CodeSentinel

Thank you for your interest in contributing to CodeSentinel! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher
- Node.js 16 or higher (for JavaScript analysis)
- Git

### Setup Development Environment

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/yourusername/CodeSentinel.git
   cd CodeSentinel
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## 📝 Development Guidelines

### Code Style

We use several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking

Run these tools before committing:
```bash
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/
```

### Testing

- Write tests for all new features
- Maintain test coverage above 70%
- Run tests before committing:
  ```bash
  pytest
  ```

### Commit Messages

Use conventional commit messages:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat: add support for TypeScript analysis

- Add TypeScript file detection
- Implement TypeScript-specific vulnerability patterns
- Add comprehensive tests for TypeScript analyzer
```

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment information**
   - OS and version
   - Python version
   - CodeSentinel version

2. **Steps to reproduce**
   - Clear, step-by-step instructions
   - Sample code that demonstrates the issue

3. **Expected vs actual behavior**
   - What you expected to happen
   - What actually happened

4. **Additional context**
   - Error messages or stack traces
   - Any relevant configuration

## ✨ Feature Requests

For feature requests:

1. **Check existing issues** first to avoid duplicates
2. **Provide a clear description** of the feature
3. **Explain the use case** and why it would be valuable
4. **Consider implementation details** if you have ideas

## 🏗️ Architecture Overview

### Core Components

- **`src/core/`**: Core analysis engine and interfaces
- **`src/application/`**: Application layer and analyzers
- **`src/infrastructure/`**: Infrastructure components (config, caching, etc.)

### Adding New Analyzers

1. **Create analyzer class** in `src/core/analyzers/`
2. **Implement the `ICodeAnalyzer` interface**
3. **Add tests** in `tests/unit/`
4. **Register in `MultiLanguageAnalyzer`** if applicable

### Adding New Vulnerability Patterns

1. **Define pattern in appropriate analyzer**
2. **Create test cases** for the pattern
3. **Update documentation** if needed

## 📖 Documentation

- Update README.md for user-facing changes
- Update inline documentation (docstrings)
- Add examples for new features

## 🔧 Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the coding standards
   - Write tests
   - Update documentation

3. **Run the test suite**
   ```bash
   pytest
   ```

4. **Run code quality checks**
   ```bash
   black src/ tests/
   isort src/ tests/
   flake8 src/ tests/
   mypy src/
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add your feature"
   ```

6. **Push and create a pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📋 Pull Request Process

1. **Ensure all tests pass**
2. **Update documentation** if needed
3. **Add a clear description** of your changes
4. **Link related issues** in the PR description
5. **Wait for code review** and address feedback

## 🏷️ Release Process

Releases are managed by the maintainers:

1. Update version numbers
2. Update CHANGELOG.md
3. Create a Git tag
4. Publish release

## ❓ Getting Help

- **Issues**: Report bugs or request features
- **Discussions**: Ask questions or share ideas
- **Documentation**: Check the docs folder

## 📄 License

By contributing to CodeSentinel, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- Annual project summary

Thank you for contributing to CodeSentinel! 🎉