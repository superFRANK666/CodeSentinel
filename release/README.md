# Release Directory

This directory contains built artifacts ready for distribution.

## Purpose

The `release/` directory contains:
- Compiled binaries and executables
- Distribution packages (wheel, tar.gz, etc.)
- Docker images (exported)
- Installation scripts
- Version-specific release artifacts

## Generation

Release artifacts are generated using:

```bash
# Python package build
python -m build

# Docker image build
docker build -t codesentinel:latest .

# Export Docker image
docker save codesentinel:latest > release/codesentinel-latest.tar
```

## Current Contents

*(This directory is currently empty - release artifacts will be added here)*

## Versioning

Each release should be properly versioned and include corresponding checksum files for integrity verification.