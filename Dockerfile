# Multi-stage build for CodeSentinel
FROM python:3.10-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r codesentinel && useradd -r -g codesentinel codesentinel

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Development stage
FROM base as development

# Install development dependencies
RUN pip install -r requirements-dev.txt

# Copy source code
COPY . .

# Install the project in development mode
RUN pip install -e .

# Switch to non-root user
USER codesentinel

# Expose port for potential web interface
EXPOSE 8000

# Default command for development
CMD ["python", "-m", "pytest", "tests/", "-v"]

# Production stage
FROM base as production

# Copy only necessary files for production
COPY src/ ./src/
COPY README.md ./
COPY LICENSE ./
COPY .env.example .env

# Install the project
RUN pip install .

# Create directories for reports and logs
RUN mkdir -p /app/reports /app/logs && \
    chown -R codesentinel:codesentinel /app

# Switch to non-root user
USER codesentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import src.core.container; print('OK')" || exit 1

# Default command
CMD ["python", "-m", "src.main", "--help"]

# Runtime stage for running as a service
FROM production as runtime

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Handle SIGTERM\n\
trap "echo \"SIGTERM received, shutting down...\"; exit 0" SIGTERM\n\
\n\
# Run the main application\n\
if [ "$1" = "analyze" ]; then\n\
    shift\n\
    exec python -m src.main analyze "$@"\n\
elif [ "$1" = "server" ]; then\n\
    shift\n\
    exec python -m src.main server "$@"\n\
else\n\
    exec python -m src.main "$@"\n\
fi'\
' > /app/entrypoint.sh && \
chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]