# Multi-stage Dockerfile for Email Security Pipeline
# Optimized for size and security

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash emailsec && \
    mkdir -p /app/logs /app/data && \
    chown -R emailsec:emailsec /app

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/emailsec/.local

# Copy application code
COPY --chown=emailsec:emailsec src/ ./src/
COPY --chown=emailsec:emailsec .env.example ./.env.example

# Set environment variables
ENV PATH=/home/emailsec/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER emailsec

# Health check
HEALTHCHECK --interval=5m --timeout=3s --start-period=30s \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Run the application
CMD ["python3", "src/main.py"]
