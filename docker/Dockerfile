# Security Scanner Dockerfile
# Multi-stage build for smaller final image

# =============================================================================
# Builder stage - install Python dependencies
# =============================================================================
FROM python:3.12-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev

WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# =============================================================================
# Production stage
# =============================================================================
FROM python:3.12-alpine

LABEL maintainer="LdesignMedia"
LABEL description="Home Network Security Scanner"
LABEL version="1.0.0"

# Install runtime dependencies
# - nmap: Port scanning (used for UDP)
# - nmap-scripts: Additional nmap scripts
# - libcap: Linux capabilities support
# - tzdata: Timezone support
# - wget/unzip: For downloading and extracting Rustscan
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    libcap \
    tzdata \
    wget \
    unzip

# Install Rustscan for fast TCP port scanning
# Rustscan scans all 65535 ports in seconds vs minutes with nmap
RUN wget -q https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip \
    && unzip -q x86_64-linux-rustscan.tar.gz.zip \
    && tar -xzf x86_64-linux-rustscan.tar.gz \
    && mv rustscan /usr/local/bin/ \
    && rm -f x86_64-linux-rustscan.tar.gz.zip x86_64-linux-rustscan.tar.gz \
    && chmod +x /usr/local/bin/rustscan

# Copy Python dependencies from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source
COPY src/ ./src/

# Create data directory for database and logs
RUN mkdir -p /app/data

# Create template and static directories
RUN mkdir -p /app/src/web/templates /app/src/web/static/css /app/src/web/static/js

# Copy web assets
COPY src/web/templates/ /app/src/web/templates/
COPY src/web/static/ /app/src/web/static/

# Note: Running as root inside container because nmap SYN scans and UDP scans
# require root privileges. The container is isolated so this is safe.
# Capabilities (setcap) don't work reliably in Docker.

# Expose web port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TARGET_HOST=example.com \
    SCAN_INTERVAL_HOURS=2 \
    LOG_LEVEL=INFO

# Run the application
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
