# =========================================================
# Stage 1: Builder
# =========================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy only dependency file for caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# =========================================================
# Stage 2: Runtime
# =========================================================
FROM python:3.11-slim

# Set timezone to UTC (CRITICAL)
ENV TZ=UTC

WORKDIR /app

# ---------------------------------------------------------
# Install system dependencies: cron + timezone tools
# ---------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata cron ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*


# ---------------------------------------------------------
# Configure timezone to UTC
# ---------------------------------------------------------
RUN ln -sf /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone

# ---------------------------------------------------------
# Copy Python dependencies from builder
# ---------------------------------------------------------
COPY --from=builder /install /usr/local

# ---------------------------------------------------------
# Copy application code
# ---------------------------------------------------------
COPY . .

# ---------------------------------------------------------
# Setup cron job
# ---------------------------------------------------------
COPY cron/2fa-cron /etc/cron.d/2fa-cron
RUN chmod 0644 /etc/cron.d/2fa-cron && \
    crontab /etc/cron.d/2fa-cron

# ---------------------------------------------------------
# Create volume mount points
# ---------------------------------------------------------
RUN mkdir -p /data /cron && \
    chmod 755 /data /cron

# ---------------------------------------------------------
# Expose API Port
# ---------------------------------------------------------
EXPOSE 8080

# ---------------------------------------------------------
# Start cron + API server
# ---------------------------------------------------------
CMD service cron start && python app.py
