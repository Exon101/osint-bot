# ─────────────────────────────────────────────
# OSINT Bot — Hugging Face Spaces Dockerfile
# ─────────────────────────────────────────────
# Optimized for HF Spaces with:
#   - Webhook mode (bot receives updates via HF public URL)
#   - Persistent storage at /data (SQLite + logs)
#   - Non-root user for security
#   - Health check for automatic restarts
# ─────────────────────────────────────────────

FROM python:3.11-slim

LABEL maintainer="OSINT Bot Contributors"
LABEL description="OSINT Investigation Bot for Telegram - 30+ modules for ethical intelligence gathering"
LABEL version="2.2.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Python env vars
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    TZ=UTC \
    WEBHOOK_MODE=true

# Install Python dependencies (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# ── Persistent Storage Setup ──────────────────
# HF Spaces mounts persistent storage at /data
RUN mkdir -p /data/logs && \
    mkdir -p /app/logs && \
    ln -sf /data/logs /app/logs && \
    touch /data/osint_bot.db && \
    ln -sf /data/osint_bot.db /app/osint_bot.db && \
    chmod -R 777 /data

# Non-root user
RUN groupadd -r botgroup && \
    useradd -r -g botgroup -d /app -s /sbin/nologin botuser && \
    chown -R botuser:botgroup /app /data

USER botuser

# Expose port for HF Spaces webhook
EXPOSE 7860

# Health check (hit the /health endpoint)
HEALTHCHECK --interval=120s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/health')" || exit 1

# Start the bot (will auto-detect webhook mode via WEBHOOK_MODE env var)
CMD ["python", "main.py"]
