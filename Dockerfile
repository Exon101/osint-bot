FROM python:3.11-slim

LABEL maintainer="OSINT Bot Contributors"
LABEL description="OSINT Investigation Bot for Telegram - 22 modules for ethical intelligence gathering"
LABEL version="2.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies needed for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set Python environment variables for clean output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# Install Python dependencies first (for Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary runtime directories
RUN mkdir -p logs && \
    chmod 755 logs && \
    touch osint_bot.db && \
    chmod 644 osint_bot.db

# Create non-root user for security
RUN groupadd -r botgroup && \
    useradd -r -g botgroup -d /app -s /sbin/nologin botuser && \
    chown -R botuser:botgroup /app

# Switch to non-root user
USER botuser

# Expose no ports (Telegram bot uses outbound polling only)
# EXPOSE 8080

# Health check: verify Python can import core modules
HEALTHCHECK --interval=120s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "from config import config; print('OK')" || exit 1

# Run the bot
CMD ["python", "main.py"]
