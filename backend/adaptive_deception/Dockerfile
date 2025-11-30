FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/models/adaptive /app/logs

# Copy application code
COPY adaptive_deception.py .

# Copy shared logging configuration if available (conditional)
RUN if [ -f "../logging_config.py" ]; then cp ../logging_config.py .; fi

EXPOSE 5007

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5007/health || exit 1

CMD ["python", "adaptive_deception.py"]