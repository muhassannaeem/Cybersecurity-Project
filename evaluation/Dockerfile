FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    nmap \
    net-tools \
    iproute2 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install additional tools if needed (these may not be available in all repositories)
RUN apt-get update && apt-get install -y \
    hydra \
    || echo "Hydra not available in repository, will use alternative methods"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/results

# Expose port
EXPOSE 5007

# Run the application
CMD ["python", "evaluation_engine.py"]
