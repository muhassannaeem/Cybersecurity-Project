FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including tcpdump and network tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    wireshark-common \
    tshark \
    net-tools \
    iproute2 \
    curl \
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Install network monitoring tools (tcpdump and tshark)
# Note: Zeek installation removed due to repository issues
RUN echo "Using tcpdump and tshark for network monitoring"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/captures /app/zeek_logs

# Expose port
EXPOSE 5003

# Run the application
CMD ["python", "traffic_monitor.py"]
