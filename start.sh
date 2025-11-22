#!/bin/bash

# Cybersecurity System Startup Script
echo "🚀 Starting Modular Containerized Cybersecurity System..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p data/{logs,models,training,decoys,stix_data,results}
mkdir -p frontend/.next
mkdir -p backend/logs

# Set proper permissions
chmod -R 755 data/
chmod -R 755 frontend/
chmod -R 755 backend/

# Build and start all services
echo "🔨 Building and starting all services..."
docker-compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Check service health
echo "🏥 Checking service health..."
services=(
    "frontend:3000"
    "backend:5000"
    "behavioral_analysis:5001"
    "decoy_generator:5002"
    "traffic_monitor:5003"
    "threat_attribution:5004"
    "visualization_dashboard:5005"
    "threat_intelligence:5006"
    "evaluation_engine:5007"
)

for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    echo "Checking $name..."
    
    # Try to connect to the service
    if curl -f -s "http://localhost:$port/health" > /dev/null 2>&1; then
        echo "✅ $name is healthy"
    else
        echo "⚠️  $name may not be ready yet"
    fi
done

# Display access information
echo ""
echo "🎉 Cybersecurity System is starting up!"
echo ""
echo "📊 Access Points:"
echo "   Frontend Dashboard:     http://localhost:3000"
echo "   Backend API:           http://localhost:5000"
echo "   Visualization Dashboard: http://localhost:5005"
echo "   Evaluation Engine:     http://localhost:5007"
echo ""
echo "🔧 Service Ports:"
echo "   Behavioral Analysis:   5001"
echo "   Decoy Generator:       5002"
echo "   Traffic Monitor:       5003"
echo "   Threat Attribution:    5004"
echo "   Threat Intelligence:   5006"
echo ""
echo "📈 Monitoring:"
echo "   View logs: docker-compose logs -f"
echo "   Stop system: docker-compose down"
echo "   Restart: docker-compose restart"
echo ""
echo "🔍 System Status:"
docker-compose ps

echo ""
echo "✨ System initialization complete!"
echo "   The system will continue to start up in the background."
echo "   Check the logs for any issues: docker-compose logs -f"
