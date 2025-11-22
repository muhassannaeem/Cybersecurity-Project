# Cybersecurity System Deployment Guide

## Overview

This modular, containerized cybersecurity system implements a comprehensive defense-in-depth approach with the following core components:

### Core Components

1. **Behavioral Analysis Engine** - ML models (LSTM, Isolation Forest, Autoencoder) for anomaly detection
2. **Decoy Generator** - Python/Go engine for dynamic honeypot and honeytoken creation
3. **Traffic Monitor** - Zeek and tcpdump integration for real-time network capture
4. **Threat Attribution Module** - MITRE ATT&CK mapping for adversary profiling
5. **Visualization Dashboard** - Flask-based GUI for telemetry and behavioral visualizations
6. **Threat Intelligence Sharing** - STIX/TAXII integration for indicator sharing

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+
- **RAM**: Minimum 8GB, Recommended 16GB+
- **Storage**: Minimum 20GB free space
- **CPU**: 4+ cores recommended

### Required Software
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(unixname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

## Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd cybersecurity-system
chmod +x start.sh
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

### 3. Start the System
```bash
# Run the startup script
./start.sh

# Or manually start with Docker Compose
docker-compose up --build -d
```

### 4. Access the System
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **Visualization Dashboard**: http://localhost:5005
- **Evaluation Engine**: http://localhost:5007

## System Architecture

### Service Ports
| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | Next.js React dashboard |
| Backend | 5000 | Main Flask API |
| Behavioral Analysis | 5001 | ML model inference |
| Decoy Generator | 5002 | Honeypot management |
| Traffic Monitor | 5003 | Network monitoring |
| Threat Attribution | 5004 | MITRE ATT&CK mapping |
| Visualization | 5005 | Dash-based dashboard |
| Threat Intelligence | 5006 | STIX/TAXII sharing |
| Evaluation Engine | 5007 | Testing framework |
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache |

### Data Flow
```
Network Traffic → Traffic Monitor → Behavioral Analysis → Threat Attribution
                                    ↓
Decoy Generator ← Backend API ← Threat Intelligence
                                    ↓
                            Visualization Dashboard
                                    ↓
                            Frontend Dashboard
```

## Component Details

### 1. Behavioral Analysis Engine
**Location**: `backend/behavioral_analysis/`

**Features**:
- LSTM neural networks for sequence-based anomaly detection
- Isolation Forest for unsupervised anomaly detection
- Autoencoder for dimensionality reduction and anomaly detection
- Real-time model inference and scoring
- Model retraining capabilities

**API Endpoints**:
- `GET /health` - Service health check
- `POST /analyze` - Analyze network data
- `POST /train` - Retrain models
- `GET /models` - List available models

### 2. Decoy Generator
**Location**: `backend/decoy_generator/`

**Features**:
- Dynamic honeypot deployment (Web servers, SSH, File shares, IoT)
- Honeytoken generation (credentials, API keys, documents)
- Docker-based containerization
- Adaptive deployment based on threat intelligence

**API Endpoints**:
- `POST /deploy` - Deploy new decoy
- `GET /decoys` - List active decoys
- `DELETE /decoys/{id}` - Remove decoy
- `POST /honeytokens` - Generate honeytokens

### 3. Traffic Monitor
**Location**: `backend/traffic_monitor/`

**Features**:
- Zeek network monitoring
- tcpdump packet capture
- Real-time traffic analysis
- Protocol detection and classification
- Anomaly detection in network flows

**API Endpoints**:
- `POST /start/zeek` - Start Zeek monitoring
- `POST /start/tcpdump` - Start packet capture
- `GET /analyze/zeek` - Analyze Zeek logs
- `GET /statistics` - Get capture statistics

### 4. Threat Attribution Module
**Location**: `backend/threat_attribution/`

**Features**:
- MITRE ATT&CK technique mapping
- Threat actor identification
- Campaign clustering
- Confidence scoring
- Automated attribution reports

**API Endpoints**:
- `POST /map_patterns` - Map indicators to ATT&CK
- `POST /cluster_indicators` - Cluster indicators
- `POST /generate_report` - Generate attribution report
- `GET /mitre_data` - Get MITRE data

### 5. Visualization Dashboard
**Location**: `backend/visualization_dashboard/`

**Features**:
- Real-time threat visualization
- Behavioral analysis charts
- Network traffic graphs
- MITRE ATT&CK mapping visualization
- Interactive dashboards

**Access**: http://localhost:5005

### 6. Threat Intelligence Sharing
**Location**: `backend/threat_intelligence/`

**Features**:
- STIX 2.1 indicator creation
- TAXII 2.0/2.1 server integration
- Automated indicator sharing
- Support for OpenCTI, MISP, AlienVault
- Background sharing threads

**API Endpoints**:
- `POST /share` - Share indicators
- `POST /receive` - Receive indicators
- `GET /statistics` - Sharing statistics
- `GET /stix/indicators` - Get STIX indicators

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://postgres:password@db:5432/cybersecurity

# Redis
REDIS_URL=redis://redis:6379

# API Keys (optional)
OPENCTI_API_KEY=your_opencti_key
MISP_API_KEY=your_misp_key
ALIENVAULT_API_KEY=your_alienvault_key

# System Configuration
FLASK_ENV=development
SECRET_KEY=your_secret_key
```

### Service Configuration
Each service can be configured through environment variables or configuration files in their respective directories.

## Monitoring and Maintenance

### Health Checks
```bash
# Check all services
docker-compose ps

# View logs
docker-compose logs -f

# Check specific service
docker-compose logs -f backend
```

### Performance Monitoring
- **CPU Usage**: Monitor container resource usage
- **Memory Usage**: Check for memory leaks
- **Network Traffic**: Monitor bandwidth usage
- **Storage**: Check disk space usage

### Backup and Recovery
```bash
# Backup database
docker-compose exec db pg_dump -U postgres cybersecurity > backup.sql

# Backup configuration
tar -czf config_backup.tar.gz data/ backend/config/

# Restore database
docker-compose exec -T db psql -U postgres cybersecurity < backup.sql
```

## Security Considerations

### Network Security
- All services communicate over internal Docker network
- External access only through specified ports
- Use reverse proxy for production deployment
- Implement SSL/TLS encryption

### Access Control
- Implement authentication for all APIs
- Use API keys for external integrations
- Regular security updates
- Monitor access logs

### Data Protection
- Encrypt sensitive data at rest
- Secure communication channels
- Regular data backups
- Compliance with data protection regulations

## Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check Docker daemon
   sudo systemctl status docker
   
   # Check available ports
   netstat -tulpn | grep :3000
   
   # View detailed logs
   docker-compose logs -f
   ```

2. **Database connection issues**
   ```bash
   # Check database status
   docker-compose exec db psql -U postgres -c "\l"
   
   # Restart database
   docker-compose restart db
   ```

3. **Memory issues**
   ```bash
   # Check memory usage
   docker stats
   
   # Increase Docker memory limit
   # Edit Docker Desktop settings or /etc/docker/daemon.json
   ```

4. **Network connectivity**
   ```bash
   # Check network connectivity
   docker-compose exec backend ping redis
   
   # Check service discovery
   docker-compose exec backend nslookup redis
   ```

### Performance Optimization

1. **Resource Allocation**
   ```yaml
   # In docker-compose.yml
   services:
     backend:
       deploy:
         resources:
           limits:
             memory: 2G
             cpus: '1.0'
   ```

2. **Caching Strategy**
   - Use Redis for session storage
   - Implement application-level caching
   - Optimize database queries

3. **Scaling**
   ```bash
   # Scale specific services
   docker-compose up --scale backend=3 --scale behavioral_analysis=2
   ```

## Development

### Adding New Components
1. Create service directory in appropriate location
2. Add Dockerfile and requirements.txt
3. Update docker-compose.yml
4. Implement health check endpoint
5. Add to startup script

### Testing
```bash
# Run evaluation tests
curl -X POST http://localhost:5007/suite

# Run specific test
curl -X POST http://localhost:5007/test/network_scanning

# View test results
curl http://localhost:5007/statistics
```

### API Documentation
Each service provides its own API documentation through health check endpoints and inline documentation.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review service logs
3. Check GitHub issues
4. Contact the development team

## License

This project is licensed under the MIT License - see the LICENSE file for details.
