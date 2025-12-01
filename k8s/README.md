# Kubernetes Deployment Guide for Cybersecurity Platform

This guide provides comprehensive instructions for deploying the cybersecurity platform to Kubernetes clusters.

## Overview

The Cybersecurity Platform consists of:
- **Frontend**: Next.js dashboard (port 3000)
- **Backend**: Main Flask API orchestrator (port 5000)
- **8 Microservices**: Specialized security services (ports 5001-5008)
- **Data Layer**: PostgreSQL, Redis
- **ELK Stack**: Elasticsearch, Logstash, Kibana, Filebeat
- **Monitoring**: HPA, Network Policies, Pod Disruption Budgets

## Prerequisites

### Required Tools
- `kubectl` (Kubernetes CLI)
- `docker` (Container runtime)
- `kustomize` (optional, kubectl has built-in support)
- Access to a Kubernetes cluster

### Kubernetes Cluster Requirements
- **Minimum**: 4 CPU cores, 8GB RAM, 50GB storage
- **Recommended**: 8 CPU cores, 16GB RAM, 100GB storage
- **Ingress Controller**: NGINX Ingress Controller
- **Storage Class**: Default storage class configured

## Quick Start

### 1. Clone and Navigate
```bash
git clone <repository-url>
cd Cybersecurity-Project
```

### 2. Build Docker Images
```bash
# Build all images
./k8s/scripts/deploy.sh

# Or build individually
docker build -t cybersecurity-backend:latest ./backend
docker build -t cybersecurity-frontend:latest ./frontend
# ... (see full build commands in deploy.sh)
```

### 3. Deploy to Development Environment
```bash
# Deploy with automatic image building
./k8s/scripts/deploy.sh --environment=development

# Deploy without rebuilding images
./k8s/scripts/deploy.sh --skip-build --environment=development
```

### 4. Deploy to Production Environment
```bash
./k8s/scripts/deploy.sh --environment=production --tag=v1.0.0
```

## Detailed Deployment Steps

### Step 1: Prepare Docker Images

Build all required Docker images:

```bash
# Backend services
docker build -t cybersecurity-backend:latest ./backend
docker build -t cybersecurity-behavioral-analysis:latest ./backend/behavioral_analysis
docker build -t cybersecurity-decoy-generator:latest ./backend/decoy_generator
docker build -t cybersecurity-traffic-monitor:latest ./backend/traffic_monitor
docker build -t cybersecurity-threat-attribution:latest ./backend/threat_attribution
docker build -t cybersecurity-visualization-dashboard:latest ./backend/visualization_dashboard
docker build -t cybersecurity-threat-intelligence:latest ./backend/threat_intelligence
docker build -t cybersecurity-adaptive-deception:latest ./backend/adaptive_deception
docker build -t cybersecurity-evaluation-engine:latest ./evaluation

# Frontend
docker build -t cybersecurity-frontend:latest ./frontend
```

### Step 2: Configure Environment

Update configuration for your environment:

#### Development Environment
```bash
# Edit development configuration
vim k8s/overlays/development/development-patches.yaml
```

#### Production Environment
```bash
# Edit production configuration
vim k8s/overlays/production/production-patches.yaml

# Update secrets with production values
kubectl create secret generic cybersecurity-secrets \
  --from-literal=POSTGRES_PASSWORD=your-secure-password \
  --from-literal=JWT_SECRET_KEY=your-jwt-secret \
  --from-literal=DATABASE_URL=postgresql://postgres:your-secure-password@postgresql:5432/cybersecurity \
  -n cybersecurity-platform --dry-run=client -o yaml > k8s/base/secrets.yaml
```

### Step 3: Deploy Infrastructure

Deploy the platform using Kustomize:

```bash
# Create namespace
kubectl apply -f k8s/base/namespace.yaml

# Deploy development environment
kubectl apply -k k8s/overlays/development

# Or deploy production environment
kubectl apply -k k8s/overlays/production
```

### Step 4: Verify Deployment

Check deployment status:

```bash
# Check all pods
kubectl get pods -n cybersecurity-platform

# Check services
kubectl get services -n cybersecurity-platform

# Check ingress
kubectl get ingress -n cybersecurity-platform

# Check logs
kubectl logs -f -n cybersecurity-platform -l app=backend
```

## Local Development Setup

### Using minikube

```bash
# Start minikube with sufficient resources
minikube start --cpus=4 --memory=8192 --disk-size=50g

# Enable ingress addon
minikube addons enable ingress

# Deploy the platform
./k8s/scripts/deploy.sh --environment=development

# Get minikube IP and add to /etc/hosts
minikube ip
# Add to /etc/hosts: <minikube-ip> cybersecurity.local

# Access the application
open http://cybersecurity.local
```

### Using kind (Kubernetes in Docker)

```bash
# Create kind cluster
kind create cluster --config=k8s/scripts/kind-config.yaml

# Install NGINX Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# Deploy the platform
./k8s/scripts/deploy.sh --environment=development

# Port forward for local access
kubectl port-forward -n cybersecurity-platform svc/frontend 3000:3000
```

## Configuration Management

### Environment Variables

Key configuration is managed through ConfigMaps and Secrets:

- **ConfigMap**: `cybersecurity-config` - Non-sensitive configuration
- **Secret**: `cybersecurity-secrets` - Sensitive data (passwords, keys)

### Persistent Storage

The platform uses multiple persistent volumes:

- **PostgreSQL**: 10Gi for database storage
- **Redis**: 5Gi for cache persistence
- **Elasticsearch**: 20Gi for log storage
- **Models**: 10Gi for ML models (shared across services)
- **Logs**: 15Gi for application logs (shared across services)

### Service Configuration

Each service can be configured through environment variables and ConfigMaps. See individual service documentation for specific configuration options.

## Scaling and Performance

### Horizontal Pod Autoscaling

HPA is configured for critical services:

```bash
# Check HPA status
kubectl get hpa -n cybersecurity-platform

# Scale manually if needed
kubectl scale deployment backend --replicas=5 -n cybersecurity-platform
```

### Resource Limits

Default resource limits are configured conservatively. Adjust based on your cluster capacity:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Security Configuration

### Network Policies

Network policies restrict inter-pod communication:

- Database access limited to backend services
- Redis accessible to all services
- External access controlled through ingress

### RBAC

Role-based access control is configured for:

- **decoy-generator**: Needs permissions to create pods/services
- **filebeat**: Needs cluster-wide read access for log collection

### Security Contexts

Services run with minimal privileges:

- Non-root users where possible
- Specific capabilities only when required (NET_ADMIN for traffic monitoring)

## Monitoring and Logging

### ELK Stack

Centralized logging is provided by:

- **Elasticsearch**: Log storage and indexing
- **Logstash**: Log processing pipeline
- **Kibana**: Log visualization dashboard
- **Filebeat**: Log collection agent (DaemonSet)

Access Kibana at: `http://cybersecurity.local/kibana`

### Health Checks

All services include:

- **Liveness probes**: Restart unhealthy containers
- **Readiness probes**: Control traffic routing
- **Startup probes**: Handle slow-starting containers

## Troubleshooting

### Common Issues

#### Pods Stuck in Pending
```bash
# Check resource availability
kubectl describe nodes

# Check PVC binding
kubectl get pv,pvc -n cybersecurity-platform

# Check events
kubectl get events -n cybersecurity-platform --sort-by='.lastTimestamp'
```

#### Services Not Accessible
```bash
# Check ingress configuration
kubectl describe ingress cybersecurity-ingress -n cybersecurity-platform

# Check service endpoints
kubectl get endpoints -n cybersecurity-platform

# Port forward for debugging
kubectl port-forward -n cybersecurity-platform svc/backend 5000:5000
```

#### Database Connection Issues
```bash
# Check PostgreSQL pod
kubectl logs -n cybersecurity-platform -l app=postgresql

# Test database connectivity
kubectl exec -it -n cybersecurity-platform deployment/backend -- python -c "
import psycopg2
conn = psycopg2.connect(
    host='postgresql',
    database='cybersecurity',
    user='postgres',
    password='cybersec123!'
)
print('Database connection successful')
"
```

### Log Collection

```bash
# Collect all logs
kubectl logs -n cybersecurity-platform --all-containers=true --previous=false > platform-logs.txt

# Monitor real-time logs
kubectl logs -f -n cybersecurity-platform -l app=backend
```

## Backup and Recovery

### Database Backup
```bash
# Create database backup
kubectl exec -n cybersecurity-platform deployment/postgresql -- pg_dump -U postgres cybersecurity > backup.sql

# Restore database
kubectl exec -i -n cybersecurity-platform deployment/postgresql -- psql -U postgres cybersecurity < backup.sql
```

### Persistent Volume Backup
```bash
# Backup persistent volumes (example for PostgreSQL)
kubectl create job postgres-backup -n cybersecurity-platform --image=postgres:13 -- \
  sh -c 'pg_dump -h postgresql -U postgres cybersecurity > /backup/db-backup-$(date +%Y%m%d).sql'
```

## Cleanup

### Remove Deployment
```bash
# Remove everything
./k8s/scripts/deploy.sh --cleanup

# Or remove manually
kubectl delete namespace cybersecurity-platform
```

### Clean Docker Images
```bash
# Remove all cybersecurity images
docker images | grep cybersecurity | awk '{print $1":"$2}' | xargs docker rmi
```

## Production Considerations

### High Availability

For production deployment:

1. **Multi-node cluster**: Deploy across multiple availability zones
2. **Database clustering**: Consider PostgreSQL clustering
3. **Redis clustering**: Use Redis Sentinel or Cluster mode
4. **Elasticsearch clustering**: Configure multi-node Elasticsearch

### Security Hardening

1. **TLS termination**: Configure SSL certificates
2. **Network segmentation**: Use dedicated subnets
3. **Secret management**: Use external secret management (HashiCorp Vault, AWS Secrets Manager)
4. **Image security**: Scan images for vulnerabilities

### Monitoring

1. **Prometheus**: Deploy Prometheus for metrics collection
2. **Grafana**: Set up dashboards for system monitoring
3. **Alerting**: Configure alerts for system health

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Deploy to Kubernetes
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Build and deploy
      run: |
        ./k8s/scripts/deploy.sh --environment=production --tag=${{ github.sha }}
```

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review pod logs and events
3. Verify cluster resources and configuration
4. Consult individual service documentation

---

**Note**: This deployment creates a complete cybersecurity platform with advanced threat detection, deception, and analysis capabilities. Ensure adequate cluster resources and security configuration for production use.