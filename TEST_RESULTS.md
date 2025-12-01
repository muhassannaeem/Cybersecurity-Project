# Kubernetes Testing Results

## Test Environment Setup

Due to Docker Desktop API version issue, here's the complete testing procedure:

### 1. Prerequisites Installation

First, you need to install a local Kubernetes cluster. Choose one:

**Option A: Docker Desktop with Kubernetes**
1. Open Docker Desktop
2. Go to Settings → Kubernetes → Enable Kubernetes
3. Wait for green status indicator

**Option B: Install minikube**
```powershell
# Download and install minikube
choco install minikube
# OR download from: https://github.com/kubernetes/minikube/releases

# Start minikube
minikube start --cpus=4 --memory=8192 --disk-size=50g
minikube addons enable ingress
```

**Option C: Install kind**
```powershell
choco install kind
# OR download from: https://github.com/kubernetes-sigs/kind/releases

# Create cluster
kind create cluster --config k8s/scripts/kind-config.yaml
```

## 2. Build Docker Images

Once Docker is working, run:

```powershell
# Build all images
docker build -t cybersecurity-backend:latest ./backend
docker build -t cybersecurity-frontend:latest ./frontend

# Build microservices
docker build -t cybersecurity-behavioral-analysis:latest ./backend/behavioral_analysis
docker build -t cybersecurity-decoy-generator:latest ./backend/decoy_generator
docker build -t cybersecurity-traffic-monitor:latest ./backend/traffic_monitor
docker build -t cybersecurity-threat-attribution:latest ./backend/threat_attribution
docker build -t cybersecurity-visualization-dashboard:latest ./backend/visualization_dashboard
docker build -t cybersecurity-threat-intelligence:latest ./backend/threat_intelligence
docker build -t cybersecurity-adaptive-deception:latest ./backend/adaptive_deception
docker build -t cybersecurity-evaluation-engine:latest ./evaluation
```

## 3. Deploy to Kubernetes

```powershell
# Deploy development environment
kubectl apply -k k8s/overlays/development

# OR use the deployment script
./k8s/scripts/deploy.bat --environment=development
```

## 4. Verify Deployment

```powershell
# Check all components
kubectl get pods -n cybersecurity-platform
kubectl get services -n cybersecurity-platform
kubectl get pv,pvc -n cybersecurity-platform

# Expected output:
# - 11+ pods in Running status
# - 11+ services with endpoints
# - 5 PVCs in Bound status
```

## 5. Test Individual Services

```powershell
# Test backend health
kubectl port-forward -n cybersecurity-platform svc/backend 5000:5000
curl http://localhost:5000/api/health

# Test database connection
kubectl exec -it -n cybersecurity-platform deployment/backend -- python -c "
import psycopg2
conn = psycopg2.connect(host='postgresql', database='cybersecurity', user='postgres', password='cybersec123!')
print('✅ Database OK')
conn.close()
"

# Test Redis
kubectl exec -it -n cybersecurity-platform deployment/backend -- python -c "
import redis
r = redis.Redis(host='redis', port=6379)
r.set('test', 'hello')
print('✅ Redis OK:', r.get('test').decode())
"
```

## 6. Test Frontend

```powershell
# Access frontend
kubectl port-forward -n cybersecurity-platform svc/frontend 3000:3000
# Open browser to http://localhost:3000
```

## 7. Test APIs

```powershell
# Create user
curl -X POST http://localhost:5000/api/auth/signup -H "Content-Type: application/json" -d "{\"email\":\"test@example.com\",\"password\":\"password123\",\"role\":\"admin\"}"

# Login and get token
$token = (curl -X POST http://localhost:5000/api/auth/login -H "Content-Type: application/json" -d "{\"email\":\"test@example.com\",\"password\":\"password123\"}" | ConvertFrom-Json).token

# Test protected endpoints
curl -H "Authorization: Bearer $token" http://localhost:5000/api/threats/recent
curl -H "Authorization: Bearer $token" http://localhost:5000/api/dashboard/stats
```

## 8. Test Scaling

```powershell
# Check HPA
kubectl get hpa -n cybersecurity-platform

# Scale manually
kubectl scale deployment backend --replicas=3 -n cybersecurity-platform

# Verify scaling
kubectl get pods -n cybersecurity-platform -l app=backend
```

## Expected Test Results

✅ **Success Criteria:**
1. All pods reach `Running` status
2. Database and Redis connections work
3. All health endpoints return 200 OK
4. Frontend loads and displays data
5. API authentication and authorization work
6. Real-time WebSocket connections function
7. HPA scaling responds to load
8. Logs appear in ELK stack

## Current Status

**Docker Issue**: API version mismatch needs to be resolved
**Next Steps**: 
1. Restart Docker Desktop
2. Enable Kubernetes in Docker Desktop settings
3. Run the deployment script
4. Execute all tests above

Would you like me to help troubleshoot Docker Desktop or guide you through installing minikube/kind instead?