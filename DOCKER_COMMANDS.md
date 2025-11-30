# Docker Commands - Cybersecurity Project

## 🔨 Build Commands

### Build all services
```bash
docker-compose build
```

### Build specific service
```bash
docker-compose build backend
docker-compose build frontend
```

### Build without cache (fresh build)
```bash
docker-compose build --no-cache
```

---

## 🚀 Run Commands

### Start all services (foreground)
```bash
docker-compose up
```

### Start all services (background/detached)
```bash
docker-compose up -d
```

### Build and start all services
```bash
docker-compose up --build
```

### Build and start in background
```bash
docker-compose up --build -d
```

### Start specific services only
```bash
docker-compose up backend frontend db redis
```

### Stop all services
```bash
docker-compose down
```

### Stop and remove volumes (clean database)
```bash
docker-compose down -v
```

### Restart a service
```bash
docker-compose restart backend
docker-compose restart frontend
```

---

## 🌐 Service Access Ports

### Main Services
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **API Documentation**: http://localhost:5000/api/docs/swagger/
- **Health Check**: http://localhost:5000/health

### Microservices
- **Behavioral Analysis**: http://localhost:5001
- **Decoy Generator**: http://localhost:5002
- **Traffic Monitor**: http://localhost:5003
- **Threat Attribution**: http://localhost:5004
- **Visualization Dashboard**: http://localhost:5005
- **Threat Intelligence**: http://localhost:5006
- **Adaptive Deception**: http://localhost:5007
- **Evaluation Engine**: http://localhost:5008

### Infrastructure Services
- **PostgreSQL Database**: localhost:5432
  - Database: `cybersecurity`
  - User: `postgres`
  - Password: `12345678`
  
- **Redis**: localhost:6379
  - No password (default)

### ELK Stack (Logging & Monitoring)
- **Kibana**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200
- **Elasticsearch Cluster**: http://localhost:9300
- **Logstash**: localhost:5044 (Beats input)
- **Logstash Monitoring**: http://localhost:9600

---

## 📊 Useful Commands

### View logs
```bash
docker-compose logs -f
```

### View logs for specific service
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f kibana
```

### Check service status
```bash
docker-compose ps
```

### View running containers
```bash
docker ps
```

### Execute command in container
```bash
docker-compose exec backend bash
docker-compose exec db psql -U postgres -d cybersecurity
docker-compose exec redis redis-cli
```
