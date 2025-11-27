# ELK Stack Quick Start Guide

## 🚀 Quick Start

### 1. Start ELK Services
```bash
docker-compose up -d elasticsearch logstash kibana filebeat
```

### 2. Wait for Services to Initialize
Wait 1-2 minutes for Elasticsearch to be ready:
```bash
# Check Elasticsearch status
curl http://localhost:9200/_cluster/health

# Or watch logs
docker-compose logs -f elasticsearch
```

### 3. Start Application Services
```bash
docker-compose up -d backend behavioral_analysis decoy_generator traffic_monitor
```

### 4. Generate Some Logs
Make some API calls to generate logs:
```bash
# Health check
curl http://localhost:5000/api/health

# Or use the frontend at http://localhost:3000
```

### 5. Access Kibana
1. Open http://localhost:5601 in your browser
2. You should see the Kibana welcome screen

### 6. Create Index Patterns
1. Go to **Stack Management** > **Index Patterns** > **Create index pattern**
2. Create these patterns (one at a time):
   - Pattern: `cybersecurity-system-*` → Time field: `@timestamp` → Create
   - Pattern: `cybersecurity-threats-*` → Time field: `@timestamp` → Create
   - Pattern: `cybersecurity-attacks-*` → Time field: `@timestamp` → Create
   - Pattern: `cybersecurity-audit-*` → Time field: `@timestamp` → Create

### 7. View Logs
1. Go to **Discover** in Kibana sidebar
2. Select an index pattern (e.g., `cybersecurity-system-*`)
3. Set time range to "Last 24 hours"
4. You should see logs!

### 8. Import Dashboards (Optional)
1. Go to **Stack Management** > **Saved Objects** > **Import**
2. Import dashboards from `elk/dashboards/` directory
3. Or create dashboards manually in **Dashboard** section

## 🔍 Verify Everything Works

### Check Elasticsearch Has Data
```bash
# List indices
curl http://localhost:9200/_cat/indices

# Count logs
curl "http://localhost:9200/cybersecurity-*/_count?pretty"

# Search logs
curl "http://localhost:9200/cybersecurity-system-*/_search?pretty&size=5"
```

### Check Logstash is Processing
```bash
# View Logstash logs
docker-compose logs logstash | tail -20

# Check Logstash stats
curl http://localhost:9600/_node/stats?pretty
```

### Check Filebeat is Shipping
```bash
# View Filebeat logs
docker-compose logs filebeat | tail -20
```

## 📊 Access Points

- **Kibana**: http://localhost:5601
- **Elasticsearch**: http://localhost:9200
- **Logstash Monitoring**: http://localhost:9600/_node/stats

## 🐛 Troubleshooting

### No logs appearing?
1. Check services are running: `docker-compose ps`
2. Check Filebeat logs: `docker-compose logs filebeat`
3. Check Logstash logs: `docker-compose logs logstash`
4. Verify application is generating logs

### Kibana shows no data?
1. Verify index patterns are created
2. Check time range (try "Last 7 days")
3. Verify Elasticsearch has data: `curl http://localhost:9200/cybersecurity-*/_count`

### Services not starting?
1. Check Docker has enough resources (RAM, disk)
2. Check logs: `docker-compose logs <service-name>`
3. Try restarting: `docker-compose restart <service-name>`

## 📚 Next Steps

- Read `elk/README.md` for detailed documentation
- Read `elk/dashboards/README.md` for dashboard setup
- Configure alerts (see `elk/scripts/setup-kibana-alerts.sh`)
- Customize dashboards for your needs

## 💡 Tips

- **Development**: Current setup uses single-node Elasticsearch (good for dev)
- **Production**: Consider multi-node cluster, authentication, SSL/TLS
- **Resource Usage**: ELK stack uses ~2-3GB RAM
- **Log Retention**: Configure ILM policies for log rotation

