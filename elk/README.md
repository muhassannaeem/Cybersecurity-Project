# ELK Stack Configuration for Cybersecurity System

This directory contains all configuration files for the ELK (Elasticsearch, Logstash, Kibana) stack used for centralized logging and monitoring.

## Directory Structure

```
elk/
├── elasticsearch/          # Elasticsearch configuration
│   └── elasticsearch.yml
├── logstash/               # Logstash configuration
│   ├── config/
│   │   └── logstash.yml
│   └── pipeline/
│       └── logstash.conf
├── kibana/                 # Kibana configuration
│   └── kibana.yml
├── filebeat/               # Filebeat configuration
│   └── filebeat.yml
├── dashboards/             # Kibana dashboard exports
│   ├── README.md
│   └── *.json
└── scripts/                # Setup and initialization scripts
    ├── init-elasticsearch.sh
    └── setup-kibana.sh
```

## Services

### Elasticsearch
- **Port**: 9200 (HTTP), 9300 (Transport)
- **Purpose**: Stores and indexes all logs
- **Indices**: `cybersecurity-system-*`, `cybersecurity-threats-*`, `cybersecurity-attacks-*`, `cybersecurity-audit-*`

### Logstash
- **Port**: 5044 (Beats input), 9600 (Monitoring)
- **Purpose**: Processes and enriches logs before sending to Elasticsearch
- **Pipeline**: Parses JSON logs, extracts fields, categorizes by type

### Kibana
- **Port**: 5601
- **Purpose**: Visualization and dashboard interface
- **Access**: http://localhost:5601

### Filebeat
- **Purpose**: Lightweight log shipper that collects logs from containers and files
- **Output**: Sends logs to Logstash on port 5044

## Quick Start

1. **Start ELK services**:
   ```bash
   docker-compose up -d elasticsearch logstash kibana filebeat
   ```

2. **Wait for services to be ready** (may take 1-2 minutes):
   ```bash
   docker-compose logs -f elasticsearch
   # Wait for "started" message
   ```

3. **Initialize Elasticsearch** (optional, runs automatically):
   ```bash
   docker-compose exec elasticsearch bash /scripts/init-elasticsearch.sh
   ```

4. **Access Kibana**:
   - Open http://localhost:5601
   - Create index patterns (see dashboards/README.md)
   - Import dashboards

## Configuration

### Environment Variables

Set these in `docker-compose.yml` or `.env`:

```bash
# Elasticsearch
ES_JAVA_OPTS=-Xms512m -Xmx512m

# Logstash
LS_JAVA_OPTS=-Xmx256m -Xms256m

# Log Levels
LOG_LEVEL=INFO
ENVIRONMENT=development
```

### Log Retention

By default, logs are retained indefinitely. To configure retention:

1. Set up Index Lifecycle Management (ILM) in Elasticsearch
2. Configure retention policies in `init-elasticsearch.sh`
3. Default: 30 days (configurable)

## Monitoring

### Check Service Health

```bash
# Elasticsearch
curl http://localhost:9200/_cluster/health

# Logstash
curl http://localhost:9600/_node/stats

# Kibana
curl http://localhost:5601/api/status
```

### View Logs

```bash
# Elasticsearch logs
docker-compose logs -f elasticsearch

# Logstash logs
docker-compose logs -f logstash

# Filebeat logs
docker-compose logs -f filebeat
```

### Query Elasticsearch

```bash
# Search all logs
curl "http://localhost:9200/cybersecurity-*/_search?pretty"

# Search by service
curl "http://localhost:9200/cybersecurity-system-*/_search?pretty&q=service:backend"

# Search errors
curl "http://localhost:9200/cybersecurity-*/_search?pretty&q=level:ERROR"
```

## Troubleshooting

### No logs appearing in Elasticsearch

1. Check Filebeat is running: `docker-compose ps filebeat`
2. Check Filebeat logs: `docker-compose logs filebeat`
3. Verify Logstash is receiving logs: `docker-compose logs logstash | grep "beats"`
4. Check Elasticsearch indices: `curl http://localhost:9200/_cat/indices`

### Logstash parsing errors

1. Check Logstash logs: `docker-compose logs logstash`
2. Verify log format matches expected JSON structure
3. Check pipeline configuration in `logstash/pipeline/logstash.conf`

### Kibana not showing data

1. Verify index patterns are created
2. Check time range in Kibana (default: Last 24 hours)
3. Verify `@timestamp` field is mapped as date type
4. Check Elasticsearch has data: `curl http://localhost:9200/cybersecurity-*/_count`

### High memory usage

1. Reduce Elasticsearch heap: Set `ES_JAVA_OPTS=-Xms256m -Xmx256m`
2. Reduce Logstash workers: Edit `logstash/config/logstash.yml`
3. Enable log rotation and retention policies

## Production Considerations

For production deployments:

1. **Security**: Enable authentication and SSL/TLS
2. **Persistence**: Use persistent volumes for Elasticsearch data
3. **Scaling**: Use multi-node Elasticsearch cluster
4. **Monitoring**: Set up monitoring for ELK stack itself
5. **Backup**: Configure regular backups of Elasticsearch indices
6. **Resource Limits**: Set appropriate CPU and memory limits

## Additional Resources

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Logstash Documentation](https://www.elastic.co/guide/en/logstash/current/index.html)
- [Kibana Documentation](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)

