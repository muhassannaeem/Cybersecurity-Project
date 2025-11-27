#!/bin/bash
# Initialize Elasticsearch with index templates and mappings

echo "Waiting for Elasticsearch to be ready..."
until curl -s http://elasticsearch:9200/_cluster/health | grep -q '"status":"green\|yellow"'; do
  sleep 2
done

echo "Elasticsearch is ready. Creating index templates..."

# Create template for cybersecurity logs
curl -X PUT "http://elasticsearch:9200/_template/cybersecurity-logs" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["cybersecurity-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "cybersecurity-policy",
    "index.lifecycle.rollover_alias": "cybersecurity-logs"
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "service": {
        "type": "keyword"
      },
      "level": {
        "type": "keyword"
      },
      "message": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "event_type": {
        "type": "keyword"
      },
      "log_type": {
        "type": "keyword"
      },
      "user_id": {
        "type": "keyword"
      },
      "ip_address": {
        "type": "ip"
      },
      "source.ip": {
        "type": "ip"
      },
      "correlation_id": {
        "type": "keyword"
      },
      "metadata": {
        "type": "object",
        "enabled": true
      },
      "environment": {
        "type": "keyword"
      }
    }
  }
}
'

echo "Index template created successfully!"

