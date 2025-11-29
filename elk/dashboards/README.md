# Kibana Dashboards Setup Guide

This directory contains Kibana dashboard configurations for the Cybersecurity System.

## Prerequisites

1. Elasticsearch, Logstash, and Kibana must be running
2. Logs must be flowing into Elasticsearch (check indices: `cybersecurity-*`)
3. Access Kibana at http://localhost:5601

## Setup Steps

### 1. Create Index Patterns

Before importing dashboards, create these index patterns in Kibana:

1. Go to **Stack Management** > **Index Patterns** > **Create index pattern**
2. Create patterns for:
   - `cybersecurity-system-*` (Time field: `@timestamp`)
   - `cybersecurity-threats-*` (Time field: `@timestamp`)
   - `cybersecurity-attacks-*` (Time field: `@timestamp`)
   - `cybersecurity-audit-*` (Time field: `@timestamp`)

### 2. Import Dashboards

1. Go to **Stack Management** > **Saved Objects** > **Import**
2. Import each dashboard JSON file:
   - `service-health-dashboard.json`
   - `threat-detection-dashboard.json`
   - `attack-behavior-dashboard.json`
   - `error-pipeline-dashboard.json`

### 3. Access Dashboards

1. Go to **Dashboard** in Kibana sidebar
2. Open any of the imported dashboards
3. Adjust time range as needed (default: Last 24 hours)

## Dashboard Descriptions

### Service Health Dashboard
- Service uptime and status
- Request rates per service
- Error rates per service
- Response time percentiles

### Threat Detection Dashboard
- Threat detection timeline
- Threat severity distribution
- Top attack types
- Top source IPs
- MITRE ATT&CK technique frequency

### Attack Behavior Dashboard
- Attacker engagement timeline
- Decoy interaction heatmap
- Attack sequence flows
- Attack success/failure rates

### Error & Pipeline Health Dashboard
- Error rate by service
- Threat intelligence sharing errors
- Attribution pipeline errors
- Failed API calls

## Manual Dashboard Creation

If JSON import doesn't work, you can manually create dashboards:

1. Go to **Dashboard** > **Create dashboard**
2. Add visualizations using the saved visualizations
3. Arrange and save the dashboard

## Troubleshooting

- **No data in dashboards**: Check that logs are being indexed in Elasticsearch
- **Missing fields**: Verify index patterns include all required fields
- **Time range issues**: Ensure `@timestamp` field is properly mapped as date type

