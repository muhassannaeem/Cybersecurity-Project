# Kibana Dashboards and Alerts

This directory contains pre-configured Kibana dashboards and alerting rules for the cybersecurity monitoring system.

## 📊 Dashboards

### 1. Service Health Monitoring (`service-health-dashboard.json`)
- **Purpose**: Real-time monitoring of microservice health and performance
- **Visualizations**:
  - Service Logs Count: Log volume per service over time
  - Service Error Rate: Error trends by service (stderr logs and error messages)
  - Service Response Metrics: Active services and log volume metrics
  - Container Status Overview: Distribution of stdout vs stderr logs

### 2. Threat Detection & Analysis (`threat-detection-dashboard.json`)
- **Purpose**: Real-time threat detection patterns and security event monitoring
- **Visualizations**:
  - Threat Activity Timeline: Timeline of threat detection events
  - Behavioral Analysis Patterns: Behavioral analysis activity over time
  - Threat Severity Distribution: Distribution of threat severity levels
  - Attack Pattern Analysis: Analysis of attack patterns by service
  - Security Events: Total security events detected

### 3. Attack Behavior Analysis (`attack-behavior-dashboard.json`)
- **Purpose**: Deep analysis of attack behaviors, patterns, and attribution
- **Visualizations**:
  - Behavioral Analysis Metrics: Processing activity over time
  - Threat Attribution Analysis: Attribution by source IP and patterns
  - Decoy System Interactions: Honeypot activity patterns
  - Network Traffic Analysis: Traffic monitoring metrics
  - Attack Behavior Log Details: Detailed log view of security events

## 🚨 Alert Rules

### Security Alerts (`alerts/security-alerts.json`)

1. **High Service Error Rate**
   - Triggers when >10 errors in 5 minutes
   - Monitors stderr logs and error messages
   - Email notification to admin

2. **Service Down Detection**
   - Triggers when service has <1 log in 10 minutes
   - Critical alert for service availability
   - Email notification to admin and ops teams

3. **Threat Detection Alert**
   - Triggers on any threat-related keywords
   - Real-time monitoring (30s intervals)
   - Email notification to security team

4. **Behavioral Anomaly Detection**
   - Triggers on ≥5 behavioral anomalies in 5 minutes
   - Monitors behavioral analysis service
   - Email notification to analysts

5. **Decoy System Interaction Alert**
   - Triggers immediately on honeypot interactions
   - High-priority security alert
   - Email notification to security team

## 🚀 Installation

### Automatic Installation
```bash
# Run the import script
cd elk/kibana
python import_dashboards.py
```

### Manual Installation

1. **Access Kibana**: http://localhost:5601

2. **Create Index Pattern**:
   - Go to Stack Management > Index Patterns
   - Create pattern: `cybersecurity-system-*`
   - Set time field: `@timestamp`

3. **Import Dashboards**:
   - Go to Stack Management > Saved Objects
   - Click "Import"
   - Upload each dashboard JSON file

4. **Setup Email Connector** (for alerts):
   - Go to Stack Management > Connectors
   - Create new Email connector:
     - Name: "Email Notifications"
     - Type: Email
     - Configure SMTP settings

5. **Import Alert Rules**:
   - Go to Stack Management > Rules and Connectors
   - Import alert rules from JSON files

## 📋 Configuration

### Email Notifications
Update the email connector settings:
```json
{
  "service": "gmail",
  "host": "smtp.gmail.com", 
  "port": 587,
  "from": "your-alerts@company.com",
  "user": "your-alerts@company.com",
  "password": "your-app-password"
}
```

### Alert Thresholds
Adjust thresholds based on your environment:
- **High Error Rate**: Default 10 errors/5min
- **Service Down**: Default <1 log/10min
- **Behavioral Anomaly**: Default 5 anomalies/5min

### Dashboard Time Ranges
- **Service Health**: Last 15 minutes (auto-refresh 10s)
- **Threat Detection**: Last 1 hour (auto-refresh 30s)
- **Attack Behavior**: Last 4 hours (auto-refresh 1min)

## 🔍 Usage Guide

### Viewing Dashboards
1. Open Kibana: http://localhost:5601
2. Go to Analytics > Dashboard
3. Select a dashboard:
   - "Service Health Monitoring"
   - "Threat Detection & Analysis" 
   - "Attack Behavior Analysis"

### Monitoring Alerts
1. Go to Observability > Alerts
2. View active/triggered alerts
3. Check alert history and status

### Analyzing Logs
1. Go to Analytics > Discover
2. Select `cybersecurity-system-*` index
3. Filter by service, time range, or keywords
4. Analyze patterns and anomalies

## 🎯 Key Metrics to Monitor

### Service Health
- Error rate trends
- Log volume patterns
- Service availability
- Container status

### Security Events
- Threat detection frequency
- Behavioral anomalies
- Decoy system interactions
- Attack attribution patterns

### Performance Indicators
- Response times
- Processing volumes
- Error patterns
- System resource usage

## 🔧 Customization

### Adding New Visualizations
1. Create visualizations in Kibana UI
2. Export as JSON
3. Add to dashboard configuration

### Modifying Alert Conditions
1. Edit alert rules in Kibana UI
2. Test with sample data
3. Export updated configuration

### Creating Custom Dashboards
1. Use existing dashboards as templates
2. Customize visualizations and layouts
3. Export for version control

## 📚 Dashboard Field Reference

### Available Log Fields
- `@timestamp`: Event timestamp
- `message`: Log message content
- `container.labels.com_docker_compose_service`: Service name
- `stream`: Log type (stdout/stderr)
- `host.ip`: Source IP address
- `container.id`: Container identifier
- `fields.project`: Project identifier
- `fields.environment`: Environment name

### Service Names
- `backend`: Main Flask application
- `behavioral_analysis`: Behavioral analysis service
- `threat_attribution`: Threat attribution service
- `decoy_generator`: Decoy system service
- `traffic_monitor`: Network traffic monitor
- `threat_intelligence`: Threat intelligence service
- `logstash`: Log processing service

## ⚠️ Troubleshooting

### Import Issues
- Verify Kibana is running: http://localhost:5601
- Check index pattern exists: `cybersecurity-system-*`
- Ensure logs are flowing from ELK pipeline

### Alert Issues
- Configure email connector properly
- Test email connectivity
- Verify alert rule conditions
- Check index permissions

### Dashboard Issues
- Refresh index patterns
- Verify data time ranges
- Check visualization queries
- Confirm field mappings

## 📈 Monitoring Best Practices

1. **Regular Review**: Check dashboards daily
2. **Threshold Tuning**: Adjust based on baseline behavior
3. **Alert Fatigue**: Balance sensitivity vs noise
4. **Documentation**: Log investigation procedures
5. **Escalation**: Define clear response procedures