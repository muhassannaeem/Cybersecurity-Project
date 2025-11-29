#!/bin/bash
# Setup script for Kibana alert rules
# Note: Kibana alerts require Kibana 7.10+ and may need to be configured via UI or API

echo "Setting up Kibana Alert Rules..."

KIBANA_URL="http://kibana:5601"
KIBANA_USER="${KIBANA_USER:-elastic}"
KIBANA_PASSWORD="${KIBANA_PASSWORD:-}"

# Wait for Kibana to be ready
echo "Waiting for Kibana to be ready..."
until curl -s "${KIBANA_URL}/api/status" | grep -q '"status":"green\|yellow"'; do
  sleep 5
done

echo "Kibana is ready!"

echo ""
echo "Kibana Alert Rules Configuration"
echo "================================"
echo ""
echo "Due to Kibana alert API complexity, alerts should be configured via the Kibana UI:"
echo ""
echo "1. Access Kibana: http://localhost:5601"
echo "2. Go to: Stack Management > Rules and Connectors"
echo "3. Create the following alert rules:"
echo ""
echo "Alert Rule 1: High Error Rate"
echo "  - Condition: Error rate > 5% in last 5 minutes"
echo "  - Query: level:ERROR"
echo "  - Threshold: > 5 errors per 5 minutes"
echo "  - Action: Send notification (email/webhook)"
echo ""
echo "Alert Rule 2: Service Down"
echo "  - Condition: No logs from service for 2 minutes"
echo "  - Query: service:<service_name>"
echo "  - Threshold: Count = 0 for 2 minutes"
echo "  - Action: Send notification"
echo ""
echo "Alert Rule 3: High Threat Detection Rate"
echo "  - Condition: > 10 threats detected per minute"
echo "  - Query: event_type:threat AND level:WARNING"
echo "  - Threshold: > 10 per minute"
echo "  - Action: Send notification"
echo ""
echo "Alert Rule 4: Critical Severity Threat"
echo "  - Condition: Critical severity threat detected"
echo "  - Query: event_type:threat AND metadata.severity:critical"
echo "  - Threshold: Any occurrence"
echo "  - Action: Immediate notification"
echo ""
echo "Alert Rule 5: Threat Intelligence Sharing Failure"
echo "  - Condition: Threat intelligence sharing error"
echo "  - Query: service:threat_intelligence AND level:ERROR"
echo "  - Threshold: Any occurrence"
echo "  - Action: Send notification"
echo ""
echo "Alert Rule 6: Attribution Pipeline Failure"
echo "  - Condition: Attribution pipeline error"
echo "  - Query: service:threat_attribution AND level:ERROR"
echo "  - Threshold: Any occurrence"
echo "  - Action: Send notification"
echo ""
echo "For API-based setup, see: elk/scripts/kibana-alerts-api.json"
echo ""

