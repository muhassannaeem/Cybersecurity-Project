#!/bin/bash
# Setup script for Kibana dashboards and index patterns
# This script helps set up Kibana after Elasticsearch is ready

echo "Setting up Kibana for Cybersecurity System..."

# Wait for Kibana to be ready
echo "Waiting for Kibana to be ready..."
until curl -s http://kibana:5601/api/status | grep -q '"status":"green\|yellow"'; do
  sleep 5
done

echo "Kibana is ready!"

echo ""
echo "Next steps:"
echo "1. Access Kibana at http://localhost:5601"
echo "2. Create index patterns:"
echo "   - cybersecurity-system-*"
echo "   - cybersecurity-threats-*"
echo "   - cybersecurity-attacks-*"
echo "   - cybersecurity-audit-*"
echo "3. Import dashboards from elk/dashboards/ directory"
echo ""
echo "For detailed instructions, see elk/dashboards/README.md"

