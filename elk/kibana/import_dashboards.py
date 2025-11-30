#!/usr/bin/env python3
"""
Kibana Dashboard and Alert Import Script
Imports pre-configured dashboards and alerting rules into Kibana
"""

import requests
import json
import os
import sys
import time
from pathlib import Path

class KibanaImporter:
    def __init__(self, kibana_url="http://localhost:5601"):
        self.kibana_url = kibana_url
        self.headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }
        
    def wait_for_kibana(self, max_retries=30, delay=10):
        """Wait for Kibana to be available"""
        print("Waiting for Kibana to be available...")
        for attempt in range(max_retries):
            try:
                response = requests.get(f"{self.kibana_url}/api/status", 
                                      headers=self.headers, timeout=5)
                if response.status_code == 200:
                    print("✓ Kibana is available")
                    return True
            except requests.RequestException:
                pass
            
            print(f"Attempt {attempt + 1}/{max_retries} - Kibana not ready, waiting {delay}s...")
            time.sleep(delay)
        
        print("✗ Kibana is not available after maximum retries")
        return False
    
    def create_index_pattern(self):
        """Create index pattern for cybersecurity logs"""
        print("Creating index pattern...")
        
        index_pattern = {
            "attributes": {
                "title": "cybersecurity-system-*",
                "timeFieldName": "@timestamp",
                "fields": json.dumps([
                    {"name": "@timestamp", "type": "date", "searchable": True, "aggregatable": True},
                    {"name": "message", "type": "string", "searchable": True, "aggregatable": False},
                    {"name": "container.labels.com_docker_compose_service", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "stream", "type": "string", "searchable": True, "aggregatable": True},
                    {"name": "host.ip", "type": "ip", "searchable": True, "aggregatable": True},
                    {"name": "container.id", "type": "string", "searchable": True, "aggregatable": True}
                ])
            }
        }
        
        try:
            response = requests.post(
                f"{self.kibana_url}/api/saved_objects/index-pattern/cybersecurity-system-*",
                headers=self.headers,
                json=index_pattern
            )
            
            if response.status_code in [200, 201, 409]:  # 409 = already exists
                print("✓ Index pattern created/exists")
                return True
            else:
                print(f"✗ Failed to create index pattern: {response.text}")
                return False
                
        except requests.RequestException as e:
            print(f"✗ Error creating index pattern: {e}")
            return False
    
    def import_saved_objects(self, file_path, object_type="dashboards"):
        """Import saved objects (dashboards/alerts) from JSON file"""
        print(f"Importing {object_type} from {file_path}...")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Use the import API for saved objects
            response = requests.post(
                f"{self.kibana_url}/api/saved_objects/_import",
                headers={'kbn-xsrf': 'true'},
                files={'file': ('export.ndjson', 
                               '\\n'.join([json.dumps(obj) for obj in data['objects']]), 
                               'application/ndjson')}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success', False):
                    print(f"✓ Successfully imported {object_type}")
                    return True
                else:
                    print(f"✗ Import failed: {result}")
                    return False
            else:
                print(f"✗ HTTP error importing {object_type}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"✗ Error importing {object_type}: {e}")
            return False
    
    def setup_email_connector(self):
        """Setup email connector for alerts"""
        print("Setting up email connector for alerts...")
        
        email_connector = {
            "name": "Email Notifications",
            "connector_type_id": ".email",
            "config": {
                "service": "gmail",  # Change as needed
                "host": "smtp.gmail.com",
                "port": 587,
                "secure": False,
                "from": "cybersecurity-alerts@company.com"
            },
            "secrets": {
                "user": "cybersecurity-alerts@company.com",
                "password": "your-app-password"  # Use app password for Gmail
            }
        }
        
        try:
            response = requests.post(
                f"{self.kibana_url}/api/actions/connector",
                headers=self.headers,
                json=email_connector
            )
            
            if response.status_code in [200, 201]:
                connector_id = response.json()['id']
                print(f"✓ Email connector created with ID: {connector_id}")
                return connector_id
            elif response.status_code == 409:
                print("✓ Email connector already exists")
                return "email-action"  # Default ID
            else:
                print(f"! Email connector setup failed: {response.text}")
                print("  Please configure email connector manually in Kibana")
                return None
                
        except requests.RequestException as e:
            print(f"! Error setting up email connector: {e}")
            print("  Please configure email connector manually in Kibana")
            return None

def main():
    """Main execution function"""
    print("Kibana Dashboard and Alert Import Tool")
    print("=" * 50)
    
    # Get script directory
    script_dir = Path(__file__).parent
    
    # Initialize importer
    importer = KibanaImporter()
    
    # Wait for Kibana to be available
    if not importer.wait_for_kibana():
        sys.exit(1)
    
    # Create index pattern
    if not importer.create_index_pattern():
        print("Warning: Index pattern creation failed, continuing anyway...")
    
    # Setup email connector
    importer.setup_email_connector()
    
    # Import dashboards
    dashboard_files = [
        script_dir / "dashboards" / "service-health-dashboard.json",
        script_dir / "dashboards" / "threat-detection-dashboard.json", 
        script_dir / "dashboards" / "attack-behavior-dashboard.json"
    ]
    
    success_count = 0
    for dashboard_file in dashboard_files:
        if dashboard_file.exists():
            if importer.import_saved_objects(dashboard_file, "dashboard"):
                success_count += 1
        else:
            print(f"✗ Dashboard file not found: {dashboard_file}")
    
    # Import alerts
    alert_files = [
        script_dir / "alerts" / "security-alerts.json"
    ]
    
    for alert_file in alert_files:
        if alert_file.exists():
            if importer.import_saved_objects(alert_file, "alerts"):
                success_count += 1
        else:
            print(f"✗ Alert file not found: {alert_file}")
    
    print("\\n" + "=" * 50)
    print(f"Import completed. Successfully imported {success_count} objects.")
    print("\\nNext steps:")
    print("1. Access Kibana at http://localhost:5601")
    print("2. Go to Analytics > Dashboard to view imported dashboards")
    print("3. Go to Management > Rules and Connectors to view alerts")
    print("4. Configure email settings in the email connector if needed")
    print("5. Adjust alert thresholds based on your environment")
    
if __name__ == "__main__":
    main()