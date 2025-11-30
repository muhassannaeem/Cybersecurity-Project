#!/usr/bin/env python3
"""
Simple Kibana Index Pattern Creator
Creates the basic index pattern needed for dashboards
"""

import requests
import json
import time

def create_kibana_index_pattern():
    kibana_url = "http://localhost:5601"
    headers = {
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true'
    }
    
    print("Creating Kibana index pattern...")
    
    # Simple index pattern payload
    index_pattern_data = {
        "attributes": {
            "title": "cybersecurity-system-*",
            "timeFieldName": "@timestamp"
        }
    }
    
    try:
        # Create index pattern
        response = requests.post(
            f"{kibana_url}/api/saved_objects/index-pattern",
            headers=headers,
            json=index_pattern_data
        )
        
        if response.status_code in [200, 201]:
            result = response.json()
            pattern_id = result['id']
            print(f"✓ Index pattern created successfully with ID: {pattern_id}")
            
            # Set as default
            default_response = requests.post(
                f"{kibana_url}/api/kibana/settings/defaultIndex",
                headers=headers,
                json={"value": pattern_id}
            )
            
            if default_response.status_code == 200:
                print("✓ Set as default index pattern")
            
            return True
            
        elif response.status_code == 409:
            print("✓ Index pattern already exists")
            return True
        else:
            print(f"✗ Failed to create index pattern: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def check_data_available():
    """Check if there's data in Elasticsearch"""
    try:
        response = requests.get("http://localhost:9200/cybersecurity-system-*/_count")
        if response.status_code == 200:
            count = response.json()['count']
            print(f"✓ Found {count:,} log documents in Elasticsearch")
            return count > 0
        else:
            print("✗ Could not check Elasticsearch data")
            return False
    except Exception as e:
        print(f"✗ Error checking Elasticsearch: {e}")
        return False

def main():
    print("Kibana Setup Tool")
    print("=" * 40)
    
    # Check if data is available
    if not check_data_available():
        print("Warning: No data found in Elasticsearch. Dashboard visualizations may be empty.")
        print("Make sure the ELK stack is running and ingesting data.")
    
    # Create index pattern
    success = create_kibana_index_pattern()
    
    print("\n" + "=" * 40)
    if success:
        print("✓ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Open Kibana: http://localhost:5601")
        print("2. Go to Analytics → Dashboard")
        print("3. Click 'Create dashboard'")
        print("4. Follow the manual setup guide to create visualizations")
        print("5. Use these common filters:")
        print("   - Service logs: container.labels.com_docker_compose_service.keyword")
        print("   - Error logs: stream: stderr")
        print("   - Security events: message: *threat* OR message: *attack*")
    else:
        print("✗ Setup failed. Please check Kibana is running at http://localhost:5601")

if __name__ == "__main__":
    main()