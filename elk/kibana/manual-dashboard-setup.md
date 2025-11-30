# Manual Kibana Dashboard Setup Guide

Since the automated import is failing due to JSON formatting issues, follow these steps to create the dashboards manually in Kibana.

## Step 1: Create Data View (Index Pattern)

1. Open Kibana: http://localhost:5601
2. Go to **Stack Management** → **Data Views**
3. Click **Create data view**
4. Set:
   - **Name**: `Cybersecurity System Logs`
   - **Index pattern**: `cybersecurity-system-*`
   - **Timestamp field**: `@timestamp`
5. Click **Save data view to Kibana**

## Step 2: Create Dashboard 1 - Service Health Monitoring

1. Go to **Analytics** → **Dashboard**
2. Click **Create dashboard**
3. Click **Add visualization**

### Visualization 1: Service Logs Count Over Time
1. Click **Create visualization**
2. Select **Line** chart
3. Configure:
   - **Horizontal axis**: `@timestamp` (Date histogram)
   - **Vertical axis**: Count of records
   - **Break down by**: `container.labels.com_docker_compose_service.keyword` (Top 5 values)
4. Click **Save and return**
5. Title: "Service Logs Count Over Time"

### Visualization 2: Error Rate by Service  
1. Add new visualization → **Bar chart**
2. Configure:
   - **Horizontal axis**: `container.labels.com_docker_compose_service.keyword`
   - **Vertical axis**: Count of records
3. Add filter: `stream: "stderr" OR message: *error* OR message: *ERROR* OR message: *exception*`
4. Title: "Error Rate by Service"

### Visualization 3: Log Type Distribution
1. Add new visualization → **Pie chart**  
2. Configure:
   - **Slice by**: `stream.keyword`
3. Title: "Log Type Distribution (stdout vs stderr)"

### Visualization 4: Active Services
1. Add new visualization → **Metric**
2. Configure:
   - **Primary metric**: Unique count of `container.labels.com_docker_compose_service.keyword`
3. Title: "Active Services Count"

4. **Save dashboard** as "Service Health Monitoring"

## Step 3: Create Dashboard 2 - Threat Detection & Analysis

1. Create new dashboard
2. Add visualizations:

### Visualization 1: Threat Timeline
1. **Line chart**
2. Configure:
   - **Horizontal axis**: `@timestamp` (Date histogram)
   - **Vertical axis**: Count
3. Add filter: `message: *threat* OR message: *attack* OR message: *malicious* OR message: *suspicious*`
4. Title: "Threat Activity Timeline"

### Visualization 2: Behavioral Analysis Activity
1. **Area chart**
2. Configure:
   - **Horizontal axis**: `@timestamp` 
   - **Vertical axis**: Count
3. Add filter: `container.labels.com_docker_compose_service: "behavioral_analysis" OR message: *behavioral*`
4. Title: "Behavioral Analysis Activity"

### Visualization 3: Security Events by Host
1. **Horizontal Bar chart**
2. Configure:
   - **Horizontal axis**: Count
   - **Vertical axis**: `host.ip.keyword`
3. Add security-related filters
4. Title: "Security Events by Host"

3. **Save dashboard** as "Threat Detection & Analysis"

## Step 4: Create Dashboard 3 - Attack Behavior Analysis

1. Create new dashboard
2. Add visualizations:

### Visualization 1: Decoy Interactions
1. **Line chart**
2. Configure:
   - **Horizontal axis**: `@timestamp`
   - **Vertical axis**: Count  
3. Add filter: `container.labels.com_docker_compose_service: "decoy_generator" OR message: *decoy* OR message: *honeypot*`
4. Title: "Decoy System Interactions"

### Visualization 2: Traffic Analysis
1. **Gauge chart**
2. Configure:
   - **Primary metric**: Count
3. Add filter: `container.labels.com_docker_compose_service: "traffic_monitor" OR message: *traffic*`
4. Title: "Network Traffic Analysis"

### Visualization 3: Attack Behavior Logs
1. **Data table**
2. Configure columns:
   - `@timestamp`
   - `container.labels.com_docker_compose_service`
   - `message`
   - `stream`
3. Add filters for attack-related keywords
4. Title: "Recent Attack Behavior Logs"

3. **Save dashboard** as "Attack Behavior Analysis"

## Step 5: Set up Alerts (Optional)

1. Go to **Stack Management** → **Rules and Connectors**
2. Click **Create rule**
3. Choose **Index threshold**
4. Configure alerts for:
   - High error rates (>10 errors in 5 minutes)
   - Service downtime (no logs in 10 minutes)
   - Security events (any threat-related keywords)

## Quick Filters for Each Dashboard

### Service Health Filters:
- Errors: `stream: "stderr"`
- Specific service: `container.labels.com_docker_compose_service: "backend"`

### Threat Detection Filters:
- Threats: `message: *threat* OR message: *attack* OR message: *suspicious*`
- Behavioral: `message: *behavioral* OR message: *anomaly*`

### Attack Analysis Filters:
- Decoys: `message: *decoy* OR message: *honeypot*`
- Attribution: `message: *attribution* OR container.labels.com_docker_compose_service: "threat_attribution"`

## Time Ranges to Set:
- **Service Health**: Last 15 minutes (refresh every 10 seconds)
- **Threat Detection**: Last 1 hour (refresh every 30 seconds)  
- **Attack Analysis**: Last 4 hours (refresh every 1 minute)

## Verification Steps:
1. Check that all 3 dashboards are created
2. Verify data is showing in visualizations
3. Test real-time updates by checking refresh intervals
4. Confirm filters are working correctly

Once complete, you'll have fully functional Kibana dashboards for monitoring your cybersecurity system!