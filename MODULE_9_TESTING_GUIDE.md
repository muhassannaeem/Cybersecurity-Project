# Module 9 Testing Guide

Step-by-step instructions to validate the centralized monitoring & logging stack (ELK) plus structured logging across microservices.

---

## Prerequisites

- Docker Desktop running
- Project dependencies assembled (same repo checkout)
- Ports free: 5000, 3000, 5601, 9200, 5044, 9600

---

## 1. Start ELK stack (Elasticsearch, Logstash, Kibana, Filebeat)

```powershell
cd "C:\Users\PMLS\Desktop\Uni\Cyber Project\Cybersecurity Project-V2\Cybersecurity Project-V2\Cybersecurity Project"
docker-compose up -d elasticsearch logstash kibana filebeat
```

> If an image pull times out, rerun the command. Wait until `docker-compose ps` shows all four services **Up**.

- Check Elasticsearch health: `curl http://localhost:9200/_cluster/health`
- View logs if needed: `docker-compose logs -f elasticsearch`

---

## 2. Start the application services (to generate logs)

```powershell
docker-compose up -d backend behavioral_analysis decoy_generator traffic_monitor threat_intelligence threat_attribution frontend
```

Now interact with the app to produce events (auth, decoy deploy, analysis run). Every action generates structured logs.

---

## 3. Frontend verification

1. Open `http://localhost:3000`
2. Sign up or log in
3. Browse Dashboard tabs:
   - Overview cards + Chart.js charts should show data
   - Deploy a decoy, run analysis, etc. (triggers new log entries)
4. Confirm actions happen without refresh due to Socket.IO events

---

## 4. Kibana setup (first-time only)

1. Open `http://localhost:5601`
2. Create index patterns:
   - Stack Management → Index Patterns → **Create**
   - Patterns & time field:  
     - `cybersecurity-system-*` (time: `@timestamp`)  
     - `cybersecurity-threats-*` (time: `@timestamp`)  
     - `cybersecurity-attacks-*` (time: `@timestamp`)  
     - `cybersecurity-audit-*` (time: `@timestamp`)

3. Import dashboards (optional but recommended):
   - Stack Management → Saved Objects → Import
   - Files: `elk/dashboards/*.json`

---

## 5. Dashboard viewing

1. Kibana → Dashboard
2. Open:
   - **Service Health Dashboard**: request rate, error rate, response times
   - **Threat Detection Dashboard**: threat timeline, severity distribution, top sources
   - **Attack Behavior Dashboard**: decoy interactions, attack sequences
   - **Error & Pipeline Dashboard**: errors for threat intelligence, attribution, etc.

3. Generate events (API calls, decoy deploy) and watch charts update within 1–2 minutes as logs arrive.

---

## 6. Log verification

### Via Docker logs

```powershell
docker-compose logs -f backend
docker-compose logs -f decoy_generator
docker-compose logs -f traffic_monitor
docker-compose logs -f behavioral_analysis
```

Expect JSON-formatted entries with fields:
`@timestamp`, `service`, `level`, `event_type`, `correlation_id`, `metadata`.

### Via Elasticsearch API

```powershell
curl "http://localhost:9200/cybersecurity-system-*/_search?pretty&size=5"
```

Check that documents contain the same structured fields as the console output.

---

## 7. Filebeat & Logstash sanity checks

```powershell
docker-compose logs -f filebeat
```
- Look for `Harvester started` & `Publishing events`

```powershell
docker-compose logs -f logstash
```
- Ensure there are no JSON parsing errors; look for pipeline running messages

---

## 8. Alert rule setup (optional)

1. Kibana → Stack Management → Rules and Connectors → Create rule
2. Sample rules to create:
   - High Error Rate (`level:ERROR`, >5 events in 5m)
   - Service Down (no logs from service in 2m)
   - High Threat Detection (`event_type:threat`, >10/min)
   - Critical Threats (`metadata.severity:critical`)
3. Trigger test errors (e.g., call an endpoint with invalid payload) and confirm rule status changes.

Templates and instructions also available in `elk/scripts/setup-kibana-alerts.sh`.

---

## 9. Cleanup / stopping services

```powershell
docker-compose down
```

- Use `docker-compose down -v` if you want to remove volumes (wipes Elasticsearch data).

---

## Quick tips

- If Kibana shows “No data,” ensure index patterns exist and you have recent logs (check time range in Discover/dashboard).
- Network issues pulling Elastic images → rerun `docker-compose up ...`.
- ELK stack uses ~2–3 GB RAM; ensure Docker Desktop has enough resources.

Testing is complete when:
- ELK services stay healthy
- Structured logs appear in Elasticsearch/Kibana
- Dashboards show real data from your actions
- Optional alerts trigger on simulated errors/conditions


