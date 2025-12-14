VIDEO DEMO GUIDE – MODULES, CONCEPTS, AND DOCKER COMMANDS

Organized using the same sections as todo.md.
Each section:
- Concept – what it is / why it matters.
- What to show in the video.
- Docker commands – how to start / verify containers.

Assume you run commands from the project root with docker-compose.yml.

For quick testing in the demo, you can also use the Python helper script:

python demo_module_tests.py <MODULE_ID>

(Example: python demo_module_tests.py 3 for Module 3, 4 for Module 4, etc.)

--------------------------------------------------
1. REAL-TIME DATA & WEBSOCKETS (SOCKET.IO)
--------------------------------------------------

CONCEPT
- Normally dashboards poll the backend every few seconds.
- With WebSockets / Socket.IO, the backend pushes new events instantly to the browser.
- You get a live SOC-style dashboard (threats / alerts / anomalies / decoy events).

WHAT TO SHOW
- Start backend + frontend + Redis.
- Open http://localhost:3000 and show tables/charts updating without refreshing.
- Optionally show API docs at http://localhost:5000/api/docs/swagger/.

DOCKER COMMANDS

docker-compose up -d backend frontend db redis
docker-compose ps backend frontend redis
docker-compose logs -f backend

STOP COMMANDS

docker-compose stop backend frontend db redis
--------------------------------------------------
2. DATA VISUALIZATION WITH CHART.JS
--------------------------------------------------

CONCEPT
- Frontend uses Chart.js to draw charts for:
  - Threats over time
  - Severity distribution
  - Attack types
- Backend exposes /api/metrics/summary used by charts + WebSockets.

WHAT TO SHOW
- With backend + frontend running:
  - Show charts on dashboard (Overview tab).
  - Mention data source is /api/metrics/summary plus live events.

DOCKER COMMANDS

docker-compose up -d backend frontend
curl http://localhost:5000/api/metrics/summary

STOP COMMANDS

docker-compose stop backend frontend
--------------------------------------------------
3. ML-BASED ADAPTIVE HONEYPOT BEHAVIOR
--------------------------------------------------

CONCEPT
- ML models + attacker behavior history = adaptive honeypots.
- Changes fake credentials, directory structures, and responses to keep attackers engaged.

WHAT TO SHOW
- Start ML + adaptive + decoy services.
- In decoy/honeypot UI:
  - Show different decoy types and status.
- Explain behavioral_analysis + adaptive_deception coordinate behind the scenes.

DOCKER COMMANDS

docker-compose up -d backend behavioral_analysis adaptive_deception decoy_generator db redis
docker-compose ps behavioral_analysis adaptive_deception decoy_generator
docker-compose logs -f adaptive_deception

TEST COMMANDS (for demo)

# Option A – run everything from Python helper (recommended for the video)
python demo_module_tests.py 3

# Option B – individual HTTP calls

# 1) Get a JWT token for protected backend APIs
curl http://localhost:5000/api/auth/test-token

# 2) Check health of ML + adaptive + decoy services
curl http://localhost:5001/health
curl http://localhost:5007/health
curl http://localhost:5002/health

# 3) (Optional) Trigger anomaly detection to generate log entries
curl -X POST http://localhost:5001/detect -H "Content-Type: application/json" -d '{"data":[[0,0,0,0,0,0,0,0,0,0],[3,3,3,3,3,3,3,3,3,3]]}'

# 4) (Optional) Show adaptive fake credentials / filesystem / banners for a session
#    First, send an attacker event to adaptive_deception with a known session_id
curl -X POST http://localhost:5007/process_event -H "Content-Type: application/json" \
  -d '{"session_id":"demo_session_1","action":"login_attempt","target":"web_server","success":true,"timestamp":"2024-01-01T00:00:00"}'

#    Then fetch adaptive content from decoy_generator
curl http://localhost:5002/adaptive/credentials/demo_session_1
curl http://localhost:5002/adaptive/filesystem/demo_session_1
curl http://localhost:5002/adaptive/banners/demo_session_1

STOP COMMANDS

docker-compose stop backend behavioral_analysis adaptive_deception decoy_generator db redis
--------------------------------------------------
4. HONEYPOT EXPANSION: DIONAEA AND CONPOT
--------------------------------------------------

CONCEPT
- Dionaea: malware-capture honeypot.
- Conpot: ICS/SCADA (industrial) honeypot.
- Decoy generator can deploy and track these in addition to basic web/SSH/etc.

WHAT TO SHOW
- Start backend + decoy generator.
- In dashboard:
  - Show decoy list containing dionaea and conpot.
  - Optionally deploy a new decoy and show it appears.

DOCKER COMMANDS

docker-compose up -d backend decoy_generator db redis
docker-compose ps decoy_generator
docker-compose logs -f decoy_generator

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 4

# Option B – individual HTTP calls

# 1) List available decoy / honeypot types
curl http://localhost:5002/types

# 2) Deploy a Dionaea honeypot directly via decoy_generator
curl -X POST http://localhost:5002/deploy/honeypot -H "Content-Type: application/json" -d '{"type":"dionaea"}'

# 3) (Optional) Deploy Dionaea via central backend API (requires JWT)
#    Replace YOUR_JWT_TOKEN with the token from /api/auth/test-token
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" -H "Content-Type: application/json" -X POST http://localhost:5000/api/decoys/deploy -d '{"type":"dionaea"}'

# 4) List decoys tracked by the backend
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/decoys

STOP COMMANDS

docker-compose stop backend decoy_generator db redis
--------------------------------------------------
5. MITRE ATT&CK ATTRIBUTION WITH SIEM INTEGRATION
--------------------------------------------------

CONCEPT (MITRE ATT&CK & attack patterns)
- MITRE ATT&CK = public catalog of attacker behaviors.
- Each technique/attack pattern has an ID like T1003 (credential dumping).
- System sends detections to Threat Attribution:
  - Adds ATT&CK technique IDs + confidence.
  - Exports enriched events to SIEM (Elastic / Splunk).

WHAT TO SHOW
- Start backend, threat_attribution, Redis, and ELK.
- In Kibana (http://localhost:5601):
  - Show index cybersecurity-system-*.
  - Show events containing MITRE fields (technique IDs).
- Optionally call /api/siem/status or /api/events/enriched.

DOCKER COMMANDS

docker-compose up -d backend threat_attribution redis elasticsearch logstash kibana filebeat db
docker-compose ps threat_attribution elasticsearch kibana
docker-compose logs -f backend
docker-compose logs -f threat_attribution

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 5

# Option B – individual HTTP calls

# 1) Get a JWT token (if you don't already have one)
curl http://localhost:5000/api/auth/test-token

# 2) Check threat_attribution microservice health
curl http://localhost:5004/health

# 3) Call metrics summary (uses MITRE ATT&CK mapping under the hood)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/metrics/summary

# 4) Generate a full MITRE ATT&CK attribution report
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/attribution/report

# 5) (Optional) Check SIEM integration status
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/siem/status

STOP COMMANDS

docker-compose stop backend threat_attribution redis elasticsearch logstash kibana filebeat db

(Optional API)

curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/siem/status
--------------------------------------------------
6. EVALUATION METRICS & AUTOMATED MODEL RETRAINING
--------------------------------------------------

CONCEPT
- Measures: detection latency, false positives, engagement time, believability, attribution accuracy.
- Automated retraining pipeline:
  - Retrains models on real data.
  - Versioning + rollback if new model is worse.

WHAT TO SHOW
- Start evaluation engine + backend + ML + DB + Redis.
- Show metrics/trends via dashboard or API.
- Explain evaluation results can trigger retraining.

DOCKER COMMANDS

docker-compose up -d backend behavioral_analysis evaluation_engine db redis
docker-compose ps evaluation_engine behavioral_analysis
docker-compose logs -f evaluation_engine

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 6

# Option B – individual HTTP calls

# 1) Check evaluation engine health
curl http://localhost:5008/health

# 2) List available evaluation scenarios
curl http://localhost:5008/scenarios

# 3) (Optional) Run a lightweight network scanning test against the backend
curl -X POST http://localhost:5008/test/network_scanning -H "Content-Type: application/json" -d '{"target_host":"backend"}'

# 4) View aggregated evaluation statistics
curl http://localhost:5008/statistics

STOP COMMANDS

docker-compose stop backend behavioral_analysis evaluation_engine db redis

(Optional)

curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/metrics/summary
--------------------------------------------------
7. SCALABLE REAL-TIME PLATFORM & KUBERNETES
--------------------------------------------------

CONCEPT
- Same system can run on Kubernetes:
  - Multiple replicas (HPA).
  - Redis message queue for Socket.IO.
  - Ingress, NetworkPolicies, PDBs, etc.

WHAT TO SHOW
- Briefly show k8s/ directory.
- Explain that on Kubernetes you would use:
  - kubectl apply -k k8s/overlays/development
  - instead of docker-compose up.

(No extra Docker commands required beyond building images.)

--------------------------------------------------
8. THREAT INTELLIGENCE SHARING (STIX2 / TAXII)
--------------------------------------------------

CONCEPT
- Shares indicators (IOCs) with other platforms (OpenCTI, MISP, AlienVault, SIEMs).
- Uses STIX 2 + TAXII 2.x.
- Indicators also include MITRE ATT&CK IDs.

WHAT TO SHOW
- Start threat_intelligence + backend + Redis.
- Show feeds / sharing configuration in UI or via API.
- Explain background sharing loop.

DOCKER COMMANDS

docker-compose up -d backend threat_intelligence redis db
docker-compose ps threat_intelligence
docker-compose logs -f threat_intelligence

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 8

# Option B – individual HTTP calls

# 1) Check threat intelligence sharing service health
curl http://localhost:5006/health

# 2) View high-level sharing statistics
curl http://localhost:5006/statistics

# 3) List configured TAXII/STIX servers or providers
curl http://localhost:5006/servers

# 4) (Optional) TAXII discovery endpoint (what a TAXII client calls)
curl http://localhost:5006/taxii2/

STOP COMMANDS

docker-compose stop backend threat_intelligence redis db
--------------------------------------------------
9. CENTRALIZED MONITORING & LOGGING (ELK)
--------------------------------------------------

CONCEPT
- Elasticsearch, Logstash, Kibana, Filebeat:
  - Collect, normalize, store logs from all services.
  - Visualize system health, attacks, errors.

WHAT TO SHOW
- Start application stack + ELK.
- Open Kibana at http://localhost:5601.
- Show dashboards for health, anomalies, errors.

DOCKER COMMANDS

docker-compose up -d backend frontend db redis \
  behavioral_analysis decoy_generator traffic_monitor threat_attribution \
  threat_intelligence adaptive_deception evaluation_engine \
  elasticsearch logstash kibana filebeat

Docker-compose ps elasticsearch logstash kibana filebeat
docker-compose logs -f kibana

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 9

# Option B – individual HTTP calls

# 1) Check Elasticsearch cluster health
curl http://localhost:9200/_cluster/health

# 2) Check Kibana API status
curl http://localhost:5601/api/status

# 3) (Optional) List indices to show logs flowing into Elasticsearch
curl http://localhost:9200/_cat/indices?v

STOP COMMANDS

docker-compose stop backend frontend db redis \
  behavioral_analysis decoy_generator traffic_monitor threat_attribution \
  threat_intelligence adaptive_deception evaluation_engine \
  elasticsearch logstash kibana filebeat
--------------------------------------------------
10. AUTHENTICATION, AUTHORIZATION, AND RBAC
--------------------------------------------------

CONCEPT
- Real backend auth:
  - Secure signup/login with hashed passwords.
  - JWT tokens for APIs + WebSockets.
  - Roles like admin, analyst.
- RBAC:
  - Sensitive actions only for certain roles.

WHAT TO SHOW
- Start backend + frontend + DB + Redis.
- Show login page and role-based UI (buttons visible only to admins/analysts).
- Optionally show Swagger with Bearer auth.

DOCKER COMMANDS

docker-compose up -d backend frontend db redis
docker-compose ps backend frontend db redis
docker-compose logs -f backend

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 10

# Option B – individual HTTP calls

# 1) Show auth help (how to get tokens)
curl http://localhost:5000/api/auth/help

# 2) Get a development JWT token
curl http://localhost:5000/api/auth/test-token

# 3) Call a protected dashboard endpoint using the token
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/dashboard/stats

STOP COMMANDS

docker-compose stop backend frontend db redis
--------------------------------------------------
11. TRAFFIC CAPTURE WITH ZEEK/TCPDUMP
--------------------------------------------------

CONCEPT
- Zeek: rich network traffic analysis.
- tcpdump: raw packet capture (PCAP).
- Traffic monitor:
  - Controls Zeek/tcpdump.
  - Parses Zeek logs.
  - Provides stats/anomalies to rest of the system.

WHAT TO SHOW
- Start backend + traffic_monitor + DB + Redis.
- Show API (start Zeek, get stats, etc.) via Postman / curl.
- Explain real traffic visibility.

DOCKER COMMANDS

docker-compose up -d backend traffic_monitor db redis
docker-compose ps traffic_monitor
docker-compose logs -f traffic_monitor

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 11

# Option B – individual HTTP calls

# 1) Check traffic_monitor health
curl http://localhost:5003/health

# 2) (Optional) After starting Zeek/tcpdump captures, fetch statistics (JWT required)
#    Replace YOUR_JWT_TOKEN with a token that matches the traffic_monitor JWT secret
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5003/statistics

STOP COMMANDS

docker-compose stop backend traffic_monitor db redis
--------------------------------------------------
12. SECURE API (FLASK/FASTAPI) & RATE LIMITING
--------------------------------------------------

CONCEPT
- Backend and traffic monitor:
  - JWT auth + roles on sensitive endpoints.
  - Input validation, safe file handling, path traversal protection.
  - Rate limits to prevent abuse (login brute-force, DoS).

WHAT TO SHOW
- Start backend + traffic_monitor + DB + Redis.
- Show secured endpoints in Swagger.
- Optionally hit a rate-limited test endpoint repeatedly and show 429 errors.

DOCKER COMMANDS

docker-compose up -d backend traffic_monitor db redis
docker-compose logs -f backend
docker-compose logs -f traffic_monitor

TEST COMMANDS (for demo)

# Option A – run everything from Python helper
python demo_module_tests.py 12

# Option B – individual HTTP calls

# 1) Backend API health (unauthenticated)
curl http://localhost:5000/api/health

# 2) Hit the rate-limited test endpoint a few times (last call should return HTTP 429)
curl http://localhost:5000/api/test/rate-limit
curl http://localhost:5000/api/test/rate-limit
curl http://localhost:5000/api/test/rate-limit
curl http://localhost:5000/api/test/rate-limit

# 3) (Optional) Traffic monitor health
curl http://localhost:5003/health

STOP COMMANDS

docker-compose stop backend traffic_monitor db redis
--------------------------------------------------
13. FULL SYSTEM UP/DOWN (FINAL SHOT)
--------------------------------------------------

FULL START

docker-compose up --build -d
docker-compose ps

STOP

docker-compose down     # keep data
docker-compose down -v  # remove volumes and data
