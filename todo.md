#
- [x] Add flask-restx to requirements and install it
# Project TODO (Remaining Requirements from System Specification)

**ALL MAJOR TASKS COMPLETED** ✅

This file lists the requirements from the system specification. All major items have been implemented and marked as DONE.

## Summary of Remaining Minor Tasks

- [x] Audit Section 11 implementation - Check codebase for Zeek/tcpdump integration and traffic capture features (Section 11). **(DONE)**
- [x] Test Section 11 code - Test traffic monitoring and Zeek/tcpdump related code for completeness and correctness. **(DONE)**

---

## 1. Real‑Time Data & WebSockets (Socket.io)

1. Implement a real‑time event channel between backend and frontend using WebSockets (Socket.io or Flask‑SocketIO), instead of only HTTP polling. **(DONE)**
2. Define server‑side event streams for: **(DONE)**
   - New threats and alerts (from `backend/app.py`).
   - Decoy / honeypot events (from `decoy_generator`).
   - Traffic anomalies (from `traffic_monitor`).
3. Add a Socket.io client layer in the Next.js frontend and wire the dashboard to live‑update threat tables and KPIs without page refresh. **(DONE)**
4. Implement backpressure and rate‑limiting on the real‑time channel so that high event volume cannot overwhelm the frontend or backend. **(DONE)**
5. Make the WebSocket layer horizontally scalable (e.g., Redis adapter for Socket.io) so multiple backend instances can broadcast events consistently. **(DONE – optional Redis message queue via SOCKETIO_MESSAGE_QUEUE_URL)**

---

## 2. Data Visualization with Chart.js

6. Add Chart.js (e.g., via `react-chartjs-2`) to the frontend and integrate it alongside or instead of the current Recharts components. **(DONE)**
7. Expose backend APIs that provide time‑series and aggregate data needed for visualization, including: **(DONE - basic aggregate + time-series metrics via /api/metrics/summary)**
   - Attack patterns and technique counts (from the threat attribution module).
   - Anomaly scores and counts (from the behavioral analysis engine).
   - Threat levels and incidence over time.
8. Build Chart.js visualizations on the dashboard, including at minimum: **(DONE)**
   - Time‑series charts for attack patterns / anomalies.
   - Bar charts for attack frequency by type / severity.
   - Any additional charts required by the system document.

---

## 3. ML‑Based Adaptive Honeypot Behavior

9. Design an adaptive deception pipeline where honeypot responses depend on attacker behavior, not only static Docker images. **(DONE)**
10. Connect decoy/honeypot telemetry (from `decoy_generator` and `traffic_monitor`) to the behavioral analysis engine so that attacker action sequences can be modeled (e.g., with LSTM). **(DONE)**
11. Implement LSTM‑based or similar sequence models that generate believable adaptive content, such as: **(DONE)**
    - Dynamic fake credentials.
    - Evolving directory structures / files exposed to attackers.
    - Protocol banners and responses that adapt to previous attacker actions.
12. Extend the `decoy_generator` service with APIs and runtime logic to: **(DONE)**
    - Request adaptive responses from the ML models.
    - Update live honeypot configuration based on model output.
    - Log and expose adaptive behavior decisions for audit and evaluation.

---

## 4. Honeypot Expansion: Dionaea and Conpot

13. Add support for **Dionaea** malware honeypots in `decoy_generator`, including:
    - Docker image selection and configuration.
    - Volumes for malware samples / logs.
    - Port mappings and environment variables. **(DONE)**
14. Add support for **Conpot** industrial/IoT honeypots in `decoy_generator`, including:
    - Docker image configuration for ICS/SCADA protocols.
    - Proper networking and logging. **(DONE)**
15. Update decoy deployment APIs and internal type registries to accept new decoy types (`dionaea`, `conpot`). **(DONE)**
16. Extend decoy listing, statistics, and any UI components so Dionaea and Conpot instances are visible and their metrics are tracked. **(DONE - types supported in decoy_generator & central decoy API/UI)**

---

## 5. MITRE ATT&CK Attribution with SIEM Integration

17. Ensure that detection events from traffic monitoring, behavioral analysis, and honeypots are consistently enriched with MITRE ATT&CK technique IDs via the threat attribution module. **(DONE)**
18. Define a common event format that includes: timestamp, source, destination, technique ID(s), confidence score, and related indicators. **(DONE)**
19. Implement outbound integrations to external SIEM platforms (e.g., Elastic SIEM, Splunk) so MITRE‑enriched events and indicators are exported in near real‑time. **(DONE)**
20. Reuse or extend the STIX/TAXII and threat‑intelligence components so that: **(DONE)**
    - ATT&CK mappings are included in shared indicators. **(DONE)**
    - SIEM exports are aligned with standard schemas (e.g., ECS for Elastic, Splunk HEC format). **(DONE)**

---

## 6. Evaluation Metrics & Automated Model Retraining


21. Implement an end‑to‑end evaluation pipeline that measures and stores the following metrics from real attack data: **(DONE)**
    - **Detection latency**: time from attack start to detection/alert. **(DONE)**
    - **False positive rate**: percentage of benign events misclassified as malicious. **(DONE)**
    - **Attacker engagement time**: duration attackers spend interacting with decoys. **(DONE)**
    - **Decoy believability score**: derived from attacker behavior and feedback (e.g., depth of interaction, repeat visits). **(DONE)**
    - **Threat actor attribution accuracy**: how often the attributed actor/techniques match ground truth in tests. **(DONE)**
22. Persist these metrics (e.g., in PostgreSQL or Redis) with sufficient granularity for trend analysis and visualization. **(DONE)**
23. Expose metrics through dedicated backend APIs so the frontend and external tools can consume them. **(DONE - /api/metrics/summary)**
24. Design and implement an automated **model retraining pipeline** that uses real captured data (not only synthetic data) to: **(DONE)**
    - Periodically retrain the LSTM, Isolation Forest, and Autoencoder models. **(DONE)**
    - Incorporate new labeled attacks and benign traffic. **(DONE)**
    - Track model versions and allow rollback if a retrain degrades performance. **(DONE)**
25. Connect evaluation results (e.g., from the evaluation engine) to the retraining logic so metrics can trigger or schedule retraining jobs. **(DONE)**

---

## 7. Scalable Real‑Time Platform & Kubernetes

26. Create Kubernetes manifests (Deployments, Services, Ingress, ConfigMaps, Secrets, etc.) for all core microservices and supporting components (database, Redis, message brokers if any). **(DONE)**
27. Define horizontal pod autoscaling rules for critical services (backend API, WebSocket/Socket.io gateway, behavioral analysis, decoy generator) based on CPU, memory, or custom metrics. **(DONE)**
28. Ensure the real‑time Socket.io / WebSocket layer is compatible with multi‑pod deployments (e.g., using a Redis or message‑queue based adapter for pub/sub fan‑out). **(DONE)**
29. Implement backpressure strategies at the platform level (queueing limits, dropping/aggregating low‑priority events) so the system can sustain high attack volumes without failing. **(DONE)**
30. Provide basic deployment documentation for running the full system on Kubernetes (local cluster and production‑style cluster). **(DONE)**

---

## 8. Threat Intelligence Sharing (STIX2 / TAXII) Enhancements

31. Re‑enable and harden TAXII client/server functionality (currently commented/disabled) so STIX objects can be exchanged over standard TAXII 2.x. **(DONE)**
32. Add configuration and health‑checking for external TAXII/STIX providers (e.g., OpenCTI, MISP, AlienVault, and any SIEMs that support STIX/TAXII). **(DONE)**
33. Improve the background sharing loop to handle failures, retries, and idempotency when pushing indicators to remote systems. **(DONE)**
34. Provide management APIs (and optionally a UI view) for: **(DONE)**
    - Viewing which external feeds are enabled. **(DONE)**
    - Adjusting sharing policies (auto‑share on/off, thresholds, batch sizes). **(DONE)**

---

## 9. Centralized Monitoring and Logging (ELK or Equivalent)

35. Design a centralized logging architecture using the ELK stack (Elasticsearch, Logstash, Kibana) or an equivalent solution. **(DONE)**
36. Configure each microservice container to ship structured logs to the central logging system (e.g., via Filebeat or Fluentd). **(DONE)**
37. Define log formats that capture both system events and attacker behavior for post‑incident analysis. **(DONE)**
38. Build Kibana (or equivalent) dashboards and alerts for:
    - Service health and performance.
    - Detected anomalies and attacks.
    - Errors in threat‑intelligence sharing, attribution, and retraining pipelines. **(DONE)**

---

## 10. Authentication, Authorization, and RBAC

39. Replace the current frontend‑only authentication (localStorage flag) with a real backend authentication system backed by the database. **(DONE)**
40. Implement secure user registration and login with hashed passwords and proper validation. **(DONE)**
41. Issue JWTs (or use OAuth2) for authenticated access to APIs and WebSocket connections. **(DONE – JWT for HTTP APIs + Socket.IO connections)**
42. Design and enforce role‑based access control (RBAC) with roles such as admin, analyst, red‑team, and read‑only. **(DONE for admin/analyst roles used in this implementation)**
43. Guard sensitive backend endpoints and dashboard views based on user roles. **(DONE)**
44. Log user actions (login, configuration changes, decoy deployments, retraining triggers, evaluation runs) for accountability and audit. **(DONE for core actions; extend as new features are implemented)**

---


## 11. Traffic Capture with Zeek/tcpdump **(DONE)**

45. Integrate **Zeek** properly into the traffic monitoring service instead of the current placeholder implementation, including:
    - Installing and configuring Zeek inside the traffic monitor environment. **(DONE)**
    - Managing Zeek start/stop lifecycle and log rotation. **(DONE)**
46. Implement real‑time parsing of Zeek logs (conn, http, dns, ssl, etc.) and enrich events with metadata required for attribution and behavioral analysis. **(DONE)**
47. Ensure tcpdump remains available for raw packet capture, and that captured PCAPs can be analyzed and correlated with Zeek events. **(DONE)**
48. Store detailed traffic logs persistently and expose summary statistics and anomalies through APIs used by dashboards and evaluation components. **(DONE)**

---

## 12. Secure API (Flask/FastAPI) & Rate Limiting

49. Review and harden all backend APIs (Flask services) to ensure they enforce authentication, authorization, and input validation. **(DONE)**
50. Add rate limiting for public and sensitive endpoints to prevent abuse and protect backend resources. **(DONE)**
51. Document the API surface (OpenAPI/Swagger or similar) so that external systems and developers can integrate safely and consistently. **(DONE)**
