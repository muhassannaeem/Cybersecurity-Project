# MITRE ATT&CK Attribution with SIEM Integration - Implementation Guide

This document explains the implementation of **Tasks 17-20** from `todo.md`: MITRE ATT&CK Attribution with SIEM Integration.

## Overview

The implementation provides:
1. **Common Event Format** - Standardized format for all detection events
2. **Automatic ATT&CK Enrichment** - Events are automatically enriched with MITRE ATT&CK technique IDs
3. **SIEM Integration** - Export enriched events to Elastic SIEM and Splunk in near real-time
4. **STIX/TAXII Enhancement** - ATT&CK mappings included in shared threat intelligence indicators

---

## Task 17: Event Enrichment with MITRE ATT&CK

### What Was Implemented

- **EventEnrichmentService** (`backend/event_enrichment.py`)
  - Automatically enriches detection events with MITRE ATT&CK technique IDs
  - Calls `threat_attribution` service to get technique mappings
  - Stores enriched events in Redis for SIEM export

### How It Works

1. Raw events from `traffic_monitor`, `behavioral_analysis`, or `decoy_generator` are received
2. Events are converted to indicator format
3. `threat_attribution` service is called to map indicators to MITRE ATT&CK techniques
4. Enriched events include:
   - Technique IDs (e.g., `T1001`, `T1003`)
   - Confidence scores
   - Threat actor information
   - Related indicators

### Usage

```python
from event_enrichment import EventEnrichmentService

# Initialize service
enrichment_service = EventEnrichmentService(
    threat_attribution_url="http://localhost:5004"
)

# Enrich a raw event
raw_event = {
    "timestamp": "2024-01-15T10:30:00Z",
    "source": "192.168.1.100",
    "destination": "10.0.0.50",
    "event_type": "threat",
    "severity": "high",
    "description": "SQL Injection attempt detected"
}

enriched_event = enrichment_service.enrich_event(
    raw_event, 
    source_service="traffic_monitor"
)

# Access enriched data
print(enriched_event.technique_ids)  # ['T1001', 'T1003']
print(enriched_event.confidence_score)  # 0.85
```

### API Endpoint

**POST `/api/events/enrich`**
- Requires authentication (admin/analyst role)
- Body:
  ```json
  {
    "event": {
      "timestamp": "2024-01-15T10:30:00Z",
      "source": "192.168.1.100",
      "destination": "10.0.0.50",
      "event_type": "threat",
      "severity": "high",
      "description": "SQL Injection attempt"
    },
    "source_service": "traffic_monitor"
  }
  ```
- Response:
  ```json
  {
    "enriched_event": {
      "event_id": "event_20240115_103000_123456",
      "timestamp": "2024-01-15T10:30:00Z",
      "source": "192.168.1.100",
      "destination": "10.0.0.50",
      "technique_ids": ["T1001", "T1003"],
      "confidence_score": 0.85,
      "related_indicators": [...],
      "metadata": {
        "technique_details": [...],
        "threat_actors": [...]
      }
    },
    "message": "Event enriched and exported to SIEM"
  }
  ```

---

## Task 18: Common Event Format

### What Was Implemented

- **EnrichedEvent Class** (`backend/event_enrichment.py`)
  - Standardized format for all detection events
  - Required fields: timestamp, source, destination, technique_ids, confidence_score, related_indicators
  - Optional fields: event_id, event_type, severity, description, source_service, metadata

### Event Format Schema

```python
{
    "event_id": "unique_event_identifier",
    "timestamp": "ISO-8601_timestamp",
    "source": "source_ip_or_identifier",
    "destination": "destination_ip_or_identifier",
    "technique_ids": ["T1001", "T1003"],  # MITRE ATT&CK technique IDs
    "confidence_score": 0.85,  # 0.0-1.0
    "related_indicators": [
        {
            "id": "indicator_id",
            "type": "ip",
            "value": "192.168.1.100",
            "tags": ["sql_injection", "high"]
        }
    ],
    "event_type": "threat" | "anomaly" | "alert" | "decoy_triggered",
    "severity": "low" | "medium" | "high" | "critical",
    "description": "Human-readable description",
    "source_service": "traffic_monitor" | "behavioral_analysis" | "decoy_generator",
    "metadata": {
        "technique_details": [...],
        "threat_actors": [...],
        "original_event": {...}
    }
}
```

### Benefits

- **Consistency**: All events follow the same format
- **Interoperability**: Easy to integrate with external systems
- **Traceability**: Full context preserved in metadata
- **Standardization**: Aligns with industry standards (MITRE ATT&CK, STIX)

---

## Task 19: SIEM Integration

### What Was Implemented

- **ElasticSIEMExporter** (`backend/siem_integration.py`)
  - Exports events to Elastic SIEM using **ECS (Elastic Common Schema)** format
  - Supports Elasticsearch API and bulk operations
  
- **SplunkSIEMExporter** (`backend/siem_integration.py`)
  - Exports events to Splunk using **HEC (HTTP Event Collector)** format
  - Supports batch operations

- **SIEMIntegrationManager** (`backend/siem_integration.py`)
  - Background thread that monitors Redis for new enriched events
  - Automatically exports to configured SIEM platforms
  - Handles retries and error recovery

### Configuration

#### Elastic SIEM

Set environment variables:
```bash
export ELASTIC_URL="http://localhost:9200"
export ELASTIC_API_KEY="your_api_key"  # OR
export ELASTIC_USERNAME="elastic"
export ELASTIC_PASSWORD="your_password"
```

#### Splunk SIEM

Set environment variables:
```bash
export SPLUNK_URL="https://localhost:8088"
export SPLUNK_TOKEN="your_hec_token"
```

### ECS Format (Elastic)

Events are exported in Elastic Common Schema format:
```json
{
    "@timestamp": "2024-01-15T10:30:00Z",
    "source": {
        "ip": "192.168.1.100"
    },
    "destination": {
        "ip": "10.0.0.50"
    },
    "event": {
        "category": "threat",
        "severity": 6,
        "type": ["threat"],
        "module": "cybersecurity_system"
    },
    "threat": {
        "technique": [
            {
                "id": "T1001",
                "name": "Data Obfuscation",
                "reference": "https://attack.mitre.org/techniques/T1001"
            }
        ]
    },
    "cybersecurity": {
        "event_id": "event_123",
        "source_service": "traffic_monitor",
        "confidence_score": 0.85
    }
}
```

### Splunk HEC Format

Events are exported in Splunk HEC format:
```json
{
    "time": 1705315800.0,
    "host": "traffic_monitor",
    "source": "traffic_monitor",
    "sourcetype": "cybersecurity:events",
    "index": "cybersecurity",
    "event": {
        "event_id": "event_123",
        "timestamp": "2024-01-15T10:30:00Z",
        "source": "192.168.1.100",
        "destination": "10.0.0.50",
        "mitre_attack": {
            "technique_ids": ["T1001", "T1003"],
            "techniques": [...],
            "threat_actors": [...]
        }
    }
}
```

### API Endpoints

**GET `/api/siem/status`**
- Returns status of SIEM integrations
- Response:
  ```json
  {
    "elastic": {
      "enabled": true,
      "url": "http://localhost:9200"
    },
    "splunk": {
      "enabled": true,
      "url": "https://localhost:8088"
    },
    "export_running": true
  }
  ```

**GET `/api/events/enriched`**
- Get recent enriched events
- Query params: `limit` (default: 100)

---

## Task 20: STIX/TAXII Enhancement

### What Was Implemented

- **Enhanced STIX Indicators** (`backend/threat_intelligence/threat_intelligence.py`)
  - STIX indicators now include MITRE ATT&CK technique IDs in labels
  - Technique details stored in `external_references`
  - Automatic enrichment when sharing indicators

### STIX Indicator with ATT&CK

```python
{
    "type": "indicator",
    "pattern": "[ipv4-addr:value = '192.168.1.100']",
    "labels": [
        "anomalous-activity",
        "mitre_attack:T1001",
        "mitre_attack:T1003"
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1001",
            "url": "https://attack.mitre.org/techniques/T1001"
        }
    ],
    "confidence": 0.85
}
```

### How It Works

1. When sharing indicators via STIX/TAXII, the system:
   - Checks if indicators have `technique_ids`
   - If not, automatically calls `threat_attribution` to enrich them
   - Includes technique IDs in STIX labels
   - Adds technique references to `external_references`

2. SIEM exports are aligned with standard schemas:
   - **Elastic**: Uses ECS (Elastic Common Schema)
   - **Splunk**: Uses HEC (HTTP Event Collector) format

---

## Integration Flow

```
┌─────────────────────┐
│ Detection Event     │
│ (traffic_monitor,   │
│  behavioral_analysis│
│  decoy_generator)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ EventEnrichment     │
│ Service             │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Threat Attribution  │
│ Service             │
│ (MITRE ATT&CK       │
│  Mapping)           │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ EnrichedEvent       │
│ (with technique_ids)│
└──────────┬──────────┘
           │
           ├─────────────────┐
           ▼                 ▼
┌──────────────────┐  ┌──────────────┐
│ SIEM Export      │  │ STIX/TAXII   │
│ (Elastic/Splunk) │  │ Sharing      │
└──────────────────┘  └──────────────┘
```

---

## Testing

### Test Event Enrichment

```bash
curl -X POST http://localhost:5000/api/events/enrich \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "timestamp": "2024-01-15T10:30:00Z",
      "source": "192.168.1.100",
      "destination": "10.0.0.50",
      "event_type": "threat",
      "severity": "high",
      "description": "SQL Injection attempt detected"
    },
    "source_service": "traffic_monitor"
  }'
```

### Check SIEM Status

```bash
curl -X GET http://localhost:5000/api/siem/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Get Enriched Events

```bash
curl -X GET http://localhost:5000/api/events/enriched?limit=10 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Environment Variables

```bash
# Threat Attribution Service
THREAT_ATTRIBUTION_URL=http://localhost:5004

# Elastic SIEM
ELASTIC_URL=http://localhost:9200
ELASTIC_API_KEY=your_api_key
# OR
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=your_password

# Splunk SIEM
SPLUNK_URL=https://localhost:8088
SPLUNK_TOKEN=your_hec_token

# Redis (for event queue)
REDIS_URL=redis://redis:6379
```

---

## Files Created/Modified

### New Files
- `backend/event_enrichment.py` - Event enrichment service and common event format
- `backend/siem_integration.py` - SIEM export modules (Elastic, Splunk)

### Modified Files
- `backend/app.py` - Added enrichment endpoints and SIEM integration
- `backend/threat_intelligence/threat_intelligence.py` - Enhanced STIX indicators with ATT&CK mappings

---

## Next Steps

1. **Configure SIEM Platforms**: Set up Elastic or Splunk and configure environment variables
2. **Test Integration**: Use the API endpoints to test event enrichment and SIEM export
3. **Monitor Exports**: Check SIEM platforms to verify events are being received
4. **Tune Mappings**: Adjust threat_attribution service to improve technique mapping accuracy
5. **Scale**: Consider using message queues (RabbitMQ, Kafka) for high-volume event processing

---

## Troubleshooting

### Events Not Being Enriched
- Check that `threat_attribution` service is running on port 5004
- Verify `THREAT_ATTRIBUTION_URL` environment variable

### SIEM Export Not Working
- Verify SIEM credentials and URLs in environment variables
- Check network connectivity to SIEM platforms
- Review logs for export errors

### STIX Indicators Missing ATT&CK Mappings
- Ensure `threat_attribution` service is accessible
- Check that indicators have sufficient metadata for mapping

---

## Summary

✅ **Task 17**: Events are automatically enriched with MITRE ATT&CK technique IDs  
✅ **Task 18**: Common event format defined and implemented  
✅ **Task 19**: SIEM integrations (Elastic, Splunk) implemented with standard schemas  
✅ **Task 20**: STIX/TAXII enhanced with ATT&CK mappings, SIEM exports use ECS/HEC formats

All four tasks from the MITRE ATT&CK Attribution with SIEM Integration section are now complete!

