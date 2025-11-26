"""
Event Enrichment Service for MITRE ATT&CK Attribution

This module provides:
1. Common event format definition
2. Automatic enrichment of detection events with MITRE ATT&CK technique IDs
3. Integration with threat_attribution service
"""

import json
import logging
import os
import requests
from datetime import datetime
from typing import Dict, List, Optional
import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Task 18: Common Event Format
# ============================================================================

class EnrichedEvent:
    """
    Common event format for all detection events.
    
    Required fields:
    - timestamp: ISO-8601 timestamp
    - source: Source IP/identifier
    - destination: Destination IP/identifier
    - technique_ids: List of MITRE ATT&CK technique IDs
    - confidence_score: Overall confidence (0.0-1.0)
    - related_indicators: List of related indicators
    
    Optional fields:
    - event_id: Unique event identifier
    - event_type: Type of event (threat, anomaly, alert, decoy_triggered, etc.)
    - severity: low/medium/high/critical
    - description: Human-readable description
    - source_service: Which service detected this (traffic_monitor, behavioral_analysis, decoy_generator)
    - metadata: Additional context
    """
    
    def __init__(self, 
                 timestamp: str,
                 source: str,
                 destination: str,
                 technique_ids: List[str],
                 confidence_score: float,
                 related_indicators: List[Dict],
                 event_id: Optional[str] = None,
                 event_type: str = "threat",
                 severity: str = "medium",
                 description: str = "",
                 source_service: str = "unknown",
                 metadata: Optional[Dict] = None):
        self.event_id = event_id or f"event_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        self.timestamp = timestamp
        self.source = source
        self.destination = destination
        self.technique_ids = technique_ids
        self.confidence_score = confidence_score
        self.related_indicators = related_indicators
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.source_service = source_service
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'source': self.source,
            'destination': self.destination,
            'technique_ids': self.technique_ids,
            'confidence_score': self.confidence_score,
            'related_indicators': self.related_indicators,
            'event_type': self.event_type,
            'severity': self.severity,
            'description': self.description,
            'source_service': self.source_service,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'EnrichedEvent':
        """Create EnrichedEvent from dictionary"""
        return cls(
            event_id=data.get('event_id'),
            timestamp=data['timestamp'],
            source=data['source'],
            destination=data['destination'],
            technique_ids=data.get('technique_ids', []),
            confidence_score=data.get('confidence_score', 0.5),
            related_indicators=data.get('related_indicators', []),
            event_type=data.get('event_type', 'threat'),
            severity=data.get('severity', 'medium'),
            description=data.get('description', ''),
            source_service=data.get('source_service', 'unknown'),
            metadata=data.get('metadata', {})
        )


# ============================================================================
# Task 17: Event Enrichment Service
# ============================================================================

class EventEnrichmentService:
    """
    Service that automatically enriches detection events with MITRE ATT&CK technique IDs.
    
    This service:
    1. Receives raw events from traffic_monitor, behavioral_analysis, decoy_generator
    2. Converts them to common event format
    3. Calls threat_attribution service to get MITRE ATT&CK mappings
    4. Returns enriched events with technique IDs and confidence scores
    """
    
    def __init__(self, 
                 threat_attribution_url: str = "http://localhost:5004",
                 redis_url: str = "redis://redis:6379"):
        self.threat_attribution_url = threat_attribution_url
        self.redis_client = redis.from_url(redis_url)
    
    def enrich_event(self, raw_event: Dict, source_service: str = "unknown") -> EnrichedEvent:
        """
        Enrich a raw detection event with MITRE ATT&CK technique IDs.
        
        Args:
            raw_event: Raw event from traffic_monitor, behavioral_analysis, or decoy_generator
            source_service: Name of the service that generated this event
        
        Returns:
            EnrichedEvent with MITRE ATT&CK technique IDs
        """
        try:
            # Convert raw event to indicator format for threat_attribution
            indicator = self._raw_event_to_indicator(raw_event, source_service)
            
            # Call threat_attribution service to get MITRE ATT&CK mappings
            technique_mappings = self._get_attack_patterns([indicator])
            
            # Extract technique IDs and confidence scores
            technique_ids = []
            confidence_scores = []
            
            if technique_mappings and 'techniques' in technique_mappings:
                for technique in technique_mappings['techniques']:
                    technique_ids.append(technique.get('id', ''))
                    confidence_scores.append(technique.get('confidence', 0.5))
            
            # Calculate overall confidence (average of top 3)
            overall_confidence = sum(sorted(confidence_scores, reverse=True)[:3]) / min(3, len(confidence_scores)) if confidence_scores else 0.5
            
            # Build related indicators list
            related_indicators = [indicator]
            
            # Create enriched event
            enriched_event = EnrichedEvent(
                timestamp=raw_event.get('timestamp', datetime.now().isoformat()),
                source=raw_event.get('source', raw_event.get('source_ip', 'unknown')),
                destination=raw_event.get('destination', raw_event.get('dest_ip', 'unknown')),
                technique_ids=technique_ids,
                confidence_score=overall_confidence,
                related_indicators=related_indicators,
                event_type=raw_event.get('event_type', 'threat'),
                severity=raw_event.get('severity', 'medium'),
                description=raw_event.get('description', raw_event.get('message', '')),
                source_service=source_service,
                metadata={
                    'original_event': raw_event,
                    'technique_details': technique_mappings.get('techniques', []),
                    'threat_actors': technique_mappings.get('threat_actors', [])
                }
            )
            
            # Store enriched event in Redis for SIEM export
            self._store_enriched_event(enriched_event)
            
            return enriched_event
            
        except Exception as e:
            logger.error(f"Error enriching event: {e}")
            # Return event without enrichment if attribution fails
            return EnrichedEvent(
                timestamp=raw_event.get('timestamp', datetime.now().isoformat()),
                source=raw_event.get('source', 'unknown'),
                destination=raw_event.get('destination', 'unknown'),
                technique_ids=[],
                confidence_score=0.0,
                related_indicators=[],
                event_type=raw_event.get('event_type', 'threat'),
                severity=raw_event.get('severity', 'medium'),
                description=raw_event.get('description', ''),
                source_service=source_service,
                metadata={'enrichment_error': str(e)}
            )
    
    def _raw_event_to_indicator(self, raw_event: Dict, source_service: str) -> Dict:
        """Convert raw event to indicator format for threat_attribution"""
        # Extract common fields
        indicator = {
            'id': raw_event.get('id', raw_event.get('event_id', '')),
            'timestamp': raw_event.get('timestamp', datetime.now().isoformat()),
            'type': self._infer_indicator_type(raw_event),
            'value': raw_event.get('source', raw_event.get('source_ip', '')),
            'severity': raw_event.get('severity', 'medium'),
            'tags': self._extract_tags(raw_event, source_service),
            'description': raw_event.get('description', raw_event.get('message', ''))
        }
        return indicator
    
    def _infer_indicator_type(self, raw_event: Dict) -> str:
        """Infer indicator type from raw event"""
        # Check for IP addresses
        if 'source_ip' in raw_event or 'source' in raw_event:
            source = raw_event.get('source_ip') or raw_event.get('source', '')
            if self._is_ip_address(source):
                return 'ip'
        
        # Check for domain names
        if 'domain' in raw_event or 'hostname' in raw_event:
            return 'domain'
        
        # Check for URLs
        if 'url' in raw_event or 'uri' in raw_event:
            return 'url'
        
        # Default to IP
        return 'ip'
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        try:
            parts = value.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _extract_tags(self, raw_event: Dict, source_service: str) -> List[str]:
        """Extract tags from raw event for ATT&CK mapping"""
        tags = []
        
        # Add source service
        tags.append(source_service)
        
        # Add event type
        if 'event_type' in raw_event:
            tags.append(raw_event['event_type'])
        if 'threat_type' in raw_event:
            tags.append(raw_event['threat_type'])
        if 'anomaly_type' in raw_event:
            tags.append(raw_event['anomaly_type'])
        
        # Add severity
        if 'severity' in raw_event:
            tags.append(raw_event['severity'])
        
        # Add protocol if present
        if 'protocol' in raw_event:
            tags.append(raw_event['protocol'])
        
        # Add port if present
        if 'port' in raw_event:
            tags.append(f"port_{raw_event['port']}")
        
        return tags
    
    def _get_attack_patterns(self, indicators: List[Dict]) -> Dict:
        """Call threat_attribution service to get MITRE ATT&CK mappings"""
        try:
            response = requests.post(
                f"{self.threat_attribution_url}/map_patterns",
                json={'indicators': indicators},
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Threat attribution service returned {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error calling threat_attribution service: {e}")
            return {}
    
    def _store_enriched_event(self, event: EnrichedEvent):
        """Store enriched event in Redis for SIEM export"""
        try:
            # Store in a queue for SIEM export
            key = f"enriched_events:queue"
            event_json = json.dumps(event.to_dict())
            self.redis_client.lpush(key, event_json)
            
            # Also store by timestamp for retrieval
            timestamp_key = f"enriched_events:{event.timestamp}"
            self.redis_client.setex(timestamp_key, 86400, event_json)  # Store for 24 hours
            
            logger.debug(f"Stored enriched event {event.event_id} in Redis")
            
        except Exception as e:
            logger.error(f"Error storing enriched event: {e}")
    
    def enrich_batch(self, raw_events: List[Dict], source_service: str = "unknown") -> List[EnrichedEvent]:
        """Enrich multiple events at once"""
        enriched_events = []
        for raw_event in raw_events:
            enriched = self.enrich_event(raw_event, source_service)
            enriched_events.append(enriched)
        return enriched_events
    
    def get_enriched_events(self, limit: int = 100) -> List[EnrichedEvent]:
        """Get recent enriched events from Redis"""
        try:
            key = "enriched_events:queue"
            events_json = self.redis_client.lrange(key, 0, limit - 1)
            
            events = []
            for event_json in events_json:
                try:
                    event_data = json.loads(event_json)
                    events.append(EnrichedEvent.from_dict(event_data))
                except Exception as e:
                    logger.error(f"Error parsing enriched event: {e}")
            
            return events
            
        except Exception as e:
            logger.error(f"Error getting enriched events: {e}")
            return []

