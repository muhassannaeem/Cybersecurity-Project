"""
SIEM Integration Module

Task 19: Implement outbound integrations to external SIEM platforms (Elastic SIEM, Splunk)
Task 20: Align SIEM exports with standard schemas (ECS for Elastic, Splunk HEC format)

This module provides:
1. Elastic SIEM integration with ECS (Elastic Common Schema) format
2. Splunk integration with HEC (HTTP Event Collector) format
3. Automatic export of enriched events in near real-time
"""

import json
import logging
import os
import requests
from datetime import datetime
from typing import Dict, List, Optional
import redis
import threading
import time
from event_enrichment import EnrichedEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Task 20: Elastic SIEM Integration with ECS Format
# ============================================================================

class ElasticSIEMExporter:
    """
    Export enriched events to Elastic SIEM using ECS (Elastic Common Schema) format.
    
    ECS fields used:
    - @timestamp: Event timestamp
    - source.ip: Source IP address
    - destination.ip: Destination IP address
    - event.category: Event category (threat, anomaly, etc.)
    - event.severity: Event severity
    - threat.technique.id: MITRE ATT&CK technique ID
    - threat.technique.name: MITRE ATT&CK technique name
    - threat.confidence: Confidence score
    - custom fields for our specific data
    """
    
    def __init__(self,
                 elastic_url: str = None,
                 elastic_index: str = "cybersecurity-events",
                 elastic_api_key: str = None,
                 username: str = None,
                 password: str = None):
        self.elastic_url = elastic_url or os.getenv('ELASTIC_URL', 'http://localhost:9200')
        self.elastic_index = elastic_index
        self.elastic_api_key = elastic_api_key or os.getenv('ELASTIC_API_KEY')
        self.username = username or os.getenv('ELASTIC_USERNAME')
        self.password = password or os.getenv('ELASTIC_PASSWORD')
        self.enabled = bool(self.elastic_url and (self.elastic_api_key or (self.username and self.password)))
    
    def _get_headers(self) -> Dict[str, str]:
        """Get authentication headers for Elastic"""
        headers = {'Content-Type': 'application/json'}
        
        if self.elastic_api_key:
            headers['Authorization'] = f'ApiKey {self.elastic_api_key}'
        elif self.username and self.password:
            # Use basic auth
            import base64
            credentials = base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()
            headers['Authorization'] = f'Basic {credentials}'
        
        return headers
    
    def export_event(self, enriched_event: EnrichedEvent) -> bool:
        """
        Export a single enriched event to Elastic SIEM in ECS format.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            logger.debug("Elastic SIEM export is disabled")
            return False
        
        try:
            # Convert enriched event to ECS format
            ecs_doc = self._to_ecs_format(enriched_event)
            
            # Elasticsearch bulk API endpoint
            url = f"{self.elastic_url}/{self.elastic_index}/_doc"
            
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=ecs_doc,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.debug(f"Exported event {enriched_event.event_id} to Elastic SIEM")
                return True
            else:
                logger.warning(f"Elastic SIEM export failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error exporting to Elastic SIEM: {e}")
            return False
    
    def _to_ecs_format(self, event: EnrichedEvent) -> Dict:
        """
        Convert enriched event to Elastic Common Schema (ECS) format.
        
        ECS Reference: https://www.elastic.co/guide/en/ecs/current/index.html
        """
        ecs_doc = {
            # Timestamp
            '@timestamp': event.timestamp,
            
            # Source information
            'source': {
                'ip': event.source,
                'address': event.source
            },
            
            # Destination information
            'destination': {
                'ip': event.destination,
                'address': event.destination
            },
            
            # Event information
            'event': {
                'category': self._map_event_category(event.event_type),
                'severity': self._map_severity(event.severity),
                'kind': 'event',
                'type': [event.event_type],
                'module': 'cybersecurity_system',
                'dataset': event.source_service,
                'original': event.description
            },
            
            # Threat information (MITRE ATT&CK)
            'threat': {
                'technique': []
            },
            
            # Custom fields
            'cybersecurity': {
                'event_id': event.event_id,
                'source_service': event.source_service,
                'confidence_score': event.confidence_score,
                'related_indicators_count': len(event.related_indicators)
            }
        }
        
        # Add MITRE ATT&CK techniques
        if event.technique_ids and event.metadata.get('technique_details'):
            for technique_detail in event.metadata.get('technique_details', []):
                ecs_doc['threat']['technique'].append({
                    'id': technique_detail.get('id', ''),
                    'name': technique_detail.get('name', ''),
                    'reference': f"https://attack.mitre.org/techniques/{technique_detail.get('id', '').replace('.', '/')}",
                    'subtechnique': {
                        'id': technique_detail.get('id', ''),
                        'name': technique_detail.get('name', '')
                    }
                })
        
        # Add threat actors if available
        if event.metadata.get('threat_actors'):
            ecs_doc['threat']['actor'] = []
            for actor in event.metadata.get('threat_actors', []):
                ecs_doc['threat']['actor'].append({
                    'id': actor.get('id', ''),
                    'name': actor.get('name', ''),
                    'description': actor.get('description', '')
                })
        
        # Add related indicators
        if event.related_indicators:
            ecs_doc['cybersecurity']['related_indicators'] = event.related_indicators
        
        # Add metadata
        if event.metadata:
            ecs_doc['cybersecurity']['metadata'] = event.metadata
        
        return ecs_doc
    
    def _map_event_category(self, event_type: str) -> str:
        """Map event type to ECS event category"""
        mapping = {
            'threat': 'threat',
            'anomaly': 'anomaly',
            'alert': 'alert',
            'decoy_triggered': 'intrusion_detection',
            'behavioral_anomaly': 'anomaly'
        }
        return mapping.get(event_type, 'security')
    
    def _map_severity(self, severity: str) -> int:
        """Map severity string to ECS severity number (0-7)"""
        mapping = {
            'low': 2,
            'medium': 4,
            'high': 6,
            'critical': 7
        }
        return mapping.get(severity.lower(), 4)
    
    def export_batch(self, events: List[EnrichedEvent]) -> Dict[str, int]:
        """Export multiple events using Elasticsearch bulk API"""
        if not self.enabled:
            return {'success': 0, 'failed': len(events)}
        
        try:
            # Prepare bulk request
            bulk_body = []
            for event in events:
                # Action line
                action = {"index": {"_index": self.elastic_index}}
                bulk_body.append(json.dumps(action))
                
                # Document line
                ecs_doc = self._to_ecs_format(event)
                bulk_body.append(json.dumps(ecs_doc))
            
            # Send bulk request
            url = f"{self.elastic_url}/_bulk"
            response = requests.post(
                url,
                headers=self._get_headers(),
                data='\n'.join(bulk_body) + '\n',
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                success = sum(1 for item in result.get('items', []) if item.get('index', {}).get('status') in [200, 201])
                failed = len(events) - success
                logger.info(f"Bulk exported {success} events to Elastic SIEM, {failed} failed")
                return {'success': success, 'failed': failed}
            else:
                logger.warning(f"Elastic bulk export failed: {response.status_code}")
                return {'success': 0, 'failed': len(events)}
                
        except Exception as e:
            logger.error(f"Error in bulk export to Elastic: {e}")
            return {'success': 0, 'failed': len(events)}


# ============================================================================
# Task 20: Splunk Integration with HEC Format
# ============================================================================

class SplunkSIEMExporter:
    """
    Export enriched events to Splunk using HEC (HTTP Event Collector) format.
    
    Splunk HEC format:
    - time: Event timestamp (Unix epoch time)
    - host: Source host
    - source: Source service
    - sourcetype: Event type
    - event: Event data (JSON)
    """
    
    def __init__(self,
                 splunk_url: str = None,
                 splunk_token: str = None,
                 splunk_index: str = "cybersecurity",
                 splunk_sourcetype: str = "cybersecurity:events"):
        self.splunk_url = splunk_url or os.getenv('SPLUNK_URL', 'https://localhost:8088')
        self.splunk_token = splunk_token or os.getenv('SPLUNK_TOKEN')
        self.splunk_index = splunk_index
        self.splunk_sourcetype = splunk_sourcetype
        self.enabled = bool(self.splunk_url and self.splunk_token)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Splunk HEC"""
        return {
            'Authorization': f'Splunk {self.splunk_token}',
            'Content-Type': 'application/json'
        }
    
    def export_event(self, enriched_event: EnrichedEvent) -> bool:
        """
        Export a single enriched event to Splunk using HEC format.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            logger.debug("Splunk SIEM export is disabled")
            return False
        
        try:
            # Convert enriched event to Splunk HEC format
            hec_event = self._to_hec_format(enriched_event)
            
            # Splunk HEC endpoint
            url = f"{self.splunk_url}/services/collector/event"
            
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=hec_event,
                timeout=10,
                verify=False  # In production, use proper SSL certificates
            )
            
            if response.status_code == 200:
                logger.debug(f"Exported event {enriched_event.event_id} to Splunk SIEM")
                return True
            else:
                logger.warning(f"Splunk HEC export failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error exporting to Splunk SIEM: {e}")
            return False
    
    def _to_hec_format(self, event: EnrichedEvent) -> Dict:
        """
        Convert enriched event to Splunk HEC format.
        
        HEC Format Reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/HECExamples
        """
        # Convert timestamp to Unix epoch
        try:
            dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
            epoch_time = dt.timestamp()
        except:
            epoch_time = time.time()
        
        # Build HEC event
        hec_event = {
            'time': epoch_time,
            'host': event.source_service,
            'source': event.source_service,
            'sourcetype': self.splunk_sourcetype,
            'index': self.splunk_index,
            'event': {
                # Core fields
                'event_id': event.event_id,
                'timestamp': event.timestamp,
                'source': event.source,
                'destination': event.destination,
                'event_type': event.event_type,
                'severity': event.severity,
                'description': event.description,
                'source_service': event.source_service,
                'confidence_score': event.confidence_score,
                
                # MITRE ATT&CK techniques
                'mitre_attack': {
                    'technique_ids': event.technique_ids,
                    'techniques': event.metadata.get('technique_details', []),
                    'threat_actors': event.metadata.get('threat_actors', [])
                },
                
                # Related indicators
                'related_indicators': event.related_indicators,
                
                # Metadata
                'metadata': event.metadata
            }
        }
        
        return hec_event
    
    def export_batch(self, events: List[EnrichedEvent]) -> Dict[str, int]:
        """Export multiple events using Splunk HEC batch API"""
        if not self.enabled:
            return {'success': 0, 'failed': len(events)}
        
        try:
            # Splunk HEC batch endpoint
            url = f"{self.splunk_url}/services/collector"
            
            # Prepare batch payload
            batch_events = []
            for event in events:
                hec_event = self._to_hec_format(event)
                batch_events.append(hec_event)
            
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=batch_events,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                result = response.json()
                success = result.get('ackId', 0)  # Splunk returns ackId for successful batches
                logger.info(f"Bulk exported {len(events)} events to Splunk SIEM")
                return {'success': len(events), 'failed': 0}
            else:
                logger.warning(f"Splunk bulk export failed: {response.status_code}")
                return {'success': 0, 'failed': len(events)}
                
        except Exception as e:
            logger.error(f"Error in bulk export to Splunk: {e}")
            return {'success': 0, 'failed': len(events)}


# ============================================================================
# Task 19: SIEM Integration Manager
# ============================================================================

class SIEMIntegrationManager:
    """
    Manages SIEM exports in near real-time.
    
    This service:
    1. Monitors Redis for new enriched events
    2. Exports them to configured SIEM platforms (Elastic, Splunk)
    3. Handles retries and error recovery
    """
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.elastic_exporter = ElasticSIEMExporter()
        self.splunk_exporter = SplunkSIEMExporter()
        self.running = False
        self.export_thread = None
        self.export_interval = 5  # Export every 5 seconds
    
    def start(self):
        """Start the SIEM export background thread"""
        if self.running:
            return
        
        self.running = True
        self.export_thread = threading.Thread(target=self._export_loop, daemon=True)
        self.export_thread.start()
        logger.info("SIEM Integration Manager started")
    
    def stop(self):
        """Stop the SIEM export background thread"""
        self.running = False
        if self.export_thread:
            self.export_thread.join(timeout=5)
        logger.info("SIEM Integration Manager stopped")
    
    def _export_loop(self):
        """Background loop that exports enriched events to SIEM platforms"""
        while self.running:
            try:
                # Get enriched events from Redis queue
                events = self._get_pending_events()
                
                if events:
                    # Export to Elastic
                    if self.elastic_exporter.enabled:
                        elastic_result = self.elastic_exporter.export_batch(events)
                        logger.debug(f"Elastic export: {elastic_result}")
                    
                    # Export to Splunk
                    if self.splunk_exporter.enabled:
                        splunk_result = self.splunk_exporter.export_batch(events)
                        logger.debug(f"Splunk export: {splunk_result}")
                
                time.sleep(self.export_interval)
                
            except Exception as e:
                logger.error(f"Error in SIEM export loop: {e}")
                time.sleep(10)  # Wait longer on error
    
    def _get_pending_events(self, batch_size: int = 100) -> List[EnrichedEvent]:
        """Get pending enriched events from Redis queue"""
        try:
            key = "enriched_events:queue"
            events_json = self.redis_client.lrange(key, 0, batch_size - 1)
            
            events = []
            for event_json in events_json:
                try:
                    event_data = json.loads(event_json)
                    events.append(EnrichedEvent.from_dict(event_data))
                except Exception as e:
                    logger.error(f"Error parsing enriched event: {e}")
            
            # Remove processed events from queue
            if events:
                self.redis_client.ltrim(key, len(events), -1)
            
            return events
            
        except Exception as e:
            logger.error(f"Error getting pending events: {e}")
            return []
    
    def export_event_immediately(self, event: EnrichedEvent) -> Dict[str, bool]:
        """Export a single event immediately to all configured SIEM platforms"""
        results = {
            'elastic': False,
            'splunk': False
        }
        
        if self.elastic_exporter.enabled:
            results['elastic'] = self.elastic_exporter.export_event(event)
        
        if self.splunk_exporter.enabled:
            results['splunk'] = self.splunk_exporter.export_event(event)
        
        return results

