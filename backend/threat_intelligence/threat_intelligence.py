import json
import logging
import os
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from flask import Flask, request, jsonify
import redis
import pandas as pd
import numpy as np
from stix2 import (
    Indicator, ThreatActor, Campaign, Malware, Tool, 
    AttackPattern, Vulnerability, ObservedData, 
    Identity, Infrastructure, IntrusionSet,
    MemoryStore, Filter
)
# from taxii2client import Server, Collection  # Temporarily disabled
import xmltodict
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligenceSharing:
    """Threat Intelligence Sharing with STIX/TAXII integration"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.stix_store = MemoryStore()
        self.taxii_servers = {}
        self.sharing_config = {
            'auto_share': True,
            'share_interval': 300,  # 5 minutes
            'confidence_threshold': 0.7,
            'max_indicators_per_batch': 100
        }
        
        # STIX/TAXII server configurations
        self.taxii_configs = {
            'opencti': {
                'url': 'https://demo.opencti.io/graphql',
                'api_key': os.getenv('OPENCTI_API_KEY', ''),
                'enabled': True
            },
            'misp': {
                'url': 'https://www.misp-project.org/feeds/',
                'api_key': os.getenv('MISP_API_KEY', ''),
                'enabled': True
            },
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/',
                'api_key': os.getenv('ALIENVAULT_API_KEY', ''),
                'enabled': True
            }
        }
        
        # Initialize STIX objects
        self._initialize_stix_objects()
        
        # Start background sharing thread
        self.sharing_thread = threading.Thread(target=self._background_sharing, daemon=True)
        self.sharing_thread.start()
        
        # TAXII functionality temporarily disabled
        logger.warning("TAXII functionality is temporarily disabled due to package issues")
    
    def _initialize_stix_objects(self):
        """Initialize STIX objects for the organization"""
        try:
            # Create organization identity
            self.organization = Identity(
                id="identity--" + "a" * 32,
                name="Cybersecurity System",
                identity_class="organization",
                description="Automated cybersecurity system for threat intelligence sharing"
            )
            
            # Add to STIX store
            self.stix_store.add(self.organization)
            
            logger.info("Initialized STIX objects")
            
        except Exception as e:
            logger.error(f"Error initializing STIX objects: {e}")
    
    def create_stix_indicator(self, indicator_data: Dict) -> Optional[Indicator]:
        """Create STIX 2.1 Indicator from indicator data"""
        try:
            # Extract indicator properties
            indicator_type = indicator_data.get('type', '')
            value = indicator_data.get('value', '')
            description = indicator_data.get('description', '')
            confidence = indicator_data.get('confidence', 0.5)
            tags = indicator_data.get('tags', [])
            
            # Create pattern based on indicator type
            pattern = self._create_stix_pattern(indicator_type, value)
            
            if not pattern:
                logger.warning(f"Could not create pattern for indicator type: {indicator_type}")
                return None
            
            # Create STIX Indicator
            stix_indicator = Indicator(
                pattern=pattern,
                pattern_type="stix",
                indicator_types=["anomalous-activity"],
                valid_from=datetime.now(),
                description=description,
                confidence=confidence,
                labels=tags,
                created_by_ref=self.organization.id,
                object_marking_refs=[]
            )
            
            return stix_indicator
            
        except Exception as e:
            logger.error(f"Error creating STIX indicator: {e}")
            return None
    
    def _create_stix_pattern(self, indicator_type: str, value: str) -> Optional[str]:
        """Create STIX pattern based on indicator type"""
        try:
            if indicator_type == 'ip':
                return f"[ipv4-addr:value = '{value}']"
            elif indicator_type == 'domain':
                return f"[domain-name:value = '{value}']"
            elif indicator_type == 'url':
                return f"[url:value = '{value}']"
            elif indicator_type == 'email':
                return f"[email-addr:value = '{value}']"
            elif indicator_type == 'hash':
                if len(value) == 32:
                    return f"[file:hashes.MD5 = '{value}']"
                elif len(value) == 40:
                    return f"[file:hashes.SHA-1 = '{value}']"
                elif len(value) == 64:
                    return f"[file:hashes.SHA-256 = '{value}']"
            elif indicator_type == 'file':
                return f"[file:name = '{value}']"
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error creating STIX pattern: {e}")
            return None
    
    def create_stix_threat_actor(self, actor_data: Dict) -> Optional[ThreatActor]:
        """Create STIX 2.1 ThreatActor from actor data"""
        try:
            actor_id = actor_data.get('id', '')
            name = actor_data.get('name', '')
            description = actor_data.get('description', '')
            aliases = actor_data.get('aliases', [])
            
            stix_actor = ThreatActor(
                name=name,
                description=description,
                threat_level="medium",
                primary_motivation="financial-gain",
                aliases=aliases,
                created_by_ref=self.organization.id
            )
            
            return stix_actor
            
        except Exception as e:
            logger.error(f"Error creating STIX threat actor: {e}")
            return None
    
    def create_stix_campaign(self, campaign_data: Dict) -> Optional[Campaign]:
        """Create STIX 2.1 Campaign from campaign data"""
        try:
            name = campaign_data.get('name', '')
            description = campaign_data.get('description', '')
            objective = campaign_data.get('objective', '')
            
            stix_campaign = Campaign(
                name=name,
                description=description,
                objective=objective,
                created_by_ref=self.organization.id
            )
            
            return stix_campaign
            
        except Exception as e:
            logger.error(f"Error creating STIX campaign: {e}")
            return None
    
    def create_stix_malware(self, malware_data: Dict) -> Optional[Malware]:
        """Create STIX 2.1 Malware from malware data"""
        try:
            name = malware_data.get('name', '')
            description = malware_data.get('description', '')
            malware_type = malware_data.get('type', '')
            
            stix_malware = Malware(
                name=name,
                description=description,
                is_family=True,
                malware_types=[malware_type],
                created_by_ref=self.organization.id
            )
            
            return stix_malware
            
        except Exception as e:
            logger.error(f"Error creating STIX malware: {e}")
            return None
    
    def share_indicators(self, indicators: List[Dict]) -> Dict:
        """Share indicators via STIX/TAXII"""
        try:
            results = {
                'shared': 0,
                'failed': 0,
                'errors': []
            }
            
            # Create STIX indicators
            stix_indicators = []
            for indicator in indicators:
                stix_indicator = self.create_stix_indicator(indicator)
                if stix_indicator:
                    stix_indicators.append(stix_indicator)
                    self.stix_store.add(stix_indicator)
            
            # Share with each configured TAXII server
            for server_name, config in self.taxii_configs.items():
                if not config['enabled']:
                    continue
                
                try:
                    success = self._share_with_taxii_server(server_name, config, stix_indicators)
                    if success:
                        results['shared'] += len(stix_indicators)
                    else:
                        results['failed'] += len(stix_indicators)
                        results['errors'].append(f"Failed to share with {server_name}")
                        
                except Exception as e:
                    results['failed'] += len(stix_indicators)
                    results['errors'].append(f"Error sharing with {server_name}: {str(e)}")
            
            # Store sharing results
            self._store_sharing_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error sharing indicators: {e}")
            return {'shared': 0, 'failed': len(indicators), 'errors': [str(e)]}
    
    def _share_with_taxii_server(self, server_name: str, config: Dict, indicators: List) -> bool:
        """Share indicators with a specific TAXII server"""
        try:
            if server_name == 'opencti':
                return self._share_with_opencti(config, indicators)
            elif server_name == 'misp':
                return self._share_with_misp(config, indicators)
            elif server_name == 'alienvault':
                return self._share_with_alienvault(config, indicators)
            else:
                logger.warning(f"Unknown TAXII server: {server_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error sharing with {server_name}: {e}")
            return False
    
    def _share_with_opencti(self, config: Dict, indicators: List) -> bool:
        """Share indicators with OpenCTI"""
        try:
            # OpenCTI uses GraphQL API
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {config["api_key"]}'
            }
            
            # Convert STIX indicators to OpenCTI format
            for indicator in indicators:
                opencti_data = {
                    'query': '''
                    mutation IndicatorAdd($input: IndicatorAddInput!) {
                        indicatorAdd(input: $input) {
                            id
                        }
                    }
                    ''',
                    'variables': {
                        'input': {
                            'name': indicator.name,
                            'pattern': indicator.pattern,
                            'pattern_type': indicator.pattern_type,
                            'indicator_types': indicator.indicator_types,
                            'description': indicator.description,
                            'confidence': indicator.confidence
                        }
                    }
                }
                
                response = requests.post(
                    config['url'],
                    headers=headers,
                    json=opencti_data,
                    timeout=30
                )
                
                if response.status_code != 200:
                    logger.warning(f"OpenCTI API error: {response.status_code}")
                    return False
            
            logger.info(f"Successfully shared {len(indicators)} indicators with OpenCTI")
            return True
            
        except Exception as e:
            logger.error(f"Error sharing with OpenCTI: {e}")
            return False
    
    def _share_with_misp(self, config: Dict, indicators: List) -> bool:
        """Share indicators with MISP"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': config['api_key']
            }
            
            # Convert STIX indicators to MISP format
            misp_events = []
            for indicator in indicators:
                misp_event = {
                    'Event': {
                        'info': f"STIX Indicator: {indicator.name}",
                        'distribution': 1,  # Your organization only
                        'threat_level_id': 2,  # Medium
                        'analysis': 1,  # Initial
                        'date': datetime.now().strftime('%Y-%m-%d'),
                        'Attribute': []
                    }
                }
                
                # Add indicator as attribute
                attribute = {
                    'type': self._get_misp_attribute_type(indicator),
                    'value': self._extract_indicator_value(indicator),
                    'comment': indicator.description,
                    'to_ids': True
                }
                misp_event['Event']['Attribute'].append(attribute)
                
                misp_events.append(misp_event)
            
            # Share events
            for event in misp_events:
                response = requests.post(
                    f"{config['url']}/events/add",
                    headers=headers,
                    json=event,
                    timeout=30
                )
                
                if response.status_code != 200:
                    logger.warning(f"MISP API error: {response.status_code}")
                    return False
            
            logger.info(f"Successfully shared {len(indicators)} indicators with MISP")
            return True
            
        except Exception as e:
            logger.error(f"Error sharing with MISP: {e}")
            return False
    
    def _share_with_alienvault(self, config: Dict, indicators: List) -> bool:
        """Share indicators with AlienVault OTX"""
        try:
            headers = {
                'X-OTX-API-KEY': config['api_key']
            }
            
            # OTX uses a different API format
            for indicator in indicators:
                otx_data = {
                    'indicator': self._extract_indicator_value(indicator),
                    'type': self._get_otx_indicator_type(indicator),
                    'description': indicator.description,
                    'tags': indicator.labels
                }
                
                response = requests.post(
                    f"{config['url']}/indicators/submit",
                    headers=headers,
                    json=otx_data,
                    timeout=30
                )
                
                if response.status_code not in [200, 201]:
                    logger.warning(f"AlienVault API error: {response.status_code}")
                    return False
            
            logger.info(f"Successfully shared {len(indicators)} indicators with AlienVault")
            return True
            
        except Exception as e:
            logger.error(f"Error sharing with AlienVault: {e}")
            return False
    
    def _get_misp_attribute_type(self, indicator) -> str:
        """Get MISP attribute type from STIX indicator"""
        pattern = indicator.pattern
        if 'ipv4-addr' in pattern:
            return 'ip-dst'
        elif 'domain-name' in pattern:
            return 'domain'
        elif 'url' in pattern:
            return 'url'
        elif 'email-addr' in pattern:
            return 'email-dst'
        elif 'file:hashes' in pattern:
            return 'sha256'
        else:
            return 'text'
    
    def _get_otx_indicator_type(self, indicator) -> str:
        """Get OTX indicator type from STIX indicator"""
        pattern = indicator.pattern
        if 'ipv4-addr' in pattern:
            return 'IPv4'
        elif 'domain-name' in pattern:
            return 'domain'
        elif 'url' in pattern:
            return 'URL'
        elif 'email-addr' in pattern:
            return 'email'
        elif 'file:hashes' in pattern:
            return 'FileHash-SHA256'
        else:
            return 'text'
    
    def _extract_indicator_value(self, indicator) -> str:
        """Extract indicator value from STIX pattern"""
        pattern = indicator.pattern
        if '=' in pattern:
            value = pattern.split('=')[1].strip()
            return value.strip("'\"")
        return pattern
    
    def receive_indicators(self, source: str, indicators: List[Dict]) -> Dict:
        """Receive indicators from external sources"""
        try:
            results = {
                'received': 0,
                'processed': 0,
                'errors': []
            }
            
            for indicator in indicators:
                try:
                    # Validate indicator
                    if self._validate_indicator(indicator):
                        # Store in STIX format
                        stix_indicator = self.create_stix_indicator(indicator)
                        if stix_indicator:
                            self.stix_store.add(stix_indicator)
                            results['processed'] += 1
                    
                    results['received'] += 1
                    
                except Exception as e:
                    results['errors'].append(f"Error processing indicator: {str(e)}")
            
            # Store received indicators
            self._store_received_indicators(source, indicators)
            
            logger.info(f"Received {results['received']} indicators from {source}")
            return results
            
        except Exception as e:
            logger.error(f"Error receiving indicators: {e}")
            return {'received': 0, 'processed': 0, 'errors': [str(e)]}
    
    def _validate_indicator(self, indicator: Dict) -> bool:
        """Validate indicator data"""
        required_fields = ['type', 'value']
        
        for field in required_fields:
            if field not in indicator or not indicator[field]:
                return False
        
        # Validate indicator type
        valid_types = ['ip', 'domain', 'url', 'email', 'hash', 'file']
        if indicator['type'] not in valid_types:
            return False
        
        # Validate confidence score
        confidence = indicator.get('confidence', 0.5)
        if not 0 <= confidence <= 1:
            return False
        
        return True
    
    def _store_sharing_results(self, results: Dict):
        """Store sharing results in Redis"""
        try:
            key = f"sharing_results:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 86400, json.dumps(results))  # Store for 24 hours
        except Exception as e:
            logger.error(f"Error storing sharing results: {e}")
    
    def _store_received_indicators(self, source: str, indicators: List[Dict]):
        """Store received indicators in Redis"""
        try:
            key = f"received_indicators:{source}:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 86400, json.dumps(indicators))  # Store for 24 hours
        except Exception as e:
            logger.error(f"Error storing received indicators: {e}")
    
    def _background_sharing(self):
        """Background thread for automatic sharing"""
        while True:
            try:
                if self.sharing_config['auto_share']:
                    # Get indicators from Redis that need sharing
                    indicators = self._get_pending_indicators()
                    
                    if indicators:
                        logger.info(f"Auto-sharing {len(indicators)} indicators")
                        self.share_indicators(indicators)
                
                time.sleep(self.sharing_config['share_interval'])
                
            except Exception as e:
                logger.error(f"Error in background sharing: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def _get_pending_indicators(self) -> List[Dict]:
        """Get indicators pending for sharing"""
        try:
            # Get indicators from Redis that haven't been shared yet
            pending_keys = self.redis_client.keys("pending_indicator:*")
            indicators = []
            
            for key in pending_keys[:self.sharing_config['max_indicators_per_batch']]:
                indicator_data = self.redis_client.get(key)
                if indicator_data:
                    indicator = json.loads(indicator_data)
                    indicators.append(indicator)
                    # Remove from pending
                    self.redis_client.delete(key)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error getting pending indicators: {e}")
            return []
    
    def get_sharing_statistics(self) -> Dict:
        """Get sharing statistics"""
        try:
            stats = {
                'total_shared': 0,
                'total_received': 0,
                'active_servers': 0,
                'last_share_time': None,
                'errors_last_24h': 0
            }
            
            # Count active servers
            for config in self.taxii_configs.values():
                if config['enabled']:
                    stats['active_servers'] += 1
            
            # Get recent sharing results
            sharing_keys = self.redis_client.keys("sharing_results:*")
            for key in sharing_keys[-10:]:  # Last 10 results
                result_data = self.redis_client.get(key)
                if result_data:
                    result = json.loads(result_data)
                    stats['total_shared'] += result.get('shared', 0)
                    stats['errors_last_24h'] += len(result.get('errors', []))
            
            # Get recent received indicators
            received_keys = self.redis_client.keys("received_indicators:*")
            for key in received_keys[-10:]:  # Last 10 batches
                indicator_data = self.redis_client.get(key)
                if indicator_data:
                    indicators = json.loads(indicator_data)
                    stats['total_received'] += len(indicators)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting sharing statistics: {e}")
            return {}

# Flask API for the threat intelligence sharing module
app = Flask(__name__)
ti_sharing = ThreatIntelligenceSharing()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'threat_intelligence_sharing',
        'active_servers': sum(1 for config in ti_sharing.taxii_configs.values() if config['enabled'])
    })

@app.route('/share', methods=['POST'])
def share_indicators():
    """Share indicators via STIX/TAXII"""
    try:
        data = request.get_json()
        indicators = data.get('indicators', [])
        
        if not indicators:
            return jsonify({'error': 'No indicators provided'}), 400
        
        results = ti_sharing.share_indicators(indicators)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/receive', methods=['POST'])
def receive_indicators():
    """Receive indicators from external sources"""
    try:
        data = request.get_json()
        source = data.get('source', 'unknown')
        indicators = data.get('indicators', [])
        
        if not indicators:
            return jsonify({'error': 'No indicators provided'}), 400
        
        results = ti_sharing.receive_indicators(source, indicators)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get sharing statistics"""
    try:
        stats = ti_sharing.get_sharing_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/config', methods=['GET', 'PUT'])
def manage_config():
    """Get or update sharing configuration"""
    try:
        if request.method == 'GET':
            return jsonify(ti_sharing.sharing_config)
        else:
            data = request.get_json()
            ti_sharing.sharing_config.update(data)
            return jsonify({'success': True, 'config': ti_sharing.sharing_config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/servers', methods=['GET'])
def get_servers():
    """Get configured TAXII servers"""
    try:
        servers = {}
        for name, config in ti_sharing.taxii_configs.items():
            servers[name] = {
                'enabled': config['enabled'],
                'url': config['url']
            }
        return jsonify(servers)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stix/indicators', methods=['GET'])
def get_stix_indicators():
    """Get STIX indicators from store"""
    try:
        indicators = list(ti_sharing.stix_store.query(Filter("type", "=", "indicator")))
        return jsonify([indicator.serialize() for indicator in indicators])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=True)
