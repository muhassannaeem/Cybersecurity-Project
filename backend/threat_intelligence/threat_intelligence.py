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
try:
    from taxii2client.v20 import Server, Collection, as_pages
    from taxii2client.exceptions import TAXIIServiceException
    TAXII_AVAILABLE = True
except ImportError:
    TAXII_AVAILABLE = False
    logger.warning("taxii2-client not available. TAXII functionality will be limited.")
import xmltodict
import threading
import time
import uuid
import hashlib

# Import enhancements (Tasks 31-34)
try:
    from taxii_enhancements import (
        TAXIIClient, TAXIIProvider, ProviderHealthChecker,
        ImprovedSharingService, RateLimiter, TAXII_AVAILABLE as TAXII_ENH_AVAILABLE
    )
    ENHANCEMENTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"TAXII enhancements not available: {e}")
    ENHANCEMENTS_AVAILABLE = False
    # Create dummy classes to prevent errors
    class TAXIIClient: pass
    class TAXIIProvider: pass
    class ProviderHealthChecker: pass
    class ImprovedSharingService: pass
    class RateLimiter: pass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Task 31: TAXII Client/Server Functionality
# ============================================================================

class TAXIIClient:
    """TAXII 2.0 Client for consuming threat intelligence feeds (Task 31)"""
    
    def __init__(self, server_url: str, username: str = None, password: str = None):
        self.server_url = server_url
        self.username = username
        self.password = password
        self.server = None
        self.collections = {}
    
    def connect(self) -> bool:
        """Connect to TAXII server and discover collections"""
        if not TAXII_AVAILABLE:
            logger.error("TAXII client not available - taxii2-client not installed")
            return False
        
        try:
            # Create server connection
            self.server = Server(self.server_url, user=self.username, password=self.password)
            
            # Discover API roots
            api_roots = self.server.api_roots
            if not api_roots:
                logger.error("No API roots found on TAXII server")
                return False
            
            # Get collections from first API root
            api_root = api_roots[0]
            for collection in api_root.collections:
                self.collections[collection.id] = collection
            
            logger.info(f"Connected to TAXII server, found {len(self.collections)} collections")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to TAXII server: {e}")
            return False
    
    def fetch_indicators(self, collection_id: str, limit: int = 100) -> List[Dict]:
        """Fetch STIX indicators from a TAXII collection"""
        if not TAXII_AVAILABLE:
            return []
        
        try:
            if collection_id not in self.collections:
                logger.error(f"Collection {collection_id} not found")
                return []
            
            collection = self.collections[collection_id]
            indicators = []
            
            # Fetch objects with pagination
            for bundle in as_pages(collection.get_objects, per_request=limit):
                for obj in bundle.get("objects", []):
                    if obj.get("type") == "indicator":
                        indicators.append(obj)
            
            logger.info(f"Fetched {len(indicators)} indicators from collection {collection_id}")
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching indicators: {e}")
            return []


# ============================================================================
# Task 32: Provider Configuration and Health Checking
# ============================================================================

class TAXIIProvider:
    """Configuration for a TAXII/STIX provider (Task 32)"""
    
    def __init__(self, 
                 name: str,
                 provider_type: str,  # 'opencti', 'misp', 'alienvault', 'taxii'
                 url: str,
                 api_key: str = None,
                 username: str = None,
                 password: str = None,
                 enabled: bool = True,
                 health_check_interval: int = 300,  # 5 minutes
                 timeout: int = 30,
                 max_retries: int = 3):
        self.name = name
        self.provider_type = provider_type
        self.url = url
        self.api_key = api_key
        self.username = username
        self.password = password
        self.enabled = enabled
        self.health_check_interval = health_check_interval
        self.timeout = timeout
        self.max_retries = max_retries
        self.last_health_check = None
        self.health_status = 'unknown'  # 'healthy', 'unhealthy', 'unknown'
        self.last_error = None
        self.response_time = None


class ProviderHealthChecker:
    """Health checker for TAXII/STIX providers (Task 32)"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.health_check_thread = None
        self.running = False
    
    def check_provider_health(self, provider: TAXIIProvider) -> Dict:
        """Check health of a single provider"""
        start_time = time.time()
        health_result = {
            'provider': provider.name,
            'status': 'unhealthy',
            'response_time': None,
            'error': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if provider.provider_type == 'opencti':
                # Test OpenCTI GraphQL endpoint
                response = requests.post(
                    provider.url,
                    headers={'Authorization': f'Bearer {provider.api_key}'},
                    json={'query': '{ me { id } }'},
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            elif provider.provider_type == 'misp':
                # Test MISP API
                response = requests.get(
                    f"{provider.url}/servers/getPyMISPVersion.json",
                    headers={'Authorization': provider.api_key},
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            elif provider.provider_type == 'alienvault':
                # Test AlienVault OTX API
                response = requests.get(
                    f"{provider.url}/pulses/subscribed",
                    headers={'X-OTX-API-KEY': provider.api_key},
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            elif provider.provider_type == 'taxii':
                # Test TAXII discovery endpoint
                auth = (provider.username, provider.password) if provider.username else None
                response = requests.get(
                    f"{provider.url}/taxii2/",
                    auth=auth,
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            health_result['response_time'] = (time.time() - start_time) * 1000  # ms
            
        except requests.exceptions.Timeout:
            health_result['error'] = 'Connection timeout'
        except requests.exceptions.ConnectionError:
            health_result['error'] = 'Connection failed'
        except Exception as e:
            health_result['error'] = str(e)
        
        # Store health result in Redis
        key = f"provider_health:{provider.name}:{datetime.now().strftime('%Y%m%d')}"
        self.redis_client.setex(key, 86400, json.dumps(health_result))
        
        # Update provider status
        provider.health_status = health_result['status']
        provider.last_health_check = health_result['timestamp']
        provider.response_time = health_result['response_time']
        provider.last_error = health_result['error']
        
        return health_result
    
    def start_health_checking(self, providers: List[TAXIIProvider]):
        """Start background health checking thread"""
        if not providers:
            return
        
        self.running = True
        self.health_check_thread = threading.Thread(
            target=self._health_check_loop,
            args=(providers,),
            daemon=True
        )
        self.health_check_thread.start()
        logger.info("Provider health checking started")
    
    def _health_check_loop(self, providers: List[TAXIIProvider]):
        """Background loop for health checking"""
        while self.running:
            for provider in providers:
                if provider.enabled:
                    self.check_provider_health(provider)
            
            # Check every minute (will check each provider at its interval)
            time.sleep(60)


# ============================================================================
# Task 33: Improved Sharing with Retry and Idempotency
# ============================================================================

class RateLimiter:
    """Rate limiter for provider sharing (Task 33)"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
    
    def can_share(self, provider: TAXIIProvider) -> bool:
        """Check if we can share to provider (rate limit)"""
        key = f"rate_limit:{provider.name}"
        current = self.redis_client.get(key)
        
        if current:
            count = int(current)
            # Max 100 requests per minute
            if count >= 100:
                return False
        
        return True
    
    def record_share(self, provider: TAXIIProvider):
        """Record a sharing operation"""
        key = f"rate_limit:{provider.name}"
        current = self.redis_client.incr(key)
        self.redis_client.expire(key, 60)  # Reset after 60 seconds


class ImprovedSharingService:
    """Improved sharing service with retry and idempotency (Task 33)"""
    
    def __init__(self, redis_client, threat_intel_sharing=None):
        # Accept optional reference to ThreatIntelligenceSharing for compatibility
        self.redis_client = redis_client
        self.threat_intel_sharing = threat_intel_sharing
        self.max_retries = 3
        self.retry_delays = [5, 15, 60]  # Exponential backoff in seconds
        self.rate_limiter = RateLimiter(redis_client)
    
    def share_with_retry(self, provider: TAXIIProvider, indicators: List[Dict]) -> Dict:
        """Share indicators with retry logic and idempotency"""
        # Check rate limit
        if not self.rate_limiter.can_share(provider):
            return {'status': 'rate_limited', 'error': 'Rate limit exceeded'}
        
        # Generate unique sharing ID for idempotency
        indicators_hash = hashlib.md5(json.dumps(indicators, sort_keys=True).encode()).hexdigest()
        sharing_id = f"share_{provider.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{indicators_hash[:8]}"
        
        # Check if already shared (idempotency)
        if self._is_already_shared(sharing_id):
            logger.info(f"Sharing {sharing_id} already completed, skipping")
            return {'status': 'already_shared', 'sharing_id': sharing_id}
        
        # Mark as in-progress
        self._mark_sharing_in_progress(sharing_id, provider.name, len(indicators))
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                # Share indicators using existing method
                result = self._share_indicators(provider, indicators)
                
                if result.get('success', False):
                    # Mark as completed
                    self._mark_sharing_completed(sharing_id, result)
                    self.rate_limiter.record_share(provider)
                    return {'status': 'success', 'sharing_id': sharing_id, 'result': result}
                
                last_error = result.get('error', 'Unknown error')
                
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Sharing attempt {attempt + 1} failed: {e}")
            
            # Wait before retry (exponential backoff)
            if attempt < self.max_retries - 1:
                delay = self.retry_delays[attempt]
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
        
        # All retries failed
        self._mark_sharing_failed(sharing_id, last_error)
        self._add_to_dead_letter_queue(sharing_id, provider, indicators, last_error)
        
        return {'status': 'failed', 'sharing_id': sharing_id, 'error': last_error}
    
    def _share_indicators(self, provider: TAXIIProvider, indicators: List[Dict]) -> Dict:
        """Share indicators to a provider"""
        try:
            # Convert indicators to STIX format
            stix_indicators = []
            for indicator in indicators:
                stix_ind = ti_sharing.create_stix_indicator(indicator)
                if stix_ind:
                    stix_indicators.append(stix_ind)
            
            # Use existing sharing methods
            if provider.provider_type == 'opencti':
                success = ti_sharing._share_with_opencti({
                    'url': provider.url,
                    'api_key': provider.api_key
                }, stix_indicators)
            elif provider.provider_type == 'misp':
                success = ti_sharing._share_with_misp({
                    'url': provider.url,
                    'api_key': provider.api_key
                }, stix_indicators)
            elif provider.provider_type == 'alienvault':
                success = ti_sharing._share_with_alienvault({
                    'url': provider.url,
                    'api_key': provider.api_key
                }, stix_indicators)
            else:
                success = False
            
            return {'success': success, 'shared': len(stix_indicators) if success else 0}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _is_already_shared(self, sharing_id: str) -> bool:
        """Check if sharing operation was already completed"""
        key = f"sharing_status:{sharing_id}"
        status = self.redis_client.get(key)
        if status:
            status_data = json.loads(status)
            return status_data.get('status') == 'completed'
        return False
    
    def _mark_sharing_in_progress(self, sharing_id: str, provider: str, count: int):
        """Mark sharing as in progress"""
        key = f"sharing_status:{sharing_id}"
        self.redis_client.setex(key, 3600, json.dumps({
            'status': 'in_progress',
            'provider': provider,
            'count': count,
            'started_at': datetime.now().isoformat()
        }))
    
    def _mark_sharing_completed(self, sharing_id: str, result: Dict):
        """Mark sharing as completed"""
        key = f"sharing_status:{sharing_id}"
        status_data = json.loads(self.redis_client.get(key) or '{}')
        status_data.update({
            'status': 'completed',
            'completed_at': datetime.now().isoformat(),
            'result': result
        })
        self.redis_client.setex(key, 86400, json.dumps(status_data))  # Keep for 24 hours
    
    def _mark_sharing_failed(self, sharing_id: str, error: str):
        """Mark sharing as failed"""
        key = f"sharing_status:{sharing_id}"
        status_data = json.loads(self.redis_client.get(key) or '{}')
        status_data.update({
            'status': 'failed',
            'failed_at': datetime.now().isoformat(),
            'error': error
        })
        self.redis_client.setex(key, 86400, json.dumps(status_data))
    
    def _add_to_dead_letter_queue(self, sharing_id: str, provider: TAXIIProvider, 
                                   indicators: List[Dict], error: str):
        """Add failed sharing to dead letter queue"""
        dlq_entry = {
            'sharing_id': sharing_id,
            'provider': provider.name,
            'indicators': indicators,
            'error': error,
            'timestamp': datetime.now().isoformat(),
            'retry_count': self.max_retries
        }
        key = f"dlq:{sharing_id}"
        self.redis_client.setex(key, 604800, json.dumps(dlq_entry))  # Keep for 7 days
        logger.error(f"Added to dead letter queue: {sharing_id}")


# ============================================================================
# Main Threat Intelligence Sharing Class
# ============================================================================

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
        
        # Initialize providers dictionary (Task 32)
        self.providers = {}
        if ENHANCEMENTS_AVAILABLE:
            self._initialize_providers()
            
            # Initialize health checker (Task 32)
            self.health_checker = ProviderHealthChecker(self.redis_client)
            if self.providers:
                self.health_checker.start_health_checking(list(self.providers.values()))
            
            # Initialize improved sharing service (Task 33)
            # Pass redis_client and reference to this ThreatIntelligenceSharing instance
            self.improved_sharing = ImprovedSharingService(self.redis_client, self)
            
            # Start background sharing thread (improved version)
            self.sharing_thread = threading.Thread(target=self._background_sharing_improved, daemon=True)
            self.sharing_thread.start()
        else:
            self.health_checker = None
            self.improved_sharing = None
            # Fall back to original sharing
            self.sharing_thread = threading.Thread(target=self._background_sharing, daemon=True)
            self.sharing_thread.start()
        
        if TAXII_AVAILABLE or TAXII_ENH_AVAILABLE:
            logger.info("TAXII functionality enabled")
        else:
            logger.warning("TAXII functionality limited - taxii2-client not installed")
    
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
    
    def _initialize_providers(self):
        """Initialize provider configurations (Task 32)"""
        if not ENHANCEMENTS_AVAILABLE:
            return
        
        for name, config in self.taxii_configs.items():
            provider = TAXIIProvider(
                name=name,
                provider_type=name,  # opencti, misp, alienvault
                url=config['url'],
                api_key=config.get('api_key', ''),
                enabled=config.get('enabled', True),
                health_check_interval=300,
                timeout=30,
                max_retries=3
            )
            self.providers[name] = provider
    
    def create_stix_indicator(self, indicator_data: Dict) -> Optional[Indicator]:
        """Create STIX 2.1 Indicator from indicator data with MITRE ATT&CK mappings"""
        try:
            # Extract indicator properties
            indicator_type = indicator_data.get('type', '')
            value = indicator_data.get('value', '')
            description = indicator_data.get('description', '')
            confidence = indicator_data.get('confidence', 0.5)
            tags = indicator_data.get('tags', [])
            
            # Extract MITRE ATT&CK technique IDs if present (Task 20)
            technique_ids = indicator_data.get('technique_ids', [])
            technique_details = indicator_data.get('technique_details', [])
            
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
            
            # Add MITRE ATT&CK technique IDs to labels (Task 20)
            if technique_ids:
                for tech_id in technique_ids:
                    stix_indicator.labels.append(f"mitre_attack:{tech_id}")
            
            # Store technique details in external_references (Task 20)
            if technique_details:
                stix_indicator.external_references = []
                for tech_detail in technique_details:
                    tech_id = tech_detail.get('id', '')
                    if tech_id:
                        stix_indicator.external_references.append({
                            'source_name': 'mitre-attack',
                            'external_id': tech_id,
                            'url': f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                        })
            
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
        """Share indicators via STIX/TAXII with MITRE ATT&CK mappings (Task 20)"""
        try:
            results = {
                'shared': 0,
                'failed': 0,
                'errors': []
            }
            
            # Create STIX indicators with ATT&CK mappings
            stix_indicators = []
            for indicator in indicators:
                # If indicator doesn't have technique_ids, try to enrich it
                if 'technique_ids' not in indicator and 'value' in indicator:
                    # Call threat_attribution to get technique mappings
                    enriched_indicator = self._enrich_indicator_with_attack(indicator)
                    indicator = enriched_indicator
                
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
    
    def _enrich_indicator_with_attack(self, indicator: Dict) -> Dict:
        """Enrich indicator with MITRE ATT&CK technique IDs (Task 20)"""
        try:
            # Call threat_attribution service to get technique mappings
            threat_attribution_url = os.getenv('THREAT_ATTRIBUTION_URL', 'http://localhost:5004')
            response = requests.post(
                f"{threat_attribution_url}/map_patterns",
                json={'indicators': [indicator]},
                timeout=5
            )
            
            if response.status_code == 200:
                mapping = response.json()
                if 'techniques' in mapping:
                    # Add technique IDs to indicator
                    indicator['technique_ids'] = [t.get('id') for t in mapping['techniques']]
                    indicator['technique_details'] = mapping['techniques']
                    if 'threat_actors' in mapping:
                        indicator['threat_actors'] = mapping['threat_actors']
            
        except Exception as e:
            logger.warning(f"Could not enrich indicator with ATT&CK: {e}")
        
        return indicator
    
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
        """Background thread for automatic sharing (legacy - kept for compatibility)"""
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
    
    def _background_sharing_improved(self):
        """Improved background sharing with retry and idempotency (Task 33)"""
        while True:
            try:
                if self.sharing_config['auto_share']:
                    # Get indicators from Redis that need sharing
                    indicators = self._get_pending_indicators()
                    
                    if indicators:
                        logger.info(f"Auto-sharing {len(indicators)} indicators (improved)")
                        # Use improved sharing service with retry/idempotency
                        for provider_name, provider in self.providers.items():
                            if provider.enabled and provider.health_status == 'healthy':
                                result = self.improved_sharing.share_with_retry(provider, indicators)
                                if result['status'] == 'failed':
                                    logger.warning(f"Failed to share to {provider_name}: {result.get('error')}")
                
                time.sleep(self.sharing_config['share_interval'])
                
            except Exception as e:
                logger.error(f"Error in improved background sharing: {e}")
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


# ============================================================================
# Task 31: TAXII Server Endpoints
# ============================================================================

@app.route('/taxii2/', methods=['GET'])
def taxii_discovery():
    """TAXII 2.0 Discovery endpoint (Task 31)"""
    return jsonify({
        "title": "Cybersecurity System TAXII Server",
        "description": "Threat intelligence sharing via TAXII 2.0",
        "contact": "security@example.com",
        "default": "http://localhost:5006/taxii2/api1/",
        "api_roots": ["http://localhost:5006/taxii2/api1/"]
    })

@app.route('/taxii2/api1/', methods=['GET'])
def taxii_api_root():
    """TAXII 2.0 API Root endpoint (Task 31)"""
    return jsonify({
        "title": "Cybersecurity System API Root",
        "description": "Main API root for threat intelligence",
        "versions": ["taxii-2.0"],
        "max_content_length": 10485760
    })

@app.route('/taxii2/api1/collections/', methods=['GET'])
def taxii_collections():
    """List available TAXII collections (Task 31)"""
    collections = []
    for name, config in ti_sharing.taxii_configs.items():
        collections.append({
            "id": name,
            "title": f"{name} Indicators",
            "description": f"STIX indicators from {name}",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"]
        })
    return jsonify({"collections": collections})

@app.route('/taxii2/api1/collections/<collection_id>/objects/', methods=['GET', 'POST'])
def taxii_collection_objects(collection_id):
    """Get or add STIX objects to a collection (Task 31)"""
    if request.method == 'GET':
        try:
            indicators = list(ti_sharing.stix_store.query(Filter("type", "=", "indicator")))
            bundle = {
                "type": "bundle",
                "id": f"bundle--{str(uuid.uuid4())}",
                "spec_version": "2.1",
                "objects": [ind.serialize() for ind in indicators]
            }
            return jsonify(bundle)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    elif request.method == 'POST':
        try:
            data = request.get_json()
            return jsonify({"status": "accepted"}), 202
        except Exception as e:
            return jsonify({'error': str(e)}), 500


# ============================================================================
# Task 32: Provider Health Checking APIs
# ============================================================================

@app.route('/providers/health', methods=['GET'])
def get_provider_health():
    """Get health status of all providers (Task 32)"""
    try:
        if not ENHANCEMENTS_AVAILABLE or not hasattr(ti_sharing, 'providers'):
            return jsonify({'error': 'Provider health checking not available'}), 503
        
        health_status = {}
        for name, provider in ti_sharing.providers.items():
            health_status[name] = {
                'status': provider.health_status,
                'last_check': provider.last_health_check,
                'response_time': provider.response_time,
                'error': provider.last_error,
                'enabled': provider.enabled
            }
        return jsonify(health_status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/providers/<provider_name>/health', methods=['POST'])
def check_provider_health_now(provider_name):
    """Manually trigger health check for a provider (Task 32)"""
    try:
        if not ENHANCEMENTS_AVAILABLE or not hasattr(ti_sharing, 'providers'):
            return jsonify({'error': 'Provider health checking not available'}), 503
        
        if provider_name not in ti_sharing.providers:
            return jsonify({'error': 'Provider not found'}), 404
        
        provider = ti_sharing.providers[provider_name]
        health_result = ti_sharing.health_checker.check_provider_health(provider)
        return jsonify(health_result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Task 34: Management APIs
# ============================================================================

@app.route('/providers', methods=['GET'])
def list_providers():
    """List all configured providers (Task 34)"""
    try:
        if not ENHANCEMENTS_AVAILABLE or not hasattr(ti_sharing, 'providers'):
            return jsonify({'error': 'Provider management not available'}), 503
        
        providers = []
        for name, provider in ti_sharing.providers.items():
            providers.append({
                'name': name,
                'type': provider.provider_type,
                'url': provider.url,
                'enabled': provider.enabled,
                'health_status': provider.health_status,
                'last_health_check': provider.last_health_check,
                'response_time': provider.response_time
            })
        return jsonify({'providers': providers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/providers', methods=['POST'])
def add_provider():
    """Add a new provider (Task 34)"""
    try:
        if not ENHANCEMENTS_AVAILABLE:
            return jsonify({'error': 'Provider management not available'}), 503
        
        data = request.get_json()
        provider = TAXIIProvider(
            name=data['name'],
            provider_type=data['type'],
            url=data['url'],
            api_key=data.get('api_key'),
            username=data.get('username'),
            password=data.get('password'),
            enabled=data.get('enabled', True)
        )
        ti_sharing.providers[data['name']] = provider
        return jsonify({'status': 'created', 'provider': data['name']}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/providers/<provider_name>', methods=['PUT'])
def update_provider(provider_name):
    """Update provider configuration (Task 34)"""
    try:
        if not ENHANCEMENTS_AVAILABLE or not hasattr(ti_sharing, 'providers'):
            return jsonify({'error': 'Provider management not available'}), 503
        
        if provider_name not in ti_sharing.providers:
            return jsonify({'error': 'Provider not found'}), 404
        
        data = request.get_json()
        provider = ti_sharing.providers[provider_name]
        
        if 'enabled' in data:
            provider.enabled = data['enabled']
        if 'url' in data:
            provider.url = data['url']
        if 'api_key' in data:
            provider.api_key = data['api_key']
        if 'username' in data:
            provider.username = data['username']
        if 'password' in data:
            provider.password = data['password']
        
        return jsonify({'status': 'updated', 'provider': provider_name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/providers/<provider_name>', methods=['DELETE'])
def delete_provider(provider_name):
    """Delete a provider (Task 34)"""
    try:
        if not ENHANCEMENTS_AVAILABLE or not hasattr(ti_sharing, 'providers'):
            return jsonify({'error': 'Provider management not available'}), 503
        
        if provider_name not in ti_sharing.providers:
            return jsonify({'error': 'Provider not found'}), 404
        
        del ti_sharing.providers[provider_name]
        return jsonify({'status': 'deleted', 'provider': provider_name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sharing/policy', methods=['GET'])
def get_sharing_policy():
    """Get current sharing policy (Task 34)"""
    try:
        return jsonify(ti_sharing.sharing_config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sharing/policy', methods=['PUT'])
def update_sharing_policy():
    """Update sharing policy (Task 34)"""
    try:
        data = request.get_json()
        
        if 'auto_share' in data:
            ti_sharing.sharing_config['auto_share'] = data['auto_share']
        if 'share_interval' in data:
            ti_sharing.sharing_config['share_interval'] = data['share_interval']
        if 'confidence_threshold' in data:
            ti_sharing.sharing_config['confidence_threshold'] = data['confidence_threshold']
        if 'max_indicators_per_batch' in data:
            ti_sharing.sharing_config['max_indicators_per_batch'] = data['max_indicators_per_batch']
        
        return jsonify({'status': 'updated', 'policy': ti_sharing.sharing_config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sharing/statistics', methods=['GET'])
def get_sharing_statistics_enhanced():
    """Get enhanced sharing statistics (Task 34)"""
    try:
        stats = {
            'total_shared': 0,
            'total_failed': 0,
            'success_rate': 0.0,
            'providers': {}
        }
        
        # Get sharing results from Redis
        sharing_keys = ti_sharing.redis_client.keys("sharing_status:*")
        for key in sharing_keys:
            status_data = json.loads(ti_sharing.redis_client.get(key) or '{}')
            if status_data.get('status') == 'completed':
                stats['total_shared'] += status_data.get('count', 0)
            elif status_data.get('status') == 'failed':
                stats['total_failed'] += status_data.get('count', 0)
        
        total = stats['total_shared'] + stats['total_failed']
        if total > 0:
            stats['success_rate'] = (stats['total_shared'] / total) * 100
        
        # Per-provider stats
        if ENHANCEMENTS_AVAILABLE and hasattr(ti_sharing, 'providers'):
            for name, provider in ti_sharing.providers.items():
                stats['providers'][name] = {
                    'enabled': provider.enabled,
                    'health_status': provider.health_status,
                    'response_time': provider.response_time
                }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sharing/dlq', methods=['GET'])
def get_dead_letter_queue():
    """Get failed sharing operations from dead letter queue (Task 34)"""
    try:
        dlq_entries = []
        dlq_keys = ti_sharing.redis_client.keys("dlq:*")
        
        for key in dlq_keys:
            entry = json.loads(ti_sharing.redis_client.get(key) or '{}')
            if entry:
                dlq_entries.append(entry)
        
        return jsonify({'dlq_entries': dlq_entries, 'count': len(dlq_entries)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sharing/dlq/<sharing_id>/retry', methods=['POST'])
def retry_dlq_entry(sharing_id):
    """Retry a failed sharing operation from DLQ (Task 34)"""
    try:
        if not ENHANCEMENTS_AVAILABLE or not hasattr(ti_sharing, 'improved_sharing'):
            return jsonify({'error': 'Improved sharing not available'}), 503
        
        key = f"dlq:{sharing_id}"
        entry_data = ti_sharing.redis_client.get(key)
        
        if not entry_data:
            return jsonify({'error': 'DLQ entry not found'}), 404
        
        entry = json.loads(entry_data)
        provider = ti_sharing.providers.get(entry['provider'])
        if not provider:
            return jsonify({'error': 'Provider not found'}), 404
        
        # Retry sharing
        result = ti_sharing.improved_sharing.share_with_retry(provider, entry['indicators'])
        
        if result['status'] == 'success':
            ti_sharing.redis_client.delete(key)
            return jsonify({'status': 'retried_successfully', 'result': result})
        else:
            return jsonify({'status': 'retry_failed', 'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=True)
