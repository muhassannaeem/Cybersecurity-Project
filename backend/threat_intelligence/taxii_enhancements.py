"""
TAXII/STIX Enhancements for Threat Intelligence Sharing
Tasks 31-34: TAXII client/server, health checking, improved sharing, management APIs
"""

import json
import logging
import os
import requests
import time
import threading
import uuid
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Try to import TAXII client
try:
    from taxii2client.v20 import Server, Collection, as_pages
    from taxii2client.exceptions import TAXIIServiceException
    TAXII_AVAILABLE = True
except ImportError:
    TAXII_AVAILABLE = False
    logger.warning("taxii2-client not available. TAXII functionality will be limited.")


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
            self.server = Server(self.server_url, user=self.username, password=self.password)
            api_roots = self.server.api_roots
            if not api_roots:
                logger.error("No API roots found on TAXII server")
                return False
            
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
                 provider_type: str,
                 url: str,
                 api_key: str = None,
                 username: str = None,
                 password: str = None,
                 enabled: bool = True,
                 health_check_interval: int = 300,
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
        self.health_status = 'unknown'
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
                response = requests.post(
                    provider.url,
                    headers={'Authorization': f'Bearer {provider.api_key}'},
                    json={'query': '{ me { id } }'},
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            elif provider.provider_type == 'misp':
                response = requests.get(
                    f"{provider.url}/servers/getPyMISPVersion.json",
                    headers={'Authorization': provider.api_key},
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            elif provider.provider_type == 'alienvault':
                response = requests.get(
                    f"{provider.url}/pulses/subscribed",
                    headers={'X-OTX-API-KEY': provider.api_key},
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            elif provider.provider_type == 'taxii':
                auth = (provider.username, provider.password) if provider.username else None
                response = requests.get(
                    f"{provider.url}/taxii2/",
                    auth=auth,
                    timeout=provider.timeout
                )
                if response.status_code == 200:
                    health_result['status'] = 'healthy'
            
            health_result['response_time'] = (time.time() - start_time) * 1000
            
        except requests.exceptions.Timeout:
            health_result['error'] = 'Connection timeout'
        except requests.exceptions.ConnectionError:
            health_result['error'] = 'Connection failed'
        except Exception as e:
            health_result['error'] = str(e)
        
        # Store in Redis
        key = f"provider_health:{provider.name}:{datetime.now().strftime('%Y%m%d')}"
        self.redis_client.setex(key, 86400, json.dumps(health_result))
        
        # Update provider
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
            if count >= 100:  # Max 100 requests per minute
                return False
        
        return True
    
    def record_share(self, provider: TAXIIProvider):
        """Record a sharing operation"""
        key = f"rate_limit:{provider.name}"
        self.redis_client.incr(key)
        self.redis_client.expire(key, 60)


class ImprovedSharingService:
    """Improved sharing service with retry and idempotency (Task 33)"""
    
    def __init__(self, redis_client, threat_intel_sharing=None):
        self.redis_client = redis_client
        self.threat_intel_sharing = threat_intel_sharing
        self.max_retries = 3
        self.retry_delays = [5, 15, 60]
        self.rate_limiter = RateLimiter(redis_client)
    
    def share_with_retry(self, provider: TAXIIProvider, indicators: List[Dict]) -> Dict:
        """Share indicators with retry logic and idempotency"""
        if not self.rate_limiter.can_share(provider):
            return {'status': 'rate_limited', 'error': 'Rate limit exceeded'}
        
        # Generate unique sharing ID
        indicators_hash = hashlib.md5(json.dumps(indicators, sort_keys=True).encode()).hexdigest()
        sharing_id = f"share_{provider.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{indicators_hash[:8]}"
        
        # Check idempotency
        if self._is_already_shared(sharing_id):
            logger.info(f"Sharing {sharing_id} already completed")
            return {'status': 'already_shared', 'sharing_id': sharing_id}
        
        self._mark_sharing_in_progress(sharing_id, provider.name, len(indicators))
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                result = self._share_indicators(provider, indicators)
                
                if result.get('success', False):
                    self._mark_sharing_completed(sharing_id, result)
                    self.rate_limiter.record_share(provider)
                    return {'status': 'success', 'sharing_id': sharing_id, 'result': result}
                
                last_error = result.get('error', 'Unknown error')
                
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Sharing attempt {attempt + 1} failed: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delays[attempt])
        
        self._mark_sharing_failed(sharing_id, last_error)
        self._add_to_dead_letter_queue(sharing_id, provider, indicators, last_error)
        
        return {'status': 'failed', 'sharing_id': sharing_id, 'error': last_error}
    
    def _share_indicators(self, provider: TAXIIProvider, indicators: List[Dict]) -> Dict:
        """Share indicators to a provider"""
        if not self.threat_intel_sharing:
            return {'success': False, 'error': 'Threat intelligence sharing not initialized'}
        
        try:
            # Convert to STIX
            stix_indicators = []
            for indicator in indicators:
                stix_ind = self.threat_intel_sharing.create_stix_indicator(indicator)
                if stix_ind:
                    stix_indicators.append(stix_ind)
            
            # Share using existing methods
            config = {
                'url': provider.url,
                'api_key': provider.api_key
            }
            
            if provider.provider_type == 'opencti':
                success = self.threat_intel_sharing._share_with_opencti(config, stix_indicators)
            elif provider.provider_type == 'misp':
                success = self.threat_intel_sharing._share_with_misp(config, stix_indicators)
            elif provider.provider_type == 'alienvault':
                success = self.threat_intel_sharing._share_with_alienvault(config, stix_indicators)
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
            return json.loads(status).get('status') == 'completed'
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
        self.redis_client.setex(key, 86400, json.dumps(status_data))
    
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
        self.redis_client.setex(key, 604800, json.dumps(dlq_entry))
        logger.error(f"Added to dead letter queue: {sharing_id}")

