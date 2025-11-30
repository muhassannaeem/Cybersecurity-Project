import docker
import yaml
import json
import os
import random
import string
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
import redis
from jinja2 import Template

# Configure structured logging
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from logging_config import setup_logging, log_info, log_error, log_attack
    logger = setup_logging(
        service_name="decoy_generator",
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        environment=os.getenv('ENVIRONMENT', 'development'),
        log_file=os.getenv('LOG_FILE', '/app/logs/decoy_generator.log')
    )
except ImportError:
    # Fallback to basic logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class DecoyGenerator:
    """Decoy Generator for creating honeypots and honeytokens"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.docker_client = docker.from_env()
        
        # Integration with adaptive deception
        self.adaptive_deception_url = "http://adaptive_deception:5007"
        
        # Decoy configurations
        self.decoy_types = {
            'web_server': {
                'image': 'nginx:alpine',
                'ports': [80, 443],
                'volumes': ['/app/decoys/web_content:/usr/share/nginx/html'],
                'environment': {}
            },
            'ssh': {
                'image': 'cowrie/cowrie:latest',
                'ports': [22],
                'volumes': ['/app/decoys/ssh_logs:/cowrie/log'],
                'environment': {}
            },
            'database': {
                'image': 'mysql:5.7',
                'ports': [3306],
                'volumes': ['/app/decoys/db_data:/var/lib/mysql'],
                'environment': {
                    'MYSQL_ROOT_PASSWORD': 'honeypot_password',
                    'MYSQL_DATABASE': 'fake_database'
                }
            },
            'file_share': {
                'image': 'dperson/samba:latest',
                'ports': [139, 445],
                'volumes': ['/app/decoys/samba_data:/share'],
                'environment': {
                    'USERID': '1000',
                    'GROUPID': '1000'
                }
            },
            'iot_device': {
                'image': 'alpine:latest',
                'ports': [8080],
                'volumes': ['/app/decoys/iot_data:/data'],
                'environment': {}
            },
            # Dionaea malware honeypot (placeholder image/config)
            'dionaea': {
                'image': 'dionaea/dionaea:latest',
                'ports': [21, 42, 135, 443, 445, 1433],
                'volumes': [
                    '/app/decoys/dionaea_logs:/var/log/dionaea',
                    '/app/decoys/dionaea_samples:/opt/dionaea/var/dionaea/binaries',
                ],
                'environment': {}
            },
            # Conpot industrial/ICS honeypot (placeholder image/config)
            'conpot': {
                'image': 'honeynet/conpot:latest',
                'ports': [80, 102, 161, 502],
                'volumes': ['/app/decoys/conpot_logs:/var/log/conpot'],
                'environment': {}
            }
        }
        
        # Honeytoken configurations
        self.honeytoken_types = {
            'credentials': {
                'username': 'admin',
                'password': 'honeypot_password_123',
                'email': 'admin@fakecompany.com'
            },
            'api_keys': {
                'aws_access_key': 'AKIA' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)),
                'aws_secret_key': ''.join(random.choices(string.ascii_letters + string.digits, k=40)),
                'github_token': 'ghp_' + ''.join(random.choices(string.ascii_letters + string.digits, k=36))
            },
            'documents': {
                'filename': 'confidential_report.pdf',
                'content': 'This is a fake confidential document for honeypot purposes.',
                'path': '/app/decoys/documents/'
            },
            'database_entries': {
                'table': 'users',
                'columns': ['id', 'username', 'email', 'password_hash'],
                'fake_data': [
                    (1, 'admin', 'admin@fake.com', 'fake_hash_123'),
                    (2, 'user1', 'user1@fake.com', 'fake_hash_456')
                ]
            }
        }
    
    def deploy_honeypot(self, decoy_type: str, name: str = None) -> Dict:
        """Deploy a honeypot container"""
        try:
            if decoy_type not in self.decoy_types:
                raise ValueError(f"Unsupported decoy type: {decoy_type}")
            
            if not name:
                name = f"{decoy_type}_honeypot_{random.randint(1000, 9999)}"
            
            config = self.decoy_types[decoy_type]
            
            # Create container
            container = self.docker_client.containers.run(
                image=config['image'],
                name=name,
                ports={f"{port}/tcp": None for port in config['ports']},
                volumes=config['volumes'],
                environment=config['environment'],
                detach=True,
                restart_policy={"Name": "unless-stopped"},
                labels={
                    "honeypot": "true",
                    "decoy_type": decoy_type,
                },
            )
            
            # Get container info
            container_info = {
                'id': container.id,
                'name': name,
                'type': decoy_type,
                'status': 'running',
                'ports': config['ports'],
                'created_at': datetime.now().isoformat(),
                'image': config['image']
            }
            
            # Store in Redis
            self._store_decoy_info(container_info)
            
            logger.info(f"Honeypot deployed: {name} ({decoy_type})")
            return container_info
            
        except Exception as e:
            logger.error(f"Error deploying honeypot: {e}")
            return {'error': str(e)}
    
    def create_honeytoken(self, token_type: str, name: str = None) -> Dict:
        """Create a honeytoken"""
        try:
            if token_type not in self.honeytoken_types:
                raise ValueError(f"Unsupported honeytoken type: {token_type}")
            
            if not name:
                name = f"{token_type}_honeytoken_{random.randint(1000, 9999)}"
            
            token_config = self.honeytoken_types[token_type].copy()
            
            # Generate unique token data
            if token_type == 'credentials':
                token_config['username'] = f"user_{random.randint(1000, 9999)}"
                token_config['password'] = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                token_config['email'] = f"{token_config['username']}@fakecompany.com"
            
            elif token_type == 'api_keys':
                token_config['aws_access_key'] = 'AKIA' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
                token_config['aws_secret_key'] = ''.join(random.choices(string.ascii_letters + string.digits, k=40))
                token_config['github_token'] = 'ghp_' + ''.join(random.choices(string.ascii_letters + string.digits, k=36))
            
            elif token_type == 'documents':
                token_config['filename'] = f"confidential_{random.randint(1000, 9999)}.pdf"
                token_config['content'] = f"This is a fake confidential document {random.randint(1000, 9999)} for honeypot purposes."
                token_config['path'] = f"/app/decoys/documents/{token_config['filename']}"
            
            honeytoken_info = {
                'id': f"token_{random.randint(10000, 99999)}",
                'name': name,
                'type': token_type,
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'data': token_config
            }
            
            # Store in Redis
            self._store_honeytoken_info(honeytoken_info)
            
            logger.info(f"Honeytoken created: {name} ({token_type})")
            return honeytoken_info
            
        except Exception as e:
            logger.error(f"Error creating honeytoken: {e}")
            return {'error': str(e)}
    
    def deploy_adaptive_decoy(self, threat_level: str, anomaly_score: float) -> Dict:
        """Deploy adaptive decoys based on threat analysis"""
        try:
            # Determine decoy type based on threat level and anomaly score
            if threat_level == 'high' and anomaly_score > 0.8:
                decoy_type = 'ssh'  # High-value target
            elif threat_level == 'medium' and anomaly_score > 0.6:
                decoy_type = 'web_server'  # Common target
            elif threat_level == 'low' and anomaly_score > 0.4:
                decoy_type = 'file_share'  # Low-value target
            else:
                decoy_type = 'iot_device'  # Default
            
            # Deploy honeypot
            honeypot = self.deploy_honeypot(decoy_type)
            
            # Create corresponding honeytokens
            honeytokens = []
            if decoy_type == 'web_server':
                honeytokens.append(self.create_honeytoken('credentials'))
                honeytokens.append(self.create_honeytoken('api_keys'))
            elif decoy_type == 'ssh':
                honeytokens.append(self.create_honeytoken('credentials'))
            elif decoy_type == 'database':
                honeytokens.append(self.create_honeytoken('database_entries'))
            elif decoy_type == 'file_share':
                honeytokens.append(self.create_honeytoken('documents'))
            
            adaptive_decoy = {
                'honeypot': honeypot,
                'honeytokens': honeytokens,
                'threat_level': threat_level,
                'anomaly_score': anomaly_score,
                'deployed_at': datetime.now().isoformat()
            }
            
            # Store adaptive decoy info
            self._store_adaptive_decoy_info(adaptive_decoy)
            
            logger.info(f"Adaptive decoy deployed for threat level: {threat_level}")
            return adaptive_decoy
            
        except Exception as e:
            logger.error(f"Error deploying adaptive decoy: {e}")
            return {'error': str(e)}
    
    def list_decoys(self) -> List[Dict]:
        """List all deployed decoys"""
        try:
            decoys = []
            
            # Get honeypots from Docker
            containers = self.docker_client.containers.list(
                filters={"label": "honeypot=true"}
            )
            
            for container in containers:
                labels = getattr(container, 'labels', None) or container.attrs.get('Config', {}).get('Labels', {})
                decoy_type = labels.get('decoy_type', 'honeypot') if isinstance(labels, dict) else 'honeypot'

                decoy_info = {
                    'id': container.id,
                    'name': container.name,
                    'type': decoy_type,
                    'status': container.status,
                    'image': container.image.tags[0] if container.image.tags else container.image.id,
                    'created_at': container.attrs['Created']
                }
                decoys.append(decoy_info)
            
            # Get honeytokens from Redis
            honeytoken_keys = self.redis_client.keys("honeytoken:*")
            for key in honeytoken_keys:
                token_data = self.redis_client.get(key)
                if token_data:
                    honeytoken = json.loads(token_data)
                    honeytoken['type'] = 'honeytoken'
                    decoys.append(honeytoken)
            
            return decoys
            
        except Exception as e:
            logger.error(f"Error listing decoys: {e}")
            return []
    
    def remove_decoy(self, decoy_id: str) -> bool:
        """Remove a decoy"""
        try:
            # Try to remove as honeypot container
            try:
                container = self.docker_client.containers.get(decoy_id)
                container.remove(force=True)
                logger.info(f"Honeypot removed: {decoy_id}")
                return True
            except docker.errors.NotFound:
                pass
            
            # Try to remove as honeytoken
            token_key = f"honeytoken:{decoy_id}"
            if self.redis_client.exists(token_key):
                self.redis_client.delete(token_key)
                logger.info(f"Honeytoken removed: {decoy_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error removing decoy: {e}")
            return False
    
    def _store_decoy_info(self, decoy_info: Dict):
        """Store decoy information in Redis"""
        try:
            key = f"decoy:{decoy_info['id']}"
            self.redis_client.setex(key, 86400, json.dumps(decoy_info))  # Store for 24 hours
        except Exception as e:
            logger.error(f"Error storing decoy info: {e}")
    
    def _store_honeytoken_info(self, token_info: Dict):
        """Store honeytoken information in Redis"""
        try:
            key = f"honeytoken:{token_info['id']}"
            self.redis_client.setex(key, 86400, json.dumps(token_info))  # Store for 24 hours
        except Exception as e:
            logger.error(f"Error storing honeytoken info: {e}")
    
    def _store_adaptive_decoy_info(self, adaptive_decoy: Dict):
        """Store adaptive decoy information in Redis"""
        try:
            key = f"adaptive_decoy:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 86400, json.dumps(adaptive_decoy))  # Store for 24 hours
        except Exception as e:
            logger.error(f"Error storing adaptive decoy info: {e}")
    
    def get_decoy_statistics(self) -> Dict:
        """Get statistics about deployed decoys"""
        try:
            decoys = self.list_decoys()
            
            stats = {
                'total_decoys': len(decoys),
                'honeypots': len([d for d in decoys if d['type'] == 'honeypot']),
                'honeytokens': len([d for d in decoys if d['type'] == 'honeytoken']),
                'active_decoys': len([d for d in decoys if d.get('status') == 'running' or d.get('status') == 'active']),
                'decoy_types': {}
            }
            
            # Count by type
            for decoy in decoys:
                decoy_type = decoy.get('type', 'unknown')
                if decoy_type not in stats['decoy_types']:
                    stats['decoy_types'][decoy_type] = 0
                stats['decoy_types'][decoy_type] += 1
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting decoy statistics: {e}")
            return {}
    
    def get_adaptive_credentials(self, session_id: str, target_type: str = 'web_server') -> Dict:
        """Get adaptive credentials from deception engine"""
        try:
            # Check Redis cache first
            cache_key = f"adaptive_creds:{session_id}"
            cached_creds = self.redis_client.get(cache_key)
            
            if cached_creds:
                return json.loads(cached_creds)
            
            # Fallback to default credentials
            return {
                'username': 'admin',
                'password': 'password123',
                'believability_score': 0.5,
                'source': 'default'
            }
            
        except Exception as e:
            logger.error(f"Error getting adaptive credentials: {e}")
            return {'username': 'admin', 'password': 'password', 'believability_score': 0.3}
    
    def get_adaptive_filesystem(self, session_id: str) -> Dict:
        """Get adaptive file system from deception engine"""
        try:
            # Check Redis cache first
            cache_key = f"adaptive_filesystem:{session_id}"
            cached_filesystem = self.redis_client.get(cache_key)
            
            if cached_filesystem:
                return json.loads(cached_filesystem)
            
            # Fallback to default filesystem
            return {
                'directories': ['/data', '/config', '/backup'],
                'files': ['readme.txt', 'config.ini', 'data.csv'],
                'hidden_files': ['.env'],
                'source': 'default'
            }
            
        except Exception as e:
            logger.error(f"Error getting adaptive filesystem: {e}")
            return {'directories': ['/data'], 'files': ['readme.txt'], 'hidden_files': []}
    
    def get_adaptive_banners(self, session_id: str) -> Dict:
        """Get adaptive protocol banners from deception engine"""
        try:
            # Check Redis cache first
            cache_key = f"adaptive_banners:{session_id}"
            cached_banners = self.redis_client.get(cache_key)
            
            if cached_banners:
                return json.loads(cached_banners)
            
            # Fallback to default banners
            return {
                'ssh': {'banner': 'SSH-2.0-OpenSSH_7.4p1 Ubuntu'},
                'http': {'server_header': 'Apache/2.4.29 (Ubuntu)'},
                'ftp': {'banner': '220 Welcome to FTP Server'},
                'source': 'default'
            }
            
        except Exception as e:
            logger.error(f"Error getting adaptive banners: {e}")
            return {'ssh': {'banner': 'SSH-2.0-OpenSSH'}, 'source': 'error'}
    
    def update_honeypot_with_adaptive_content(self, honeypot_id: str, session_id: str) -> bool:
        """Update running honeypot with adaptive content"""
        try:
            # Get adaptive content
            credentials = self.get_adaptive_credentials(session_id)
            filesystem = self.get_adaptive_filesystem(session_id)
            banners = self.get_adaptive_banners(session_id)
            
            # Store adaptive configuration for the honeypot
            adaptive_config = {
                'honeypot_id': honeypot_id,
                'session_id': session_id,
                'credentials': credentials,
                'filesystem': filesystem,
                'banners': banners,
                'updated_at': datetime.now().isoformat()
            }
            
            # Store in Redis for honeypot to access
            config_key = f"honeypot_config:{honeypot_id}"
            self.redis_client.setex(config_key, 3600, json.dumps(adaptive_config))
            
            logger.info(f"Updated honeypot {honeypot_id} with adaptive content for session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating honeypot with adaptive content: {e}")
            return False

# Flask API for the decoy generator
app = Flask(__name__)
decoy_generator = DecoyGenerator()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'decoy_generator',
        'docker_available': decoy_generator.docker_client.ping()
    })

@app.route('/deploy/honeypot', methods=['POST'])
def deploy_honeypot():
    """Deploy a honeypot"""
    try:
        data = request.get_json() or {}
        decoy_type = data.get('type', 'web_server')
        name = data.get('name')
        
        result = decoy_generator.deploy_honeypot(decoy_type, name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/create/honeytoken', methods=['POST'])
def create_honeytoken():
    """Create a honeytoken"""
    try:
        data = request.get_json() or {}
        token_type = data.get('type', 'credentials')
        name = data.get('name')
        
        result = decoy_generator.create_honeytoken(token_type, name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/deploy/adaptive', methods=['POST'])
def deploy_adaptive_decoy():
    """Deploy adaptive decoy based on threat analysis"""
    try:
        data = request.get_json() or {}
        threat_level = data.get('threat_level', 'medium')
        anomaly_score = data.get('anomaly_score', 0.5)
        
        result = decoy_generator.deploy_adaptive_decoy(threat_level, anomaly_score)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decoys', methods=['GET'])
def list_decoys():
    """List all decoys"""
    try:
        decoys = decoy_generator.list_decoys()
        return jsonify(decoys)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decoys/<decoy_id>', methods=['DELETE'])
def remove_decoy(decoy_id):
    """Remove a decoy"""
    try:
        success = decoy_generator.remove_decoy(decoy_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get decoy statistics"""
    try:
        stats = decoy_generator.get_decoy_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/types', methods=['GET'])
def get_decoy_types():
    """Get available decoy types"""
    return jsonify({
        'honeypot_types': list(decoy_generator.decoy_types.keys()),
        'honeytoken_types': list(decoy_generator.honeytoken_types.keys())
    })

@app.route('/adaptive/credentials/<session_id>', methods=['GET'])
def get_adaptive_credentials(session_id):
    """Get adaptive credentials for a session"""
    try:
        target_type = request.args.get('target_type', 'web_server')
        credentials = decoy_generator.get_adaptive_credentials(session_id, target_type)
        return jsonify(credentials)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/adaptive/filesystem/<session_id>', methods=['GET'])
def get_adaptive_filesystem(session_id):
    """Get adaptive file system for a session"""
    try:
        filesystem = decoy_generator.get_adaptive_filesystem(session_id)
        return jsonify(filesystem)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/adaptive/banners/<session_id>', methods=['GET'])
def get_adaptive_banners(session_id):
    """Get adaptive protocol banners for a session"""
    try:
        banners = decoy_generator.get_adaptive_banners(session_id)
        return jsonify(banners)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/adaptive/update/<honeypot_id>', methods=['POST'])
def update_honeypot_adaptive(honeypot_id):
    """Update honeypot with adaptive content"""
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'session_id required'}), 400
        
        success = decoy_generator.update_honeypot_with_adaptive_content(honeypot_id, session_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
