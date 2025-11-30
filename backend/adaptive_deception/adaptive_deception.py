import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, Embedding, GRU, Attention
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler, LabelEncoder
import json
import logging
import os
import redis
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from flask import Flask, request, jsonify
import joblib
from collections import defaultdict, deque
import random
import string

# Configure structured logging
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from logging_config import setup_logging, log_info, log_error, log_warning
    logger = setup_logging(
        service_name="adaptive_deception",
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        environment=os.getenv('ENVIRONMENT', 'development'),
        log_file=os.getenv('LOG_FILE', '/app/logs/adaptive_deception.log')
    )
except ImportError:
    # Fallback to basic logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class AttackerBehaviorModeler:
    """LSTM-based model for learning and predicting attacker behavior sequences"""
    
    def __init__(self, model_path: str = "/app/models/adaptive"):
        self.model_path = model_path
        self.sequence_length = 10  # Number of actions to look back
        self.action_encoder = LabelEncoder()
        self.target_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        
        # Models for different aspects of behavior
        self.action_sequence_model = None
        self.credential_model = None
        self.file_access_model = None
        self.protocol_model = None
        
        # Behavior tracking
        self.attacker_sessions = defaultdict(lambda: {
            'actions': deque(maxlen=self.sequence_length),
            'targets': deque(maxlen=self.sequence_length),
            'timestamps': deque(maxlen=self.sequence_length),
            'success_rate': 0.0,
            'skill_level': 'novice',
            'persistence': 0.0
        })
        
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize or load LSTM models"""
        try:
            os.makedirs(self.model_path, exist_ok=True)
            
            # Load existing models or create new ones
            self._load_or_create_action_sequence_model()
            self._load_or_create_credential_model()
            self._load_or_create_file_access_model()
            self._load_or_create_protocol_model()
            
            logger.info("Adaptive deception models initialized")
            
        except Exception as e:
            logger.error(f"Error initializing models: {e}")
    
    def _load_or_create_action_sequence_model(self):
        """Load or create LSTM model for action sequence prediction"""
        model_file = f"{self.model_path}/action_sequence_model.h5"
        
        try:
            if os.path.exists(model_file):
                self.action_sequence_model = tf.keras.models.load_model(model_file)
                logger.info("Action sequence model loaded")
            else:
                # Create new model
                self.action_sequence_model = Sequential([
                    LSTM(128, return_sequences=True, input_shape=(self.sequence_length, 20)),
                    Dropout(0.3),
                    LSTM(64, return_sequences=False),
                    Dropout(0.3),
                    Dense(32, activation='relu'),
                    Dense(50, activation='softmax')  # 50 possible actions
                ])
                
                self.action_sequence_model.compile(
                    optimizer=Adam(learning_rate=0.001),
                    loss='categorical_crossentropy',
                    metrics=['accuracy']
                )
                
                self.action_sequence_model.save(model_file)
                logger.info("Action sequence model created and saved")
                
        except Exception as e:
            logger.error(f"Error with action sequence model: {e}")
    
    def _load_or_create_credential_model(self):
        """Load or create model for generating believable credentials"""
        model_file = f"{self.model_path}/credential_model.h5"
        
        try:
            if os.path.exists(model_file):
                self.credential_model = tf.keras.models.load_model(model_file)
                logger.info("Credential model loaded")
            else:
                # Create new model for credential generation
                self.credential_model = Sequential([
                    LSTM(64, return_sequences=True, input_shape=(None, 128)),
                    Dropout(0.2),
                    LSTM(32),
                    Dropout(0.2),
                    Dense(64, activation='relu'),
                    Dense(128, activation='sigmoid')  # Character-level generation
                ])
                
                self.credential_model.compile(
                    optimizer=Adam(learning_rate=0.001),
                    loss='binary_crossentropy',
                    metrics=['accuracy']
                )
                
                self.credential_model.save(model_file)
                logger.info("Credential model created and saved")
                
        except Exception as e:
            logger.error(f"Error with credential model: {e}")
    
    def _load_or_create_file_access_model(self):
        """Load or create model for predicting file access patterns"""
        model_file = f"{self.model_path}/file_access_model.h5"
        
        try:
            if os.path.exists(model_file):
                self.file_access_model = tf.keras.models.load_model(model_file)
                logger.info("File access model loaded")
            else:
                # Create new model
                self.file_access_model = Sequential([
                    LSTM(96, return_sequences=True, input_shape=(self.sequence_length, 15)),
                    Dropout(0.25),
                    LSTM(48),
                    Dropout(0.25),
                    Dense(24, activation='relu'),
                    Dense(100, activation='softmax')  # 100 possible file types/paths
                ])
                
                self.file_access_model.compile(
                    optimizer=Adam(learning_rate=0.001),
                    loss='categorical_crossentropy',
                    metrics=['accuracy']
                )
                
                self.file_access_model.save(model_file)
                logger.info("File access model created and saved")
                
        except Exception as e:
            logger.error(f"Error with file access model: {e}")
    
    def _load_or_create_protocol_model(self):
        """Load or create model for protocol banner adaptation"""
        model_file = f"{self.model_path}/protocol_model.h5"
        
        try:
            if os.path.exists(model_file):
                self.protocol_model = tf.keras.models.load_model(model_file)
                logger.info("Protocol model loaded")
            else:
                # Create new model
                self.protocol_model = Sequential([
                    LSTM(80, return_sequences=True, input_shape=(None, 256)),
                    Dropout(0.3),
                    LSTM(40),
                    Dropout(0.3),
                    Dense(80, activation='relu'),
                    Dense(256, activation='softmax')  # Character-level protocol response
                ])
                
                self.protocol_model.compile(
                    optimizer=Adam(learning_rate=0.001),
                    loss='categorical_crossentropy',
                    metrics=['accuracy']
                )
                
                self.protocol_model.save(model_file)
                logger.info("Protocol model created and saved")
                
        except Exception as e:
            logger.error(f"Error with protocol model: {e}")
    
    def update_attacker_behavior(self, session_id: str, action: str, target: str, 
                                success: bool, timestamp: datetime = None):
        """Update attacker behavior tracking"""
        try:
            if timestamp is None:
                timestamp = datetime.now()
            
            session = self.attacker_sessions[session_id]
            
            # Add new action to sequence
            session['actions'].append(action)
            session['targets'].append(target)
            session['timestamps'].append(timestamp)
            
            # Calculate success rate
            recent_actions = list(session['actions'])[-5:]  # Last 5 actions
            if recent_actions:
                success_count = sum(1 for _ in recent_actions if success)
                session['success_rate'] = success_count / len(recent_actions)
            
            # Estimate skill level based on action patterns
            session['skill_level'] = self._estimate_skill_level(session)
            
            # Calculate persistence (time spent attacking)
            if len(session['timestamps']) >= 2:
                time_diff = session['timestamps'][-1] - session['timestamps'][0]
                session['persistence'] = time_diff.total_seconds() / 3600  # Hours
            
            logger.debug(f"Updated behavior for session {session_id}: {action} on {target}")
            
        except Exception as e:
            logger.error(f"Error updating attacker behavior: {e}")
    
    def _estimate_skill_level(self, session: Dict) -> str:
        """Estimate attacker skill level based on action patterns"""
        try:
            actions = list(session['actions'])
            if len(actions) < 3:
                return 'novice'
            
            # Advanced patterns
            advanced_actions = ['sql_injection', 'buffer_overflow', 'privilege_escalation', 
                              'lateral_movement', 'persistence_mechanism']
            
            # Intermediate patterns  
            intermediate_actions = ['directory_traversal', 'password_attack', 'service_enumeration',
                                  'vulnerability_scan']
            
            # Count action types
            advanced_count = sum(1 for action in actions if action in advanced_actions)
            intermediate_count = sum(1 for action in actions if action in intermediate_actions)
            
            if advanced_count >= 2:
                return 'expert'
            elif intermediate_count >= 3 or advanced_count >= 1:
                return 'intermediate'
            else:
                return 'novice'
                
        except Exception as e:
            logger.error(f"Error estimating skill level: {e}")
            return 'novice'
    
    def predict_next_actions(self, session_id: str, n_predictions: int = 3) -> List[Dict]:
        """Predict next likely actions for an attacker session"""
        try:
            session = self.attacker_sessions[session_id]
            
            if len(session['actions']) < 3:
                # Not enough data for prediction, return common next steps
                return self._get_default_predictions(session['skill_level'])
            
            # Prepare sequence data
            sequence_data = self._prepare_sequence_data(session)
            
            if sequence_data is None:
                return self._get_default_predictions(session['skill_level'])
            
            # Predict using action sequence model
            predictions = self.action_sequence_model.predict(sequence_data)
            top_indices = np.argsort(predictions[0])[-n_predictions:][::-1]
            
            # Convert predictions to action names
            predicted_actions = []
            for idx in top_indices:
                action_name = self._index_to_action(idx)
                confidence = float(predictions[0][idx])
                
                predicted_actions.append({
                    'action': action_name,
                    'confidence': confidence,
                    'recommended_response': self._get_recommended_response(action_name, session)
                })
            
            return predicted_actions
            
        except Exception as e:
            logger.error(f"Error predicting next actions: {e}")
            return self._get_default_predictions('novice')
    
    def _prepare_sequence_data(self, session: Dict) -> Optional[np.ndarray]:
        """Prepare session data for LSTM prediction"""
        try:
            actions = list(session['actions'])
            targets = list(session['targets'])
            timestamps = list(session['timestamps'])
            
            if len(actions) < self.sequence_length:
                # Pad with default values
                actions.extend(['no_action'] * (self.sequence_length - len(actions)))
                targets.extend(['unknown'] * (self.sequence_length - len(targets)))
                timestamps.extend([datetime.now()] * (self.sequence_length - len(timestamps)))
            
            # Convert to numerical features
            features = []
            for i in range(self.sequence_length):
                action_vec = self._action_to_vector(actions[i])
                target_vec = self._target_to_vector(targets[i])
                time_features = self._extract_time_features(timestamps[i])
                
                feature_vector = np.concatenate([action_vec, target_vec, time_features])
                features.append(feature_vector)
            
            return np.array([features])
            
        except Exception as e:
            logger.error(f"Error preparing sequence data: {e}")
            return None
    
    def _action_to_vector(self, action: str) -> np.ndarray:
        """Convert action string to numerical vector"""
        # Simple encoding - in practice, use learned embeddings
        action_map = {
            'port_scan': [1, 0, 0, 0, 0, 0, 0, 0],
            'service_enum': [0, 1, 0, 0, 0, 0, 0, 0],
            'login_attempt': [0, 0, 1, 0, 0, 0, 0, 0],
            'file_access': [0, 0, 0, 1, 0, 0, 0, 0],
            'command_exec': [0, 0, 0, 0, 1, 0, 0, 0],
            'privilege_esc': [0, 0, 0, 0, 0, 1, 0, 0],
            'lateral_move': [0, 0, 0, 0, 0, 0, 1, 0],
            'data_exfil': [0, 0, 0, 0, 0, 0, 0, 1],
            'no_action': [0, 0, 0, 0, 0, 0, 0, 0]
        }
        return np.array(action_map.get(action, [0, 0, 0, 0, 0, 0, 0, 0]))
    
    def _target_to_vector(self, target: str) -> np.ndarray:
        """Convert target string to numerical vector"""
        target_map = {
            'web_server': [1, 0, 0, 0, 0, 0],
            'ssh_server': [0, 1, 0, 0, 0, 0],
            'database': [0, 0, 1, 0, 0, 0],
            'file_server': [0, 0, 0, 1, 0, 0],
            'domain_controller': [0, 0, 0, 0, 1, 0],
            'workstation': [0, 0, 0, 0, 0, 1],
            'unknown': [0, 0, 0, 0, 0, 0]
        }
        return np.array(target_map.get(target, [0, 0, 0, 0, 0, 0]))
    
    def _extract_time_features(self, timestamp: datetime) -> np.ndarray:
        """Extract time-based features"""
        hour = timestamp.hour / 24.0
        day_of_week = timestamp.weekday() / 6.0
        return np.array([hour, day_of_week, 0.0, 0.0, 0.0, 0.0])  # 6 features
    
    def _index_to_action(self, index: int) -> str:
        """Convert prediction index to action name"""
        actions = ['port_scan', 'service_enum', 'login_attempt', 'file_access', 
                  'command_exec', 'privilege_esc', 'lateral_move', 'data_exfil']
        return actions[index % len(actions)]
    
    def _get_recommended_response(self, action: str, session: Dict) -> str:
        """Get recommended deception response for predicted action"""
        skill_level = session['skill_level']
        
        responses = {
            'port_scan': {
                'novice': 'Show basic services with obvious vulnerabilities',
                'intermediate': 'Show realistic service mix with subtle honeypots',
                'expert': 'Advanced deception with believable hardened services'
            },
            'login_attempt': {
                'novice': 'Accept weak credentials quickly',
                'intermediate': 'Delay response, then accept with warning logs',
                'expert': 'Multi-factor auth simulation with eventual bypass'
            },
            'file_access': {
                'novice': 'Show obvious valuable files',
                'intermediate': 'Mix real and fake files with access logs',
                'expert': 'Sophisticated file system with audit trails'
            }
        }
        
        return responses.get(action, {}).get(skill_level, 'Standard deception response')
    
    def _get_default_predictions(self, skill_level: str) -> List[Dict]:
        """Get default predictions when insufficient data"""
        defaults = {
            'novice': [
                {'action': 'port_scan', 'confidence': 0.7, 'recommended_response': 'Show basic vulnerable services'},
                {'action': 'login_attempt', 'confidence': 0.6, 'recommended_response': 'Accept weak credentials'},
                {'action': 'file_access', 'confidence': 0.5, 'recommended_response': 'Show obvious valuable files'}
            ],
            'intermediate': [
                {'action': 'service_enum', 'confidence': 0.8, 'recommended_response': 'Show realistic service details'},
                {'action': 'login_attempt', 'confidence': 0.7, 'recommended_response': 'Simulate authentication delays'},
                {'action': 'privilege_esc', 'confidence': 0.6, 'recommended_response': 'Present escalation opportunities'}
            ],
            'expert': [
                {'action': 'lateral_move', 'confidence': 0.9, 'recommended_response': 'Simulate network segmentation'},
                {'action': 'privilege_esc', 'confidence': 0.8, 'recommended_response': 'Advanced privilege simulation'},
                {'action': 'data_exfil', 'confidence': 0.7, 'recommended_response': 'Monitor exfiltration attempts'}
            ]
        }
        
        return defaults.get(skill_level, defaults['novice'])


class AdaptiveContentGenerator:
    """Generate adaptive deception content based on attacker behavior"""
    
    def __init__(self, behavior_modeler: AttackerBehaviorModeler):
        self.behavior_modeler = behavior_modeler
        self.content_templates = self._load_content_templates()
    
    def _load_content_templates(self) -> Dict:
        """Load content templates for different deception types"""
        return {
            'credentials': {
                'admin_accounts': [
                    {'username': 'admin', 'password': 'Admin123!'},
                    {'username': 'administrator', 'password': 'P@ssw0rd'},
                    {'username': 'root', 'password': 'toor'},
                    {'username': 'sysadmin', 'password': 'SysAdmin2024'},
                ],
                'service_accounts': [
                    {'username': 'service_sql', 'password': 'SqlService123'},
                    {'username': 'backup_svc', 'password': 'BackupPass!'},
                    {'username': 'monitoring', 'password': 'Monitor@2024'},
                ],
                'user_accounts': [
                    {'username': 'jsmith', 'password': 'Summer2024!'},
                    {'username': 'mjohnson', 'password': 'Password123'},
                    {'username': 'dconnor', 'password': 'Welcome@2024'},
                ]
            },
            'files': {
                'config_files': [
                    'database.conf', 'server.xml', 'app.properties', 
                    'credentials.txt', 'backup.cfg'
                ],
                'valuable_files': [
                    'customer_data.xlsx', 'financial_report.pdf', 'employee_list.csv',
                    'product_roadmap.docx', 'source_code.zip'
                ],
                'system_files': [
                    'system.log', 'access.log', 'security.audit',
                    'backup.tar.gz', 'update.sh'
                ]
            },
            'directories': {
                'common_paths': [
                    '/var/log', '/etc/config', '/opt/apps', '/home/users',
                    '/backup', '/data', '/shared'
                ],
                'valuable_paths': [
                    '/confidential', '/financial', '/customer_data',
                    '/source_code', '/backups/production'
                ]
            },
            'protocol_banners': {
                'ssh': [
                    'SSH-2.0-OpenSSH_7.4p1 Ubuntu-10ubuntu1.1',
                    'SSH-2.0-OpenSSH_8.0p1 Ubuntu-6ubuntu0.1',
                    'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2'
                ],
                'http': [
                    'Apache/2.4.29 (Ubuntu)',
                    'nginx/1.14.0 (Ubuntu)',
                    'Microsoft-IIS/10.0'
                ],
                'ftp': [
                    'vsftpd 3.0.3',
                    'ProFTPD 1.3.5 Server',
                    'Pure-FTPd'
                ]
            }
        }
    
    def generate_adaptive_credentials(self, session_id: str, target_type: str) -> Dict:
        """Generate adaptive credentials based on attacker behavior"""
        try:
            session = self.behavior_modeler.attacker_sessions[session_id]
            skill_level = session['skill_level']
            
            # Select credential type based on target and skill level
            if target_type in ['database', 'admin_panel']:
                cred_type = 'admin_accounts'
            elif target_type in ['service', 'api']:
                cred_type = 'service_accounts'
            else:
                cred_type = 'user_accounts'
            
            # Get base credentials
            base_creds = random.choice(self.content_templates['credentials'][cred_type])
            
            # Adapt based on skill level
            adapted_creds = self._adapt_credentials_to_skill(base_creds, skill_level)
            
            # Add believability factors
            adapted_creds['believability_score'] = self._calculate_believability_score(
                adapted_creds, session
            )
            
            logger.info(f"Generated adaptive credentials for session {session_id}")
            return adapted_creds
            
        except Exception as e:
            logger.error(f"Error generating adaptive credentials: {e}")
            return {'username': 'admin', 'password': 'password', 'believability_score': 0.5}
    
    def _adapt_credentials_to_skill(self, base_creds: Dict, skill_level: str) -> Dict:
        """Adapt credentials based on attacker skill level"""
        adapted = base_creds.copy()
        
        if skill_level == 'novice':
            # Make credentials more obvious for novice attackers
            if 'admin' in adapted['username'].lower():
                adapted['password'] = random.choice(['password', 'admin', '123456', 'welcome'])
        
        elif skill_level == 'intermediate':
            # Slightly more realistic but still crackable
            current_year = datetime.now().year
            adapted['password'] = f"{adapted['password'].split('!')[0]}{current_year}!"
        
        elif skill_level == 'expert':
            # More sophisticated, appears properly configured
            adapted['password'] = self._generate_complex_password()
            adapted['last_changed'] = (datetime.now() - timedelta(days=random.randint(30, 90))).isoformat()
            adapted['mfa_enabled'] = random.choice([True, False])
        
        return adapted
    
    def _generate_complex_password(self) -> str:
        """Generate a complex-looking password"""
        parts = [
            random.choice(['Enterprise', 'Corporate', 'Business', 'Company']),
            str(random.randint(2020, 2024)),
            random.choice(['!', '@', '#', '$'])
        ]
        return ''.join(parts)
    
    def _calculate_believability_score(self, credentials: Dict, session: Dict) -> float:
        """Calculate how believable the credentials are"""
        score = 0.5  # Base score
        
        # Increase score based on complexity
        password = credentials.get('password', '')
        if len(password) >= 8:
            score += 0.1
        if any(c.isupper() for c in password):
            score += 0.1
        if any(c.islower() for c in password):
            score += 0.1
        if any(c.isdigit() for c in password):
            score += 0.1
        if any(c in '!@#$%^&*' for c in password):
            score += 0.1
        
        # Adjust based on session context
        if session['success_rate'] > 0.7:
            score += 0.1  # High success rate = make it more challenging
        
        return min(1.0, score)
    
    def generate_adaptive_file_system(self, session_id: str) -> Dict:
        """Generate adaptive file system structure"""
        try:
            session = self.behavior_modeler.attacker_sessions[session_id]
            skill_level = session['skill_level']
            
            file_system = {
                'directories': [],
                'files': [],
                'hidden_files': [],
                'access_controls': {}
            }
            
            # Add directories based on skill level
            if skill_level == 'novice':
                file_system['directories'] = ['/backup', '/config', '/data']
                file_system['files'] = ['passwords.txt', 'config.ini', 'backup.zip']
            
            elif skill_level == 'intermediate':
                file_system['directories'] = ['/var/log', '/opt/apps', '/home/users', '/backup']
                file_system['files'] = ['database.conf', 'app.properties', 'users.csv']
                file_system['hidden_files'] = ['.env', '.credentials', '.backup_key']
            
            elif skill_level == 'expert':
                file_system['directories'] = [
                    '/var/log', '/etc/config', '/opt/enterprise', '/home/users',
                    '/backup/encrypted', '/data/customer', '/shared/financial'
                ]
                file_system['files'] = [
                    'enterprise.conf', 'security_policies.pdf', 'audit_trail.log',
                    'customer_database.backup', 'financial_reports.xlsx'
                ]
                file_system['hidden_files'] = [
                    '.env.production', '.ssh/id_rsa.backup', '.db_credentials'
                ]
                file_system['access_controls'] = {
                    '/data/customer': 'requires_elevated_privileges',
                    '/backup/encrypted': 'encrypted_access_only',
                    '/shared/financial': 'audit_logged'
                }
            
            logger.info(f"Generated adaptive file system for session {session_id}")
            return file_system
            
        except Exception as e:
            logger.error(f"Error generating adaptive file system: {e}")
            return {'directories': ['/data'], 'files': ['readme.txt'], 'hidden_files': []}
    
    def generate_adaptive_protocol_responses(self, session_id: str, protocol: str) -> Dict:
        """Generate adaptive protocol responses"""
        try:
            session = self.behavior_modeler.attacker_sessions[session_id]
            skill_level = session['skill_level']
            
            if protocol.lower() == 'ssh':
                return self._generate_ssh_responses(skill_level)
            elif protocol.lower() == 'http':
                return self._generate_http_responses(skill_level)
            elif protocol.lower() == 'ftp':
                return self._generate_ftp_responses(skill_level)
            else:
                return {'banner': 'Service available', 'responses': {}}
                
        except Exception as e:
            logger.error(f"Error generating protocol responses: {e}")
            return {'banner': 'Service available', 'responses': {}}
    
    def _generate_ssh_responses(self, skill_level: str) -> Dict:
        """Generate SSH-specific adaptive responses"""
        if skill_level == 'novice':
            return {
                'banner': 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2',
                'responses': {
                    'login_prompt': 'Password:',
                    'failed_login': 'Permission denied, please try again.',
                    'successful_login': 'Last login: Mon Dec  4 10:15:32 2023',
                    'command_not_found': 'bash: command not found'
                },
                'vulnerable_config': True,
                'allows_root_login': True
            }
        elif skill_level == 'intermediate':
            return {
                'banner': 'SSH-2.0-OpenSSH_7.4p1 Ubuntu-10ubuntu1.1',
                'responses': {
                    'login_prompt': 'Password:',
                    'failed_login': 'Permission denied (publickey,password).',
                    'successful_login': 'Welcome to Ubuntu 16.04.3 LTS',
                    'motd': 'System maintenance scheduled for tonight'
                },
                'security_notices': ['Failed login attempts will be logged'],
                'allows_root_login': False
            }
        else:  # expert
            return {
                'banner': 'SSH-2.0-OpenSSH_8.0p1 Ubuntu-6ubuntu0.1',
                'responses': {
                    'login_prompt': 'Password:',
                    'failed_login': 'Permission denied (publickey).',
                    'successful_login': 'Last login: Mon Dec  4 15:32:18 2023 from 10.0.1.50',
                    'motd': 'Unauthorized access is prohibited. All connections are logged.',
                    'security_warning': 'This system is monitored for security compliance.'
                },
                'multi_factor': True,
                'key_based_auth': True,
                'connection_monitoring': True
            }
    
    def _generate_http_responses(self, skill_level: str) -> Dict:
        """Generate HTTP-specific adaptive responses"""
        if skill_level == 'novice':
            return {
                'server_header': 'Apache/2.2.22 (Ubuntu)',
                'pages': {
                    '/admin': 'Admin Login',
                    '/backup': 'Directory Listing Enabled',
                    '/config': 'Configuration Files'
                },
                'vulnerabilities': ['directory_traversal', 'weak_authentication']
            }
        elif skill_level == 'intermediate':
            return {
                'server_header': 'Apache/2.4.29 (Ubuntu)',
                'pages': {
                    '/admin': 'Admin Portal - Requires Authentication',
                    '/api': 'API Endpoints',
                    '/docs': 'Documentation'
                },
                'security_headers': ['X-Frame-Options: DENY'],
                'authentication_required': True
            }
        else:  # expert
            return {
                'server_header': 'nginx/1.14.0 (Ubuntu)',
                'pages': {
                    '/admin': 'Enterprise Admin Console',
                    '/api/v1': 'REST API v1.0',
                    '/monitoring': 'System Monitoring Dashboard'
                },
                'security_headers': [
                    'Strict-Transport-Security: max-age=31536000',
                    'X-Content-Type-Options: nosniff',
                    'X-Frame-Options: DENY'
                ],
                'rate_limiting': True,
                'ssl_required': True
            }
    
    def _generate_ftp_responses(self, skill_level: str) -> Dict:
        """Generate FTP-specific adaptive responses"""
        if skill_level == 'novice':
            return {
                'banner': '220 Welcome to Basic FTP Server',
                'anonymous_allowed': True,
                'directory_listing': ['readme.txt', 'backup.zip', 'data.csv']
            }
        elif skill_level == 'intermediate':
            return {
                'banner': '220 ProFTPD 1.3.5 Server ready',
                'anonymous_allowed': False,
                'authentication_required': True,
                'directory_listing': ['reports/', 'archives/', 'temp/']
            }
        else:  # expert
            return {
                'banner': '220 Enterprise FTP Server - Authorized Access Only',
                'encryption_required': True,
                'certificate_auth': True,
                'access_logging': True,
                'directory_listing': ['encrypted/', 'audit_logs/', 'secure_backup/']
            }


class AdaptiveDeceptionEngine:
    """Main engine that coordinates adaptive deception based on attacker behavior"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.behavior_modeler = AttackerBehaviorModeler()
        self.content_generator = AdaptiveContentGenerator(self.behavior_modeler)
        
        # Integration endpoints
        self.decoy_generator_url = "http://decoy_generator:5002"
        self.behavioral_analysis_url = "http://behavioral_analysis:5001"
        self.traffic_monitor_url = "http://traffic_monitor:5003"
    
    def process_attacker_event(self, event_data: Dict) -> Dict:
        """Process an attacker event and trigger adaptive responses"""
        try:
            session_id = event_data.get('session_id', 'unknown')
            action = event_data.get('action', 'unknown')
            target = event_data.get('target', 'unknown')
            success = event_data.get('success', False)
            timestamp = datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat()))
            
            # Update behavior model
            self.behavior_modeler.update_attacker_behavior(
                session_id, action, target, success, timestamp
            )
            
            # Get next action predictions
            predictions = self.behavior_modeler.predict_next_actions(session_id)
            
            # Generate adaptive responses
            adaptive_responses = []
            for prediction in predictions:
                response = self._generate_adaptive_response(session_id, prediction)
                if response:
                    adaptive_responses.append(response)
            
            # Store results
            result = {
                'session_id': session_id,
                'processed_at': datetime.now().isoformat(),
                'predictions': predictions,
                'adaptive_responses': adaptive_responses,
                'behavior_analysis': {
                    'skill_level': self.behavior_modeler.attacker_sessions[session_id]['skill_level'],
                    'success_rate': self.behavior_modeler.attacker_sessions[session_id]['success_rate'],
                    'persistence': self.behavior_modeler.attacker_sessions[session_id]['persistence']
                }
            }
            
            self._store_adaptive_decision(result)
            
            # Trigger actual adaptive changes
            self._apply_adaptive_changes(session_id, adaptive_responses)
            
            logger.info(f"Processed adaptive deception for session {session_id}")
            return result
            
        except Exception as e:
            logger.error(f"Error processing attacker event: {e}")
            return {'error': str(e)}
    
    def _generate_adaptive_response(self, session_id: str, prediction: Dict) -> Optional[Dict]:
        """Generate specific adaptive response for a prediction"""
        try:
            action = prediction['action']
            confidence = prediction['confidence']
            
            if confidence < 0.3:
                return None  # Skip low confidence predictions
            
            response = {
                'action': action,
                'confidence': confidence,
                'adaptive_content': {}
            }
            
            if action == 'login_attempt':
                response['adaptive_content'] = self.content_generator.generate_adaptive_credentials(
                    session_id, 'web_server'
                )
            
            elif action == 'file_access':
                response['adaptive_content'] = self.content_generator.generate_adaptive_file_system(
                    session_id
                )
            
            elif action in ['port_scan', 'service_enum']:
                response['adaptive_content'] = self.content_generator.generate_adaptive_protocol_responses(
                    session_id, 'ssh'
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating adaptive response: {e}")
            return None
    
    def _apply_adaptive_changes(self, session_id: str, adaptive_responses: List[Dict]):
        """Apply adaptive changes to running honeypots"""
        try:
            for response in adaptive_responses:
                action = response['action']
                content = response['adaptive_content']
                
                if action == 'login_attempt' and 'username' in content:
                    # Update honeypot credentials
                    self._update_honeypot_credentials(session_id, content)
                
                elif action == 'file_access' and 'directories' in content:
                    # Update honeypot file system
                    self._update_honeypot_filesystem(session_id, content)
                
                elif action in ['port_scan', 'service_enum'] and 'banner' in content:
                    # Update service banners
                    self._update_service_banners(session_id, content)
            
            logger.info(f"Applied {len(adaptive_responses)} adaptive changes for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error applying adaptive changes: {e}")
    
    def _update_honeypot_credentials(self, session_id: str, credentials: Dict):
        """Update honeypot credentials based on adaptive content"""
        try:
            # Store adaptive credentials in Redis
            key = f"adaptive_creds:{session_id}"
            self.redis_client.setex(key, 3600, json.dumps(credentials))
            
            # Notify honeypots to use new credentials
            # This would integrate with existing honeypot APIs
            logger.debug(f"Updated adaptive credentials for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error updating honeypot credentials: {e}")
    
    def _update_honeypot_filesystem(self, session_id: str, filesystem: Dict):
        """Update honeypot file system based on adaptive content"""
        try:
            # Store adaptive filesystem in Redis
            key = f"adaptive_filesystem:{session_id}"
            self.redis_client.setex(key, 3600, json.dumps(filesystem))
            
            logger.debug(f"Updated adaptive filesystem for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error updating honeypot filesystem: {e}")
    
    def _update_service_banners(self, session_id: str, banners: Dict):
        """Update service banners based on adaptive content"""
        try:
            # Store adaptive banners in Redis
            key = f"adaptive_banners:{session_id}"
            self.redis_client.setex(key, 3600, json.dumps(banners))
            
            logger.debug(f"Updated adaptive banners for session {session_id}")
            
        except Exception as e:
            logger.error(f"Error updating service banners: {e}")
    
    def _store_adaptive_decision(self, decision: Dict):
        """Store adaptive decision for audit and evaluation"""
        try:
            key = f"adaptive_decision:{decision['session_id']}:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 86400, json.dumps(decision))
            logger.debug("Stored adaptive decision for audit")
        except Exception as e:
            logger.error(f"Error storing adaptive decision: {e}")
    
    def get_session_analytics(self, session_id: str) -> Dict:
        """Get analytics for a specific attacker session"""
        try:
            session = self.behavior_modeler.attacker_sessions[session_id]
            
            analytics = {
                'session_id': session_id,
                'skill_level': session['skill_level'],
                'success_rate': session['success_rate'],
                'persistence': session['persistence'],
                'total_actions': len(session['actions']),
                'action_sequence': list(session['actions']),
                'target_sequence': list(session['targets']),
                'last_activity': session['timestamps'][-1].isoformat() if session['timestamps'] else None
            }
            
            # Get adaptive decisions
            decision_keys = self.redis_client.keys(f"adaptive_decision:{session_id}:*")
            analytics['adaptive_decisions'] = len(decision_keys)
            
            return analytics
            
        except Exception as e:
            logger.error(f"Error getting session analytics: {e}")
            return {'error': str(e)}
    
    def get_global_analytics(self) -> Dict:
        """Get global analytics across all sessions"""
        try:
            total_sessions = len(self.behavior_modeler.attacker_sessions)
            
            skill_distribution = defaultdict(int)
            avg_success_rate = 0
            avg_persistence = 0
            
            for session in self.behavior_modeler.attacker_sessions.values():
                skill_distribution[session['skill_level']] += 1
                avg_success_rate += session['success_rate']
                avg_persistence += session['persistence']
            
            if total_sessions > 0:
                avg_success_rate /= total_sessions
                avg_persistence /= total_sessions
            
            return {
                'total_sessions': total_sessions,
                'skill_distribution': dict(skill_distribution),
                'average_success_rate': avg_success_rate,
                'average_persistence_hours': avg_persistence,
                'total_adaptive_decisions': len(self.redis_client.keys("adaptive_decision:*"))
            }
            
        except Exception as e:
            logger.error(f"Error getting global analytics: {e}")
            return {'error': str(e)}


# Flask API
app = Flask(__name__)
adaptive_engine = AdaptiveDeceptionEngine()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'adaptive_deception',
        'models_loaded': True
    })

@app.route('/process_event', methods=['POST'])
def process_event():
    """Process attacker event and generate adaptive responses"""
    try:
        event_data = request.get_json()
        if not event_data:
            return jsonify({'error': 'No event data provided'}), 400
        
        result = adaptive_engine.process_attacker_event(event_data)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/session/<session_id>/analytics', methods=['GET'])
def get_session_analytics(session_id):
    """Get analytics for specific session"""
    try:
        analytics = adaptive_engine.get_session_analytics(session_id)
        return jsonify(analytics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analytics/global', methods=['GET'])
def get_global_analytics():
    """Get global analytics"""
    try:
        analytics = adaptive_engine.get_global_analytics()
        return jsonify(analytics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/session/<session_id>/predictions', methods=['GET'])
def get_predictions(session_id):
    """Get next action predictions for session"""
    try:
        predictions = adaptive_engine.behavior_modeler.predict_next_actions(session_id)
        return jsonify(predictions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True)