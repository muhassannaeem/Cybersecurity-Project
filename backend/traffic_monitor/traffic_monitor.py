import subprocess
import threading
import time
import json
import logging
import os
import signal
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from functools import wraps
import redis
import requests
import jwt
from marshmallow import Schema, fields, ValidationError
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# import pandas as pd  # Commented out to avoid dependency issues
# import numpy as np   # Commented out to avoid dependency issues  
# from scapy.all import sniff, IP, TCP, UDP  # Commented out to avoid dependency issues
# import pyshark  # Commented out to avoid dependency issues
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from zeek_parser import ZeekLogParser, parse_all_zeek_logs

# Configure structured logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from logging_config import setup_logging, log_info, log_error, log_warning
    logger = setup_logging(
        service_name="traffic_monitor",
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        environment=os.getenv('ENVIRONMENT', 'development'),
        log_file=os.getenv('LOG_FILE', '/app/logs/traffic_monitor.log')
    )
except ImportError:
    # Fallback to basic logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class ZeekLogEventHandler(FileSystemEventHandler):
    """Handle file system events for Zeek log files"""
    
    def __init__(self, traffic_monitor):
        self.traffic_monitor = traffic_monitor
        self.parser = ZeekLogParser()
        
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and event.src_path.endswith('.log'):
            self._process_log_file(event.src_path)
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and event.src_path.endswith('.log'):
            # Wait a moment for file to be written
            time.sleep(1)
            self._process_log_file(event.src_path)
    
    def _process_log_file(self, file_path):
        """Process a Zeek log file that was created or modified"""
        try:
            # Get only the latest entries (last 100 lines)
            entries = self.parser.get_latest_entries(file_path, 100)
            
            if entries:
                # Enrich events with MITRE ATT&CK attribution
                enriched_entries = self.traffic_monitor._enrich_events_with_attribution(entries)
                
                # Store in Redis for real-time access
                self.traffic_monitor._store_realtime_events(enriched_entries)
                
                # Detect anomalies on enriched events
                anomalies = self.traffic_monitor._detect_zeek_anomalies(enriched_entries)
                
                # Prioritize anomalies based on attribution
                if anomalies:
                    prioritized_anomalies = self.traffic_monitor._prioritize_anomalies_by_attribution(anomalies)
                    self.traffic_monitor._store_anomalies(prioritized_anomalies)
                    
                    # Send events to adaptive deception engine
                    self.traffic_monitor._send_to_adaptive_deception(prioritized_anomalies)
                
                logger.debug(f"Processed {len(enriched_entries)} enriched entries from {file_path}")
        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {e}")

class TrafficMonitor:
    """Traffic Monitor using tcpdump and pyshark for real-time network capture"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.capture_processes = {}
        self.monitoring_active = False
        self.capture_stats = {
            'packets_captured': 0,
            'connections_analyzed': 0,
            'anomalies_detected': 0,
            'start_time': None
        }
        
        # Integration with adaptive deception
        self.adaptive_deception_url = "http://adaptive_deception:5007"
        
        # Traffic analysis thresholds
        self.thresholds = {
            'packet_rate': 1000,  # packets per second
            'connection_rate': 100,  # connections per minute
            'data_volume': 1000000,  # bytes per minute
            'suspicious_ports': [22, 23, 3389, 445, 1433, 3306]
        }
    
    def start_zeek_monitoring(self, interface: str = "eth0", log_dir: str = "/app/zeek_logs"):
        """Start Zeek network monitoring with real process management"""
        try:
            # Create log directory
            os.makedirs(log_dir, exist_ok=True)
            
            # Check if Zeek is available
            try:
                result = subprocess.run(['zeek', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.warning("Zeek not found - using tcpdump fallback")
                    return self.start_tcpdump_capture(interface, f"{log_dir}/capture.pcap")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning("Zeek not available - using tcpdump fallback")
                return self.start_tcpdump_capture(interface, f"{log_dir}/capture.pcap")
            
            # Stop existing Zeek process if running
            if f"zeek_{interface}" in self.capture_processes:
                self.stop_zeek_monitoring(interface)
            
            # Prepare Zeek command
            cmd = [
                "zeek",
                "-i", interface,
                "-C",  # Ignore checksum errors
                "local",  # Use local site configuration
                f"Log::default_logdir={log_dir}"
            ]
            
            # Start Zeek process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=log_dir
            )
            
            # Store process information
            self.capture_processes[f"zeek_{interface}"] = {
                'process': process,
                'interface': interface,
                'log_dir': log_dir,
                'start_time': datetime.now(),
                'type': 'zeek'
            }
            
            # Start log file monitoring
            self._start_log_monitoring(log_dir)
            
            logger.info(f"Zeek monitoring started on interface {interface}, logs in {log_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting Zeek monitoring: {e}")
            return False
    
    def stop_zeek_monitoring(self, interface: str = "eth0"):
        """Stop Zeek network monitoring"""
        try:
            key = f"zeek_{interface}"
            if key in self.capture_processes:
                process_info = self.capture_processes[key]
                
                # Send SIGTERM to Zeek process
                process_info['process'].terminate()
                
                # Wait for graceful shutdown
                try:
                    process_info['process'].wait(timeout=10)
                    logger.info(f"Zeek process terminated gracefully on {interface}")
                except subprocess.TimeoutExpired:
                    # Force kill if necessary
                    process_info['process'].kill()
                    logger.warning(f"Zeek process killed forcefully on {interface}")
                
                # Stop log monitoring
                self._stop_log_monitoring(process_info['log_dir'])
                
                del self.capture_processes[key]
                return True
        except Exception as e:
            logger.error(f"Error stopping Zeek monitoring: {e}")
        
        return False
    
    def _start_log_monitoring(self, log_dir: str):
        """Start monitoring Zeek log directory for new files"""
        try:
            if not hasattr(self, 'log_observers'):
                self.log_observers = {}
            
            if log_dir in self.log_observers:
                return  # Already monitoring this directory
            
            # Create file system event handler
            event_handler = ZeekLogEventHandler(self)
            
            # Create observer
            observer = Observer()
            observer.schedule(event_handler, log_dir, recursive=True)
            observer.start()
            
            self.log_observers[log_dir] = observer
            logger.info(f"Started monitoring log directory: {log_dir}")
            
        except Exception as e:
            logger.error(f"Error starting log monitoring: {e}")
    
    def _stop_log_monitoring(self, log_dir: str):
        """Stop monitoring Zeek log directory"""
        try:
            if hasattr(self, 'log_observers') and log_dir in self.log_observers:
                observer = self.log_observers[log_dir]
                observer.stop()
                observer.join(timeout=5)
                del self.log_observers[log_dir]
                logger.info(f"Stopped monitoring log directory: {log_dir}")
        except Exception as e:
            logger.error(f"Error stopping log monitoring: {e}")
    
    def start_tcpdump_capture(self, interface: str = "eth0", capture_file: str = "/app/captures/capture.pcap"):
        """Start tcpdump packet capture"""
        try:
            if f"tcpdump_{interface}" in self.capture_processes:
                logger.warning(f"tcpdump capture already running on {interface}")
                return False
            
            # Create capture directory
            os.makedirs(os.path.dirname(capture_file), exist_ok=True)
            
            # Start tcpdump
            cmd = [
                "tcpdump",
                "-i", interface,
                "-w", capture_file,
                "-s", "0",  # Capture full packets
                "-C", "100",  # Rotate files at 100MB
                "-W", "10"  # Keep 10 files
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.capture_processes[f"tcpdump_{interface}"] = {
                'process': process,
                'interface': interface,
                'capture_file': capture_file,
                'start_time': datetime.now()
            }
            
            logger.info(f"tcpdump capture started on interface {interface}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting tcpdump capture: {e}")
            return False
    
    def stop_tcpdump_capture(self, interface: str = "eth0"):
        """Stop tcpdump packet capture"""
        try:
            key = f"tcpdump_{interface}"
            if key in self.capture_processes:
                process_info = self.capture_processes[key]
                process_info['process'].terminate()
                process_info['process'].wait(timeout=10)
                del self.capture_processes[key]
                logger.info(f"tcpdump capture stopped on interface {interface}")
                return True
        except subprocess.TimeoutExpired:
            process_info['process'].kill()
            logger.warning(f"tcpdump process killed forcefully on {interface}")
        except Exception as e:
            logger.error(f"Error stopping tcpdump capture: {e}")
        
        return False
    
    def analyze_zeek_logs(self, log_dir: str = "/app/zeek_logs") -> Dict:
        """Analyze Zeek log files for network activity using the new parser"""
        try:
            # Use the new Zeek parser
            parser = ZeekLogParser()
            all_logs = parser.parse_log_directory(log_dir)
            
            analysis_results = {
                'connections': all_logs.get('conn', []),
                'http_requests': all_logs.get('http', []),
                'dns_queries': all_logs.get('dns', []),
                'ssl_certificates': all_logs.get('ssl', []),
                'weird_events': all_logs.get('weird', []),
                'files': all_logs.get('files', []),
                'anomalies': [],
                'summary': {}
            }
            
            # Generate summary for each log type
            for log_type, entries in all_logs.items():
                if entries:
                    summary = parser.summarize_log_data(entries)
                    analysis_results['summary'][log_type] = summary
            
            # Detect anomalies across all log types
            all_entries = []
            for entries in all_logs.values():
                all_entries.extend(entries)
            
            if all_entries:
                # Enrich events with MITRE ATT&CK attribution
                logger.info(f"Enriching {len(all_entries)} events with threat attribution...")
                enriched_entries = self._enrich_events_with_attribution(all_entries)
                
                # Update the analysis results with enriched data
                enriched_by_type = {}
                for entry in enriched_entries:
                    log_type = entry.get('_log_type', 'unknown')
                    if log_type not in enriched_by_type:
                        enriched_by_type[log_type] = []
                    enriched_by_type[log_type].append(entry)
                
                # Replace with enriched data
                analysis_results['connections'] = enriched_by_type.get('conn', [])
                analysis_results['http_requests'] = enriched_by_type.get('http', [])
                analysis_results['dns_queries'] = enriched_by_type.get('dns', [])
                analysis_results['ssl_certificates'] = enriched_by_type.get('ssl', [])
                analysis_results['weird_events'] = enriched_by_type.get('weird', [])
                analysis_results['files'] = enriched_by_type.get('files', [])
                
                # Detect anomalies on enriched data
                anomalies = self._detect_zeek_anomalies(enriched_entries)
                prioritized_anomalies = self._prioritize_anomalies_by_attribution(anomalies)
                analysis_results['anomalies'] = prioritized_anomalies
                
                # Update capture stats
                self.capture_stats['connections_analyzed'] += len(analysis_results['connections'])
                self.capture_stats['anomalies_detected'] += len(prioritized_anomalies)
                
                logger.info(f"Analysis complete: {len(enriched_entries)} events, {len(prioritized_anomalies)} anomalies")
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek logs: {e}")
            return {
                'connections': [],
                'http_requests': [],
                'dns_queries': [],
                'ssl_certificates': [],
                'weird_events': [],
                'files': [],
                'anomalies': [],
                'summary': {}
            }
    
    def _parse_zeek_log(self, log_file: str) -> List[Dict]:
        """Parse Zeek log file"""
        try:
            entries = []
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    try:
                        # Parse JSON log entry
                        entry = json.loads(line.strip())
                        entries.append(entry)
                    except json.JSONDecodeError:
                        # Fallback to tab-separated format
                        fields = line.strip().split('\t')
                        if len(fields) > 1:
                            entry = {
                                'timestamp': fields[0],
                                'data': fields[1:]
                            }
                            entries.append(entry)
            
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing Zeek log {log_file}: {e}")
            return []
    
    def _detect_connection_anomalies(self, connections: List[Dict]) -> List[Dict]:
        """Detect anomalies in network connections"""
        try:
            anomalies = []
            
            for conn in connections:
                # Check for suspicious ports
                if 'id.resp_p' in conn and conn['id.resp_p'] in self.thresholds['suspicious_ports']:
                    anomalies.append({
                        'type': 'suspicious_port',
                        'connection': conn,
                        'severity': 'medium',
                        'description': f"Connection to suspicious port {conn['id.resp_p']}"
                    })
                
                # Check for high data volume
                if 'orig_bytes' in conn and conn['orig_bytes'] > self.thresholds['data_volume']:
                    anomalies.append({
                        'type': 'high_data_volume',
                        'connection': conn,
                        'severity': 'high',
                        'description': f"High data volume: {conn['orig_bytes']} bytes"
                    })
                
                # Check for failed connections
                if 'conn_state' in conn and conn['conn_state'] == 'REJ':
                    anomalies.append({
                        'type': 'failed_connection',
                        'connection': conn,
                        'severity': 'low',
                        'description': "Failed connection attempt"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting connection anomalies: {e}")
            return []
    
    def _detect_zeek_anomalies(self, entries: List[Dict]) -> List[Dict]:
        """Enhanced anomaly detection for Zeek log entries"""
        try:
            anomalies = []
            
            # Group entries by type for specific detection
            by_type = {}
            for entry in entries:
                log_type = entry.get('_log_type', 'unknown')
                if log_type not in by_type:
                    by_type[log_type] = []
                by_type[log_type].append(entry)
            
            # Connection anomalies
            if 'conn' in by_type:
                conn_anomalies = self._detect_connection_anomalies(by_type['conn'])
                anomalies.extend(conn_anomalies)
            
            # HTTP anomalies
            if 'http' in by_type:
                http_anomalies = self._detect_http_anomalies(by_type['http'])
                anomalies.extend(http_anomalies)
            
            # DNS anomalies
            if 'dns' in by_type:
                dns_anomalies = self._detect_dns_anomalies(by_type['dns'])
                anomalies.extend(dns_anomalies)
            
            # SSL anomalies
            if 'ssl' in by_type:
                ssl_anomalies = self._detect_ssl_anomalies(by_type['ssl'])
                anomalies.extend(ssl_anomalies)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting Zeek anomalies: {e}")
            return []
    
    def _detect_http_anomalies(self, http_entries: List[Dict]) -> List[Dict]:
        """Detect HTTP-specific anomalies"""
        try:
            anomalies = []
            
            for entry in http_entries:
                # Check for suspicious user agents
                user_agent = entry.get('user_agent', '')
                if user_agent and any(sus in user_agent.lower() for sus in 
                                    ['bot', 'crawler', 'scanner', 'sqlmap', 'nikto']):
                    anomalies.append({
                        'type': 'suspicious_user_agent',
                        'entry': entry,
                        'severity': 'medium',
                        'description': f"Suspicious user agent: {user_agent}"
                    })
                
                # Check for unusual status codes
                status_code = entry.get('status_code')
                if status_code and status_code in [401, 403, 404, 500]:
                    anomalies.append({
                        'type': 'error_status_code',
                        'entry': entry,
                        'severity': 'low',
                        'description': f"HTTP error status: {status_code}"
                    })
                
                # Check for large request/response bodies
                req_len = entry.get('request_body_len', 0) or 0
                resp_len = entry.get('response_body_len', 0) or 0
                
                if req_len > 1000000:  # 1MB
                    anomalies.append({
                        'type': 'large_http_request',
                        'entry': entry,
                        'severity': 'medium',
                        'description': f"Large HTTP request: {req_len} bytes"
                    })
                
                if resp_len > 10000000:  # 10MB
                    anomalies.append({
                        'type': 'large_http_response',
                        'entry': entry,
                        'severity': 'medium',
                        'description': f"Large HTTP response: {resp_len} bytes"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting HTTP anomalies: {e}")
            return []
    
    def _detect_dns_anomalies(self, dns_entries: List[Dict]) -> List[Dict]:
        """Detect DNS-specific anomalies"""
        try:
            anomalies = []
            
            for entry in dns_entries:
                # Check for suspicious domains
                query = entry.get('query', '').lower()
                if query and any(sus in query for sus in 
                               ['dga', 'malware', 'phish', 'botnet', 'c2']):
                    anomalies.append({
                        'type': 'suspicious_dns_query',
                        'entry': entry,
                        'severity': 'high',
                        'description': f"Suspicious DNS query: {query}"
                    })
                
                # Check for DNS tunneling (unusually long queries)
                if len(query) > 100:
                    anomalies.append({
                        'type': 'dns_tunneling',
                        'entry': entry,
                        'severity': 'high',
                        'description': f"Possible DNS tunneling: {len(query)} character query"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting DNS anomalies: {e}")
            return []
    
    def _detect_ssl_anomalies(self, ssl_entries: List[Dict]) -> List[Dict]:
        """Detect SSL/TLS-specific anomalies"""
        try:
            anomalies = []
            
            for entry in ssl_entries:
                # Check for self-signed or suspicious certificates
                subject = entry.get('subject', '')
                issuer = entry.get('issuer', '')
                
                if subject == issuer and subject:
                    anomalies.append({
                        'type': 'self_signed_certificate',
                        'entry': entry,
                        'severity': 'medium',
                        'description': f"Self-signed certificate: {subject}"
                    })
                
                # Check for weak ciphers
                cipher = entry.get('cipher', '')
                if cipher and any(weak in cipher.lower() for weak in 
                                ['null', 'anon', 'export', 'des', 'rc4']):
                    anomalies.append({
                        'type': 'weak_ssl_cipher',
                        'entry': entry,
                        'severity': 'medium',
                        'description': f"Weak SSL cipher: {cipher}"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting SSL anomalies: {e}")
            return []
    
    def _store_realtime_events(self, events: List[Dict]):
        """Store real-time events in Redis for immediate access"""
        try:
            for event in events:
                key = f"traffic_event:{datetime.now().strftime('%Y%m%d_%H%M%S')}:{id(event)}"
                self.redis_client.setex(key, 300, json.dumps(event, default=str))  # 5 min TTL
            
            logger.debug(f"Stored {len(events)} real-time events")
        except Exception as e:
            logger.error(f"Error storing real-time events: {e}")
    
    def _store_anomalies(self, anomalies: List[Dict]):
        """Store anomalies in Redis for alerting"""
        try:
            for anomaly in anomalies:
                key = f"traffic_anomaly:{datetime.now().strftime('%Y%m%d_%H%M%S')}:{id(anomaly)}"
                self.redis_client.setex(key, 3600, json.dumps(anomaly, default=str))  # 1 hour TTL
            
            logger.info(f"Stored {len(anomalies)} traffic anomalies")
        except Exception as e:
            logger.error(f"Error storing anomalies: {e}")
    
    def _send_to_adaptive_deception(self, anomalies: List[Dict]):
        """Send anomaly events to adaptive deception engine"""
        try:
            for anomaly in anomalies:
                # Create event data for adaptive deception
                event_data = {
                    'session_id': self._extract_session_id(anomaly),
                    'action': self._categorize_traffic_action(anomaly),
                    'target': self._identify_target(anomaly),
                    'success': anomaly.get('severity', 'low') in ['high', 'critical'],
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': anomaly.get('source_ip'),
                    'destination_ip': anomaly.get('destination_ip'),
                    'mitre_techniques': anomaly.get('mitre_techniques', []),
                    'severity': anomaly.get('severity', 'low'),
                    'confidence': anomaly.get('confidence', 0.5)
                }
                
                try:
                    response = requests.post(
                        f"{self.adaptive_deception_url}/process_event",
                        json=event_data,
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        logger.debug(f"Sent traffic event to adaptive deception: {event_data['action']}")
                    else:
                        logger.warning(f"Adaptive deception responded with status {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Could not reach adaptive deception service: {e}")
                    
        except Exception as e:
            logger.error(f"Error sending events to adaptive deception: {e}")
    
    def _extract_session_id(self, anomaly: Dict) -> str:
        """Extract or generate session ID from anomaly data"""
        try:
            # Try to use source IP + destination for session tracking
            source_ip = anomaly.get('source_ip', 'unknown')
            dest_ip = anomaly.get('destination_ip', 'unknown')
            return f"traffic_{source_ip}_{dest_ip}_{datetime.now().strftime('%Y%m%d_%H')}"
        except Exception:
            return f"traffic_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _categorize_traffic_action(self, anomaly: Dict) -> str:
        """Categorize the traffic anomaly into an action type"""
        try:
            # Look for indicators in the anomaly data
            techniques = anomaly.get('mitre_techniques', [])
            service = anomaly.get('service', '').lower()
            protocol = anomaly.get('protocol', '').lower()
            
            # Map based on MITRE techniques
            if 'T1595' in techniques:  # Active Scanning
                return 'port_scan'
            elif 'T1110' in techniques:  # Brute Force
                return 'login_attempt'
            elif 'T1021' in techniques:  # Remote Services
                return 'service_enum'
            elif 'T1083' in techniques:  # File and Directory Discovery
                return 'file_access'
            elif 'T1059' in techniques:  # Command and Scripting Interpreter
                return 'command_exec'
            
            # Map based on service/protocol
            elif service in ['ssh', 'ftp', 'telnet']:
                return 'login_attempt'
            elif service in ['http', 'https']:
                return 'web_access'
            elif protocol in ['tcp', 'udp'] and anomaly.get('severity') == 'high':
                return 'port_scan'
            else:
                return 'network_activity'
                
        except Exception:
            return 'unknown_activity'
    
    def _identify_target(self, anomaly: Dict) -> str:
        """Identify the target type from anomaly data"""
        try:
            dest_port = anomaly.get('destination_port')
            service = anomaly.get('service', '').lower()
            
            # Map based on port/service
            if dest_port in [80, 443, 8080] or service in ['http', 'https']:
                return 'web_server'
            elif dest_port == 22 or service == 'ssh':
                return 'ssh_server'
            elif dest_port in [3306, 5432, 1433] or service in ['mysql', 'postgresql', 'mssql']:
                return 'database'
            elif dest_port in [139, 445] or service == 'smb':
                return 'file_server'
            elif dest_port == 21 or service == 'ftp':
                return 'file_server'
            else:
                return 'unknown'
                
        except Exception:
            return 'unknown'
    
    def _enrich_events_with_attribution(self, events: List[Dict]) -> List[Dict]:
        """Enrich events with MITRE ATT&CK attribution from threat attribution service"""
        try:
            enriched_events = []
            attribution_url = os.getenv('THREAT_ATTRIBUTION_URL', 'http://localhost:5005')
            
            for event in events:
                enriched_event = event.copy()
                
                try:
                    # Prepare attribution request
                    attribution_request = {
                        'event_type': 'network_traffic',
                        'source_ip': event.get('id.orig_h'),
                        'destination_ip': event.get('id.resp_h'),
                        'source_port': event.get('id.orig_p'),
                        'destination_port': event.get('id.resp_p'),
                        'protocol': event.get('proto'),
                        'service': event.get('service'),
                        'log_type': event.get('_log_type'),
                        'user_agent': event.get('user_agent'),
                        'dns_query': event.get('query'),
                        'http_method': event.get('method'),
                        'http_uri': event.get('uri'),
                        'ssl_subject': event.get('subject'),
                        'timestamp': event.get('ts')
                    }
                    
                    # Remove None values
                    attribution_request = {k: v for k, v in attribution_request.items() if v is not None}
                    
                    # Call threat attribution service
                    response = requests.post(
                        f"{attribution_url}/analyze",
                        json=attribution_request,
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        attribution = response.json()
                        
                        # Add MITRE ATT&CK techniques
                        enriched_event['mitre_techniques'] = attribution.get('techniques', [])
                        enriched_event['threat_score'] = attribution.get('threat_score', 0.0)
                        enriched_event['confidence'] = attribution.get('confidence', 0.0)
                        enriched_event['threat_actors'] = attribution.get('threat_actors', [])
                        enriched_event['iocs'] = attribution.get('indicators', [])
                        enriched_event['attribution_metadata'] = attribution.get('metadata', {})
                        
                        logger.debug(f"Enriched event with {len(enriched_event['mitre_techniques'])} MITRE techniques")
                    else:
                        logger.warning(f"Attribution service returned {response.status_code}")
                        
                except requests.RequestException as e:
                    logger.debug(f"Could not reach threat attribution service: {e}")
                    # Continue without attribution
                except Exception as e:
                    logger.error(f"Error during attribution enrichment: {e}")
                
                enriched_events.append(enriched_event)
            
            return enriched_events
            
        except Exception as e:
            logger.error(f"Error enriching events with attribution: {e}")
            return events
    
    def _prioritize_anomalies_by_attribution(self, anomalies: List[Dict]) -> List[Dict]:
        """Prioritize anomalies based on MITRE ATT&CK attribution"""
        try:
            for anomaly in anomalies:
                entry = anomaly.get('entry', {})
                
                # Increase severity if MITRE techniques are present
                mitre_techniques = entry.get('mitre_techniques', [])
                threat_score = entry.get('threat_score', 0.0)
                
                if mitre_techniques:
                    # High-impact techniques that should increase priority
                    high_impact_techniques = [
                        'T1055',  # Process Injection
                        'T1059',  # Command and Scripting Interpreter  
                        'T1071',  # Application Layer Protocol
                        'T1090',  # Proxy
                        'T1105',  # Ingress Tool Transfer
                        'T1572',  # Protocol Tunneling
                        'T1573'   # Encrypted Channel
                    ]
                    
                    for technique in mitre_techniques:
                        technique_id = technique.get('id', '')
                        if any(high_impact in technique_id for high_impact in high_impact_techniques):
                            # Upgrade severity
                            current_severity = anomaly.get('severity', 'low')
                            if current_severity == 'low':
                                anomaly['severity'] = 'medium'
                            elif current_severity == 'medium':
                                anomaly['severity'] = 'high'
                            
                            anomaly['mitre_escalated'] = True
                            break
                
                # Add threat score to description
                if threat_score > 0.5:
                    original_desc = anomaly.get('description', '')
                    anomaly['description'] = f"{original_desc} (Threat Score: {threat_score:.2f})"
            
            # Sort by severity and threat score
            severity_order = {'high': 3, 'medium': 2, 'low': 1}
            
            anomalies.sort(key=lambda x: (
                severity_order.get(x.get('severity', 'low'), 1),
                x.get('entry', {}).get('threat_score', 0.0)
            ), reverse=True)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error prioritizing anomalies by attribution: {e}")
            return anomalies
    
    def analyze_pcap_file(self, pcap_file: str) -> Dict:
        """Analyze PCAP file - simplified version without pyshark dependency"""
        try:
            # Simplified analysis without pyshark
            analysis_results = {
                'packets': [],
                'protocols': {},
                'ips': {},
                'ports': {},
                'anomalies': [],
                'message': 'PCAP analysis requires pyshark library (currently disabled)'
            }
            
            if not os.path.exists(pcap_file):
                logger.warning(f"PCAP file not found: {pcap_file}")
                return analysis_results
            
            # Basic file info
            file_size = os.path.getsize(pcap_file)
            analysis_results['file_size'] = file_size
            analysis_results['file_path'] = pcap_file
            
            logger.info(f"PCAP file analysis requested for {pcap_file} ({file_size} bytes)")
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")
            return {
                'packets': [],
                'protocols': {},
                'ips': {},
                'ports': {},
                'anomalies': [],
                'error': str(e)
            }
    
    def _detect_pcap_anomalies(self, analysis_results: Dict) -> List[Dict]:
        """Detect anomalies in PCAP analysis results"""
        try:
            anomalies = []
            
            # Check for unusual protocol distribution
            total_packets = len(analysis_results['packets'])
            if total_packets > 0:
                for protocol, count in analysis_results['protocols'].items():
                    percentage = (count / total_packets) * 100
                    if percentage > 80:  # More than 80% of traffic is one protocol
                        anomalies.append({
                            'type': 'protocol_anomaly',
                            'protocol': protocol,
                            'percentage': percentage,
                            'severity': 'medium',
                            'description': f"Unusual protocol distribution: {protocol} ({percentage:.1f}%)"
                        })
            
            # Check for unusual port activity
            for port, count in analysis_results['ports'].items():
                if count > 1000:  # More than 1000 packets to/from one port
                    anomalies.append({
                        'type': 'port_anomaly',
                        'port': port,
                        'count': count,
                        'severity': 'high',
                        'description': f"Unusual port activity: port {port} ({count} packets)"
                    })
            
            # Check for unusual IP activity
            for ip, count in analysis_results['ips'].items():
                if count > 5000:  # More than 5000 packets to/from one IP
                    anomalies.append({
                        'type': 'ip_anomaly',
                        'ip': ip,
                        'count': count,
                        'severity': 'high',
                        'description': f"Unusual IP activity: {ip} ({count} packets)"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting PCAP anomalies: {e}")
            return []
    
    def get_capture_statistics(self) -> Dict:
        """Get statistics about current captures"""
        try:
            stats = {
                'zeek_running': False,  # Zeek not available
                'tcpdump_captures': len(self.capture_processes),
                'capture_stats': self.capture_stats.copy(),
                'active_captures': []
            }
            
            for name, info in self.capture_processes.items():
                if info['process'].poll() is None:
                    stats['active_captures'].append({
                        'name': name,
                        'interface': info['interface'],
                        'capture_file': info['capture_file'],
                        'start_time': info['start_time'].isoformat()
                    })
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting capture statistics: {e}")
            return {}
    
    def store_analysis_results(self, results: Dict):
        """Store analysis results in Redis"""
        try:
            key = f"traffic_analysis:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 3600, json.dumps(results))  # Store for 1 hour
            logger.info(f"Traffic analysis results stored in Redis with key: {key}")
        except Exception as e:
            logger.error(f"Error storing analysis results: {e}")


# Flask API for the traffic monitor
app = Flask(__name__)

# Register API Documentation
try:
    from traffic_api_docs import traffic_api_blueprint
    app.register_blueprint(traffic_api_blueprint)
except ImportError:
    pass  # API docs optional

# JWT Configuration for authentication
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
app.config['JWT_ALGORITHM'] = os.getenv('JWT_ALGORITHM', 'HS256')

# Rate limiting configuration
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"]
)
limiter.init_app(app)

def auth_required(f):
    """Decorator to require JWT authentication for traffic monitor endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            return jsonify({'error': 'Authorization header required'}), 401
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'error': 'Invalid authorization header format'}), 401
        
        token = parts[1]
        try:
            jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Input validation schemas
class ZeekStartSchema(Schema):
    interface = fields.Str(missing='eth0', validate=lambda x: len(x) > 0 and len(x) < 50)
    log_dir = fields.Str(missing='/app/zeek_logs', validate=lambda x: len(x) > 0 and len(x) < 200)

class TcpdumpStartSchema(Schema):
    interface = fields.Str(missing='eth0', validate=lambda x: len(x) > 0 and len(x) < 50)
    capture_file = fields.Str(missing='/app/captures/capture.pcap')

traffic_monitor = TrafficMonitor()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'traffic_monitor',
        'statistics': traffic_monitor.get_capture_statistics()
    })

@app.route('/start/zeek', methods=['POST'])
@limiter.limit("10 per minute")
@auth_required
def start_zeek():
    """Start Zeek monitoring"""
    try:
        data = request.get_json() or {}
        schema = ZeekStartSchema()
        try:
            validated_data = schema.load(data)
        except ValidationError as e:
            return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
        
        interface = validated_data['interface']
        log_dir = validated_data['log_dir']
        
        # Sanitize log_dir to prevent directory traversal
        log_dir = os.path.normpath(log_dir)
        if '..' in log_dir:
            return jsonify({'error': 'Invalid log directory path'}), 400
        
        success = traffic_monitor.start_zeek_monitoring(interface, log_dir)
        return jsonify({'success': success})
    except Exception as e:
        logger.error(f"Error starting Zeek: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/stop/zeek', methods=['POST'])
@limiter.limit("10 per minute")
@auth_required
def stop_zeek():
    """Stop Zeek monitoring"""
    try:
        success = traffic_monitor.stop_zeek_monitoring()
        return jsonify({'success': success})
    except Exception as e:
        logger.error(f"Error stopping Zeek: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/start/tcpdump', methods=['POST'])
@limiter.limit("10 per minute")
@auth_required
def start_tcpdump():
    """Start tcpdump capture"""
    try:
        data = request.get_json() or {}
        schema = TcpdumpStartSchema()
        try:
            validated_data = schema.load(data)
        except ValidationError as e:
            return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
        
        interface = validated_data['interface']
        capture_file = validated_data['capture_file']
        
        # Sanitize capture_file to prevent directory traversal
        capture_file = os.path.normpath(capture_file)
        if '..' in capture_file:
            return jsonify({'error': 'Invalid capture file path'}), 400
        
        success = traffic_monitor.start_tcpdump_capture(interface, capture_file)
        return jsonify({'success': success})
    except Exception as e:
        logger.error(f"Error starting tcpdump: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/stop/tcpdump', methods=['POST'])
@limiter.limit("10 per minute")
@auth_required
def stop_tcpdump():
    """Stop tcpdump capture"""
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'eth0')
        
        # Validate interface parameter
        if not interface or len(interface) > 50:
            return jsonify({'error': 'Invalid interface parameter'}), 400
        
        success = traffic_monitor.stop_tcpdump_capture(interface)
        return jsonify({'success': success})
    except Exception as e:
        logger.error(f"Error stopping tcpdump: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analyze/zeek', methods=['GET'])
@limiter.limit("30 per minute")
@auth_required
def analyze_zeek():
    """Analyze Zeek logs"""
    try:
        log_dir = request.args.get('log_dir', '/app/zeek_logs')
        
        # Validate and sanitize log_dir
        if not log_dir or len(log_dir) > 200:
            return jsonify({'error': 'Invalid log_dir parameter'}), 400
        
        log_dir = os.path.normpath(log_dir)
        if '..' in log_dir:
            return jsonify({'error': 'Invalid log directory path'}), 400
        
        results = traffic_monitor.analyze_zeek_logs(log_dir)
        traffic_monitor.store_analysis_results(results)
        
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error analyzing Zeek logs: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analyze/pcap', methods=['POST'])
@limiter.limit("10 per minute")  # More restrictive for file uploads
@auth_required
def analyze_pcap():
    """Analyze PCAP file"""
    try:
        data = request.get_json() or {}
        pcap_file = data.get('pcap_file', '/app/captures/capture.pcap')
        
        # Validate and sanitize pcap_file
        if not pcap_file or len(pcap_file) > 200:
            return jsonify({'error': 'Invalid pcap_file parameter'}), 400
        
        pcap_file = os.path.normpath(pcap_file)
        if '..' in pcap_file:
            return jsonify({'error': 'Invalid PCAP file path'}), 400
        
        results = traffic_monitor.analyze_pcap_file(pcap_file)
        traffic_monitor.store_analysis_results(results)
        
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error analyzing PCAP: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/statistics', methods=['GET'])
@limiter.limit("60 per minute")
@auth_required
def get_statistics():
    """Get capture statistics"""
    try:
        stats = traffic_monitor.get_capture_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Shutting down traffic monitor...")
    for interface in list(traffic_monitor.capture_processes.keys()):
        traffic_monitor.stop_tcpdump_capture(interface.split('_')[1])
    sys.exit(0)

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run without debug to avoid threading conflicts
    app.run(host='0.0.0.0', port=5003, debug=False)
