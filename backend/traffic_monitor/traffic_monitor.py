import subprocess
import threading
import time
import json
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
import redis
import requests
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
import pyshark

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        
        # Traffic analysis thresholds
        self.thresholds = {
            'packet_rate': 1000,  # packets per second
            'connection_rate': 100,  # connections per minute
            'data_volume': 1000000,  # bytes per minute
            'suspicious_ports': [22, 23, 3389, 445, 1433, 3306]
        }
    
    def start_zeek_monitoring(self, interface: str = "eth0", log_dir: str = "/app/zeek_logs"):
        """Start Zeek network monitoring (placeholder - Zeek not available)"""
        logger.warning("Zeek monitoring not available - using tcpdump instead")
        return self.start_tcpdump_capture(interface, f"{log_dir}/capture.pcap")
    
    def stop_zeek_monitoring(self):
        """Stop Zeek network monitoring (placeholder)"""
        logger.warning("Zeek monitoring not available")
        return True
    
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
        """Analyze Zeek log files for network activity"""
        try:
            analysis_results = {
                'connections': [],
                'http_requests': [],
                'dns_queries': [],
                'ssl_certificates': [],
                'anomalies': []
            }
            
            # Read connection log
            conn_log = os.path.join(log_dir, "conn.log")
            if os.path.exists(conn_log):
                connections = self._parse_zeek_log(conn_log)
                analysis_results['connections'] = connections
                
                # Detect anomalies in connections
                anomalies = self._detect_connection_anomalies(connections)
                analysis_results['anomalies'].extend(anomalies)
            
            # Read HTTP log
            http_log = os.path.join(log_dir, "http.log")
            if os.path.exists(http_log):
                http_requests = self._parse_zeek_log(http_log)
                analysis_results['http_requests'] = http_requests
            
            # Read DNS log
            dns_log = os.path.join(log_dir, "dns.log")
            if os.path.exists(dns_log):
                dns_queries = self._parse_zeek_log(dns_log)
                analysis_results['dns_queries'] = dns_queries
            
            # Read SSL log
            ssl_log = os.path.join(log_dir, "ssl.log")
            if os.path.exists(ssl_log):
                ssl_certs = self._parse_zeek_log(ssl_log)
                analysis_results['ssl_certificates'] = ssl_certs
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing Zeek logs: {e}")
            return {}
    
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
    
    def analyze_pcap_file(self, pcap_file: str) -> Dict:
        """Analyze PCAP file using pyshark"""
        try:
            analysis_results = {
                'packets': [],
                'protocols': {},
                'ips': {},
                'ports': {},
                'anomalies': []
            }
            
            if not os.path.exists(pcap_file):
                logger.warning(f"PCAP file not found: {pcap_file}")
                return analysis_results
            
            # Use pyshark to analyze PCAP
            cap = pyshark.FileCapture(pcap_file)
            
            for packet in cap:
                try:
                    packet_info = {
                        'timestamp': packet.sniff_timestamp,
                        'length': packet.length,
                        'protocol': packet.highest_layer
                    }
                    
                    # Extract IP information
                    if hasattr(packet, 'ip'):
                        packet_info['src_ip'] = packet.ip.src
                        packet_info['dst_ip'] = packet.ip.dst
                        
                        # Count IP addresses
                        analysis_results['ips'][packet.ip.src] = analysis_results['ips'].get(packet.ip.src, 0) + 1
                        analysis_results['ips'][packet.ip.dst] = analysis_results['ips'].get(packet.ip.dst, 0) + 1
                    
                    # Extract port information
                    if hasattr(packet, 'tcp'):
                        packet_info['src_port'] = packet.tcp.srcport
                        packet_info['dst_port'] = packet.tcp.dstport
                        
                        # Count ports
                        analysis_results['ports'][packet.tcp.srcport] = analysis_results['ports'].get(packet.tcp.srcport, 0) + 1
                        analysis_results['ports'][packet.tcp.dstport] = analysis_results['ports'].get(packet.tcp.dstport, 0) + 1
                    
                    elif hasattr(packet, 'udp'):
                        packet_info['src_port'] = packet.udp.srcport
                        packet_info['dst_port'] = packet.udp.dstport
                        
                        # Count ports
                        analysis_results['ports'][packet.udp.srcport] = analysis_results['ports'].get(packet.udp.srcport, 0) + 1
                        analysis_results['ports'][packet.udp.dstport] = analysis_results['ports'].get(packet.udp.dstport, 0) + 1
                    
                    # Count protocols
                    protocol = packet.highest_layer
                    analysis_results['protocols'][protocol] = analysis_results['protocols'].get(protocol, 0) + 1
                    
                    analysis_results['packets'].append(packet_info)
                    
                except Exception as e:
                    logger.warning(f"Error processing packet: {e}")
                    continue
            
            cap.close()
            
            # Detect anomalies
            anomalies = self._detect_pcap_anomalies(analysis_results)
            analysis_results['anomalies'] = anomalies
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")
            return {}
    
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
def start_zeek():
    """Start Zeek monitoring"""
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'eth0')
        log_dir = data.get('log_dir', '/app/zeek_logs')
        
        success = traffic_monitor.start_zeek_monitoring(interface, log_dir)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stop/zeek', methods=['POST'])
def stop_zeek():
    """Stop Zeek monitoring"""
    try:
        success = traffic_monitor.stop_zeek_monitoring()
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/start/tcpdump', methods=['POST'])
def start_tcpdump():
    """Start tcpdump capture"""
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'eth0')
        capture_file = data.get('capture_file', f'/app/captures/capture_{interface}.pcap')
        
        success = traffic_monitor.start_tcpdump_capture(interface, capture_file)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stop/tcpdump', methods=['POST'])
def stop_tcpdump():
    """Stop tcpdump capture"""
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'eth0')
        
        success = traffic_monitor.stop_tcpdump_capture(interface)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze/zeek', methods=['GET'])
def analyze_zeek():
    """Analyze Zeek logs"""
    try:
        data = request.get_json() or {}
        log_dir = data.get('log_dir', '/app/zeek_logs')
        
        results = traffic_monitor.analyze_zeek_logs(log_dir)
        traffic_monitor.store_analysis_results(results)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze/pcap', methods=['POST'])
def analyze_pcap():
    """Analyze PCAP file"""
    try:
        data = request.get_json() or {}
        pcap_file = data.get('pcap_file', '/app/captures/capture.pcap')
        
        results = traffic_monitor.analyze_pcap_file(pcap_file)
        traffic_monitor.store_analysis_results(results)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get capture statistics"""
    try:
        stats = traffic_monitor.get_capture_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    
    app.run(host='0.0.0.0', port=5003, debug=True)
