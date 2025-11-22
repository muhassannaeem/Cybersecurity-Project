import json
import logging
import os
import subprocess
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from flask import Flask, request, jsonify
import redis
import pandas as pd
import numpy as np
import requests
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EvaluationEngine:
    """Evaluation Engine for testing cybersecurity system with red-team tools"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.evaluation_results = {}
        self.test_scenarios = {}
        self.metrics = {
            'detection_latency': [],
            'false_positive_rate': [],
            'attacker_engagement_time': [],
            'decoy_believability': [],
            'overall_performance': []
        }
        
        # Red-team tools configuration
        self.red_team_tools = {
            'nmap': {
                'command': 'nmap',
                'description': 'Network scanning and enumeration',
                'enabled': True
            },
            'metasploit': {
                'command': 'msfconsole',
                'description': 'Penetration testing framework',
                'enabled': True
            },
            'hydra': {
                'command': 'hydra',
                'description': 'Password cracking tool',
                'enabled': True
            },
            'sqlmap': {
                'command': 'sqlmap',
                'description': 'SQL injection testing',
                'enabled': True
            }
        }
        
        # Test scenarios
        self._initialize_test_scenarios()
    
    def _initialize_test_scenarios(self):
        """Initialize predefined test scenarios"""
        self.test_scenarios = {
            'network_scanning': {
                'name': 'Network Scanning Test',
                'description': 'Test system detection of network scanning activities',
                'tools': ['nmap'],
                'expected_detection_time': 30,  # seconds
                'severity': 'medium'
            },
            'password_attack': {
                'name': 'Password Attack Test',
                'description': 'Test system detection of password cracking attempts',
                'tools': ['hydra'],
                'expected_detection_time': 60,  # seconds
                'severity': 'high'
            },
            'sql_injection': {
                'name': 'SQL Injection Test',
                'description': 'Test system detection of SQL injection attempts',
                'tools': ['sqlmap'],
                'expected_detection_time': 45,  # seconds
                'severity': 'high'
            },
            'exploit_attempt': {
                'name': 'Exploit Attempt Test',
                'description': 'Test system detection of exploit attempts',
                'tools': ['metasploit'],
                'expected_detection_time': 90,  # seconds
                'severity': 'critical'
            },
            'decoy_interaction': {
                'name': 'Decoy Interaction Test',
                'description': 'Test decoy believability and engagement',
                'tools': ['nmap', 'hydra'],
                'expected_detection_time': 15,  # seconds
                'severity': 'low'
            }
        }
    
    def run_evaluation_test(self, scenario_name: str, target_host: str = "localhost") -> Dict:
        """Run a specific evaluation test scenario"""
        try:
            if scenario_name not in self.test_scenarios:
                return {'error': f'Unknown test scenario: {scenario_name}'}
            
            scenario = self.test_scenarios[scenario_name]
            logger.info(f"Starting evaluation test: {scenario['name']}")
            
            # Initialize test results
            test_result = {
                'scenario': scenario_name,
                'start_time': datetime.now().isoformat(),
                'target_host': target_host,
                'detection_time': None,
                'detected': False,
                'false_positive': False,
                'attacker_engagement': None,
                'decoy_believability': None,
                'overall_score': 0,
                'details': {}
            }
            
            # Start monitoring for detections
            detection_thread = threading.Thread(
                target=self._monitor_detections,
                args=(scenario_name, test_result)
            )
            detection_thread.start()
            
            # Run the attack scenario
            attack_result = self._run_attack_scenario(scenario, target_host)
            test_result['details']['attack'] = attack_result
            
            # Wait for detection or timeout
            detection_thread.join(timeout=scenario['expected_detection_time'] * 2)
            
            # Calculate metrics
            self._calculate_test_metrics(test_result, scenario)
            
            # Store results
            self._store_evaluation_result(test_result)
            
            logger.info(f"Completed evaluation test: {scenario['name']}")
            return test_result
            
        except Exception as e:
            logger.error(f"Error running evaluation test: {e}")
            return {'error': str(e)}
    
    def _run_attack_scenario(self, scenario: Dict, target_host: str) -> Dict:
        """Run the actual attack scenario using red-team tools"""
        try:
            attack_result = {
                'tools_used': [],
                'commands_executed': [],
                'success': False,
                'output': {}
            }
            
            for tool_name in scenario['tools']:
                if tool_name in self.red_team_tools and self.red_team_tools[tool_name]['enabled']:
                    tool_result = self._execute_red_team_tool(tool_name, target_host)
                    attack_result['tools_used'].append(tool_name)
                    attack_result['commands_executed'].extend(tool_result.get('commands', []))
                    attack_result['output'][tool_name] = tool_result.get('output', '')
                    
                    if tool_result.get('success', False):
                        attack_result['success'] = True
            
            return attack_result
            
        except Exception as e:
            logger.error(f"Error running attack scenario: {e}")
            return {'error': str(e)}
    
    def _execute_red_team_tool(self, tool_name: str, target_host: str) -> Dict:
        """Execute a specific red-team tool"""
        try:
            result = {
                'success': False,
                'commands': [],
                'output': '',
                'error': None
            }
            
            if tool_name == 'nmap':
                result = self._execute_nmap(target_host)
            elif tool_name == 'hydra':
                result = self._execute_hydra(target_host)
            elif tool_name == 'sqlmap':
                result = self._execute_sqlmap(target_host)
            elif tool_name == 'metasploit':
                result = self._execute_metasploit(target_host)
            else:
                result['error'] = f'Unknown tool: {tool_name}'
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _execute_nmap(self, target_host: str) -> Dict:
        """Execute Nmap network scanning"""
        try:
            commands = [
                f"nmap -sS -sV -O {target_host}",
                f"nmap -p 80,443,22,21,23,25,53 {target_host}",
                f"nmap --script=vuln {target_host}"
            ]
            
            output = []
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd.split(),
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    output.append(f"Command: {cmd}")
                    output.append(f"Output: {result.stdout}")
                    if result.stderr:
                        output.append(f"Error: {result.stderr}")
                except subprocess.TimeoutExpired:
                    output.append(f"Command timed out: {cmd}")
                except Exception as e:
                    output.append(f"Command failed: {cmd} - {e}")
            
            return {
                'success': True,
                'commands': commands,
                'output': '\n'.join(output)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_hydra(self, target_host: str) -> Dict:
        """Execute Hydra password cracking"""
        try:
            commands = [
                f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target_host} ssh",
                f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target_host} ftp"
            ]
            
            output = []
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd.split(),
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    output.append(f"Command: {cmd}")
                    output.append(f"Output: {result.stdout}")
                    if result.stderr:
                        output.append(f"Error: {result.stderr}")
                except subprocess.TimeoutExpired:
                    output.append(f"Command timed out: {cmd}")
                except Exception as e:
                    output.append(f"Command failed: {cmd} - {e}")
            
            return {
                'success': True,
                'commands': commands,
                'output': '\n'.join(output)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_sqlmap(self, target_host: str) -> Dict:
        """Execute SQLMap SQL injection testing"""
        try:
            commands = [
                f"sqlmap -u http://{target_host}/login.php --forms --batch",
                f"sqlmap -u http://{target_host}/search.php?id=1 --batch --dbs"
            ]
            
            output = []
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd.split(),
                        capture_output=True,
                        text=True,
                        timeout=180
                    )
                    output.append(f"Command: {cmd}")
                    output.append(f"Output: {result.stdout}")
                    if result.stderr:
                        output.append(f"Error: {result.stderr}")
                except subprocess.TimeoutExpired:
                    output.append(f"Command timed out: {cmd}")
                except Exception as e:
                    output.append(f"Command failed: {cmd} - {e}")
            
            return {
                'success': True,
                'commands': commands,
                'output': '\n'.join(output)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_metasploit(self, target_host: str) -> Dict:
        """Execute Metasploit exploit attempts"""
        try:
            # Create a simple Metasploit script
            msf_script = f"""
use auxiliary/scanner/portscan/tcp
set RHOSTS {target_host}
run
use auxiliary/scanner/ssh/ssh_version
set RHOSTS {target_host}
run
use auxiliary/scanner/http/http_version
set RHOSTS {target_host}
run
exit
"""
            
            # Write script to temporary file
            script_file = f"/tmp/msf_script_{int(time.time())}.rc"
            with open(script_file, 'w') as f:
                f.write(msf_script)
            
            try:
                result = subprocess.run(
                    ['msfconsole', '-r', script_file],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                output = f"Metasploit script executed:\n{msf_script}\nOutput:\n{result.stdout}"
                if result.stderr:
                    output += f"\nError:\n{result.stderr}"
                
                # Clean up
                os.remove(script_file)
                
                return {
                    'success': True,
                    'commands': [f"msfconsole -r {script_file}"],
                    'output': output
                }
                
            except subprocess.TimeoutExpired:
                os.remove(script_file)
                return {
                    'success': False,
                    'commands': [f"msfconsole -r {script_file}"],
                    'output': "Metasploit execution timed out"
                }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _monitor_detections(self, scenario_name: str, test_result: Dict):
        """Monitor for detections during the test"""
        try:
            start_time = datetime.now()
            detection_found = False
            
            # Monitor for detections for the expected detection time
            scenario = self.test_scenarios[scenario_name]
            timeout = scenario['expected_detection_time']
            
            while (datetime.now() - start_time).total_seconds() < timeout and not detection_found:
                # Check for new alerts/threats in the system
                alerts = self._check_for_alerts()
                
                if alerts:
                    # Check if any alert is related to our test
                    for alert in alerts:
                        if self._is_alert_related_to_test(alert, scenario_name):
                            test_result['detected'] = True
                            test_result['detection_time'] = (datetime.now() - start_time).total_seconds()
                            detection_found = True
                            break
                
                time.sleep(1)  # Check every second
            
            if not detection_found:
                test_result['detected'] = False
                test_result['detection_time'] = timeout
            
        except Exception as e:
            logger.error(f"Error monitoring detections: {e}")
    
    def _check_for_alerts(self) -> List[Dict]:
        """Check for new alerts in the system"""
        try:
            # Query the backend API for recent alerts
            response = requests.get('http://backend:5000/api/threats', timeout=5)
            if response.status_code == 200:
                threats = response.json()
                # Filter for recent threats (last 5 minutes)
                recent_threats = [
                    threat for threat in threats
                    if (datetime.now() - datetime.fromisoformat(threat['timestamp'])).total_seconds() < 300
                ]
                return recent_threats
            return []
        except:
            return []
    
    def _is_alert_related_to_test(self, alert: Dict, scenario_name: str) -> bool:
        """Check if an alert is related to the current test scenario"""
        try:
            # Simple keyword matching based on scenario
            scenario_keywords = {
                'network_scanning': ['scan', 'nmap', 'port', 'enumeration'],
                'password_attack': ['password', 'hydra', 'brute', 'crack'],
                'sql_injection': ['sql', 'injection', 'database', 'query'],
                'exploit_attempt': ['exploit', 'vulnerability', 'metasploit'],
                'decoy_interaction': ['decoy', 'honeypot', 'honeytoken']
            }
            
            keywords = scenario_keywords.get(scenario_name, [])
            alert_text = f"{alert.get('threatType', '')} {alert.get('description', '')}".lower()
            
            return any(keyword in alert_text for keyword in keywords)
            
        except Exception as e:
            logger.error(f"Error checking alert relation: {e}")
            return False
    
    def _calculate_test_metrics(self, test_result: Dict, scenario: Dict):
        """Calculate performance metrics for the test"""
        try:
            # Detection latency
            detection_time = test_result.get('detection_time', scenario['expected_detection_time'])
            latency_score = max(0, 1 - (detection_time / scenario['expected_detection_time']))
            
            # False positive rate (simplified - would need more sophisticated analysis)
            false_positive_rate = 0.1 if test_result.get('false_positive', False) else 0.0
            
            # Attacker engagement time (simplified)
            engagement_time = min(300, detection_time)  # Cap at 5 minutes
            engagement_score = engagement_time / 300
            
            # Decoy believability (simplified)
            decoy_believability = 0.8 if test_result.get('detected', False) else 0.3
            
            # Overall performance score
            overall_score = (
                latency_score * 0.3 +
                (1 - false_positive_rate) * 0.2 +
                engagement_score * 0.2 +
                decoy_believability * 0.3
            )
            
            # Store metrics
            test_result['metrics'] = {
                'detection_latency': detection_time,
                'latency_score': latency_score,
                'false_positive_rate': false_positive_rate,
                'attacker_engagement_time': engagement_time,
                'engagement_score': engagement_score,
                'decoy_believability': decoy_believability,
                'overall_score': overall_score
            }
            
            # Update global metrics
            self.metrics['detection_latency'].append(detection_time)
            self.metrics['false_positive_rate'].append(false_positive_rate)
            self.metrics['attacker_engagement_time'].append(engagement_time)
            self.metrics['decoy_believability'].append(decoy_believability)
            self.metrics['overall_performance'].append(overall_score)
            
        except Exception as e:
            logger.error(f"Error calculating metrics: {e}")
    
    def _store_evaluation_result(self, test_result: Dict):
        """Store evaluation result in Redis"""
        try:
            key = f"evaluation_result:{test_result['scenario']}:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 86400, json.dumps(test_result))  # Store for 24 hours
            
            # Store in local results
            if test_result['scenario'] not in self.evaluation_results:
                self.evaluation_results[test_result['scenario']] = []
            self.evaluation_results[test_result['scenario']].append(test_result)
            
        except Exception as e:
            logger.error(f"Error storing evaluation result: {e}")
    
    def run_full_evaluation_suite(self, target_host: str = "localhost") -> Dict:
        """Run the complete evaluation suite"""
        try:
            logger.info("Starting full evaluation suite")
            
            suite_results = {
                'start_time': datetime.now().isoformat(),
                'target_host': target_host,
                'scenarios': {},
                'overall_score': 0,
                'summary': {}
            }
            
            # Run each test scenario
            for scenario_name in self.test_scenarios.keys():
                logger.info(f"Running scenario: {scenario_name}")
                result = self.run_evaluation_test(scenario_name, target_host)
                suite_results['scenarios'][scenario_name] = result
                
                # Wait between tests
                time.sleep(30)
            
            # Calculate overall suite metrics
            self._calculate_suite_metrics(suite_results)
            
            # Store suite results
            self._store_suite_results(suite_results)
            
            logger.info("Completed full evaluation suite")
            return suite_results
            
        except Exception as e:
            logger.error(f"Error running evaluation suite: {e}")
            return {'error': str(e)}
    
    def _calculate_suite_metrics(self, suite_results: Dict):
        """Calculate overall metrics for the evaluation suite"""
        try:
            scores = []
            detection_times = []
            false_positives = 0
            total_tests = 0
            
            for scenario_name, result in suite_results['scenarios'].items():
                if 'metrics' in result:
                    metrics = result['metrics']
                    scores.append(metrics['overall_score'])
                    detection_times.append(metrics['detection_latency'])
                    if metrics['false_positive_rate'] > 0:
                        false_positives += 1
                    total_tests += 1
            
            if scores:
                suite_results['overall_score'] = np.mean(scores)
                suite_results['summary'] = {
                    'average_detection_time': np.mean(detection_times),
                    'false_positive_rate': false_positives / total_tests if total_tests > 0 else 0,
                    'total_tests': total_tests,
                    'successful_detections': sum(1 for r in suite_results['scenarios'].values() if r.get('detected', False))
                }
            
        except Exception as e:
            logger.error(f"Error calculating suite metrics: {e}")
    
    def _store_suite_results(self, suite_results: Dict):
        """Store suite results in Redis"""
        try:
            key = f"evaluation_suite:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 86400, json.dumps(suite_results))  # Store for 24 hours
        except Exception as e:
            logger.error(f"Error storing suite results: {e}")
    
    def get_evaluation_statistics(self) -> Dict:
        """Get evaluation statistics"""
        try:
            stats = {
                'total_tests_run': 0,
                'average_detection_time': 0,
                'average_false_positive_rate': 0,
                'average_overall_score': 0,
                'scenario_performance': {}
            }
            
            # Calculate statistics from stored metrics
            if self.metrics['detection_latency']:
                stats['total_tests_run'] = len(self.metrics['detection_latency'])
                stats['average_detection_time'] = np.mean(self.metrics['detection_latency'])
                stats['average_false_positive_rate'] = np.mean(self.metrics['false_positive_rate'])
                stats['average_overall_score'] = np.mean(self.metrics['overall_performance'])
            
            # Calculate per-scenario performance
            for scenario_name, results in self.evaluation_results.items():
                if results:
                    scenario_scores = [r.get('metrics', {}).get('overall_score', 0) for r in results]
                    stats['scenario_performance'][scenario_name] = {
                        'average_score': np.mean(scenario_scores),
                        'tests_run': len(results),
                        'success_rate': sum(1 for r in results if r.get('detected', False)) / len(results)
                    }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting evaluation statistics: {e}")
            return {}

# Flask API for the evaluation engine
app = Flask(__name__)
evaluation_engine = EvaluationEngine()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'evaluation_engine',
        'available_scenarios': list(evaluation_engine.test_scenarios.keys())
    })

@app.route('/test/<scenario_name>', methods=['POST'])
def run_test(scenario_name):
    """Run a specific evaluation test"""
    try:
        data = request.get_json() or {}
        target_host = data.get('target_host', 'localhost')
        
        result = evaluation_engine.run_evaluation_test(scenario_name, target_host)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/suite', methods=['POST'])
def run_suite():
    """Run the complete evaluation suite"""
    try:
        data = request.get_json() or {}
        target_host = data.get('target_host', 'localhost')
        
        result = evaluation_engine.run_full_evaluation_suite(target_host)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scenarios', methods=['GET'])
def get_scenarios():
    """Get available test scenarios"""
    try:
        return jsonify(evaluation_engine.test_scenarios)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get evaluation statistics"""
    try:
        stats = evaluation_engine.get_evaluation_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/tools', methods=['GET'])
def get_tools():
    """Get available red-team tools"""
    try:
        return jsonify(evaluation_engine.red_team_tools)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True)
