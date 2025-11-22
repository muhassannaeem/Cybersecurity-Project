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
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from stix2 import AttackPattern, ThreatActor, Campaign, Malware, Tool
# from taxii2client import Server, Collection  # Temporarily disabled

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatAttributionModule:
    """Threat Attribution Module with MITRE ATT&CK mapping and adversary profiling"""
    
    def __init__(self, redis_url: str = "redis://redis:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.mitre_attack_data = {}
        self.threat_actors = {}
        self.campaigns = {}
        self.attack_patterns = {}
        
        # MITRE ATT&CK API endpoints
        self.mitre_api_base = "https://attack.mitre.org/api/"
        self.attack_enterprise_url = "https://attack.mitre.org/enterprise/attack/"
        
        # Load MITRE ATT&CK data
        self._load_mitre_attack_data()
        
        # TAXII functionality temporarily disabled
        logger.warning("TAXII functionality is temporarily disabled due to package issues")
    
    def _load_mitre_attack_data(self):
        """Load MITRE ATT&CK data from API"""
        try:
            # Load attack patterns (techniques)
            attack_patterns_url = f"{self.mitre_api_base}techniques/enterprise/"
            response = requests.get(attack_patterns_url)
            if response.status_code == 200:
                self.attack_patterns = response.json()
                logger.info(f"Loaded {len(self.attack_patterns)} attack patterns")
            
            # Load threat actors
            actors_url = f"{self.mitre_api_base}groups/"
            response = requests.get(actors_url)
            if response.status_code == 200:
                self.threat_actors = response.json()
                logger.info(f"Loaded {len(self.threat_actors)} threat actors")
            
            # Load campaigns
            campaigns_url = f"{self.mitre_api_base}campaigns/"
            response = requests.get(campaigns_url)
            if response.status_code == 200:
                self.campaigns = response.json()
                logger.info(f"Loaded {len(self.campaigns)} campaigns")
            
            # Load malware
            malware_url = f"{self.mitre_api_base}software/"
            response = requests.get(malware_url)
            if response.status_code == 200:
                self.malware = response.json()
                logger.info(f"Loaded {len(self.malware)} malware families")
            
            # Load tools
            tools_url = f"{self.mitre_api_base}tools/"
            response = requests.get(tools_url)
            if response.status_code == 200:
                self.tools = response.json()
                logger.info(f"Loaded {len(self.tools)} tools")
                
        except Exception as e:
            logger.error(f"Error loading MITRE ATT&CK data: {e}")
            # Load fallback data from local files
            self._load_fallback_data()
    
    def _load_fallback_data(self):
        """Load fallback MITRE ATT&CK data from local files"""
        try:
            # Create fallback data structure
            self.attack_patterns = {
                "T1001": {
                    "id": "T1001",
                    "name": "Data Obfuscation",
                    "description": "Adversaries may obfuscate data to make it more difficult to detect.",
                    "tactic": "Defense Evasion"
                },
                "T1003": {
                    "id": "T1003",
                    "name": "OS Credential Dumping",
                    "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
                    "tactic": "Credential Access"
                },
                "T1005": {
                    "id": "T1005",
                    "name": "Data from Local System",
                    "description": "Adversaries may search local system sources to find files of interest.",
                    "tactic": "Collection"
                },
                "T1007": {
                    "id": "T1007",
                    "name": "System Service Discovery",
                    "description": "Adversaries may try to get information about registered services.",
                    "tactic": "Discovery"
                },
                "T1008": {
                    "id": "T1008",
                    "name": "Fallback Channels",
                    "description": "Adversaries may use fallback or alternate communication channels if the primary channel is compromised.",
                    "tactic": "Command and Control"
                }
            }
            
            self.threat_actors = {
                "APT1": {
                    "id": "APT1",
                    "name": "APT1",
                    "description": "APT1 is a Chinese cyber espionage group.",
                    "aliases": ["Comment Crew", "Comment Panda"]
                },
                "APT28": {
                    "id": "APT28",
                    "name": "APT28",
                    "description": "APT28 is a Russian cyber espionage group.",
                    "aliases": ["Fancy Bear", "Sofacy"]
                },
                "APT29": {
                    "id": "APT29",
                    "name": "APT29",
                    "description": "APT29 is a Russian cyber espionage group.",
                    "aliases": ["Cozy Bear", "CozyDuke"]
                }
            }
            
            logger.info("Loaded fallback MITRE ATT&CK data")
            
        except Exception as e:
            logger.error(f"Error loading fallback data: {e}")
    
    def map_attack_pattern(self, indicators: List[Dict]) -> Dict:
        """Map security indicators to MITRE ATT&CK patterns"""
        try:
            mapped_patterns = {
                'techniques': [],
                'tactics': {},
                'threat_actors': [],
                'confidence_scores': {}
            }
            
            for indicator in indicators:
                # Extract features from indicator
                features = self._extract_indicator_features(indicator)
                
                # Find matching attack patterns
                matches = self._find_pattern_matches(features)
                
                for match in matches:
                    technique_id = match['technique_id']
                    confidence = match['confidence']
                    
                    # Add technique
                    if technique_id not in [t['id'] for t in mapped_patterns['techniques']]:
                        mapped_patterns['techniques'].append({
                            'id': technique_id,
                            'name': match['technique_name'],
                            'tactic': match['tactic'],
                            'confidence': confidence,
                            'indicators': [indicator]
                        })
                        
                        # Count tactics
                        tactic = match['tactic']
                        mapped_patterns['tactics'][tactic] = mapped_patterns['tactics'].get(tactic, 0) + 1
                        
                        # Store confidence score
                        mapped_patterns['confidence_scores'][technique_id] = confidence
            
            # Find potential threat actors based on techniques
            threat_actors = self._identify_threat_actors(mapped_patterns['techniques'])
            mapped_patterns['threat_actors'] = threat_actors
            
            return mapped_patterns
            
        except Exception as e:
            logger.error(f"Error mapping attack patterns: {e}")
            return {}
    
    def _extract_indicator_features(self, indicator: Dict) -> Dict:
        """Extract features from security indicator"""
        features = {
            'type': indicator.get('type', ''),
            'value': indicator.get('value', ''),
            'tags': indicator.get('tags', []),
            'description': indicator.get('description', ''),
            'severity': indicator.get('severity', 'medium')
        }
        
        # Extract additional features based on indicator type
        if features['type'] == 'ip':
            features['is_private'] = self._is_private_ip(features['value'])
            features['geolocation'] = self._get_ip_geolocation(features['value'])
        elif features['type'] == 'domain':
            features['tld'] = features['value'].split('.')[-1] if '.' in features['value'] else ''
        elif features['type'] == 'url':
            features['protocol'] = features['value'].split('://')[0] if '://' in features['value'] else ''
            features['path'] = features['value'].split('/')[3:] if '/' in features['value'] else []
        
        return features
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            return (
                first_octet == 10 or
                (first_octet == 172 and 16 <= second_octet <= 31) or
                (first_octet == 192 and second_octet == 168)
            )
        except:
            return False
    
    def _get_ip_geolocation(self, ip: str) -> Dict:
        """Get IP geolocation information"""
        try:
            # This would typically call a geolocation service
            # For now, return mock data
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0
            }
        except:
            return {'country': 'Unknown', 'city': 'Unknown', 'latitude': 0, 'longitude': 0}
    
    def _find_pattern_matches(self, features: Dict) -> List[Dict]:
        """Find MITRE ATT&CK patterns that match the indicator features"""
        matches = []
        
        # Simple keyword-based matching
        keywords = features['description'].lower() + ' ' + ' '.join(features['tags']).lower()
        
        for technique_id, technique in self.attack_patterns.items():
            score = 0
            
            # Check technique name
            if technique['name'].lower() in keywords:
                score += 0.3
            
            # Check technique description
            if technique['description'].lower() in keywords:
                score += 0.4
            
            # Check for specific patterns
            if features['type'] == 'ip' and 'command and control' in technique['description'].lower():
                score += 0.2
            
            if features['type'] == 'domain' and 'phishing' in technique['description'].lower():
                score += 0.2
            
            if score > 0.1:  # Minimum threshold
                matches.append({
                    'technique_id': technique_id,
                    'technique_name': technique['name'],
                    'tactic': technique.get('tactic', 'Unknown'),
                    'confidence': min(score, 1.0)
                })
        
        # Sort by confidence
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return matches[:5]  # Return top 5 matches
    
    def _identify_threat_actors(self, techniques: List[Dict]) -> List[Dict]:
        """Identify potential threat actors based on techniques used"""
        try:
            actor_scores = {}
            
            for technique in techniques:
                technique_id = technique['id']
                
                # Check which threat actors use this technique
                for actor_id, actor in self.threat_actors.items():
                    if actor_id not in actor_scores:
                        actor_scores[actor_id] = {
                            'actor': actor,
                            'score': 0,
                            'techniques': []
                        }
                    
                    # Simple scoring based on technique usage
                    # In a real implementation, this would use actual technique-actor mappings
                    if technique['confidence'] > 0.5:
                        actor_scores[actor_id]['score'] += technique['confidence'] * 0.1
                        actor_scores[actor_id]['techniques'].append(technique_id)
            
            # Filter actors with significant scores
            significant_actors = [
                {
                    'id': actor_id,
                    'name': data['actor']['name'],
                    'description': data['actor']['description'],
                    'confidence': min(data['score'], 1.0),
                    'techniques': data['techniques']
                }
                for actor_id, data in actor_scores.items()
                if data['score'] > 0.1
            ]
            
            # Sort by confidence
            significant_actors.sort(key=lambda x: x['confidence'], reverse=True)
            return significant_actors
            
        except Exception as e:
            logger.error(f"Error identifying threat actors: {e}")
            return []
    
    def cluster_indicators(self, indicators: List[Dict]) -> List[Dict]:
        """Cluster indicators to identify potential campaigns"""
        try:
            if len(indicators) < 2:
                return []
            
            # Extract features for clustering
            features = []
            for indicator in indicators:
                feature_vector = self._create_feature_vector(indicator)
                features.append(feature_vector)
            
            # Convert to numpy array
            X = np.array(features)
            
            # Perform clustering
            clustering = DBSCAN(eps=0.5, min_samples=2)
            cluster_labels = clustering.fit_predict(X)
            
            # Group indicators by cluster
            clusters = {}
            for i, label in enumerate(cluster_labels):
                if label not in clusters:
                    clusters[label] = []
                clusters[label].append(indicators[i])
            
            # Convert to result format
            campaign_clusters = []
            for label, cluster_indicators in clusters.items():
                if label == -1:  # Noise points
                    continue
                
                # Analyze cluster characteristics
                cluster_analysis = self._analyze_cluster(cluster_indicators)
                
                campaign_clusters.append({
                    'cluster_id': f"campaign_{label}",
                    'indicators': cluster_indicators,
                    'analysis': cluster_analysis,
                    'size': len(cluster_indicators)
                })
            
            return campaign_clusters
            
        except Exception as e:
            logger.error(f"Error clustering indicators: {e}")
            return []
    
    def _create_feature_vector(self, indicator: Dict) -> List[float]:
        """Create feature vector for clustering"""
        features = []
        
        # Type encoding
        type_encoding = {'ip': 0, 'domain': 1, 'url': 2, 'hash': 3, 'email': 4}
        features.append(type_encoding.get(indicator.get('type', ''), 5))
        
        # Severity encoding
        severity_encoding = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        features.append(severity_encoding.get(indicator.get('severity', 'medium'), 1))
        
        # Tag count
        features.append(len(indicator.get('tags', [])))
        
        # Description length
        features.append(len(indicator.get('description', '')))
        
        # Timestamp (normalized)
        timestamp = indicator.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        features.append(timestamp.timestamp() / 1000000)  # Normalize timestamp
        
        return features
    
    def _analyze_cluster(self, indicators: List[Dict]) -> Dict:
        """Analyze characteristics of a cluster"""
        try:
            analysis = {
                'types': {},
                'severities': {},
                'common_tags': {},
                'time_range': {},
                'attack_patterns': []
            }
            
            # Count types
            for indicator in indicators:
                indicator_type = indicator.get('type', 'unknown')
                analysis['types'][indicator_type] = analysis['types'].get(indicator_type, 0) + 1
            
            # Count severities
            for indicator in indicators:
                severity = indicator.get('severity', 'medium')
                analysis['severities'][severity] = analysis['severities'].get(severity, 0) + 1
            
            # Count tags
            for indicator in indicators:
                for tag in indicator.get('tags', []):
                    analysis['common_tags'][tag] = analysis['common_tags'].get(tag, 0) + 1
            
            # Time range
            timestamps = []
            for indicator in indicators:
                timestamp = indicator.get('timestamp', datetime.now())
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                timestamps.append(timestamp)
            
            if timestamps:
                analysis['time_range'] = {
                    'start': min(timestamps).isoformat(),
                    'end': max(timestamps).isoformat(),
                    'duration_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600
                }
            
            # Map attack patterns
            attack_patterns = self.map_attack_pattern(indicators)
            analysis['attack_patterns'] = attack_patterns.get('techniques', [])
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing cluster: {e}")
            return {}
    
    def generate_attribution_report(self, indicators: List[Dict]) -> Dict:
        """Generate comprehensive attribution report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': {},
                'attack_patterns': {},
                'threat_actors': [],
                'campaigns': [],
                'recommendations': []
            }
            
            # Map attack patterns
            attack_mapping = self.map_attack_pattern(indicators)
            report['attack_patterns'] = attack_mapping
            
            # Cluster indicators
            clusters = self.cluster_indicators(indicators)
            report['campaigns'] = clusters
            
            # Generate summary
            report['summary'] = {
                'total_indicators': len(indicators),
                'unique_techniques': len(attack_mapping.get('techniques', [])),
                'campaigns_identified': len(clusters),
                'threat_actors_identified': len(attack_mapping.get('threat_actors', [])),
                'highest_confidence': max([t.get('confidence', 0) for t in attack_mapping.get('techniques', [])], default=0)
            }
            
            # Generate recommendations
            report['recommendations'] = self._generate_recommendations(attack_mapping, clusters)
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating attribution report: {e}")
            return {}
    
    def _generate_recommendations(self, attack_mapping: Dict, clusters: List[Dict]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Check for high-confidence techniques
        high_confidence_techniques = [
            t for t in attack_mapping.get('techniques', [])
            if t.get('confidence', 0) > 0.7
        ]
        
        if high_confidence_techniques:
            recommendations.append(
                f"High-confidence attack techniques detected: {', '.join([t['id'] for t in high_confidence_techniques])}"
            )
        
        # Check for multiple campaigns
        if len(clusters) > 1:
            recommendations.append(
                f"Multiple potential campaigns identified ({len(clusters)}). Consider separate response strategies."
            )
        
        # Check for threat actors
        if attack_mapping.get('threat_actors'):
            actor_names = [a['name'] for a in attack_mapping['threat_actors']]
            recommendations.append(
                f"Potential threat actors identified: {', '.join(actor_names)}. Review their TTPs."
            )
        
        # General recommendations
        recommendations.extend([
            "Implement additional monitoring for identified attack techniques",
            "Review and update detection rules based on observed patterns",
            "Consider threat intelligence sharing for identified indicators"
        ])
        
        return recommendations
    
    def store_attribution_data(self, report: Dict):
        """Store attribution report in Redis"""
        try:
            key = f"attribution_report:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, 7200, json.dumps(report))  # Store for 2 hours
            logger.info(f"Attribution report stored in Redis with key: {key}")
        except Exception as e:
            logger.error(f"Error storing attribution data: {e}")

# Flask API for the threat attribution module
app = Flask(__name__)
attribution_module = ThreatAttributionModule()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'threat_attribution',
        'mitre_data_loaded': len(attribution_module.attack_patterns) > 0
    })

@app.route('/map_patterns', methods=['POST'])
def map_patterns():
    """Map indicators to MITRE ATT&CK patterns"""
    try:
        data = request.get_json()
        indicators = data.get('indicators', [])
        
        if not indicators:
            return jsonify({'error': 'No indicators provided'}), 400
        
        mapping = attribution_module.map_attack_pattern(indicators)
        return jsonify(mapping)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cluster_indicators', methods=['POST'])
def cluster_indicators():
    """Cluster indicators to identify campaigns"""
    try:
        data = request.get_json()
        indicators = data.get('indicators', [])
        
        if not indicators:
            return jsonify({'error': 'No indicators provided'}), 400
        
        clusters = attribution_module.cluster_indicators(indicators)
        return jsonify({'clusters': clusters})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate comprehensive attribution report"""
    try:
        data = request.get_json()
        indicators = data.get('indicators', [])
        
        if not indicators:
            return jsonify({'error': 'No indicators provided'}), 400
        
        report = attribution_module.generate_attribution_report(indicators)
        attribution_module.store_attribution_data(report)
        
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/mitre_data', methods=['GET'])
def get_mitre_data():
    """Get loaded MITRE ATT&CK data"""
    try:
        data_type = request.args.get('type', 'all')
        
        if data_type == 'techniques':
            return jsonify(attribution_module.attack_patterns)
        elif data_type == 'actors':
            return jsonify(attribution_module.threat_actors)
        elif data_type == 'campaigns':
            return jsonify(attribution_module.campaigns)
        else:
            return jsonify({
                'techniques': len(attribution_module.attack_patterns),
                'actors': len(attribution_module.threat_actors),
                'campaigns': len(attribution_module.campaigns)
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
