from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import random
import json

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cybersecurity.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

db = SQLAlchemy(app)

# Database Models
class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    threat_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='active')
    description = db.Column(db.Text)

class Decoy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    port = db.Column(db.Integer)
    ip_address = db.Column(db.String(15))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='new')

# Mock data for demonstration
def generate_mock_stats():
    return {
        'totalAlerts': random.randint(50, 200),
        'activeThreats': random.randint(5, 25),
        'decoysDeployed': random.randint(10, 50),
        'detectionRate': random.uniform(85.0, 98.0),
        'falsePositives': random.randint(2, 15),
        'responseTime': random.randint(100, 500)
    }

def generate_mock_threats():
    threat_types = ['SQL Injection', 'XSS', 'DDoS', 'Brute Force', 'Malware', 'Phishing']
    sources = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.10']
    destinations = ['web-server-01', 'database-01', 'api-gateway', 'load-balancer']
    severities = ['low', 'medium', 'high', 'critical']
    statuses = ['active', 'resolved', 'investigating']
    
    threats = []
    for i in range(random.randint(5, 15)):
        threats.append({
            'id': f'threat_{i}',
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            'source': random.choice(sources),
            'destination': random.choice(destinations),
            'threatType': random.choice(threat_types),
            'severity': random.choice(severities),
            'status': random.choice(statuses)
        })
    return threats

# API Routes
@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        stats = generate_mock_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/recent', methods=['GET'])
def get_recent_threats():
    """Get recent threats"""
    try:
        threats = generate_mock_threats()
        return jsonify(threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decoys/deploy', methods=['POST'])
def deploy_decoy():
    """Deploy a new decoy"""
    try:
        data = request.get_json() or {}
        decoy_type = data.get('type', 'web_server')
        
        # Create decoy object
        decoy = Decoy(
            name=f'decoy_{random.randint(1000, 9999)}',
            type=decoy_type,
            status='active',
            port=random.randint(8000, 9000),
            ip_address=f'10.0.0.{random.randint(100, 200)}'
        )
        
        # Add to database and commit
        db.session.add(decoy)
        db.session.commit()
        
        # In a real implementation, this would trigger actual decoy deployment
        return jsonify({
            'message': 'Decoy deployed successfully',
            'decoy_id': decoy.id,
            'type': decoy.type,
            'port': decoy.port
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/run', methods=['POST'])
def run_analysis():
    """Run behavioral analysis"""
    try:
        data = request.get_json() or {}
        analysis_type = data.get('type', 'full')
        
        # Mock analysis execution
        return jsonify({
            'message': f'{analysis_type} analysis started',
            'analysis_id': f'analysis_{random.randint(1000, 9999)}',
            'status': 'running'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get all threats with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        severity = request.args.get('severity')
        status = request.args.get('status')
        
        # Mock threat data with filtering
        threats = generate_mock_threats()
        
        if severity:
            threats = [t for t in threats if t['severity'] == severity]
        if status:
            threats = [t for t in threats if t['status'] == status]
        
        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_threats = threats[start:end]
        
        return jsonify({
            'threats': paginated_threats,
            'total': len(threats),
            'page': page,
            'per_page': per_page,
            'pages': (len(threats) + per_page - 1) // per_page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decoys', methods=['GET'])
def get_decoys():
    """Get all decoys"""
    try:
        decoys = [
            {
                'id': i,
                'name': f'decoy_{i}',
                'type': random.choice(['web_server', 'ssh', 'database', 'file_share']),
                'status': random.choice(['active', 'inactive', 'compromised']),
                'created_at': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
                'port': random.randint(8000, 9000),
                'ip_address': f'10.0.0.{random.randint(100, 200)}'
            }
            for i in range(1, random.randint(5, 15))
        ]
        return jsonify(decoys)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts"""
    try:
        alerts = [
            {
                'id': i,
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
                'type': random.choice(['threat_detected', 'decoy_triggered', 'anomaly_detected']),
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'message': f'Alert message {i}',
                'status': random.choice(['new', 'acknowledged', 'resolved'])
            }
            for i in range(1, random.randint(10, 30))
        ]
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
