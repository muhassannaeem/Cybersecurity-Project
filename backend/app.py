from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, disconnect
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
import random
import json
from collections import Counter, defaultdict
import jwt
import requests

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cybersecurity.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

# JWT configuration (used for API + future WebSocket auth)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', app.config['SECRET_KEY'])
app.config['JWT_ALGORITHM'] = os.getenv('JWT_ALGORITHM', 'HS256')
# Default: 1 hour access token lifetime
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600'))

# Socket.IO for real-time events
# Optional Redis message queue for horizontal scaling (TODO item 5)
_socketio_mq_url = os.getenv('SOCKETIO_MESSAGE_QUEUE_URL')
if _socketio_mq_url:
    socketio = SocketIO(app, cors_allowed_origins="*", message_queue=_socketio_mq_url)
else:
    socketio = SocketIO(app, cors_allowed_origins="*")


@socketio.on('connect')
def socket_auth_connect(auth):
    """Authenticate Socket.IO connections using the same JWT as HTTP APIs.

    The frontend passes the token via the Socket.IO `auth` payload:
      io(API_URL, { auth: { token: '<JWT>' } })
    """
    token = None

    # Preferred: token in `auth` payload
    if isinstance(auth, dict):
        token = auth.get('token')

    # Fallback: token in query string, e.g. ?token=...
    if not token:
        token = request.args.get('token')

    if not token:
        return False  # Reject connection

    try:
        payload = _decode_auth_token(token)
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False

    user_id = payload.get('sub')
    if not user_id:
        return False

    user = User.query.get(user_id)
    if not user:
        return False

    # Optionally attach minimal user context for this connection
    g.current_user = user
    g.current_user_id = user.id
    g.current_user_role = user.role

    # Connection is accepted by returning None / not returning False
    return None

db = SQLAlchemy(app)

# Token serializer for auth (uses Flask SECRET_KEY)
token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# In-memory state for smoother, more realistic mock data
STATS_STATE = None
THREATS_STATE = []
ALERTS_STATE = []
ANOMALIES_STATE = []
DECOYS_STATE = []
THREAT_SEQ = 0
ALERT_SEQ = 0
ANOMALY_SEQ = 0

# Simple in-process cache for metrics so we can expose them via dedicated APIs
METRICS_CACHE = {}

# External service URLs
DECOY_GENERATOR_URL = os.getenv('DECOY_GENERATOR_URL', 'http://localhost:5002')
THREAT_ATTRIBUTION_URL = os.getenv('THREAT_ATTRIBUTION_URL', 'http://localhost:5004')

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='analyst')  # admin, analyst, viewer, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


def _user_to_dict(user: "User") -> dict:
    """Serialize a User object for API responses (without password)."""
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def _generate_auth_token(user: "User") -> str:
    """Issue a signed JWT for the given user.

    The frontend stores this in localStorage and sends it as
    `Authorization: Bearer <token>` on subsequent requests.
    """
    now = datetime.utcnow()
    exp_seconds = app.config['JWT_ACCESS_TOKEN_EXPIRES']
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(seconds=exp_seconds),
    }
    token = jwt.encode(
        payload,
        app.config['JWT_SECRET_KEY'],
        algorithm=app.config['JWT_ALGORITHM'],
    )
    # PyJWT>=2 returns a string already; earlier versions return bytes.
    return token if isinstance(token, str) else token.decode("utf-8")


def _decode_auth_token(token: str):
    """Decode and validate a JWT, returning its payload or raising.

    Raises jwt.ExpiredSignatureError, jwt.InvalidTokenError on failure.
    """
    return jwt.decode(
        token,
        app.config['JWT_SECRET_KEY'],
        algorithms=[app.config['JWT_ALGORITHM']],
    )


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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


# Simple audit logging helper
def log_action(action: str, details=None, user_id: int | None = None, ip_address: str | None = None):
    """Persist a lightweight audit log entry.

    This is deliberately tolerant of failures so it never breaks the main request
    flow in this demo app.
    """
    try:
        if isinstance(details, (dict, list)):
            details_str = json.dumps(details)
        elif details is None:
            details_str = None
        else:
            details_str = str(details)

        entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details_str,
            ip_address=ip_address,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        # Never let logging errors crash the request handler in this demo app
        db.session.rollback()


# Auth decorator with JWT validation and optional RBAC enforcement
from functools import wraps


def auth_required(roles=None):
    """Require a valid JWT and (optionally) a specific user role.

    Usage:
        @auth_required()                  # any authenticated user
        @auth_required(roles=["admin"])   # only admins

    On success, attaches `g.current_user`, `g.current_user_id`, `g.current_user_role`.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            parts = auth_header.split()

            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({"error": "Missing or invalid Authorization header"}), 401

            token = parts[1]
            try:
                payload = _decode_auth_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token has expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid authentication token"}), 401

            user_id = payload.get("sub")
            if not user_id:
                return jsonify({"error": "Invalid authentication payload"}), 401

            user = User.query.get(user_id)
            if not user:
                return jsonify({"error": "User no longer exists"}), 401

            # Enforce role-based access control if roles are specified.
            if roles is not None and user.role not in roles:
                log_action(
                    "unauthorized_access",
                    {
                        "endpoint": request.path,
                        "method": request.method,
                        "required_roles": roles,
                        "user_role": user.role,
                    },
                    user_id=user.id,
                    ip_address=request.remote_addr,
                )
                return jsonify({"error": "Forbidden: insufficient permissions"}), 403

            # Attach user to the global request context
            g.current_user = user
            g.current_user_id = user.id
            g.current_user_role = user.role

            return fn(*args, **kwargs)

        return wrapper

    return decorator


# Mock data for demonstration (now stateful for realism)
def generate_mock_stats():
    """Generate smoother, stateful dashboard stats so values don't jump randomly."""
    global STATS_STATE

    if STATS_STATE is None:
        # Initial baseline
        STATS_STATE = {
            'totalAlerts': random.randint(80, 120),
            'activeThreats': random.randint(8, 15),
            'decoysDeployed': random.randint(5, 15),
            'detectionRate': random.uniform(90.0, 96.0),
            'falsePositives': random.randint(3, 8),
            'responseTime': random.randint(150, 300),
        }
        return STATS_STATE

    # Small jitter around the current values
    def jitter_int(key, low, high, step):
        value = STATS_STATE[key]
        delta = random.randint(-step, step)
        STATS_STATE[key] = max(low, min(high, value + delta))

    def jitter_float(key, low, high, step):
        value = STATS_STATE[key]
        delta = random.uniform(-step, step)
        STATS_STATE[key] = max(low, min(high, value + delta))

    jitter_int('totalAlerts', 0, 500, 5)
    jitter_int('activeThreats', 0, 100, 2)
    jitter_int('decoysDeployed', 0, 50, 1)
    jitter_float('detectionRate', 80.0, 99.5, 0.3)
    jitter_int('falsePositives', 0, 50, 1)
    jitter_int('responseTime', 50, 1000, 10)

    return STATS_STATE


def generate_mock_threats():
    """Stateful threat list that grows gradually instead of regenerating each time."""
    global THREATS_STATE, THREAT_SEQ, METRICS_CACHE

    threat_types = ['SQL Injection', 'XSS', 'DDoS', 'Brute Force', 'Malware', 'Phishing']
    sources = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.10']
    destinations = ['web-server-01', 'database-01', 'api-gateway', 'load-balancer']
    severities = ['low', 'medium', 'high', 'critical']
    statuses = ['active', 'resolved', 'investigating']

    # Seed initial data
    if not THREATS_STATE:
        for _ in range(random.randint(10, 20)):
            THREAT_SEQ += 1
            THREATS_STATE.append({
                'id': f'threat_{THREAT_SEQ}',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(10, 90))).isoformat(),
                'source': random.choice(sources),
                'destination': random.choice(destinations),
                'threatType': random.choice(threat_types),
                'severity': random.choice(severities),
                'status': random.choice(statuses),
            })

    # Occasionally add a few new threats
    for _ in range(random.randint(0, 3)):
        THREAT_SEQ += 1
        THREATS_STATE.append({
            'id': f'threat_{THREAT_SEQ}',
            'timestamp': datetime.now().isoformat(),
            'source': random.choice(sources),
            'destination': random.choice(destinations),
            'threatType': random.choice(threat_types),
            'severity': random.choice(severities),
            'status': 'active',
        })

    # Occasionally resolve some existing threats
    for t in THREATS_STATE:
        if t['status'] == 'active' and random.random() < 0.05:
            t['status'] = 'resolved'

    # Compute and cache simple aggregate metrics for threats (for metrics APIs)
    severity_counts = Counter(t['severity'] for t in THREATS_STATE)
    status_counts = Counter(t['status'] for t in THREATS_STATE)
    METRICS_CACHE['threats_summary'] = {
        'total': len(THREATS_STATE),
        'by_severity': dict(severity_counts),
        'by_status': dict(status_counts),
    }

    # Return most recent 50 threats
    sorted_threats = sorted(THREATS_STATE, key=lambda x: x['timestamp'], reverse=True)
    return sorted_threats[:50]


def generate_mock_anomalies():
    """Stateful traffic anomalies; new ones appear but history is kept per run."""
    global ANOMALIES_STATE, ANOMALY_SEQ

    anomaly_types = ['suspicious_port', 'high_data_volume', 'failed_connection', 'protocol_anomaly']
    severities = ['low', 'medium', 'high', 'critical']
    sources = ['192.168.1.10', '10.0.0.20', '172.16.1.5', '198.51.100.23']
    destinations = ['zeek-sensor-01', 'core-router', 'edge-firewall', 'vpn-gateway']

    # Seed initial anomalies
    if not ANOMALIES_STATE:
        for _ in range(random.randint(5, 10)):
            ANOMALY_SEQ += 1
            anomaly_type = random.choice(anomaly_types)
            ANOMALIES_STATE.append({
                'id': f'anomaly_{ANOMALY_SEQ}',
                'timestamp': (datetime.now() - timedelta(minutes=random.randint(5, 60))).isoformat(),
                'source': random.choice(sources),
                'destination': random.choice(destinations),
                'type': anomaly_type,
                'severity': random.choice(severities),
                'description': f'Mock {anomaly_type.replace("_", " ")} detected in traffic monitor.',
            })

    # Add a small number of new anomalies
    for _ in range(random.randint(0, 2)):
        ANOMALY_SEQ += 1
        anomaly_type = random.choice(anomaly_types)
        ANOMALIES_STATE.append({
            'id': f'anomaly_{ANOMALY_SEQ}',
            'timestamp': datetime.now().isoformat(),
            'source': random.choice(sources),
            'destination': random.choice(destinations),
            'type': anomaly_type,
            'severity': random.choice(severities),
            'description': f'Mock {anomaly_type.replace("_", " ")} detected in traffic monitor.',
        })

    # Cache anomaly counts for metrics APIs
    severity_counts = Counter(a['severity'] for a in ANOMALIES_STATE)
    type_counts = Counter(a['type'] for a in ANOMALIES_STATE)
    METRICS_CACHE['anomalies_summary'] = {
        'total': len(ANOMALIES_STATE),
        'by_severity': dict(severity_counts),
        'by_type': dict(type_counts),
    }

    sorted_anomalies = sorted(ANOMALIES_STATE, key=lambda x: x['timestamp'], reverse=True)
    return sorted_anomalies[:50]

# Auth & User


@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """Create a new user account and return an auth token.

    Expected JSON body: {"name", "email", "password"}
    """
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"error": "name, email and password are required"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Ensure email is unique
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": "An account with this email already exists"}), 400

    try:
        user = User(email=email, name=name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        token = _generate_auth_token(user)
        log_action(
            "signup",
            {"user_id": user.id, "email": user.email},
            user_id=user.id,
            ip_address=request.remote_addr,
        )

        return jsonify({
            "token": token,
            "user": _user_to_dict(user),
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate a user and return an auth token.

    Expected JSON body: {"email", "password"}
    """
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        # Deliberately generic message
        return jsonify({"error": "Invalid email or password"}), 401

    token = _generate_auth_token(user)
    log_action(
        "login",
        {"user_id": user.id, "email": user.email},
        user_id=user.id,
        ip_address=request.remote_addr,
    )

    return jsonify({
        "token": token,
        "user": _user_to_dict(user),
    })


@app.route('/api/dashboard/stats', methods=['GET'])
@auth_required()
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        stats = generate_mock_stats()
        # Emit real-time update over Socket.IO
        socketio.emit('stats_update', stats)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/recent', methods=['GET'])
@auth_required()
def get_recent_threats():
    """Get recent threats"""
    try:
        threats = generate_mock_threats()
        # Emit real-time update over Socket.IO
        socketio.emit('threat_update', threats)
        return jsonify(threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/anomalies/recent', methods=['GET'])
@auth_required()
def get_recent_anomalies():
    """Get recent traffic anomalies (mocked from traffic monitor)."""
    try:
        anomalies = generate_mock_anomalies()
        # Emit real-time traffic anomaly updates
        socketio.emit('traffic_anomaly', anomalies)
        return jsonify(anomalies)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decoys/deploy', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def deploy_decoy():
    """Deploy a new decoy.

    This endpoint represents the "central" decoy deployment API used by the
    dashboard. It validates the requested decoy type, delegates container
    deployment to the decoy_generator microservice when available, and
    persists a Decoy record in the central database so metrics and UI can
    track Dionaea/Conpot instances as well.
    """
    try:
        data = request.get_json() or {}
        decoy_type = data.get('type', 'web_server')
        name = data.get('name') or f'decoy_{random.randint(1000, 9999)}'

        allowed_types = [
            'web_server',
            'ssh',
            'database',
            'file_share',
            'iot_device',
            'dionaea',
            'conpot',
        ]
        if decoy_type not in allowed_types:
            return jsonify({'error': f'Unsupported decoy type: {decoy_type}'}), 400

        # Best-effort call to decoy_generator microservice to deploy the
        # actual honeypot container. Failure here should not crash the API;
        # the central Decoy record is still created so the UI remains
        # consistent even if the underlying container deployment fails.
        external_info = None
        try:
            resp = requests.post(
                f"{DECOY_GENERATOR_URL}/deploy/honeypot",
                json={'type': decoy_type, 'name': name},
                timeout=5,
            )
            if resp.ok:
                external_info = resp.json()
        except Exception:
            external_info = None

        # Derive simple networking fields for UI; if the decoy_generator ever
        # exposes concrete port/IP info, this can be wired through here.
        port = random.randint(8000, 9000)
        ip_address = f'10.0.0.{random.randint(100, 200)}'

        # Create decoy object in central DB
        decoy = Decoy(
            name=name,
            type=decoy_type,
            status='active',
            port=port,
            ip_address=ip_address,
        )

        db.session.add(decoy)
        db.session.commit()

        payload = {
            'id': decoy.id,
            'name': decoy.name,
            'type': decoy.type,
            'status': decoy.status,
            'port': decoy.port,
            'ip_address': decoy.ip_address,
            'created_at': decoy.created_at.isoformat(),
            'external': external_info,
        }

        # Emit real-time decoy update
        socketio.emit('decoy_update', payload)

        log_action(
            'deploy_decoy',
            {'decoy_type': decoy.type, 'decoy_id': decoy.id, 'external': external_info},
            user_id=getattr(g, 'current_user_id', None),
            ip_address=request.remote_addr,
        )
        return jsonify({
            'message': 'Decoy deployed successfully',
            'decoy_id': decoy.id,
            'type': decoy.type,
            'port': decoy.port,
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/run', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def run_analysis():
    """Run behavioral analysis"""
    try:
        data = request.get_json() or {}
        analysis_type = data.get('type', 'full')
        
        # Mock analysis execution
        result = {
            'message': f'{analysis_type} analysis started',
            'analysis_id': f'analysis_{random.randint(1000, 9999)}',
            'status': 'running'
        }
        log_action(
            'run_analysis',
            {'analysis_type': analysis_type, 'analysis_id': result['analysis_id']},
            user_id=getattr(g, 'current_user_id', None),
            ip_address=request.remote_addr,
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats', methods=['GET'])
@auth_required()
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
@auth_required()
def get_decoys():
    """Get all decoys tracked by the central backend.

    This now reads from the `Decoy` table instead of an in-memory list so that
    Dionaea/Conpot deployments are persisted and can be used for metrics and
    UI filtering (TODO items 15 & 16).
    """
    try:
        # Seed a few sample decoys on first run so the UI has data to show.
        if Decoy.query.count() == 0:
            sample_types = ['web_server', 'ssh', 'database', 'file_share', 'dionaea', 'conpot']
            for i in range(1, 6):
                d = Decoy(
                    name=f'decoy_{i}',
                    type=random.choice(sample_types),
                    status=random.choice(['active', 'inactive', 'compromised']),
                    created_at=datetime.now() - timedelta(hours=random.randint(1, 24)),
                    port=random.randint(8000, 9000),
                    ip_address=f'10.0.0.{random.randint(100, 200)}',
                )
                db.session.add(d)
            db.session.commit()

        decoys = [
            {
                'id': d.id,
                'name': d.name,
                'type': d.type,
                'status': d.status,
                'created_at': d.created_at.isoformat() if d.created_at else None,
                'port': d.port,
                'ip_address': d.ip_address,
            }
            for d in Decoy.query.order_by(Decoy.created_at.desc()).all()
        ]

        # Emit decoy list snapshot for real-time dashboards
        socketio.emit('decoy_update', decoys)
        return jsonify(decoys)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@auth_required()
def get_alerts():
    """Get all alerts"""
    try:
        global ALERTS_STATE, ALERT_SEQ

        alert_types = ['threat_detected', 'decoy_triggered', 'anomaly_detected']
        severities = ['low', 'medium', 'high', 'critical']
        statuses = ['new', 'acknowledged', 'resolved']

        # Seed some initial alerts
        if not ALERTS_STATE:
            for _ in range(random.randint(10, 20)):
                ALERT_SEQ += 1
                ALERTS_STATE.append({
                    'id': ALERT_SEQ,
                    'timestamp': (datetime.now() - timedelta(minutes=random.randint(5, 90))).isoformat(),
                    'type': random.choice(alert_types),
                    'severity': random.choice(severities),
                    'message': f'Alert message {ALERT_SEQ}',
                    'status': random.choice(statuses),
                })

        # Occasionally add a new alert
        for _ in range(random.randint(0, 2)):
            ALERT_SEQ += 1
            ALERTS_STATE.append({
                'id': ALERT_SEQ,
                'timestamp': datetime.now().isoformat(),
                'type': random.choice(alert_types),
                'severity': random.choice(severities),
                'message': f'Alert message {ALERT_SEQ}',
                'status': 'new',
            })

        # Occasionally move some alerts forward in lifecycle
        for a in ALERTS_STATE:
            if a['status'] == 'new' and random.random() < 0.05:
                a['status'] = 'acknowledged'
            elif a['status'] == 'acknowledged' and random.random() < 0.05:
                a['status'] = 'resolved'

        alerts = sorted(ALERTS_STATE, key=lambda x: x['timestamp'], reverse=True)[:50]

        # Cache alert counts for metrics APIs
        severity_counts = Counter(a['severity'] for a in ALERTS_STATE)
        status_counts = Counter(a['status'] for a in ALERTS_STATE)
        METRICS_CACHE['alerts_summary'] = {
            'total': len(ALERTS_STATE),
            'by_severity': dict(severity_counts),
            'by_status': dict(status_counts),
        }

        # Emit alerts snapshot for real-time dashboards
        socketio.emit('alert_update', alerts)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _build_attribution_indicators():
    """Build a common indicator/event format for MITRE ATT&CK attribution.

    Each indicator is a dict with at least:
      - id: unique identifier from the source event
      - timestamp: ISO-8601 string
      - type: 'threat' | 'anomaly' | 'alert'
      - severity: low/medium/high/critical
      - value: primary indicator value (e.g., source IP)
      - tags: list of strings used for keyword-based mapping
      - description: free-text description of the event

    This schema is consumed by the threat_attribution microservice.
    """
    indicators = []

    # Threats
    for t in THREATS_STATE:
        indicators.append({
            'id': t.get('id'),
            'timestamp': t.get('timestamp'),
            'type': 'threat',
            'severity': t.get('severity', 'medium'),
            'value': t.get('source'),
            'tags': [
                t.get('threatType', ''),
                t.get('severity', ''),
                t.get('status', ''),
            ],
            'description': f"{t.get('threatType')} from {t.get('source')} to {t.get('destination')} status={t.get('status')}",
        })

    # Anomalies
    for a in ANOMALIES_STATE:
        indicators.append({
            'id': a.get('id'),
            'timestamp': a.get('timestamp'),
            'type': 'anomaly',
            'severity': a.get('severity', 'medium'),
            'value': a.get('source'),
            'tags': [
                a.get('type', ''),
                a.get('severity', ''),
            ],
            'description': a.get('description', ''),
        })

    # Alerts
    for al in ALERTS_STATE:
        indicators.append({
            'id': al.get('id'),
            'timestamp': al.get('timestamp'),
            'type': 'alert',
            'severity': al.get('severity', 'medium'),
            'value': al.get('type'),
            'tags': [
                al.get('type', ''),
                al.get('status', ''),
            ],
            'description': al.get('message', ''),
        })

    return indicators


@app.route('/api/metrics/summary', methods=['GET'])
@auth_required()
def get_metrics_summary():
    """Expose aggregate metrics for dashboard and external tools (TODO items 7 & 23).

    MITRE ATT&CK technique counts are derived via the threat_attribution
    microservice when available; otherwise we fall back to mock data.
    """
    # Ensure underlying generators have run at least once so METRICS_CACHE is populated
    generate_mock_stats()
    generate_mock_threats()
    generate_mock_anomalies()
    get_alerts()

    # Threat levels and incidence over time (simple bucket by hour)
    threats_by_hour = defaultdict(int)
    for t in THREATS_STATE:
        dt = datetime.fromisoformat(t['timestamp']) if isinstance(t['timestamp'], str) else t['timestamp']
        hour_label = dt.replace(minute=0, second=0, microsecond=0).isoformat()
        threats_by_hour[hour_label] += 1

    anomalies_by_hour = defaultdict(int)
    for a in ANOMALIES_STATE:
        dt = datetime.fromisoformat(a['timestamp']) if isinstance(a['timestamp'], str) else a['timestamp']
        hour_label = dt.replace(minute=0, second=0, microsecond=0).isoformat()
        anomalies_by_hour[hour_label] += 1

    # MITRE ATT&CK technique counts via threat_attribution microservice, with
    # graceful fallback to mock data if the service is unavailable.
    attack_patterns = {}
    try:
        indicators = _build_attribution_indicators()
        resp = requests.post(
            f"{THREAT_ATTRIBUTION_URL}/map_patterns",
            json={'indicators': indicators},
            timeout=5,
        )
        if resp.ok:
            mapping = resp.json() or {}
            for tech in mapping.get('techniques', []):
                tech_id = tech.get('id') or tech.get('technique_id')
                if not tech_id:
                    continue
                name = tech.get('name') or tech.get('technique_name', tech_id)
                confidence = float(tech.get('confidence', 0.5) or 0.5)
                # Use a simple scaled confidence as a pseudo-count
                count = max(1, int(confidence * 10))
                if tech_id not in attack_patterns:
                    attack_patterns[tech_id] = {'name': name, 'count': 0}
                attack_patterns[tech_id]['count'] += count

        # If the call failed or returned no techniques, fall back to mock data
        if not attack_patterns:
            raise RuntimeError('No techniques returned from threat_attribution')
    except Exception:
        attack_patterns = {
            'T1001': {'name': 'Data Obfuscation', 'count': random.randint(5, 20)},
            'T1003': {'name': 'OS Credential Dumping', 'count': random.randint(3, 15)},
            'T1005': {'name': 'Data from Local System', 'count': random.randint(2, 10)},
        }

    response = {
        'stats': STATS_STATE,
        'threats_summary': METRICS_CACHE.get('threats_summary', {}),
        'alerts_summary': METRICS_CACHE.get('alerts_summary', {}),
        'anomalies_summary': METRICS_CACHE.get('anomalies_summary', {}),
        'threats_over_time': {
            'labels': list(threats_by_hour.keys()),
            'values': list(threats_by_hour.values()),
        },
        'anomalies_over_time': {
            'labels': list(anomalies_by_hour.keys()),
            'values': list(anomalies_by_hour.values()),
        },
        'attack_patterns': attack_patterns,
    }
    return jsonify(response)


@app.route('/api/attribution/report', methods=['GET'])
@auth_required()
def get_attribution_report():
    """Generate a MITRE ATT&CK attribution report for current detections.

    This endpoint aggregates the current threats, anomalies, and alerts into
    a common indicator format and forwards them to the threat_attribution
    microservice's `/generate_report` API.
    """
    # Ensure we have fresh state
    generate_mock_threats()
    generate_mock_anomalies()
    get_alerts()

    indicators = _build_attribution_indicators()

    try:
        resp = requests.post(
            f"{THREAT_ATTRIBUTION_URL}/generate_report",
            json={'indicators': indicators},
            timeout=15,
        )
        if not resp.ok:
            return jsonify({'error': 'threat_attribution service returned non-200', 'status_code': resp.status_code}), 502
        report = resp.json()
    except Exception as e:
        return jsonify({'error': f'Failed to contact threat_attribution service: {e}'}), 502

    return jsonify({
        'indicators': indicators,
        'report': report,
    })


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
    # Use Socket.IO server for real-time capabilities
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
