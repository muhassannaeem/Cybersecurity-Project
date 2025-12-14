from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, disconnect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
import random
import json
from collections import Counter, defaultdict, deque
import jwt
import requests
import redis
import sys
import logging
import time
import threading

# Add backend directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up structured logging
try:
    from logging_config import setup_logging, log_info, log_error, log_warning, log_audit, log_threat
    logger = setup_logging(
        service_name="backend",
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        environment=os.getenv('ENVIRONMENT', 'development'),
        log_file=os.getenv('LOG_FILE', '/app/logs/backend.log')
    )
except ImportError:
    # Fallback to basic logging if module not available
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

# Import event enrichment and SIEM integration (Tasks 17-20)
try:
    from event_enrichment import EventEnrichmentService, EnrichedEvent
    from siem_integration import SIEMIntegrationManager
    ENRICHMENT_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Event enrichment modules not available: {e}")
    ENRICHMENT_AVAILABLE = False

app = Flask(__name__)
CORS(app)

# Register API Documentation Blueprint
try:
    from api_docs import api_blueprint
    app.register_blueprint(api_blueprint)
except ImportError:
    pass  # API docs optional

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cybersecurity.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

# Rate limiting configuration
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)
limiter.init_app(app)

# JWT configuration (used for API + future WebSocket auth)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', app.config['SECRET_KEY'])
app.config['JWT_ALGORITHM'] = os.getenv('JWT_ALGORITHM', 'HS256')
# Default: 1 hour access token lifetime
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600'))

# Socket.IO for real-time events with backpressure and rate limiting
# Optional Redis message queue for horizontal scaling (TODO item 5)
_socketio_mq_url = os.getenv('SOCKETIO_MESSAGE_QUEUE_URL')
if _socketio_mq_url:
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*", 
        message_queue=_socketio_mq_url,
        async_mode='threading',
        logger=True,
        engineio_logger=False
    )
else:
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*",
        async_mode='threading',
        logger=True,
        engineio_logger=False
    )

# Backpressure and rate limiting configuration
SOCKET_RATE_LIMIT_CONFIG = {
    'events_per_second': int(os.getenv('SOCKET_EVENTS_PER_SECOND', '10')),
    'max_queue_size': int(os.getenv('SOCKET_MAX_QUEUE_SIZE', '100')),
    'client_rate_limit': int(os.getenv('SOCKET_CLIENT_RATE_LIMIT', '5'))  # events per second per client
}

# Global event queue for backpressure management
event_queue = deque(maxlen=SOCKET_RATE_LIMIT_CONFIG['max_queue_size'])
event_queue_lock = threading.Lock()

# Per-client rate limiting tracking
client_rate_trackers = {}
client_trackers_lock = threading.Lock()


class RateLimitTracker:
    """Track rate limiting for individual clients."""
    
    def __init__(self, limit_per_second=5):
        self.limit_per_second = limit_per_second
        self.events = deque(maxlen=limit_per_second * 2)  # 2 second window
        self.lock = threading.Lock()
    
    def can_emit(self):
        """Check if client can emit based on rate limit."""
        with self.lock:
            now = time.time()
            # Remove events older than 1 second
            while self.events and self.events[0] < now - 1.0:
                self.events.popleft()
            
            # Check if under rate limit
            if len(self.events) < self.limit_per_second:
                self.events.append(now)
                return True
            return False


class EventQueue:
    """Manages backpressure for Socket.IO event emission."""
    
    def __init__(self, max_size=100, max_rate=10):
        self.max_size = max_size
        self.max_rate = max_rate  # events per second
        self.queue = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.last_emit_time = 0
        self.emit_interval = 1.0 / max_rate
        
    def add_event(self, event_name, data, room=None):
        """Add event to queue with backpressure."""
        with self.lock:
            if len(self.queue) >= self.max_size:
                # Drop oldest event (backpressure)
                dropped = self.queue.popleft()
                try:
                    log_warning(
                        logger,
                        f"Event queue full, dropped event: {dropped['event']}",
                        event_type="system",
                        metadata={"dropped_event": dropped['event'], "queue_size": len(self.queue)}
                    )
                except Exception:
                    pass
            
            self.queue.append({
                'event': event_name,
                'data': data,
                'room': room,
                'timestamp': time.time()
            })
    
    def process_queue(self):
        """Process events from queue with rate limiting."""
        while True:
            with self.lock:
                if not self.queue:
                    continue
                
                now = time.time()
                if now - self.last_emit_time < self.emit_interval:
                    continue
                    
                event = self.queue.popleft()
                self.last_emit_time = now
            
            try:
                if event['room']:
                    socketio.emit(event['event'], event['data'], room=event['room'])
                else:
                    socketio.emit(event['event'], event['data'])
            except Exception as e:
                try:
                    log_error(
                        logger,
                        f"Failed to emit Socket.IO event: {e}",
                        event_type="system",
                        metadata={"event": event['event'], "error": str(e)}
                    )
                except Exception:
                    pass
            
            time.sleep(0.01)  # Small sleep to prevent busy waiting


# Initialize global event queue and processor
global_event_queue = EventQueue(
    max_size=SOCKET_RATE_LIMIT_CONFIG['max_queue_size'],
    max_rate=SOCKET_RATE_LIMIT_CONFIG['events_per_second']
)

# Start background event processor
def start_event_processor():
    """Start the background event processor thread."""
    processor_thread = threading.Thread(target=global_event_queue.process_queue, daemon=True)
    processor_thread.start()
    return processor_thread


def emit_with_backpressure(event_name, data, room=None):
    """Emit Socket.IO event with backpressure and rate limiting."""
    global_event_queue.add_event(event_name, data, room)


def get_or_create_rate_tracker(client_id):
    """Get or create rate tracker for a client."""
    with client_trackers_lock:
        if client_id not in client_rate_trackers:
            client_rate_trackers[client_id] = RateLimitTracker(
                SOCKET_RATE_LIMIT_CONFIG['client_rate_limit']
            )
        return client_rate_trackers[client_id]


def cleanup_old_trackers():
    """Periodically clean up old rate trackers."""
    while True:
        with client_trackers_lock:
            # Remove trackers that haven't been used in 5 minutes
            current_time = time.time()
            to_remove = []
            for client_id, tracker in client_rate_trackers.items():
                with tracker.lock:
                    if not tracker.events or tracker.events[-1] < current_time - 300:
                        to_remove.append(client_id)
            
            for client_id in to_remove:
                del client_rate_trackers[client_id]
        
        time.sleep(60)  # Check every minute


# Start background threads
start_event_processor()
cleanup_thread = threading.Thread(target=cleanup_old_trackers, daemon=True)
cleanup_thread.start()


@socketio.on('connect')
def socket_auth_connect(auth):
    """Authenticate Socket.IO connections using the same JWT as HTTP APIs.
    
    Includes rate limiting and connection tracking for backpressure management.
    The frontend passes the token via the Socket.IO `auth` payload:
      io(API_URL, { auth: { token: '<JWT>' } })
    """
    client_id = request.sid
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    
    token = None

    # Preferred: token in `auth` payload
    if isinstance(auth, dict):
        token = auth.get('token')

    # Fallback: token in query string, e.g. ?token=...
    if not token:
        token = request.args.get('token')

    if not token:
        try:
            log_warning(
                logger,
                f"Socket.IO connection rejected: no token provided",
                event_type="security",
                ip_address=client_ip,
                metadata={"client_id": client_id, "reason": "no_token"}
            )
        except Exception:
            pass
        return False  # Reject connection

    try:
        payload = _decode_auth_token(token)
    except jwt.ExpiredSignatureError:
        try:
            log_warning(
                logger,
                f"Socket.IO connection rejected: expired token",
                event_type="security",
                ip_address=client_ip,
                metadata={"client_id": client_id, "reason": "expired_token"}
            )
        except Exception:
            pass
        return False
    except jwt.InvalidTokenError:
        try:
            log_warning(
                logger,
                f"Socket.IO connection rejected: invalid token",
                event_type="security",
                ip_address=client_ip,
                metadata={"client_id": client_id, "reason": "invalid_token"}
            )
        except Exception:
            pass
        return False

    user_id = payload.get('sub')
    if not user_id:
        return False

    user = User.query.get(user_id)
    if not user:
        return False

    # Create rate tracker for this client
    get_or_create_rate_tracker(client_id)

    # Optionally attach minimal user context for this connection
    g.current_user = user
    g.current_user_id = user.id
    g.current_user_role = user.role

    try:
        log_info(
            logger,
            f"Socket.IO connection established",
            event_type="system",
            user_id=user.id,
            ip_address=client_ip,
            metadata={
                "client_id": client_id, 
                "user_email": user.email,
                "user_role": user.role
            }
        )
    except Exception:
        pass

    # Connection is accepted by returning None / not returning False
    return None


@socketio.on('disconnect')
def socket_disconnect():
    """Handle client disconnection and cleanup rate trackers."""
    client_id = request.sid
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    
    # Clean up rate tracker for disconnected client
    with client_trackers_lock:
        if client_id in client_rate_trackers:
            del client_rate_trackers[client_id]
    
    try:
        log_info(
            logger,
            f"Socket.IO client disconnected",
            event_type="system",
            ip_address=client_ip,
            metadata={"client_id": client_id}
        )
    except Exception:
        pass

db = SQLAlchemy(app)

# Request logging middleware
@app.before_request
def log_request():
    """Log incoming requests with correlation ID."""
    import uuid
    g.correlation_id = str(uuid.uuid4())
    g.request_start_time = datetime.utcnow()
    
    # Skip logging for health checks
    if request.path != '/api/health':
        try:
            log_info(
                logger,
                f"{request.method} {request.path}",
                event_type="system",
                correlation_id=g.correlation_id,
                ip_address=request.remote_addr,
                metadata={
                    "method": request.method,
                    "path": request.path,
                    "query_params": dict(request.args),
                    "user_agent": request.headers.get('User-Agent', '')
                }
            )
        except Exception:
            pass  # Don't break requests if logging fails

@app.after_request
def log_response(response):
    """Log response after request completes."""
    if request.path != '/api/health':
        try:
            duration_ms = int((datetime.utcnow() - g.request_start_time).total_seconds() * 1000)
            log_info(
                logger,
                f"{request.method} {request.path} - {response.status_code}",
                event_type="system",
                correlation_id=getattr(g, 'correlation_id', None),
                ip_address=request.remote_addr,
                metadata={
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "method": request.method,
                    "path": request.path
                }
            )
        except Exception:
            pass
    return response

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

# Initialize event enrichment and SIEM integration (Tasks 17-20)
if ENRICHMENT_AVAILABLE:
    enrichment_service = EventEnrichmentService(
        threat_attribution_url=THREAT_ATTRIBUTION_URL
    )
    siem_manager = SIEMIntegrationManager()
    siem_manager.start()  # Start background SIEM export thread
else:
    enrichment_service = None
    siem_manager = None

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


# =====================================================
# Metrics Models (Section 6 - Task 21-22)
# =====================================================

class EvaluationMetric(db.Model):
    """Store comprehensive evaluation test results"""
    __tablename__ = 'evaluation_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    scenario_name = db.Column(db.String(100), nullable=False, index=True)
    test_id = db.Column(db.String(255), unique=True)
    
    # Core Metrics (Task 21)
    detection_latency = db.Column(db.Numeric(10, 3))
    false_positive_rate = db.Column(db.Numeric(5, 4))
    attacker_engagement_time = db.Column(db.Numeric(10, 3))
    decoy_believability_score = db.Column(db.Numeric(5, 4))
    threat_actor_attribution_accuracy = db.Column(db.Numeric(5, 4))
    
    # Additional Metrics
    overall_score = db.Column(db.Numeric(5, 4))
    detected = db.Column(db.Boolean, default=False, index=True)
    target_host = db.Column(db.String(255))
    
    # Additional metadata/context
    extra_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class DetectionEvent(db.Model):
    """Track detection latency from real attack data"""
    __tablename__ = 'detection_events'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    attack_start_time = db.Column(db.DateTime, nullable=False, index=True)
    detection_time = db.Column(db.DateTime, nullable=False, index=True)
    detection_latency_seconds = db.Column(db.Numeric(10, 3), nullable=False)
    
    # Attack Details
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    attack_type = db.Column(db.String(100), index=True)
    detected_by = db.Column(db.String(100), index=True)
    confidence_score = db.Column(db.Numeric(5, 4))
    
    # Additional Context
    threat_id = db.Column(db.Integer)
    alert_id = db.Column(db.Integer)
    extra_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class FalsePositiveEvent(db.Model):
    """Track false positive classifications"""
    __tablename__ = 'false_positive_events'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    event_type = db.Column(db.String(100), nullable=False, index=True)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    
    # False Positive Details
    false_positive_type = db.Column(db.String(100), index=True)
    original_label = db.Column(db.String(100))
    corrected_label = db.Column(db.String(100))
    confidence_score = db.Column(db.Numeric(5, 4))
    
    # Context
    detected_by = db.Column(db.String(100))
    corrected_by = db.Column(db.String(100))
    correction_timestamp = db.Column(db.DateTime)
    
    # Additional metadata/context
    extra_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class DecoyInteraction(db.Model):
    """Track attacker engagement with decoys"""
    __tablename__ = 'decoy_interactions'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    decoy_id = db.Column(db.Integer, index=True)
    decoy_type = db.Column(db.String(50))
    attacker_ip = db.Column(db.String(45), nullable=False, index=True)
    
    # Engagement Timing
    interaction_start = db.Column(db.DateTime, nullable=False, index=True)
    interaction_end = db.Column(db.DateTime)
    engagement_duration = db.Column(db.Numeric(10, 3))
    
    # Engagement Metrics
    actions_count = db.Column(db.Integer, default=0)
    depth_score = db.Column(db.Numeric(5, 4))
    believability_score = db.Column(db.Numeric(5, 4))
    repeat_visits = db.Column(db.Integer, default=0)
    
    # Interaction Details
    first_action = db.Column(db.String(255))
    last_action = db.Column(db.String(255))
    actions_taken = db.Column(db.JSON)
    
    # Additional metadata/context
    extra_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ThreatAttributionAccuracy(db.Model):
    """Track accuracy of threat actor attribution"""
    __tablename__ = 'threat_attribution_accuracy'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    test_id = db.Column(db.String(255), index=True)
    evaluation_metric_id = db.Column(db.Integer, index=True)
    
    # Attribution Details
    ground_truth_actor = db.Column(db.String(255))
    attributed_actor = db.Column(db.String(255))
    ground_truth_techniques = db.Column(db.JSON)
    attributed_techniques = db.Column(db.JSON)
    
    # Accuracy Metrics
    actor_match = db.Column(db.Boolean, index=True)
    technique_matches = db.Column(db.Integer)
    technique_total = db.Column(db.Integer)
    accuracy_score = db.Column(db.Numeric(5, 4))
    
    # Confidence
    confidence_score = db.Column(db.Numeric(5, 4))
    
    # Additional metadata/context
    extra_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ModelVersion(db.Model):
    """Track ML model versions and performance"""
    __tablename__ = 'model_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(100), nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Training Details
    training_data_size = db.Column(db.Integer)
    training_start_time = db.Column(db.DateTime)
    training_end_time = db.Column(db.DateTime)
    training_duration_seconds = db.Column(db.Integer)
    
    # Performance Metrics
    performance_metrics = db.Column(db.JSON)
    validation_metrics = db.Column(db.JSON)
    test_metrics = db.Column(db.JSON)
    
    # Model Storage
    file_path = db.Column(db.String(500))
    file_size_bytes = db.Column(db.BigInteger)
    model_hash = db.Column(db.String(64))
    
    # Version Management
    is_active = db.Column(db.Boolean, default=False, index=True)
    previous_version_id = db.Column(db.Integer, index=True)
    activated_at = db.Column(db.DateTime)
    deactivated_at = db.Column(db.DateTime)
    
    # Additional metadata/context
    extra_metadata = db.Column(db.JSON)
    created_at_timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        db.UniqueConstraint('model_name', 'version', name='unique_model_version'),
    )


class RetrainingJob(db.Model):
    """Track automated model retraining jobs"""
    __tablename__ = 'retraining_jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    model_name = db.Column(db.String(100), nullable=False, index=True)
    status = db.Column(db.String(50), default='pending', index=True)
    
    # Job Timing
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    
    # Trigger Information
    trigger_type = db.Column(db.String(100), index=True)
    trigger_reason = db.Column(db.Text)
    triggered_by = db.Column(db.String(100))
    
    # Training Data
    training_data_size = db.Column(db.Integer)
    real_attack_samples = db.Column(db.Integer)
    benign_samples = db.Column(db.Integer)
    synthetic_samples = db.Column(db.Integer)
    
    # Results
    new_version_id = db.Column(db.Integer, index=True)
    previous_version_id = db.Column(db.Integer)
    performance_comparison = db.Column(db.JSON)
    rollback_performed = db.Column(db.Boolean, default=False)
    rollback_reason = db.Column(db.Text)
    
    # Error Handling
    error_message = db.Column(db.Text)
    error_traceback = db.Column(db.Text)
    
    # Additional metadata/context
    extra_metadata = db.Column(db.JSON)


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
@limiter.limit("5 per minute")  # Prevent spam account creation
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
        
        # Structured logging
        try:
            log_audit(
                logger,
                f"User signup: {user.email}",
                user_id=user.id,
                ip_address=request.remote_addr,
                correlation_id=getattr(g, 'correlation_id', None),
                metadata={"email": user.email, "role": user.role}
            )
        except Exception:
            pass

        return jsonify({
            "token": token,
            "user": _user_to_dict(user),
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")  # Prevent brute force attacks
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
    
    # Structured logging
    try:
        log_audit(
            logger,
            f"User login: {user.email}",
            user_id=user.id,
            ip_address=request.remote_addr,
            correlation_id=getattr(g, 'correlation_id', None),
            metadata={"email": user.email, "role": user.role}
        )
    except Exception:
        pass

    return jsonify({
        "token": token,
        "user": _user_to_dict(user),
    })


@app.route('/api/dashboard/stats', methods=['GET'])
@auth_required()
@limiter.limit("30 per minute")
def get_dashboard_stats():
    """Get dashboard statistics with rate limiting"""
    try:
        stats = generate_mock_stats()
        # Emit real-time update with backpressure
        emit_with_backpressure('stats_update', stats)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/recent', methods=['GET'])
@auth_required()
@limiter.limit("20 per minute")
def get_recent_threats():
    """Get recent threats with rate limiting"""
    try:
        threats = generate_mock_threats()
        # Emit real-time update with backpressure
        emit_with_backpressure('threat_update', threats)
        return jsonify(threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/anomalies/recent', methods=['GET'])
@auth_required()
@limiter.limit("20 per minute")
def get_recent_anomalies():
    """Get recent traffic anomalies with rate limiting."""
    try:
        anomalies = generate_mock_anomalies()
        # Emit real-time traffic anomaly updates with backpressure
        emit_with_backpressure('traffic_anomaly', anomalies)
        return jsonify(anomalies)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decoys/deploy', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
@limiter.limit("10 per minute")
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

        # Structured logging for decoy deployment
        try:
            log_audit(
                logger,
                f"Decoy deployed: {decoy.name} (type: {decoy.type})",
                user_id=g.current_user_id,
                ip_address=request.remote_addr,
                correlation_id=getattr(g, 'correlation_id', None),
                metadata={
                    "decoy_id": decoy.id,
                    "decoy_type": decoy.type,
                    "decoy_name": decoy.name,
                    "port": decoy.port,
                    "ip_address": decoy.ip_address
                }
            )
        except Exception:
            pass

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

        # Emit real-time decoy update with backpressure
        emit_with_backpressure('decoy_update', payload)

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
@limiter.limit("60 per minute")
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

        # Emit decoy list snapshot for real-time dashboards with backpressure
        emit_with_backpressure('decoy_update', decoys)
        return jsonify(decoys)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@auth_required()
@limiter.limit("30 per minute")
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

        # Emit alerts snapshot for real-time dashboards with backpressure
        emit_with_backpressure('alert_update', alerts)
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


# ================================
# Enhanced Metrics API Endpoints (Section 6 - Task 23)
# ================================

# Initialize metrics service
try:
    from metrics_service import MetricsService
    metrics_service = MetricsService(db.session)
except Exception as e:
    logger.warning(f"Could not initialize metrics service: {e}")
    metrics_service = None


@app.route('/api/metrics/evaluation', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def store_evaluation_metric():
    """Store evaluation metric from evaluation engine (Section 6 - Task 22)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        metric_id = metrics_service.store_evaluation_metric(data)
        if metric_id:
            return jsonify({'id': metric_id, 'message': 'Metric stored successfully'}), 201
        else:
            return jsonify({'error': 'Failed to store metric'}), 500
            
    except Exception as e:
        logger.error(f"Error storing evaluation metric: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/evaluation', methods=['GET'])
@auth_required()
def get_evaluation_metrics():
    """Get evaluation metrics with filtering (Section 6 - Task 23)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        scenario_name = request.args.get('scenario')
        days = request.args.get('days', 30, type=int)
        
        summary = metrics_service.get_evaluation_summary(scenario_name, days)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error getting evaluation metrics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/detection-latency', methods=['GET'])
@auth_required()
def get_detection_latency_trends():
    """Get detection latency trends over time (Section 6 - Task 23)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        days = request.args.get('days', 30, type=int)
        trends = metrics_service.get_detection_latency_trends(days)
        return jsonify({'trends': trends, 'days': days})
        
    except Exception as e:
        logger.error(f"Error getting detection latency trends: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/false-positives', methods=['GET'])
@auth_required()
def get_false_positive_trends():
    """Get false positive rate trends over time (Section 6 - Task 23)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        days = request.args.get('days', 30, type=int)
        trends = metrics_service.get_false_positive_rate_trends(days)
        return jsonify({'trends': trends, 'days': days})
        
    except Exception as e:
        logger.error(f"Error getting false positive trends: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/decoy-engagement', methods=['GET'])
@auth_required()
def get_decoy_engagement_metrics():
    """Get decoy engagement metrics (Section 6 - Task 23)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        days = request.args.get('days', 30, type=int)
        metrics = metrics_service.get_decoy_engagement_metrics(days)
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Error getting decoy engagement metrics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/attribution-accuracy', methods=['GET'])
@auth_required()
def get_attribution_accuracy_metrics():
    """Get threat attribution accuracy metrics (Section 6 - Task 23)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        days = request.args.get('days', 30, type=int)
        metrics = metrics_service.get_attribution_accuracy_metrics(days)
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Error getting attribution accuracy metrics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics/trends', methods=['GET'])
@auth_required()
def get_all_metrics_trends():
    """Get aggregated trends for all metrics (Section 6 - Task 23)"""
    try:
        if not metrics_service:
            return jsonify({'error': 'Metrics service not available'}), 503
        
        days = request.args.get('days', 30, type=int)
        
        return jsonify({
            'detection_latency': metrics_service.get_detection_latency_trends(days),
            'false_positive_rate': metrics_service.get_false_positive_rate_trends(days),
            'decoy_engagement': metrics_service.get_decoy_engagement_metrics(days),
            'attribution_accuracy': metrics_service.get_attribution_accuracy_metrics(days),
            'evaluation_summary': metrics_service.get_evaluation_summary(days=days),
            'days': days
        })
        
    except Exception as e:
        logger.error(f"Error getting metrics trends: {e}")
        return jsonify({'error': str(e)}), 500


# ================================
# Traffic Monitoring API Endpoints
# ================================

TRAFFIC_MONITOR_URL = os.getenv('TRAFFIC_MONITOR_URL', 'http://localhost:5003')

@app.route('/api/traffic/status', methods=['GET'])
@auth_required()
def get_traffic_monitor_status():
    """Get traffic monitoring status"""
    try:
        response = requests.get(f"{TRAFFIC_MONITOR_URL}/health", timeout=5)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Traffic monitor not available'}), 503
    except requests.RequestException as e:
        logger.error(f"Error connecting to traffic monitor: {e}")
        return jsonify({'error': 'Traffic monitor unreachable'}), 503

@app.route('/api/traffic/zeek/start', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def start_zeek_monitoring():
    """Start Zeek network monitoring"""
    try:
        data = request.get_json() or {}
        
        # Log the action
        log_action(
            user_id=g.current_user_id,
            action='start_zeek_monitoring',
            details={'interface': data.get('interface', 'eth0'), 'log_dir': data.get('log_dir')},
            ip_address=request.remote_addr
        )
        
        response = requests.post(f"{TRAFFIC_MONITOR_URL}/start/zeek", json=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            
            # Emit real-time update
            emit_with_backpressure(
                'traffic_update',
                {
                    'type': 'zeek_started',
                    'success': result.get('success', False),
                    'interface': data.get('interface', 'eth0'),
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            return jsonify(result)
        else:
            return jsonify({'error': 'Failed to start Zeek monitoring'}), 500
            
    except Exception as e:
        logger.error(f"Error starting Zeek monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/zeek/stop', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def stop_zeek_monitoring():
    """Stop Zeek network monitoring"""
    try:
        data = request.get_json() or {}
        
        # Log the action
        log_action(
            user_id=g.current_user_id,
            action='stop_zeek_monitoring',
            details={'interface': data.get('interface', 'eth0')},
            ip_address=request.remote_addr
        )
        
        response = requests.post(f"{TRAFFIC_MONITOR_URL}/stop/zeek", json=data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            
            # Emit real-time update
            emit_with_backpressure(
                'traffic_update',
                {
                    'type': 'zeek_stopped',
                    'success': result.get('success', False),
                    'interface': data.get('interface', 'eth0'),
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            return jsonify(result)
        else:
            return jsonify({'error': 'Failed to stop Zeek monitoring'}), 500
            
    except Exception as e:
        logger.error(f"Error stopping Zeek monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/zeek/analyze', methods=['GET'])
@auth_required()
def analyze_zeek_logs():
    """Analyze Zeek logs and return results"""
    try:
        log_dir = request.args.get('log_dir', '/app/zeek_logs')
        
        response = requests.get(f"{TRAFFIC_MONITOR_URL}/analyze/zeek", 
                              params={'log_dir': log_dir}, timeout=30)
        
        if response.status_code == 200:
            analysis = response.json()
            
            # Emit real-time update with analysis summary
            emit_with_backpressure(
                'traffic_analysis',
                {
                    'type': 'zeek_analysis_complete',
                    'connections_count': len(analysis.get('connections', [])),
                    'http_requests_count': len(analysis.get('http_requests', [])),
                    'dns_queries_count': len(analysis.get('dns_queries', [])),
                    'anomalies_count': len(analysis.get('anomalies', [])),
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            return jsonify(analysis)
        else:
            return jsonify({'error': 'Failed to analyze Zeek logs'}), 500
            
    except Exception as e:
        logger.error(f"Error analyzing Zeek logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/statistics', methods=['GET'])
@auth_required()
def get_traffic_statistics():
    """Get traffic capture and analysis statistics"""
    try:
        response = requests.get(f"{TRAFFIC_MONITOR_URL}/statistics", timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Failed to get traffic statistics'}), 500
            
    except Exception as e:
        logger.error(f"Error getting traffic statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/pcap/analyze', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def analyze_pcap_file():
    """Analyze a PCAP file"""
    try:
        data = request.get_json() or {}
        pcap_file = data.get('pcap_file')
        
        if not pcap_file:
            return jsonify({'error': 'pcap_file parameter required'}), 400
        
        # Log the action
        log_action(
            user_id=g.current_user_id,
            action='analyze_pcap',
            details={'pcap_file': pcap_file},
            ip_address=request.remote_addr
        )
        
        response = requests.post(f"{TRAFFIC_MONITOR_URL}/analyze/pcap", 
                               json=data, timeout=60)
        
        if response.status_code == 200:
            analysis = response.json()
            
            # Emit real-time update
            emit_with_backpressure(
                'traffic_analysis',
                {
                    'type': 'pcap_analysis_complete',
                    'packets_count': len(analysis.get('packets', [])),
                    'anomalies_count': len(analysis.get('anomalies', [])),
                    'pcap_file': pcap_file,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            return jsonify(analysis)
        else:
            return jsonify({'error': 'Failed to analyze PCAP file'}), 500
            
    except Exception as e:
        logger.error(f"Error analyzing PCAP file: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/events/recent', methods=['GET'])
@auth_required()
def get_recent_traffic_events():
    """Get recent traffic events from Redis"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        # Get recent traffic events from Redis
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        
        # Scan for traffic event keys
        traffic_keys = []
        for key in redis_client.scan_iter(match="traffic_event:*"):
            traffic_keys.append(key.decode() if isinstance(key, bytes) else key)
        
        # Sort by timestamp (newest first)
        traffic_keys.sort(reverse=True)
        traffic_keys = traffic_keys[:limit]
        
        # Get event data
        events = []
        for key in traffic_keys:
            try:
                event_data = redis_client.get(key)
                if event_data:
                    if isinstance(event_data, bytes):
                        event_data = event_data.decode()
                    events.append(json.loads(event_data))
            except (json.JSONDecodeError, redis.RedisError):
                continue
        
        return jsonify({
            'events': events,
            'total': len(events),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting recent traffic events: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/anomalies', methods=['GET'])
@auth_required()
def get_traffic_anomalies():
    """Get traffic anomalies from Redis"""
    try:
        limit = request.args.get('limit', 100, type=int)
        
        # Get traffic anomalies from Redis
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        
        # Scan for anomaly keys
        anomaly_keys = []
        for key in redis_client.scan_iter(match="traffic_anomaly:*"):
            anomaly_keys.append(key.decode() if isinstance(key, bytes) else key)
        
        # Sort by timestamp (newest first)
        anomaly_keys.sort(reverse=True)
        anomaly_keys = anomaly_keys[:limit]
        
        # Get anomaly data
        anomalies = []
        for key in anomaly_keys:
            try:
                anomaly_data = redis_client.get(key)
                if anomaly_data:
                    if isinstance(anomaly_data, bytes):
                        anomaly_data = anomaly_data.decode()
                    anomalies.append(json.loads(anomaly_data))
            except (json.JSONDecodeError, redis.RedisError):
                continue
        
        # Emit real-time update if new anomalies
        if anomalies:
            emit_with_backpressure(
                'traffic_anomaly',
                {
                    'type': 'new_anomalies',
                    'count': len(anomalies),
                    'latest_anomaly': anomalies[0] if anomalies else None,
                    'timestamp': datetime.now().isoformat()
                }
            )
        
        return jsonify({
            'anomalies': anomalies,
            'total': len(anomalies),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting traffic anomalies: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/socket-stats', methods=['GET'])
@auth_required(roles=['admin'])
def get_socket_stats():
    """Get Socket.IO backpressure and rate limiting statistics."""
    try:
        with client_trackers_lock:
            active_clients = len(client_rate_trackers)
            client_event_counts = {}
            for client_id, tracker in client_rate_trackers.items():
                with tracker.lock:
                    client_event_counts[client_id] = len(tracker.events)
        
        with global_event_queue.lock:
            queue_size = len(global_event_queue.queue)
            max_queue_size = global_event_queue.max_size
        
        stats = {
            'backpressure': {
                'queue_size': queue_size,
                'max_queue_size': max_queue_size,
                'queue_utilization': round(queue_size / max_queue_size * 100, 2),
                'events_per_second_limit': global_event_queue.max_rate
            },
            'rate_limiting': {
                'active_clients': active_clients,
                'client_event_counts': client_event_counts,
                'config': SOCKET_RATE_LIMIT_CONFIG
            },
            'performance': {
                'last_emit_time': global_event_queue.last_emit_time,
                'emit_interval': global_event_queue.emit_interval
            }
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/socket-config', methods=['GET', 'POST'])
@auth_required(roles=['admin'])
def socket_config():
    """Get or update Socket.IO rate limiting configuration."""
    try:
        if request.method == 'GET':
            return jsonify({
                'config': SOCKET_RATE_LIMIT_CONFIG,
                'current_limits': {
                    'queue_size': global_event_queue.max_size,
                    'events_per_second': global_event_queue.max_rate
                }
            })
        
        if request.method == 'POST':
            data = request.get_json() or {}
            
            # Update configuration with validation
            if 'events_per_second' in data:
                new_rate = int(data['events_per_second'])
                if 1 <= new_rate <= 100:
                    SOCKET_RATE_LIMIT_CONFIG['events_per_second'] = new_rate
                    global_event_queue.max_rate = new_rate
                    global_event_queue.emit_interval = 1.0 / new_rate
            
            if 'max_queue_size' in data:
                new_size = int(data['max_queue_size'])
                if 10 <= new_size <= 1000:
                    SOCKET_RATE_LIMIT_CONFIG['max_queue_size'] = new_size
                    global_event_queue.max_size = new_size
                    global_event_queue.queue = deque(
                        list(global_event_queue.queue)[-new_size:],
                        maxlen=new_size
                    )
            
            if 'client_rate_limit' in data:
                new_limit = int(data['client_rate_limit'])
                if 1 <= new_limit <= 50:
                    SOCKET_RATE_LIMIT_CONFIG['client_rate_limit'] = new_limit
            
            log_action(
                'socket_config_update',
                {'config': SOCKET_RATE_LIMIT_CONFIG},
                user_id=getattr(g, 'current_user_id', None),
                ip_address=request.remote_addr,
            )
            
            return jsonify({'message': 'Configuration updated', 'config': SOCKET_RATE_LIMIT_CONFIG})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/health', methods=['GET'])
@limiter.limit("60 per minute")
def health_check():
    """System health check including backpressure status."""
    try:
        # Basic health indicators
        health = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'services': {
                'database': 'healthy',
                'socketio': 'healthy'
            }
        }
        
        # Check queue health
        with global_event_queue.lock:
            queue_utilization = len(global_event_queue.queue) / global_event_queue.max_size
            if queue_utilization > 0.9:
                health['status'] = 'degraded'
                health['services']['socketio'] = 'overloaded'
            elif queue_utilization > 0.7:
                health['status'] = 'warning'
                health['services']['socketio'] = 'high_load'
        
        # Check database
        try:
            db.session.execute('SELECT 1')
        except Exception:
            health['status'] = 'unhealthy'
            health['services']['database'] = 'unhealthy'
        
        return jsonify(health)
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


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
@limiter.limit("5 per minute")  # Very low limit for testing
def basic_health_check():
    """Basic health check endpoint with rate limiting"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'enrichment_available': ENRICHMENT_AVAILABLE
    })

@app.route('/api/test/rate-limit', methods=['GET'])
@limiter.limit("3 per minute")  # Very aggressive limit for testing
def test_rate_limiting():
    """Test endpoint specifically for rate limiting"""
    return jsonify({
        'message': 'Rate limit test successful',
        'timestamp': datetime.now().isoformat(),
        'limit_info': 'This endpoint allows only 3 requests per minute'
    })

@app.route('/api/auth/test-token', methods=['GET', 'POST'])
def get_test_token():
    """
    Development endpoint to get a test JWT token for API testing.
    
    This endpoint creates a test user if it doesn't exist and returns a token.
    For production, use /api/auth/login or /api/auth/signup instead.
    
    Usage in Postman:
    1. GET or POST to http://localhost:5000/api/auth/test-token
    2. Copy the "token" from response
    3. Use in Authorization header: "Bearer <token>"
    """
    try:
        with app.app_context():
            # Check if test user exists, create if not
            test_email = "test@example.com"
            test_user = User.query.filter_by(email=test_email).first()
            
            if not test_user:
                # Create test user
                test_user = User(
                    email=test_email,
                    name="Test User",
                    role="admin"  # Give admin role for full access
                )
                test_user.set_password("test123456")
                db.session.add(test_user)
                db.session.commit()
                logger.info("Created test user for API testing")
            
            # Generate token
            token = _generate_auth_token(test_user)
            
            return jsonify({
                "token": token,
                "user": _user_to_dict(test_user),
                "instructions": {
                    "usage": "Use this token in Postman Authorization header",
                    "header_format": "Authorization: Bearer <token>",
                    "example": f"Authorization: Bearer {token[:20]}...",
                    "note": "This is a development endpoint. Use /api/auth/login for production."
                }
            }), 200
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# Task 17-20: MITRE ATT&CK Attribution and SIEM Integration Endpoints
# ============================================================================

@app.route('/api/events/enrich', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def enrich_event():
    """
    Task 17: Enrich a detection event with MITRE ATT&CK technique IDs.
    
    Expected JSON body: {
        "event": {raw event data},
        "source_service": "traffic_monitor" | "behavioral_analysis" | "decoy_generator"
    }
    """
    if not ENRICHMENT_AVAILABLE:
        return jsonify({'error': 'Event enrichment service not available'}), 503
    
    try:
        data = request.get_json() or {}
        raw_event = data.get('event', {})
        source_service = data.get('source_service', 'unknown')
        
        if not raw_event:
            return jsonify({'error': 'No event data provided'}), 400
        
        # Enrich the event
        enriched_event = enrichment_service.enrich_event(raw_event, source_service)
        
        # Export to SIEM immediately if configured
        if siem_manager:
            siem_manager.export_event_immediately(enriched_event)
        
        return jsonify({
            'enriched_event': enriched_event.to_dict(),
            'message': 'Event enriched and exported to SIEM'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/enriched', methods=['GET'])
@auth_required()
def get_enriched_events():
    """Get recent enriched events"""
    if not ENRICHMENT_AVAILABLE:
        return jsonify({'error': 'Event enrichment service not available'}), 503
    
    try:
        limit = request.args.get('limit', 100, type=int)
        events = enrichment_service.get_enriched_events(limit=limit)
        
        return jsonify({
            'events': [e.to_dict() for e in events],
            'count': len(events)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/siem/status', methods=['GET'])
@auth_required()
def get_siem_status():
    """Get status of SIEM integrations"""
    if not ENRICHMENT_AVAILABLE:
        return jsonify({'error': 'SIEM integration not available'}), 503
    
    try:
        status = {
            'elastic': {
                'enabled': siem_manager.elastic_exporter.enabled if siem_manager else False,
                'url': siem_manager.elastic_exporter.elastic_url if siem_manager else None
            },
            'splunk': {
                'enabled': siem_manager.splunk_exporter.enabled if siem_manager else False,
                'url': siem_manager.splunk_exporter.splunk_url if siem_manager else None
            },
            'export_running': siem_manager.running if siem_manager else False
        }
        
        return jsonify(status), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/help', methods=['GET'])
def auth_help():
    """
    Help endpoint showing how to authenticate for API testing.
    
    Returns instructions for getting and using JWT tokens.
    """
    return jsonify({
        "message": "How to get an authentication token for API testing",
        "methods": {
            "method_1_test_token": {
                "description": "Quick test token (development only)",
                "endpoint": "GET /api/auth/test-token",
                "example": "http://localhost:5000/api/auth/test-token",
                "returns": "Token for test user (admin role)"
            },
            "method_2_signup": {
                "description": "Create new user account",
                "endpoint": "POST /api/auth/signup",
                "body": {
                    "name": "Your Name",
                    "email": "your@email.com",
                    "password": "yourpassword"
                },
                "returns": "Token for new user"
            },
            "method_3_login": {
                "description": "Login with existing account",
                "endpoint": "POST /api/auth/login",
                "body": {
                    "email": "your@email.com",
                    "password": "yourpassword"
                },
                "returns": "Token for authenticated user"
            }
        },
        "usage_in_postman": {
            "step_1": "Get token using one of the methods above",
            "step_2": "Copy the 'token' value from response",
            "step_3": "In Postman, go to Authorization tab",
            "step_4": "Select 'Bearer Token' type",
            "step_5": "Paste token in Token field",
            "step_6": "Or manually add header: Authorization: Bearer <token>"
        },
        "example_curl": {
            "get_token": "curl -X GET http://localhost:5000/api/auth/test-token",
            "use_token": "curl -X GET http://localhost:5000/api/siem/status -H 'Authorization: Bearer YOUR_TOKEN_HERE'"
        }
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    try:
        log_warning(
            logger,
            f"404 Not Found: {request.path}",
            correlation_id=getattr(g, 'correlation_id', None),
            ip_address=request.remote_addr,
            metadata={"method": request.method, "path": request.path}
        )
    except Exception:
        pass
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    try:
        log_error(
            logger,
            f"500 Internal Server Error: {str(error)}",
            correlation_id=getattr(g, 'correlation_id', None),
            ip_address=request.remote_addr,
            metadata={
                "method": request.method,
                "path": request.path,
                "error": str(error)
            }
        )
    except Exception:
        pass
    return jsonify({'error': 'Internal server error'}), 500

# ================================
# Model Versioning & Retraining API Endpoints (Section 6 - Task 24-25)
# ================================

# Initialize model versioning and retraining
# Note: We use a factory function to create instances with proper session handling
try:
    from model_versioning import ModelVersionManager
    from model_retraining import ModelRetrainingPipeline
    from retraining_triggers import RetrainingTriggerSystem
    
    # Create factory functions that use db.session within request context
    def get_model_version_manager():
        """Get model version manager with current session"""
        return ModelVersionManager(db.session)
    
    def get_retraining_pipeline():
        """Get retraining pipeline with current session"""
        return ModelRetrainingPipeline(db.session)
    
    def get_retraining_trigger_system():
        """Get retraining trigger system with current session"""
        pipeline = get_retraining_pipeline()
        return RetrainingTriggerSystem(db.session, pipeline)
    
    # Initialize for background thread (needs app context)
    with app.app_context():
        model_version_manager = ModelVersionManager(db.session)
        retraining_pipeline = ModelRetrainingPipeline(db.session)
        retraining_trigger_system = RetrainingTriggerSystem(db.session, retraining_pipeline)
        
        # Start background monitoring
        retraining_trigger_system.start()
        logger.info("Model retraining trigger system initialized and started")
except Exception as e:
    logger.warning(f"Could not initialize model retraining system: {e}")
    import traceback
    logger.warning(traceback.format_exc())
    model_version_manager = None
    retraining_pipeline = None
    retraining_trigger_system = None


@app.route('/api/models/versions', methods=['GET'])
@auth_required()
def get_model_versions():
    """Get model version history (Section 6 - Task 24)"""
    try:
        if not model_version_manager:
            return jsonify({'error': 'Model versioning not available'}), 503
        
        model_name = request.args.get('model_name')
        if not model_name:
            return jsonify({'error': 'model_name parameter required'}), 400
        
        limit = request.args.get('limit', 10, type=int)
        versions = model_version_manager.get_version_history(model_name, limit)
        return jsonify({'model_name': model_name, 'versions': versions})
        
    except Exception as e:
        logger.error(f"Error getting model versions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/active', methods=['GET'])
@auth_required()
def get_active_model_version():
    """Get active model version (Section 6 - Task 24)"""
    try:
        from model_versioning import ModelVersionManager
        
        model_name = request.args.get('model_name')
        if not model_name:
            return jsonify({'error': 'model_name parameter required'}), 400
        
        version_mgr = ModelVersionManager(db.session)
        version = version_mgr.get_active_version(model_name)
        if version:
            return jsonify(version)
        else:
            return jsonify({'error': 'No active version found'}), 404
            
    except Exception as e:
        logger.error(f"Error getting active version: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/rollback', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def rollback_model_version():
    """Rollback to a previous model version (Section 6 - Task 24)"""
    try:
        from model_versioning import ModelVersionManager
        
        data = request.get_json()
        model_name = data.get('model_name')
        version = data.get('version')
        
        if not model_name or not version:
            return jsonify({'error': 'model_name and version required'}), 400
        
        version_mgr = ModelVersionManager(db.session)
        success = version_mgr.rollback_to_version(model_name, version)
        if success:
            log_action(
                'rollback_model',
                {'model_name': model_name, 'version': version},
                user_id=getattr(g, 'current_user_id', None),
                ip_address=request.remote_addr
            )
            return jsonify({'success': True, 'message': f'Rolled back {model_name} to version {version}'})
        else:
            return jsonify({'error': 'Rollback failed'}), 500
            
    except Exception as e:
        logger.error(f"Error rolling back model: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/compare', methods=['GET'])
@auth_required()
def compare_model_versions():
    """Compare two model versions (Section 6 - Task 24)"""
    try:
        from model_versioning import ModelVersionManager
        
        model_name = request.args.get('model_name')
        version1 = request.args.get('version1', type=int)
        version2 = request.args.get('version2', type=int)
        
        if not all([model_name, version1, version2]):
            return jsonify({'error': 'model_name, version1, and version2 required'}), 400
        
        version_mgr = ModelVersionManager(db.session)
        comparison = version_mgr.compare_versions(model_name, version1, version2)
        if comparison:
            return jsonify(comparison)
        else:
            return jsonify({'error': 'Versions not found'}), 404
            
    except Exception as e:
        logger.error(f"Error comparing versions: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/retrain', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def trigger_model_retraining():
    """Manually trigger model retraining (Section 6 - Task 24)"""
    try:
        from model_retraining import ModelRetrainingPipeline
        
        data = request.get_json() or {}
        model_name = data.get('model_name', 'lstm')
        
        pipeline = ModelRetrainingPipeline(db.session)
        job_id = pipeline.schedule_retraining(
            model_name=model_name,
            trigger_type='manual',
            trigger_reason=data.get('reason', 'Manual retraining request')
        )
        
        if job_id:
            log_action(
                'trigger_retraining',
                {'model_name': model_name, 'job_id': job_id},
                user_id=getattr(g, 'current_user_id', None),
                ip_address=request.remote_addr
            )
            
            # Execute in background with app context
            import threading
            def execute_with_context():
                with app.app_context():
                    pipeline.execute_retraining_job(job_id)
            
            threading.Thread(target=execute_with_context, daemon=True).start()
            
            return jsonify({'job_id': job_id, 'status': 'scheduled', 'message': 'Retraining job scheduled'}), 202
        else:
            return jsonify({'error': 'Failed to schedule retraining'}), 500
            
    except Exception as e:
        logger.error(f"Error triggering retraining: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/retrain/jobs', methods=['GET'])
@auth_required()
def get_retraining_jobs():
    """Get retraining job history (Section 6 - Task 24)"""
    try:
        from app import RetrainingJob
        
        model_name = request.args.get('model_name')
        status = request.args.get('status')
        limit = request.args.get('limit', 20, type=int)
        
        query = db.session.query(RetrainingJob)
        
        if model_name:
            query = query.filter(RetrainingJob.model_name == model_name)
        if status:
            query = query.filter(RetrainingJob.status == status)
        
        jobs = query.order_by(RetrainingJob.created_at.desc()).limit(limit).all()
        
        return jsonify({
            'jobs': [
                {
                    'job_id': job.job_id,
                    'model_name': job.model_name,
                    'status': job.status,
                    'trigger_type': job.trigger_type,
                    'trigger_reason': job.trigger_reason,
                    'created_at': job.created_at.isoformat() if job.created_at else None,
                    'started_at': job.started_at.isoformat() if job.started_at else None,
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                    'duration_seconds': job.duration_seconds,
                    'new_version_id': job.new_version_id,
                    'rollback_performed': job.rollback_performed,
                    'error_message': job.error_message
                }
                for job in jobs
            ]
        })
        
    except Exception as e:
        logger.error(f"Error getting retraining jobs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/models/retrain/check', methods=['POST'])
@auth_required(roles=['admin', 'analyst'])
def check_retraining_conditions():
    """Manually check retraining conditions (Section 6 - Task 25)"""
    try:
        from retraining_triggers import RetrainingTriggerSystem
        from model_retraining import ModelRetrainingPipeline
        
        data = request.get_json() or {}
        model_name = data.get('model_name')
        
        pipeline = ModelRetrainingPipeline(db.session)
        trigger_system = RetrainingTriggerSystem(db.session, pipeline)
        
        if model_name:
            # Check specific model
            performance_check = trigger_system._check_performance_degradation(model_name)
            data_check = trigger_system._check_sufficient_new_data(model_name)
            scheduled_check = trigger_system._check_scheduled_retrain(model_name)
            
            return jsonify({
                'model_name': model_name,
                'performance_degradation': performance_check,
                'sufficient_new_data': data_check,
                'scheduled_retrain_due': scheduled_check,
                'should_retrain': performance_check or data_check or scheduled_check
            })
        else:
            # Check all models
            trigger_system.check_retraining_conditions()
            return jsonify({'message': 'Retraining conditions checked for all models'})
            
    except Exception as e:
        logger.error(f"Error checking retraining conditions: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Use Socket.IO server for real-time capabilities
    # allow_unsafe_werkzeug=True is required with newer Werkzeug when running
    # the development server in a non-debug container environment.
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
