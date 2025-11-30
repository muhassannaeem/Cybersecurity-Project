"""
API Documentation Module using Flask-RESTX
Provides OpenAPI/Swagger documentation for all backend services
"""

from flask_restx import Api, Resource, fields, Namespace
from flask import Blueprint

# Create Blueprint for API docs
api_blueprint = Blueprint('api_docs', __name__, url_prefix='/api/docs')

# Initialize Flask-RESTX API
api = Api(
    api_blueprint,
    version='1.0',
    title='Cybersecurity Platform API',
    description='Advanced Cybersecurity Platform with AI-driven threat detection, honeypots, and real-time monitoring',
    doc='/swagger/',
    security='apikey',
    authorizations={
        'apikey': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'JWT token in format: Bearer <token>'
        }
    }
)

# Define common models
error_model = api.model('Error', {
    'error': fields.String(required=True, description='Error message'),
    'details': fields.Raw(description='Additional error details')
})

success_model = api.model('Success', {
    'success': fields.Boolean(required=True, description='Operation success status'),
    'message': fields.String(description='Success message')
})

# Authentication namespace
auth_ns = Namespace('auth', description='Authentication operations')

# Authentication models
user_signup_model = auth_ns.model('UserSignup', {
    'name': fields.String(required=True, description='User full name'),
    'email': fields.String(required=True, description='User email address'),
    'password': fields.String(required=True, description='User password (min 8 characters)')
})

user_login_model = auth_ns.model('UserLogin', {
    'email': fields.String(required=True, description='User email address'),
    'password': fields.String(required=True, description='User password')
})

auth_response_model = auth_ns.model('AuthResponse', {
    'token': fields.String(required=True, description='JWT authentication token'),
    'user': fields.Raw(description='User information')
})

@auth_ns.route('/signup')
class UserSignup(Resource):
    @auth_ns.expect(user_signup_model)
    @auth_ns.response(201, 'User created successfully', auth_response_model)
    @auth_ns.response(400, 'Invalid input data', error_model)
    @auth_ns.response(409, 'User already exists', error_model)
    def post(self):
        """Create a new user account"""
        pass

@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.expect(user_login_model)
    @auth_ns.response(200, 'Login successful', auth_response_model)
    @auth_ns.response(401, 'Invalid credentials', error_model)
    @auth_ns.response(400, 'Invalid input data', error_model)
    def post(self):
        """Authenticate user and return JWT token"""
        pass

@auth_ns.route('/test-token')
class TestToken(Resource):
    @auth_ns.response(200, 'Token is valid')
    @auth_ns.response(401, 'Invalid token', error_model)
    @auth_ns.doc(security='apikey')
    def get(self):
        """Test JWT token validity"""
        pass
        
    @auth_ns.response(200, 'Token test completed')
    def post(self):
        """Test JWT token creation"""
        pass

@auth_ns.route('/help')
class AuthHelp(Resource):
    @auth_ns.response(200, 'Authentication help information')
    def get(self):
        """Get authentication help and documentation"""
        pass

# Dashboard namespace
dashboard_ns = Namespace('dashboard', description='Dashboard data operations')

dashboard_stats_model = dashboard_ns.model('DashboardStats', {
    'total_threats': fields.Integer(description='Total number of threats detected'),
    'active_decoys': fields.Integer(description='Number of active honeypots'),
    'recent_attacks': fields.Integer(description='Recent attacks count'),
    'system_health': fields.String(description='Overall system health status')
})

@dashboard_ns.route('/stats')
class DashboardStats(Resource):
    @dashboard_ns.response(200, 'Success', dashboard_stats_model)
    @dashboard_ns.response(401, 'Authentication required', error_model)
    @dashboard_ns.doc(security='apikey')
    def get(self):
        """Get dashboard statistics"""
        pass

# Anomalies namespace
anomalies_ns = Namespace('anomalies', description='Anomaly detection and management')

anomaly_model = anomalies_ns.model('Anomaly', {
    'id': fields.Integer(description='Anomaly ID'),
    'timestamp': fields.DateTime(description='Detection timestamp'),
    'type': fields.String(description='Anomaly type'),
    'severity': fields.String(description='Severity level'),
    'confidence': fields.Float(description='Detection confidence'),
    'details': fields.Raw(description='Anomaly details')
})

@anomalies_ns.route('/recent')
class RecentAnomalies(Resource):
    @anomalies_ns.response(200, 'Success', [anomaly_model])
    @anomalies_ns.response(401, 'Authentication required', error_model)
    @anomalies_ns.doc(security='apikey')
    def get(self):
        """Get recent anomalies detected by the system"""
        pass

# Threats namespace
threats_ns = Namespace('threats', description='Threat detection and management')

threat_model = threats_ns.model('Threat', {
    'id': fields.Integer(description='Threat ID'),
    'timestamp': fields.DateTime(description='Threat detection timestamp'),
    'source': fields.String(description='Threat source IP'),
    'destination': fields.String(description='Threat destination IP'),
    'threat_type': fields.String(description='Type of threat detected'),
    'severity': fields.String(description='Threat severity level'),
    'status': fields.String(description='Threat status'),
    'description': fields.String(description='Threat description'),
    'mitre_techniques': fields.List(fields.String, description='MITRE ATT&CK techniques')
})

@threats_ns.route('')
@threats_ns.route('/recent')
class Threats(Resource):
    @threats_ns.response(200, 'Success', [threat_model])
    @threats_ns.response(401, 'Authentication required', error_model)
    @threats_ns.doc(security='apikey')
    def get(self):
        """Get recent threats"""
        pass

# Decoys namespace
decoys_ns = Namespace('decoys', description='Honeypot management')

decoy_deploy_model = decoys_ns.model('DecoyDeploy', {
    'name': fields.String(required=True, description='Decoy name'),
    'type': fields.String(required=True, description='Decoy type (ssh, web, ftp, etc.)'),
    'config': fields.Raw(description='Decoy configuration parameters')
})

decoy_response_model = decoys_ns.model('DecoyResponse', {
    'id': fields.String(description='Decoy ID'),
    'name': fields.String(description='Decoy name'),
    'type': fields.String(description='Decoy type'),
    'status': fields.String(description='Decoy status'),
    'created_at': fields.DateTime(description='Creation timestamp')
})

@decoys_ns.route('/deploy')
class DecoyDeploy(Resource):
    @decoys_ns.expect(decoy_deploy_model)
    @decoys_ns.response(201, 'Decoy deployed successfully', decoy_response_model)
    @decoys_ns.response(400, 'Invalid configuration', error_model)
    @decoys_ns.response(401, 'Authentication required', error_model)
    @decoys_ns.doc(security='apikey')
    def post(self):
        """Deploy a new honeypot decoy"""
        pass

@decoys_ns.route('')
class DecoyList(Resource):
    @decoys_ns.response(200, 'Success', [decoy_response_model])
    @decoys_ns.response(401, 'Authentication required', error_model)
    @decoys_ns.doc(security='apikey')
    def get(self):
        """List all deployed decoys"""
        pass

# Traffic namespace
traffic_ns = Namespace('traffic', description='Network traffic monitoring')

traffic_status_model = traffic_ns.model('TrafficStatus', {
    'zeek_running': fields.Boolean(description='Zeek monitoring status'),
    'tcpdump_running': fields.Boolean(description='Tcpdump capture status'),
    'active_captures': fields.List(fields.String, description='Active capture interfaces')
})

zeek_control_model = traffic_ns.model('ZeekControl', {
    'interface': fields.String(description='Network interface to monitor'),
    'log_dir': fields.String(description='Directory for Zeek logs')
})

traffic_event_model = traffic_ns.model('TrafficEvent', {
    'timestamp': fields.DateTime(description='Event timestamp'),
    'source_ip': fields.String(description='Source IP address'),
    'destination_ip': fields.String(description='Destination IP address'),
    'protocol': fields.String(description='Network protocol'),
    'event_type': fields.String(description='Type of traffic event')
})

traffic_anomaly_model = traffic_ns.model('TrafficAnomaly', {
    'timestamp': fields.DateTime(description='Anomaly detection timestamp'),
    'anomaly_type': fields.String(description='Type of anomaly detected'),
    'severity': fields.String(description='Anomaly severity level'),
    'details': fields.Raw(description='Anomaly details')
})

@traffic_ns.route('/status')
class TrafficStatus(Resource):
    @traffic_ns.response(200, 'Success', traffic_status_model)
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def get(self):
        """Get traffic monitoring status"""
        pass

@traffic_ns.route('/zeek/start')
class ZeekStart(Resource):
    @traffic_ns.expect(zeek_control_model)
    @traffic_ns.response(200, 'Zeek started successfully', success_model)
    @traffic_ns.response(400, 'Invalid parameters', error_model)
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def post(self):
        """Start Zeek network monitoring"""
        pass

@traffic_ns.route('/zeek/stop')
class ZeekStop(Resource):
    @traffic_ns.expect(zeek_control_model)
    @traffic_ns.response(200, 'Zeek stopped successfully', success_model)
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def post(self):
        """Stop Zeek network monitoring"""
        pass

@traffic_ns.route('/zeek/analyze')
class ZeekAnalyze(Resource):
    @traffic_ns.response(200, 'Analysis results', success_model)
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def get(self):
        """Analyze Zeek logs"""
        pass

@traffic_ns.route('/statistics')
class TrafficStatistics(Resource):
    @traffic_ns.response(200, 'Traffic statistics', traffic_status_model)
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def get(self):
        """Get traffic monitoring statistics"""
        pass

@traffic_ns.route('/pcap/analyze')
class PcapAnalyze(Resource):
    @traffic_ns.response(200, 'PCAP analysis results', success_model)
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def post(self):
        """Analyze PCAP file"""
        pass

@traffic_ns.route('/events/recent')
class TrafficEvents(Resource):
    @traffic_ns.response(200, 'Recent traffic events', [traffic_event_model])
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def get(self):
        """Get recent traffic events"""
        pass

@traffic_ns.route('/anomalies')
class TrafficAnomalies(Resource):
    @traffic_ns.response(200, 'Traffic anomalies', [traffic_anomaly_model])
    @traffic_ns.response(401, 'Authentication required', error_model)
    @traffic_ns.doc(security='apikey')
    def get(self):
        """Get detected traffic anomalies"""
        pass

# Metrics namespace
metrics_ns = Namespace('metrics', description='System metrics and analytics')

metrics_summary_model = metrics_ns.model('MetricsSummary', {
    'detection_latency': fields.Float(description='Average detection latency in seconds'),
    'false_positive_rate': fields.Float(description='False positive rate percentage'),
    'threat_trends': fields.Raw(description='Threat trend data'),
    'system_performance': fields.Raw(description='System performance metrics')
})

@metrics_ns.route('/summary')
class MetricsSummary(Resource):
    @metrics_ns.response(200, 'Success', metrics_summary_model)
    @metrics_ns.response(401, 'Authentication required', error_model)
    @metrics_ns.doc(security='apikey')
    def get(self):
        """Get system metrics summary"""
        pass

# Analysis namespace
analysis_ns = Namespace('analysis', description='Behavioral analysis operations')

analysis_run_model = analysis_ns.model('AnalysisRun', {
    'analysis_type': fields.String(required=True, description='Type of analysis to run'),
    'parameters': fields.Raw(description='Analysis parameters')
})

@analysis_ns.route('/run')
class AnalysisRun(Resource):
    @analysis_ns.expect(analysis_run_model)
    @analysis_ns.response(200, 'Analysis started', success_model)
    @analysis_ns.response(400, 'Invalid parameters', error_model)
    @analysis_ns.response(401, 'Authentication required', error_model)
    @analysis_ns.doc(security='apikey')
    def post(self):
        """Run behavioral analysis"""
        pass

# System namespace
system_ns = Namespace('system', description='System management operations')

health_model = system_ns.model('HealthStatus', {
    'status': fields.String(description='Overall system status'),
    'services': fields.Raw(description='Individual service statuses'),
    'uptime': fields.String(description='System uptime'),
    'version': fields.String(description='System version')
})

socket_stats_model = system_ns.model('SocketStats', {
    'connected_clients': fields.Integer(description='Number of connected WebSocket clients'),
    'total_connections': fields.Integer(description='Total connections since start'),
    'events_sent': fields.Integer(description='Total events sent'),
    'uptime': fields.String(description='Server uptime')
})

socket_config_model = system_ns.model('SocketConfig', {
    'max_connections': fields.Integer(description='Maximum allowed connections'),
    'event_rate_limit': fields.Integer(description='Event rate limit per client'),
    'enabled': fields.Boolean(description='WebSocket service enabled')
})

@system_ns.route('/health')
class SystemHealth(Resource):
    @system_ns.response(200, 'System is healthy', health_model)
    @system_ns.response(503, 'System issues detected', error_model)
    def get(self):
        """Get comprehensive system health status"""
        pass

@system_ns.route('/socket-stats')
class SocketStats(Resource):
    @system_ns.response(200, 'WebSocket statistics', socket_stats_model)
    @system_ns.response(401, 'Authentication required', error_model)
    @system_ns.doc(security='apikey')
    def get(self):
        """Get WebSocket connection statistics"""
        pass

@system_ns.route('/socket-config')
class SocketConfig(Resource):
    @system_ns.response(200, 'WebSocket configuration', socket_config_model)
    @system_ns.response(401, 'Authentication required', error_model)
    @system_ns.doc(security='apikey')
    def get(self):
        """Get WebSocket configuration"""
        pass
        
    @system_ns.expect(socket_config_model)
    @system_ns.response(200, 'Configuration updated', success_model)
    @system_ns.response(401, 'Authentication required', error_model)
    @system_ns.doc(security='apikey')
    def post(self):
        """Update WebSocket configuration"""
        pass

# Register namespaces with correct paths matching actual endpoints
api.add_namespace(auth_ns, path='/auth')
api.add_namespace(dashboard_ns, path='/dashboard')
api.add_namespace(anomalies_ns, path='/anomalies')
api.add_namespace(threats_ns, path='/threats')
api.add_namespace(decoys_ns, path='/decoys')
api.add_namespace(traffic_ns, path='/traffic')
api.add_namespace(metrics_ns, path='/metrics')
api.add_namespace(analysis_ns, path='/analysis')
api.add_namespace(system_ns, path='/system')

# Add missing namespaces for actual endpoints
alerts_ns = Namespace('alerts', description='Alert management')
events_ns = Namespace('events', description='Event enrichment')
siem_ns = Namespace('siem', description='SIEM integration')
attribution_ns = Namespace('attribution', description='Threat attribution')
health_ns = Namespace('health', description='System health')
test_ns = Namespace('test', description='Testing endpoints')

# Health endpoints
@health_ns.route('')
class Health(Resource):
    @health_ns.response(200, 'System is healthy')
    def get(self):
        """Get basic system health status"""
        pass

# Alerts endpoints  
alert_model = alerts_ns.model('Alert', {
    'id': fields.Integer(description='Alert ID'),
    'timestamp': fields.DateTime(description='Alert timestamp'),
    'severity': fields.String(description='Alert severity'),
    'message': fields.String(description='Alert message'),
    'source': fields.String(description='Alert source')
})

@alerts_ns.route('')
class AlertList(Resource):
    @alerts_ns.response(200, 'Success', [alert_model])
    @alerts_ns.response(401, 'Authentication required', error_model)
    @alerts_ns.doc(security='apikey')
    def get(self):
        """Get recent alerts"""
        pass

# Events endpoints
enriched_event_model = events_ns.model('EnrichedEvent', {
    'event_id': fields.String(description='Event ID'),
    'timestamp': fields.DateTime(description='Event timestamp'),
    'source_ip': fields.String(description='Source IP address'),
    'destination_ip': fields.String(description='Destination IP address'),
    'mitre_techniques': fields.List(fields.String, description='MITRE ATT&CK techniques'),
    'confidence_score': fields.Float(description='Attribution confidence score')
})

@events_ns.route('/enrich')
class EventEnrich(Resource):
    @events_ns.response(200, 'Event enriched successfully')
    @events_ns.response(401, 'Authentication required', error_model)
    @events_ns.doc(security='apikey')
    def post(self):
        """Enrich event with threat intelligence"""
        pass

@events_ns.route('/enriched')
class EnrichedEvents(Resource):
    @events_ns.response(200, 'Success', [enriched_event_model])
    @events_ns.response(401, 'Authentication required', error_model)
    @events_ns.doc(security='apikey')
    def get(self):
        """Get enriched events"""
        pass

# SIEM endpoints
@siem_ns.route('/status')
class SIEMStatus(Resource):
    @siem_ns.response(200, 'SIEM integration status')
    @siem_ns.response(401, 'Authentication required', error_model)
    @siem_ns.doc(security='apikey')
    def get(self):
        """Get SIEM integration status"""
        pass

# Attribution endpoints
@attribution_ns.route('/report')
class AttributionReport(Resource):
    @attribution_ns.response(200, 'Attribution report')
    @attribution_ns.response(401, 'Authentication required', error_model)
    @attribution_ns.doc(security='apikey')
    def get(self):
        """Get threat attribution report"""
        pass

# Test endpoints
@test_ns.route('/rate-limit')
class RateLimitTest(Resource):
    @test_ns.response(200, 'Rate limit test response')
    def get(self):
        """Test rate limiting functionality"""
        pass

# Register additional namespaces
api.add_namespace(alerts_ns, path='/alerts')
api.add_namespace(events_ns, path='/events') 
api.add_namespace(siem_ns, path='/siem')
api.add_namespace(attribution_ns, path='/attribution')
api.add_namespace(health_ns, path='/health')
api.add_namespace(test_ns, path='/test')