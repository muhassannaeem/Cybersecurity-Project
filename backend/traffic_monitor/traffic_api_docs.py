"""
Traffic Monitor API Documentation
OpenAPI/Swagger documentation for the Traffic Monitor microservice
"""

from flask_restx import Api, Resource, fields, Namespace
from flask import Blueprint

# Create Blueprint for traffic monitor API docs
traffic_api_blueprint = Blueprint('traffic_api_docs', __name__, url_prefix='/docs')

# Initialize Flask-RESTX API for traffic monitor
traffic_api = Api(
    traffic_api_blueprint,
    version='1.0',
    title='Traffic Monitor API',
    description='Network traffic monitoring and analysis service with Zeek and tcpdump integration',
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

# Common models
error_model = traffic_api.model('Error', {
    'error': fields.String(required=True, description='Error message')
})

success_model = traffic_api.model('Success', {
    'success': fields.Boolean(required=True, description='Operation success status')
})

# Health namespace
health_ns = Namespace('health', description='Service health monitoring')

health_response_model = health_ns.model('HealthResponse', {
    'status': fields.String(description='Service health status'),
    'service': fields.String(description='Service name'),
    'statistics': fields.Raw(description='Service statistics')
})

@health_ns.route('')
class HealthCheck(Resource):
    @health_ns.response(200, 'Service is healthy', health_response_model)
    def get(self):
        """Check service health status"""
        pass

# Zeek control namespace
zeek_ns = Namespace('zeek', description='Zeek network monitoring control')

zeek_start_model = zeek_ns.model('ZeekStartRequest', {
    'interface': fields.String(description='Network interface to monitor (default: eth0)', example='eth0'),
    'log_dir': fields.String(description='Directory for Zeek logs (default: /app/zeek_logs)', example='/app/zeek_logs')
})

zeek_stop_model = zeek_ns.model('ZeekStopRequest', {
    'interface': fields.String(description='Network interface to stop monitoring', example='eth0')
})

@zeek_ns.route('/start')
class ZeekStart(Resource):
    @zeek_ns.expect(zeek_start_model)
    @zeek_ns.response(200, 'Zeek monitoring started', success_model)
    @zeek_ns.response(400, 'Invalid input parameters', error_model)
    @zeek_ns.response(401, 'Authentication required', error_model)
    @zeek_ns.response(500, 'Internal server error', error_model)
    @zeek_ns.doc(security='apikey')
    def post(self):
        """Start Zeek network monitoring on specified interface"""
        pass

@zeek_ns.route('/stop')
class ZeekStop(Resource):
    @zeek_ns.expect(zeek_stop_model)
    @zeek_ns.response(200, 'Zeek monitoring stopped', success_model)
    @zeek_ns.response(400, 'Invalid input parameters', error_model)
    @zeek_ns.response(401, 'Authentication required', error_model)
    @zeek_ns.response(500, 'Internal server error', error_model)
    @zeek_ns.doc(security='apikey')
    def post(self):
        """Stop Zeek network monitoring on specified interface"""
        pass

# Tcpdump control namespace
tcpdump_ns = Namespace('tcpdump', description='Tcpdump packet capture control')

tcpdump_start_model = tcpdump_ns.model('TcpdumpStartRequest', {
    'interface': fields.String(description='Network interface to capture from', example='eth0'),
    'capture_file': fields.String(description='File path for packet capture', example='/app/captures/capture.pcap')
})

tcpdump_stop_model = tcpdump_ns.model('TcpdumpStopRequest', {
    'interface': fields.String(description='Network interface to stop capturing', example='eth0')
})

@tcpdump_ns.route('/start')
class TcpdumpStart(Resource):
    @tcpdump_ns.expect(tcpdump_start_model)
    @tcpdump_ns.response(200, 'Packet capture started', success_model)
    @tcpdump_ns.response(400, 'Invalid input parameters', error_model)
    @tcpdump_ns.response(401, 'Authentication required', error_model)
    @tcpdump_ns.response(500, 'Internal server error', error_model)
    @tcpdump_ns.doc(security='apikey')
    def post(self):
        """Start tcpdump packet capture on specified interface"""
        pass

@tcpdump_ns.route('/stop')
class TcpdumpStop(Resource):
    @tcpdump_ns.expect(tcpdump_stop_model)
    @tcpdump_ns.response(200, 'Packet capture stopped', success_model)
    @tcpdump_ns.response(400, 'Invalid input parameters', error_model)
    @tcpdump_ns.response(401, 'Authentication required', error_model)
    @tcpdump_ns.response(500, 'Internal server error', error_model)
    @tcpdump_ns.doc(security='apikey')
    def post(self):
        """Stop tcpdump packet capture on specified interface"""
        pass

# Analysis namespace
analysis_ns = Namespace('analysis', description='Traffic analysis operations')

zeek_analysis_model = analysis_ns.model('ZeekAnalysisResponse', {
    'status': fields.String(description='Analysis status'),
    'results': fields.Raw(description='Analysis results')
})

pcap_analysis_model = analysis_ns.model('PcapAnalysisRequest', {
    'pcap_file': fields.String(description='Path to PCAP file for analysis', example='/app/captures/capture.pcap')
})

@analysis_ns.route('/zeek')
class ZeekAnalysis(Resource):
    @analysis_ns.param('log_dir', 'Directory containing Zeek logs', type='string', default='/app/zeek_logs')
    @analysis_ns.response(200, 'Analysis completed', zeek_analysis_model)
    @analysis_ns.response(400, 'Invalid log directory', error_model)
    @analysis_ns.response(401, 'Authentication required', error_model)
    @analysis_ns.response(500, 'Internal server error', error_model)
    @analysis_ns.doc(security='apikey')
    def get(self):
        """Analyze Zeek logs and extract network insights"""
        pass

@analysis_ns.route('/pcap')
class PcapAnalysis(Resource):
    @analysis_ns.expect(pcap_analysis_model)
    @analysis_ns.response(200, 'PCAP analysis completed', zeek_analysis_model)
    @analysis_ns.response(400, 'Invalid PCAP file', error_model)
    @analysis_ns.response(401, 'Authentication required', error_model)
    @analysis_ns.response(500, 'Internal server error', error_model)
    @analysis_ns.doc(security='apikey')
    def post(self):
        """Analyze uploaded PCAP file for network anomalies"""
        pass

# Statistics namespace
stats_ns = Namespace('statistics', description='Traffic monitoring statistics')

statistics_model = stats_ns.model('TrafficStatistics', {
    'zeek_running': fields.Boolean(description='Zeek monitoring status'),
    'active_captures': fields.List(fields.String, description='Active capture interfaces'),
    'capture_stats': fields.Raw(description='Detailed capture statistics'),
    'tcpdump_captures': fields.Integer(description='Number of active tcpdump captures')
})

@stats_ns.route('')
class TrafficStatistics(Resource):
    @stats_ns.response(200, 'Statistics retrieved', statistics_model)
    @stats_ns.response(401, 'Authentication required', error_model)
    @stats_ns.response(500, 'Internal server error', error_model)
    @stats_ns.doc(security='apikey')
    def get(self):
        """Get current traffic monitoring statistics"""
        pass

# Register namespaces
traffic_api.add_namespace(health_ns, path='/health')
traffic_api.add_namespace(zeek_ns, path='/start')  # Maps to /start/zeek, /stop/zeek
traffic_api.add_namespace(tcpdump_ns, path='/start')  # Maps to /start/tcpdump, /stop/tcpdump
traffic_api.add_namespace(analysis_ns, path='/analyze')
traffic_api.add_namespace(stats_ns, path='/statistics')