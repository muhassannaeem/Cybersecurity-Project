import dash
from dash import dcc, html, Input, Output, callback
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import json
import redis
import requests
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Optional
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "Cybersecurity System Dashboard"

# Redis connection
redis_client = redis.from_url("redis://redis:6379")

# API endpoints
API_ENDPOINTS = {
    'backend': 'http://backend:5000',
    'behavioral_analysis': 'http://behavioral_analysis:5001',
    'decoy_generator': 'http://decoy_generator:5002',
    'traffic_monitor': 'http://traffic_monitor:5003',
    'threat_attribution': 'http://threat_attribution:5004'
}

class DashboardDataManager:
    """Manages data collection and processing for the dashboard"""
    
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 30  # seconds
        self.last_update = {}
    
    def get_cached_data(self, key: str, fetch_func, force_refresh=False):
        """Get cached data or fetch new data if needed"""
        current_time = time.time()
        
        if (force_refresh or 
            key not in self.cache or 
            key not in self.last_update or
            current_time - self.last_update[key] > self.cache_timeout):
            
            try:
                self.cache[key] = fetch_func()
                self.last_update[key] = current_time
                logger.info(f"Refreshed cache for {key}")
            except Exception as e:
                logger.error(f"Error fetching data for {key}: {e}")
                if key not in self.cache:
                    self.cache[key] = {}
        
        return self.cache[key]
    
    def fetch_dashboard_stats(self):
        """Fetch dashboard statistics from backend"""
        try:
            response = requests.get(f"{API_ENDPOINTS['backend']}/api/dashboard/stats", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return self._generate_mock_stats()
        except:
            return self._generate_mock_stats()
    
    def fetch_threat_data(self):
        """Fetch threat data from backend"""
        try:
            response = requests.get(f"{API_ENDPOINTS['backend']}/api/threats", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return self._generate_mock_threats()
        except:
            return self._generate_mock_threats()
    
    def fetch_behavioral_analysis(self):
        """Fetch behavioral analysis data"""
        try:
            response = requests.get(f"{API_ENDPOINTS['behavioral_analysis']}/health", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return self._generate_mock_behavioral_data()
        except:
            return self._generate_mock_behavioral_data()
    
    def fetch_traffic_data(self):
        """Fetch traffic monitoring data"""
        try:
            response = requests.get(f"{API_ENDPOINTS['traffic_monitor']}/statistics", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return self._generate_mock_traffic_data()
        except:
            return self._generate_mock_traffic_data()
    
    def fetch_attribution_data(self):
        """Fetch threat attribution data"""
        try:
            response = requests.get(f"{API_ENDPOINTS['threat_attribution']}/mitre_data", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return self._generate_mock_attribution_data()
        except:
            return self._generate_mock_attribution_data()
    
    def _generate_mock_stats(self):
        """Generate mock dashboard statistics"""
        return {
            'totalAlerts': 156,
            'activeThreats': 23,
            'decoysDeployed': 8,
            'detectionRate': 94.2,
            'falsePositives': 12,
            'responseTime': 2.3
        }
    
    def _generate_mock_threats(self):
        """Generate mock threat data"""
        threats = []
        threat_types = ['Malware', 'Phishing', 'DDoS', 'Data Exfiltration', 'Ransomware']
        severities = ['low', 'medium', 'high', 'critical']
        statuses = ['active', 'resolved', 'investigating']
        
        for i in range(20):
            threats.append({
                'id': f"threat_{i}",
                'timestamp': (datetime.now() - timedelta(hours=np.random.randint(1, 72))).isoformat(),
                'source': f"192.168.1.{np.random.randint(1, 255)}",
                'destination': f"10.0.0.{np.random.randint(1, 255)}",
                'threatType': np.random.choice(threat_types),
                'severity': np.random.choice(severities),
                'status': np.random.choice(statuses)
            })
        
        return threats
    
    def _generate_mock_behavioral_data(self):
        """Generate mock behavioral analysis data"""
        return {
            'models': {
                'lstm': {'accuracy': 0.89, 'anomalies_detected': 45},
                'isolation_forest': {'accuracy': 0.92, 'anomalies_detected': 38},
                'autoencoder': {'accuracy': 0.87, 'anomalies_detected': 52}
            },
            'recent_anomalies': [
                {'timestamp': datetime.now().isoformat(), 'score': 0.95, 'type': 'network_traffic'},
                {'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(), 'score': 0.87, 'type': 'user_behavior'},
                {'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(), 'score': 0.92, 'type': 'system_activity'}
            ]
        }
    
    def _generate_mock_traffic_data(self):
        """Generate mock traffic data"""
        return {
            'zeek_running': True,
            'tcpdump_captures': 2,
            'capture_stats': {
                'packets_captured': 15420,
                'connections_analyzed': 892,
                'anomalies_detected': 23
            },
            'active_captures': [
                {'name': 'tcpdump_eth0', 'interface': 'eth0', 'start_time': datetime.now().isoformat()}
            ]
        }
    
    def _generate_mock_attribution_data(self):
        """Generate mock attribution data"""
        return {
            'techniques': 5,
            'actors': 3,
            'campaigns': 2
        }

# Initialize data manager
data_manager = DashboardDataManager()

# Dashboard layout
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1("Cybersecurity System Dashboard", className="text-center mb-4"),
            html.Hr()
        ])
    ]),
    
    # Statistics Cards
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="total-alerts", className="card-title"),
                    html.P("Total Alerts", className="card-text")
                ])
            ], color="primary", outline=True)
        ], width=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="active-threats", className="card-title"),
                    html.P("Active Threats", className="card-text")
                ])
            ], color="danger", outline=True)
        ], width=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="decoys-deployed", className="card-title"),
                    html.P("Decoys Deployed", className="card-text")
                ])
            ], color="warning", outline=True)
        ], width=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="detection-rate", className="card-title"),
                    html.P("Detection Rate (%)", className="card-text")
                ])
            ], color="success", outline=True)
        ], width=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="false-positives", className="card-title"),
                    html.P("False Positives", className="card-text")
                ])
            ], color="info", outline=True)
        ], width=2),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4(id="response-time", className="card-title"),
                    html.P("Response Time (min)", className="card-text")
                ])
            ], color="secondary", outline=True)
        ], width=2)
    ], className="mb-4"),
    
    # Main Content Tabs
    dbc.Tabs([
        # Overview Tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="threat-timeline")
                ], width=6),
                dbc.Col([
                    dcc.Graph(id="threat-severity-pie")
                ], width=6)
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="threat-type-bar")
                ], width=12)
            ])
        ], label="Overview", tab_id="overview"),
        
        # Behavioral Analysis Tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="model-performance")
                ], width=6),
                dbc.Col([
                    dcc.Graph(id="anomaly-timeline")
                ], width=6)
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="anomaly-scores")
                ], width=12)
            ])
        ], label="Behavioral Analysis", tab_id="behavioral"),
        
        # Traffic Monitor Tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="traffic-stats")
                ], width=6),
                dbc.Col([
                    dcc.Graph(id="protocol-distribution")
                ], width=6)
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    html.Div(id="capture-status")
                ], width=12)
            ])
        ], label="Traffic Monitor", tab_id="traffic"),
        
        # Threat Attribution Tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="attack-techniques")
                ], width=6),
                dbc.Col([
                    dcc.Graph(id="threat-actors")
                ], width=6)
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    html.Div(id="mitre-data-status")
                ], width=12)
            ])
        ], label="Threat Attribution", tab_id="attribution"),
        
        # Decoy Generator Tab
        dbc.Tab([
            dbc.Row([
                dbc.Col([
                    dcc.Graph(id="decoy-status")
                ], width=6),
                dbc.Col([
                    dcc.Graph(id="honeytoken-activity")
                ], width=6)
            ], className="mb-4"),
            dbc.Row([
                dbc.Col([
                    html.Div(id="decoy-controls")
                ], width=12)
            ])
        ], label="Decoy Generator", tab_id="decoys")
    ], id="tabs", active_tab="overview"),
    
    # Refresh Button
    dbc.Row([
        dbc.Col([
            dbc.Button("Refresh Data", id="refresh-btn", color="primary", className="mt-3")
        ], className="text-center")
    ]),
    
    # Interval component for auto-refresh
    dcc.Interval(
        id='interval-component',
        interval=30*1000,  # 30 seconds
        n_intervals=0
    )
], fluid=True)

# Callbacks
@app.callback(
    [Output("total-alerts", "children"),
     Output("active-threats", "children"),
     Output("decoys-deployed", "children"),
     Output("detection-rate", "children"),
     Output("false-positives", "children"),
     Output("response-time", "children")],
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_stats(n_clicks, n_intervals):
    """Update dashboard statistics"""
    stats = data_manager.get_cached_data("stats", data_manager.fetch_dashboard_stats)
    
    return (
        stats.get('totalAlerts', 0),
        stats.get('activeThreats', 0),
        stats.get('decoysDeployed', 0),
        f"{stats.get('detectionRate', 0):.1f}",
        stats.get('falsePositives', 0),
        f"{stats.get('responseTime', 0):.1f}"
    )

@app.callback(
    Output("threat-timeline", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_threat_timeline(n_clicks, n_intervals):
    """Update threat timeline chart"""
    threats = data_manager.get_cached_data("threats", data_manager.fetch_threat_data)
    
    if not threats:
        return go.Figure()
    
    df = pd.DataFrame(threats)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['date'] = df['timestamp'].dt.date
    
    daily_counts = df.groupby('date').size().reset_index(name='count')
    
    fig = px.line(daily_counts, x='date', y='count', 
                  title="Threats Over Time",
                  labels={'date': 'Date', 'count': 'Number of Threats'})
    fig.update_layout(showlegend=False)
    
    return fig

@app.callback(
    Output("threat-severity-pie", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_threat_severity_pie(n_clicks, n_intervals):
    """Update threat severity pie chart"""
    threats = data_manager.get_cached_data("threats", data_manager.fetch_threat_data)
    
    if not threats:
        return go.Figure()
    
    df = pd.DataFrame(threats)
    severity_counts = df['severity'].value_counts()
    
    fig = px.pie(values=severity_counts.values, names=severity_counts.index,
                 title="Threat Severity Distribution")
    
    return fig

@app.callback(
    Output("threat-type-bar", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_threat_type_bar(n_clicks, n_intervals):
    """Update threat type bar chart"""
    threats = data_manager.get_cached_data("threats", data_manager.fetch_threat_data)
    
    if not threats:
        return go.Figure()
    
    df = pd.DataFrame(threats)
    type_counts = df['threatType'].value_counts()
    
    fig = px.bar(x=type_counts.index, y=type_counts.values,
                 title="Threat Types",
                 labels={'x': 'Threat Type', 'y': 'Count'})
    
    return fig

@app.callback(
    Output("model-performance", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_model_performance(n_clicks, n_intervals):
    """Update model performance chart"""
    behavioral_data = data_manager.get_cached_data("behavioral", data_manager.fetch_behavioral_analysis)
    
    models = behavioral_data.get('models', {})
    if not models:
        return go.Figure()
    
    model_names = list(models.keys())
    accuracies = [models[model]['accuracy'] for model in model_names]
    anomalies = [models[model]['anomalies_detected'] for model in model_names]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(name='Accuracy', x=model_names, y=accuracies, yaxis='y'))
    fig.add_trace(go.Scatter(name='Anomalies Detected', x=model_names, y=anomalies, yaxis='y2'))
    
    fig.update_layout(
        title="ML Model Performance",
        yaxis=dict(title="Accuracy", range=[0, 1]),
        yaxis2=dict(title="Anomalies Detected", overlaying="y", side="right"),
        barmode='group'
    )
    
    return fig

@app.callback(
    Output("anomaly-timeline", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_anomaly_timeline(n_clicks, n_intervals):
    """Update anomaly timeline chart"""
    behavioral_data = data_manager.get_cached_data("behavioral", data_manager.fetch_behavioral_analysis)
    
    anomalies = behavioral_data.get('recent_anomalies', [])
    if not anomalies:
        return go.Figure()
    
    df = pd.DataFrame(anomalies)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    fig = px.scatter(df, x='timestamp', y='score', color='type',
                     title="Recent Anomalies",
                     labels={'timestamp': 'Time', 'score': 'Anomaly Score'})
    
    return fig

@app.callback(
    Output("traffic-stats", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_traffic_stats(n_clicks, n_intervals):
    """Update traffic statistics chart"""
    traffic_data = data_manager.get_cached_data("traffic", data_manager.fetch_traffic_data)
    
    stats = traffic_data.get('capture_stats', {})
    if not stats:
        return go.Figure()
    
    metrics = ['Packets Captured', 'Connections Analyzed', 'Anomalies Detected']
    values = [stats.get('packets_captured', 0), 
              stats.get('connections_analyzed', 0), 
              stats.get('anomalies_detected', 0)]
    
    fig = px.bar(x=metrics, y=values,
                 title="Traffic Monitoring Statistics",
                 labels={'x': 'Metric', 'y': 'Count'})
    
    return fig

@app.callback(
    Output("attack-techniques", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_attack_techniques(n_clicks, n_intervals):
    """Update attack techniques chart"""
    attribution_data = data_manager.get_cached_data("attribution", data_manager.fetch_attribution_data)
    
    # Mock data for techniques
    techniques = ['T1001', 'T1003', 'T1005', 'T1007', 'T1008']
    counts = [15, 23, 8, 12, 19]
    
    fig = px.bar(x=techniques, y=counts,
                 title="MITRE ATT&CK Techniques Detected",
                 labels={'x': 'Technique ID', 'y': 'Detection Count'})
    
    return fig

@app.callback(
    Output("threat-actors", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_threat_actors(n_clicks, n_intervals):
    """Update threat actors chart"""
    # Mock data for threat actors
    actors = ['APT1', 'APT28', 'APT29', 'Unknown']
    confidence = [0.85, 0.72, 0.68, 0.45]
    
    fig = px.bar(x=actors, y=confidence,
                 title="Threat Actor Attribution Confidence",
                 labels={'x': 'Threat Actor', 'y': 'Confidence Score'})
    
    return fig

@app.callback(
    Output("decoy-status", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_decoy_status(n_clicks, n_intervals):
    """Update decoy status chart"""
    # Mock data for decoy status
    decoy_types = ['Web Server', 'SSH', 'File Share', 'IoT Emulator']
    active = [3, 2, 1, 2]
    total = [5, 3, 2, 3]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(name='Active', x=decoy_types, y=active))
    fig.add_trace(go.Bar(name='Total', x=decoy_types, y=total))
    
    fig.update_layout(
        title="Decoy Deployment Status",
        barmode='group',
        xaxis_title="Decoy Type",
        yaxis_title="Count"
    )
    
    return fig

@app.callback(
    Output("honeytoken-activity", "figure"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_honeytoken_activity(n_clicks, n_intervals):
    """Update honeytoken activity chart"""
    # Mock data for honeytoken activity
    token_types = ['Credentials', 'API Keys', 'Documents', 'Database Records']
    triggers = [12, 8, 15, 6]
    
    fig = px.pie(values=triggers, names=token_types,
                 title="Honeytoken Trigger Activity")
    
    return fig

@app.callback(
    Output("capture-status", "children"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_capture_status(n_clicks, n_intervals):
    """Update capture status display"""
    traffic_data = data_manager.get_cached_data("traffic", data_manager.fetch_traffic_data)
    
    zeek_status = "🟢 Running" if traffic_data.get('zeek_running', False) else "🔴 Stopped"
    tcpdump_count = traffic_data.get('tcpdump_captures', 0)
    
    return dbc.Card([
        dbc.CardBody([
            html.H5("Capture Status", className="card-title"),
            html.P(f"Zeek Monitoring: {zeek_status}"),
            html.P(f"Active tcpdump Captures: {tcpdump_count}"),
            html.P(f"Packets Captured: {traffic_data.get('capture_stats', {}).get('packets_captured', 0):,}")
        ])
    ])

@app.callback(
    Output("mitre-data-status", "children"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_mitre_status(n_clicks, n_intervals):
    """Update MITRE data status display"""
    attribution_data = data_manager.get_cached_data("attribution", data_manager.fetch_attribution_data)
    
    return dbc.Card([
        dbc.CardBody([
            html.H5("MITRE ATT&CK Data Status", className="card-title"),
            html.P(f"Techniques Loaded: {attribution_data.get('techniques', 0)}"),
            html.P(f"Threat Actors: {attribution_data.get('actors', 0)}"),
            html.P(f"Campaigns: {attribution_data.get('campaigns', 0)}")
        ])
    ])

@app.callback(
    Output("decoy-controls", "children"),
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals")]
)
def update_decoy_controls(n_clicks, n_intervals):
    """Update decoy controls display"""
    return dbc.Card([
        dbc.CardBody([
            html.H5("Decoy Controls", className="card-title"),
            dbc.Button("Deploy Web Server Decoy", color="primary", className="me-2"),
            dbc.Button("Deploy SSH Decoy", color="primary", className="me-2"),
            dbc.Button("Deploy File Share Decoy", color="primary", className="me-2"),
            dbc.Button("Deploy IoT Emulator", color="primary", className="me-2"),
            html.Hr(),
            dbc.Button("Remove All Decoys", color="danger")
        ])
    ])

if __name__ == '__main__':
    app.run_server(host='0.0.0.0', port=5005, debug=True)
