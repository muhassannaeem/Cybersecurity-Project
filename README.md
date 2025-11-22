# Modular Containerized Cybersecurity System

A comprehensive, modular cybersecurity system with behavioral analysis, decoy generation, threat attribution, and visualization capabilities.

## System Architecture

### Core Components

1. **Behavioral Analysis Engine** - ML models (LSTM, Isolation Forest, Autoencoder) for anomaly detection
2. **Decoy Generator** - Python/Go engine for dynamic honeypot and honeytoken creation
3. **Traffic Monitor** - Zeek and tcpdump integration for real-time network capture
4. **Threat Attribution Module** - MITRE ATT&CK mapping for adversary profiling
5. **Visualization Dashboard** - Flask-based GUI for telemetry and behavioral visualizations
6. **Threat Intelligence Sharing** - STIX/TAXII integration for indicator sharing

### Machine Learning Models

- **LSTM** - Sequence-based anomaly detection
- **Isolation Forest** - Unsupervised anomaly detection
- **Autoencoder** - Dimensionality reduction and anomaly detection

### Decoy Types

- **Web servers** (Apache/Nginx)
- **SSH** (Cowrie)
- **File shares** (Samba)
- **IoT emulators**
- **Honeytokens** - Fake credentials, documents, API keys

## Folder Structure

cybersecurity-system/
├── frontend/                 # Next.js frontend
├── backend/                  # Python backend
│   ├── behavioral_analysis/  # ML models
│   ├── decoy_generator/      # Honeypot/honeytoken engine
│   ├── traffic_monitor/      # Zeek/tcpdump integration
│   ├── threat_attribution/   # MITRE ATT&CK mapping
│   ├── visualization/        # Flask dashboard
│   └── threat_intelligence/  # STIX/TAXII integration
├── docker/                   # Container configurations
├── evaluation/               # Red-team testing tools
└── docs/                     # Documentation

## Quick Start

1. **Clone the repository**
2. **Install dependencies**: `docker-compose up -d`
3. **Access dashboard**: http://localhost:3000
4. **API endpoints**: http://localhost:5000

## Evaluation Metrics

- Detection latency
- False positive rate
- Attacker engagement time
- Decoy believability

## Red-Team Tools Integration

- Metasploit
- Nmap
- Hydra
- SQLMap

## License

MIT License
