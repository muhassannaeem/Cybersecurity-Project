---
title: Cybersecurity System
sdk: docker
---

# Cybersecurity System

This is a comprehensive cybersecurity system with behavioral analysis, decoy generation, threat attribution, and visualization capabilities.

## Deployment

This system is designed to run as a complete package using Docker Compose. The deployment exposes:

- Frontend Dashboard: Port 7860 (Hugging Face compatible)
- Backend API: Port 7861 (Hugging Face compatible)
- All other services on their standard ports

## Accessing the System

After deployment completes:
- Frontend Dashboard: Visit the Hugging Face Space URL
- Backend API: Access through the Space's API endpoint
- Kibana Visualization: Port 5601 (if exposed)