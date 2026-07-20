#!/usr/bin/env python3
"""
Generate Mermaid diagrams from security scan results
"""
import json
import os
import argparse
from datetime import datetime
from pathlib import Path

def generate_pipeline_diagram(data):
    """Generate pipeline flow diagram"""
    return """
```mermaid
graph TD
    A[🚀 Push to Main] --> B[Checkout Code]
    B --> C[Build Docker Image]
    
    C --> D1[🔒 Trivy Scan]
    C --> D2[🔒 Grype Scan]
    C --> D3[📦 Syft SBOM]
    C --> D4[🛡️ Dockle Scan]
    C --> D5[🚀 Snyk Scan]
    
    D1 --> E[✅ Validate Scans]
    D2 --> E
    D3 --> E
    D4 --> E
    D5 --> E
    
    E -->|✅ All Passed| F[📦 Push to Registry]
    E -->|❌ Failed| G[🚫 Block Deployment]
    
    E --> H1[🗺️ Cartography + Trivy]
    E --> H2[🗺️ Cartography + Syft]
    
    H1 --> I[📊 Vulnerability Graph]
    H2 --> J[📊 Dependency Graph]
    
    F --> K[✅ Image Published]
    
    style A fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    style E fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style F fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style G fill:#ffebee,stroke:#c62828,stroke-width:2px
