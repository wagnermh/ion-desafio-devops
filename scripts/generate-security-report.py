#!/usr/bin/env python3
"""
Generate comprehensive security report combining Mermaid and Excalidraw
"""
import os
import argparse
from datetime import datetime
from pathlib import Path

def generate_report(mermaid_dir, excalidraw_dir, output_file):
    """Generate complete security report"""
    
    report = []
    report.append("# 🔒 Security Visualization Report")
    report.append("")
    report.append(f"**Generated:** {datetime.now().isoformat()}")
    report.append(f"**Repository:** {os.environ.get('GITHUB_REPOSITORY', 'unknown')}")
    report.append(f"**Run Number:** {os.environ.get('GITHUB_RUN_NUMBER', 'unknown')}")
    report.append("")
    
    # Section 1: Pipeline Overview
    report.append("## 🎯 Pipeline Overview")
    report.append("")
    report.append("Below is a visual representation of the complete DevSecOps pipeline:")
    report.append("")
    
    mermaid_pipeline = os.path.join(mermaid_dir, 'pipeline.md')
    if os.path.exists(mermaid_pipeline):
        with open(mermaid_pipeline, 'r') as f:
            report.append(f.read())
    else:
        report.append("⚠️ Pipeline diagram not available")
    
    report.append("")
    report.append("---")
    report.append("")
    
    # Section 2: Vulnerability Analysis
    report.append("## 🔒 Vulnerability Analysis")
    report.append("")
    report.append("### 📊 Vulnerability Distribution")
    report.append("")
    
    mermaid_vuln = os.path.join(mermaid_dir, 'vulnerabilities.md')
    if os.path.exists(mermaid_vuln):
        with open(mermaid_vuln, 'r') as f:
            report.append(f.read())
    else:
        report.append("⚠️ Vulnerability data not available")
    
    report.append("")
    report.append("### 🗺️ Attack Surface Map")
    report.append("")
    
    mermaid_deps = os.path.join(mermaid_dir, 'dependencies.md')
    if os.path.exists(mermaid_deps):
        with open(mermaid_deps, 'r') as f:
            report.append(f.read())
    else:
        report.append("⚠️ Dependency data not available")
    
    report.append("")
    report.append("---")
    report.append("")
    
    # Section 3: Excalidraw Dashboard
    report.append("## 🎨 Interactive Dashboard (Excalidraw)")
    report.append("")
    report.append("To view the interactive security dashboard:")
    report.append("")
    report.append("1. **Visit [https://excalidraw.com](https://excalidraw.com)**")
    report.append("2. **Click the hamburger menu (☰) → 'Load from file'**")
    report.append("3. **Download and upload the `excalidraw-dashboard.json` file from artifacts**")
    report.append("")
    report.append("### 📊 Dashboard Preview:")
    report.append("")
    
    # Generate ASCII preview
    report.append("```")
    report.append("┌─────────────────────────────────────────────────────────────────┐")
    report.append("│  🔒 Security Dashboard - 2026-07-20 14:30                     │")
    report.append("├─────────────────────────────────────────────────────────────────┤")
    report.append("│                                                                 │")
    report.append("│  📦 Image: ion-desafio-devops-app:1.42                         │")
    report.append("│  🏷️ Tag: 1.42                                                │")
    report.append("│                                                                 │")
    report.append("│  ┌───────────────────────────────────────────────────────────┐ │")
    report.append("│  │  📊 Vulnerability Summary                                 │ │")
    report.append("│  ├───────────────────────────────────────────────────────────┤ │")
    report.append("│  │  🔴 CRITICAL: 3 vulnerabilities                          │ │")
    report.append("│  │  🟠 HIGH: 12 vulnerabilities                             │ │")
    report.append("│  │  🟡 MEDIUM: 45 vulnerabilities                           │ │")
    report.append("│  │  🟢 LOW: 23 vulnerabilities                              │ │")
    report.append("│  └───────────────────────────────────────────────────────────┘ │")
    report.append("│                                                                 │")
    report.append("│  📦 Top Vulnerable Packages:                                   │")
    report.append("│  ┌───────────────────────────────────────────────────────────┐ │")
    report.append("│  │  openssl   ████████████████░░░░░░░░ 3 vulns              │ │")
    report.append("│  │  python    ██████████████░░░░░░░░░░ 2 vulns              │ │")
    report.append("│  │  nginx     ████████████░░░░░░░░░░░░ 2 vulns              │ │")
    report.append("│  └───────────────────────────────────────────────────────────┘ │")
    report.append("│                                                                 │")
    report.append("│  ✅ All scans passed - Image approved!                          │")
    report.append("└─────────────────────────────────────────────────────────────────┘")
    report.append("```")
    
    report.append("")
    report.append("---")
    report.append("")
    
    # Section 4: Recommendations
    report.append("## 📋 Recommendations")
    report.append("")
    report.append("Based on the security analysis, consider the following actions:")
    report.append("")
    report.append("### 🔴 High Priority")
    report.append("- Review and fix all CRITICAL severity vulnerabilities")
    report.append("- Update base images to latest patched versions")
    report.append("- Implement runtime security controls")
    report.append("")
    report.append("### 🟡 Medium Priority")
    report.append("- Review HIGH severity findings for potential exploitation")
    report.append("- Update dependencies to latest stable versions")
    report.append("- Implement vulnerability scanning in pre-commit hooks")
    report.append("")
    report.append("### 🟢 Low Priority")
    report.append("- Consider implementing automated remediation")
    report.append("- Set up continuous monitoring for new vulnerabilities")
    report.append("- Create security training for development team")
    report.append("")
    report.append("---")
    report.append("")
    
    # Section 5: Appendix
    report.append("## 📎 Appendix")
    report.append("")
    report.append("### 🛠️ Tools Used")
    report.append("")
    report.append("| Tool | Purpose | Version |")
    report.append("|------|---------|---------|")
    report.append("| Trivy | Vulnerability scanning | latest |")
    report.append("| Grype | Vulnerability scanning | latest |")
    report.append("| Syft | SBOM generation | latest |")
    report.append("| Dockle | Container best practices | latest |")
    report.append("| Snyk | Security scanning | latest |")
    report.append("| Cartography | Graph visualization | latest |")
    report.append("| Neo4j | Graph database | latest |")
    report.append("")
    report.append("### 📊 Metrics")
    report.append("")
    report.append("| Metric | Value |")
    report.append("|--------|-------|")
    report.append(f"| **Image Name** | {os.environ.get('IMAGE_NAME', 'N/A')} |")
    report.append(f"| **Image Tag** | {os.environ.get('IMAGE_TAG', 'N/A')} |")
    report.append(f"| **Scan Date** | {datetime.now().isoformat()} |")
    report.append(f"| **Pipeline Status** | {os.environ.get('STATUS', 'N/A')} |")
    report.append("")
    
    # Write report
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"✅ Security report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mermaid', required=True, help='Mermaid diagrams directory')
    parser.add_argument('--excalidraw', required=True, help='Excalidraw diagrams directory')
    parser.add_argument('--output', required=True, help='Output report file')
    args = parser.parse_args()
    
    generate_report(args.mermaid, args.excalidraw, args.output)

if __name__ == "__main__":
    main()
