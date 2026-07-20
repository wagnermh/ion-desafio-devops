#!/usr/bin/env python3
"""
Parse Trivy SARIF results and extract structured vulnerability data
for visualization and analysis.
"""
import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class TrivyResultParser:
    """Parser for Trivy SARIF results"""
    
    def __init__(self, sarif_file_path: str):
        self.sarif_file_path = sarif_file_path
        self.data = None
        self.parsed_data = {
            'image': {},
            'vulnerabilities': [],
            'packages': [],
            'summary': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'unknown': 0
            },
            'affected_packages': {},
            'cve_by_severity': {},
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def load_sarif(self) -> bool:
        """Load and parse SARIF file"""
        try:
            if not os.path.exists(self.sarif_file_path):
                print(f"❌ File not found: {self.sarif_file_path}")
                return False
            
            with open(self.sarif_file_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            
            print(f"✅ Loaded SARIF file: {self.sarif_file_path}")
            return True
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON: {e}")
            return False
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return False
    
    def extract_image_info(self):
        """Extract image information from SARIF metadata"""
        try:
            runs = self.data.get('runs', [])
            if runs:
                run = runs[0]
                # Try to get image info from tool metadata
                tool = run.get('tool', {})
                driver = tool.get('driver', {})
                
                # Extract image name from rules or results
                results = run.get('results', [])
                if results:
                    # Try to get image from first result
                    for result in results:
                        locations = result.get('locations', [])
                        if locations:
                            artifact = locations[0].get('physicalLocation', {}).get('artifactLocation', {})
                            uri = artifact.get('uri', '')
                            if uri and '@' in uri:
                                # Format: package@version
                                parts = uri.split('@')
                                if len(parts) >= 2:
                                    self.parsed_data['image']['name'] = parts[0]
                                    self.parsed_data['image']['version'] = parts[1]
                                    break
                
                # If we still don't have image info, use default
                if not self.parsed_data['image'].get('name'):
                    self.parsed_data['image']['name'] = os.environ.get('IMAGE_NAME', 'unknown-image')
                    self.parsed_data['image']['version'] = os.environ.get('IMAGE_TAG', 'latest')
                
                self.parsed_data['image']['scanner'] = 'trivy'
                self.parsed_data['image']['scanned_at'] = datetime.now().isoformat()
                
        except Exception as e:
            print(f"⚠️ Error extracting image info: {e}")
            self.parsed_data['image'] = {
                'name': os.environ.get('IMAGE_NAME', 'unknown-image'),
                'version': os.environ.get('IMAGE_TAG', 'latest'),
                'scanner': 'trivy',
                'scanned_at': datetime.now().isoformat()
            }
    
    def parse_results(self):
        """Parse SARIF results into structured data"""
        try:
            runs = self.data.get('runs', [])
            if not runs:
                print("⚠️ No runs found in SARIF file")
                return
            
            for run in runs:
                results = run.get('results', [])
                print(f"📊 Found {len(results)} results")
                
                for result in results:
                    self._parse_single_result(result)
                
            # Calculate summary statistics
            self._calculate_summary()
            
            print(f"✅ Parsed {self.parsed_data['summary']['total']} vulnerabilities")
            print(f"   Critical: {self.parsed_data['summary']['critical']}")
            print(f"   High: {self.parsed_data['summary']['high']}")
            print(f"   Medium: {self.parsed_data['summary']['medium']}")
            print(f"   Low: {self.parsed_data['summary']['low']}")
            
        except Exception as e:
            print(f"❌ Error parsing results: {e}")
    
    def _parse_single_result(self, result: Dict):
        """Parse a single SARIF result"""
        try:
            # Extract vulnerability info
            rule_id = result.get('ruleId', 'UNKNOWN')
            level = result.get('level', 'UNKNOWN').upper()
            message = result.get('message', {})
            text = message.get('text', 'No description')
            
            # Extract package info from locations
            package_name = 'unknown'
            package_version = 'unknown'
            
            locations = result.get('locations', [])
            if locations:
                for loc in locations:
                    physical_location = loc.get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    uri = artifact_location.get('uri', '')
                    
                    if uri:
                        # Try to parse package@version format
                        if '@' in uri:
                            parts = uri.split('@')
                            package_name = parts[0]
                            package_version = parts[1] if len(parts) > 1 else 'unknown'
                        else:
                            # Try to extract from path
                            path_parts = uri.split('/')
                            if path_parts:
                                package_name = path_parts[-1]
                        break
            
            # Create vulnerability entry
            vuln = {
                'id': f"trivy_{len(self.parsed_data['vulnerabilities'])}",
                'cve': rule_id,
                'severity': level,
                'title': text[:200],  # Truncate long titles
                'description': text,
                'package': package_name,
                'version': package_version,
                'scanner': 'trivy',
                'scanned_at': datetime.now().isoformat()
            }
            
            self.parsed_data['vulnerabilities'].append(vuln)
            
            # Track packages
            if package_name != 'unknown':
                package_key = f"{package_name}@{package_version}"
                if package_key not in self.parsed_data['affected_packages']:
                    self.parsed_data['affected_packages'][package_key] = {
                        'name': package_name,
                        'version': package_version,
                        'vulnerabilities': []
                    }
                self.parsed_data['affected_packages'][package_key]['vulnerabilities'].append(rule_id)
            
            # Track CVEs by severity
            if level not in self.parsed_data['cve_by_severity']:
                self.parsed_data['cve_by_severity'][level] = []
            self.parsed_data['cve_by_severity'][level].append(rule_id)
            
        except Exception as e:
            print(f"⚠️ Error parsing result: {e}")
    
    def _calculate_summary(self):
        """Calculate summary statistics"""
        total = len(self.parsed_data['vulnerabilities'])
        self.parsed_data['summary']['total'] = total
        
        for vuln in self.parsed_data['vulnerabilities']:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            if severity == 'CRITICAL':
                self.parsed_data['summary']['critical'] += 1
            elif severity == 'HIGH':
                self.parsed_data['summary']['high'] += 1
            elif severity == 'MEDIUM':
                self.parsed_data['summary']['medium'] += 1
            elif severity == 'LOW':
                self.parsed_data['summary']['low'] += 1
            else:
                self.parsed_data['summary']['unknown'] += 1
    
    def get_top_affected_packages(self, limit: int = 10) -> List[Dict]:
        """Get top packages with most vulnerabilities"""
        packages = []
        for key, data in self.parsed_data['affected_packages'].items():
            packages.append({
                'name': data['name'],
                'version': data['version'],
                'vuln_count': len(data['vulnerabilities']),
                'vulnerabilities': data['vulnerabilities']
            })
        
        packages.sort(key=lambda x: x['vuln_count'], reverse=True)
        return packages[:limit]
    
    def get_critical_vulnerabilities(self) -> List[Dict]:
        """Get all CRITICAL vulnerabilities"""
        return [v for v in self.parsed_data['vulnerabilities'] 
                if v.get('severity', '').upper() == 'CRITICAL']
    
    def get_high_vulnerabilities(self) -> List[Dict]:
        """Get all HIGH vulnerabilities"""
        return [v for v in self.parsed_data['vulnerabilities'] 
                if v.get('severity', '').upper() == 'HIGH']
    
    def get_severity_distribution(self) -> Dict:
        """Get severity distribution for charts"""
        return {
            'CRITICAL': self.parsed_data['summary']['critical'],
            'HIGH': self.parsed_data['summary']['high'],
            'MEDIUM': self.parsed_data['summary']['medium'],
            'LOW': self.parsed_data['summary']['low'],
            'UNKNOWN': self.parsed_data['summary']['unknown']
        }
    
    def to_json(self) -> Dict:
        """Convert parsed data to JSON-serializable dict"""
        return {
            'image': self.parsed_data['image'],
            'summary': self.parsed_data['summary'],
            'vulnerabilities': self.parsed_data['vulnerabilities'],
            'affected_packages': self.parsed_data['affected_packages'],
            'cve_by_severity': self.parsed_data['cve_by_severity'],
            'top_affected_packages': self.get_top_affected_packages(),
            'critical_vulnerabilities': self.get_critical_vulnerabilities(),
            'high_vulnerabilities': self.get_high_vulnerabilities(),
            'severity_distribution': self.get_severity_distribution(),
            'scan_timestamp': self.parsed_data['scan_timestamp']
        }
    
    def save_json(self, output_path: str):
        """Save parsed data to JSON file"""
        try:
            data = self.to_json()
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"✅ Saved parsed data to: {output_path}")
        except Exception as e:
            print(f"❌ Error saving JSON: {e}")
    
    def generate_markdown_report(self, output_path: str):
        """Generate Markdown report from parsed data"""
        try:
            lines = []
            lines.append("# 🔒 Trivy Security Scan Report")
            lines.append("")
            lines.append(f"**Generated:** {self.parsed_data['scan_timestamp']}")
            lines.append(f"**Image:** {self.parsed_data['image'].get('name', 'unknown')}")
            lines.append(f"**Tag:** {self.parsed_data['image'].get('version', 'latest')}")
            lines.append("")
            
            # Summary
            lines.append("## 📊 Summary")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            lines.append(f"| 🔴 **Critical** | {self.parsed_data['summary']['critical']} |")
            lines.append(f"| 🟠 **High** | {self.parsed_data['summary']['high']} |")
            lines.append(f"| 🟡 **Medium** | {self.parsed_data['summary']['medium']} |")
            lines.append(f"| 🟢 **Low** | {self.parsed_data['summary']['low']} |")
            lines.append(f"| ⚪ **Unknown** | {self.parsed_data['summary']['unknown']} |")
            lines.append(f"| **Total** | **{self.parsed_data['summary']['total']}** |")
            lines.append("")
            
            # Top affected packages
            lines.append("## 📦 Top Affected Packages")
            lines.append("")
            lines.append("| Package | Version | Vulnerabilities |")
            lines.append("|---------|---------|-----------------|")
            
            top_packages = self.get_top_affected_packages(10)
            for pkg in top_packages:
                lines.append(f"| {pkg['name']} | {pkg['version']} | {pkg['vuln_count']} |")
            lines.append("")
            
            # Critical vulnerabilities
            critical = self.get_critical_vulnerabilities()
            if critical:
                lines.append("## 🔴 Critical Vulnerabilities")
                lines.append("")
                lines.append("| CVE | Package | Version | Title |")
                lines.append("|-----|---------|---------|-------|")
                for vuln in critical[:10]:
                    lines.append(f"| {vuln['cve']} | {vuln['package']} | {vuln['version']} | {vuln['title'][:50]}... |")
                if len(critical) > 10:
                    lines.append(f"| ... and {len(critical) - 10} more | | | |")
                lines.append("")
            
            # High vulnerabilities
            high = self.get_high_vulnerabilities()
            if high:
                lines.append("## 🟠 High Vulnerabilities")
                lines.append("")
                lines.append("| CVE | Package | Version | Title |")
                lines.append("|-----|---------|---------|-------|")
                for vuln in high[:10]:
                    lines.append(f"| {vuln['cve']} | {vuln['package']} | {vuln['version']} | {vuln['title'][:50]}... |")
                if len(high) > 10:
                    lines.append(f"| ... and {len(high) - 10} more | | | |")
                lines.append("")
            
            # Recommendations
            lines.append("## 📋 Recommendations")
            lines.append("")
            
            if self.parsed_data['summary']['critical'] > 0:
                lines.append("### 🔴 Immediate Action Required")
                lines.append("")
                lines.append(f"Found **{self.parsed_data['summary']['critical']} CRITICAL** vulnerabilities that must be fixed immediately:")
                lines.append("")
                for vuln in self.get_critical_vulnerabilities()[:5]:
                    lines.append(f"- **{vuln['cve']}** in `{vuln['package']}`@{vuln['version']}: {vuln['title'][:100]}")
                lines.append("")
            
            if self.parsed_data['summary']['high'] > 0:
                lines.append("### 🟠 High Priority")
                lines.append("")
                lines.append(f"Found **{self.parsed_data['summary']['high']} HIGH** vulnerabilities that should be addressed soon:")
                lines.append("")
                for vuln in self.get_high_vulnerabilities()[:5]:
                    lines.append(f"- **{vuln['cve']}** in `{vuln['package']}`@{vuln['version']}: {vuln['title'][:100]}")
                lines.append("")
            
            lines.append("### ✅ Best Practices")
            lines.append("")
            lines.append("1. **Update base images** to latest patched versions")
            lines.append("2. **Use minimal base images** (Alpine, Distroless) to reduce attack surface")
            lines.append("3. **Pin dependencies** to known good versions")
            lines.append("4. **Implement vulnerability scanning** in pre-commit hooks")
            lines.append("5. **Monitor CVEs** regularly using Trivy, Grype, or Snyk")
            lines.append("")
            
            # Write file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            print(f"✅ Markdown report generated: {output_path}")
            
        except Exception as e:
            print(f"❌ Error generating markdown: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Parse Trivy SARIF results and generate structured data'
    )
    parser.add_argument(
        '--input', 
        required=True, 
        help='Path to Trivy SARIF results file (trivy-results.sarif)'
    )
    parser.add_argument(
        '--output-json', 
        default='trivy-parsed.json',
        help='Output JSON file path'
    )
    parser.add_argument(
        '--output-markdown', 
        default='trivy-report.md',
        help='Output Markdown report file path'
    )
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for all files'
    )
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Build full output paths
    json_path = os.path.join(args.output_dir, args.output_json)
    md_path = os.path.join(args.output_dir, args.output_markdown)
    
    # Parse
    parser_obj = TrivyResultParser(args.input)
    
    if not parser_obj.load_sarif():
        sys.exit(1)
    
    parser_obj.extract_image_info()
    parser_obj.parse_results()
    
    # Save outputs
    parser_obj.save_json(json_path)
    parser_obj.generate_markdown_report(md_path)
    
    # Also save a simplified version for dashboards
    simplified = {
        'severity_counts': parser_obj.get_severity_distribution(),
        'top_packages': parser_obj.get_top_affected_packages(5),
        'critical_count': parser_obj.parsed_data['summary']['critical'],
        'high_count': parser_obj.parsed_data['summary']['high'],
        'total_count': parser_obj.parsed_data['summary']['total'],
        'image': parser_obj.parsed_data['image']
    }
    
    simple_path = os.path.join(args.output_dir, 'trivy-simplified.json')
    with open(simple_path, 'w', encoding='utf-8') as f:
        json.dump(simplified, f, indent=2)
    
    print(f"✅ Simplified data saved to: {simple_path}")
    print("✅ Trivy parsing complete!")

if __name__ == "__main__":
    main()
