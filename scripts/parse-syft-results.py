#!/usr/bin/env python3
"""
Parse Syft SBOM results and extract structured dependency data
for visualization and analysis.
"""
import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

class SyftResultParser:
    """Parser for Syft SBOM results"""
    
    def __init__(self, syft_json_path: str):
        self.syft_json_path = syft_json_path
        self.data = None
        self.parsed_data = {
            'image': {},
            'packages': [],
            'dependencies': [],
            'summary': {
                'total_packages': 0,
                'by_type': {},
                'total_dependencies': 0,
                'max_depth': 0
            },
            'package_relationships': [],
            'package_dependents': defaultdict(list),
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def load_sbom(self) -> bool:
        """Load and parse Syft JSON SBOM"""
        try:
            if not os.path.exists(self.syft_json_path):
                print(f"❌ File not found: {self.syft_json_path}")
                return False
            
            with open(self.syft_json_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            
            print(f"✅ Loaded Syft SBOM file: {self.syft_json_path}")
            return True
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON: {e}")
            return False
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return False
    
    def extract_image_info(self):
        """Extract image information from SBOM"""
        try:
            # Try to get image info from descriptor
            descriptor = self.data.get('descriptor', {})
            if descriptor:
                self.parsed_data['image']['name'] = os.environ.get('IMAGE_NAME', 'unknown-image')
                self.parsed_data['image']['version'] = os.environ.get('IMAGE_TAG', 'latest')
                self.parsed_data['image']['scanner'] = 'syft'
                self.parsed_data['image']['format'] = descriptor.get('name', 'unknown')
                self.parsed_data['image']['version'] = descriptor.get('version', 'unknown')
                self.parsed_data['image']['scanned_at'] = datetime.now().isoformat()
            else:
                # Fallback to environment variables
                self.parsed_data['image'] = {
                    'name': os.environ.get('IMAGE_NAME', 'unknown-image'),
                    'version': os.environ.get('IMAGE_TAG', 'latest'),
                    'scanner': 'syft',
                    'scanned_at': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"⚠️ Error extracting image info: {e}")
            self.parsed_data['image'] = {
                'name': os.environ.get('IMAGE_NAME', 'unknown-image'),
                'version': os.environ.get('IMAGE_TAG', 'latest'),
                'scanner': 'syft',
                'scanned_at': datetime.now().isoformat()
            }
    
    def parse_packages(self):
        """Parse packages from SBOM"""
        try:
            # Try to find packages in different possible locations
            packages = []
            
            # Check if packages are in 'artifacts' (Syft v0.x format)
            if 'artifacts' in self.data:
                packages = self.data.get('artifacts', [])
            # Check if packages are in 'packages' (Syft v1.x format)  
            elif 'packages' in self.data:
                packages = self.data.get('packages', [])
            else:
                # Try to find packages in nested structure
                for key in ['sbom', 'bom', 'components']:
                    if key in self.data:
                        packages = self.data.get(key, [])
                        break
            
            print(f"📦 Found {len(packages)} packages in SBOM")
            
            # Process each package
            for idx, pkg in enumerate(packages):
                parsed_pkg = self._parse_single_package(pkg, idx)
                if parsed_pkg:
                    self.parsed_data['packages'].append(parsed_pkg)
                    
                    # Track type distribution
                    pkg_type = parsed_pkg.get('type', 'unknown')
                    self.parsed_data['summary']['by_type'][pkg_type] = \
                        self.parsed_data['summary']['by_type'].get(pkg_type, 0) + 1
            
            self.parsed_data['summary']['total_packages'] = len(self.parsed_data['packages'])
            
        except Exception as e:
            print(f"❌ Error parsing packages: {e}")
    
    def _parse_single_package(self, pkg: Dict, idx: int) -> Optional[Dict]:
        """Parse a single package from SBOM"""
        try:
            # Extract package metadata
            pkg_id = pkg.get('id', f"pkg_{idx}")
            name = pkg.get('name', 'unknown')
            version = pkg.get('version', 'unknown')
            pkg_type = pkg.get('type', 'unknown')
            
            # Try to get licensing info
            licenses = pkg.get('licenses', [])
            if isinstance(licenses, list):
                licenses = [l.get('value', '') if isinstance(l, dict) else str(l) for l in licenses]
            
            # Try to get upstream info
            upstreams = pkg.get('upstreams', [])
            if upstreams and isinstance(upstreams, list):
                upstream_names = [u.get('name', '') for u in upstreams if isinstance(u, dict)]
            else:
                upstream_names = []
            
            # Extract language/platform
            language = pkg.get('language', 'unknown')
            if not language or language == 'unknown':
                # Try to infer from type
                if pkg_type in ['python', 'npm', 'gem', 'go', 'rust', 'java']:
                    language = pkg_type
            
            parsed = {
                'id': pkg_id,
                'name': name,
                'version': version,
                'type': pkg_type,
                'language': language,
                'licenses': licenses,
                'upstreams': upstream_names,
                'source': pkg.get('source', ''),
                'metadata': pkg.get('metadata', {}),
                'purl': pkg.get('purl', f"pkg:{pkg_type}/{name}@{version}")
            }
            
            return parsed
            
        except Exception as e:
            print(f"⚠️ Error parsing package {idx}: {e}")
            return None
    
    def parse_dependencies(self):
        """Parse dependencies from SBOM"""
        try:
            # Try to find relationships in different locations
            relationships = []
            
            # Syft v0.x format: artifactRelationships
            if 'artifactRelationships' in self.data:
                relationships = self.data.get('artifactRelationships', [])
            # Syft v1.x format: relationships
            elif 'relationships' in self.data:
                relationships = self.data.get('relationships', [])
            # CycloneDX format: dependencies
            elif 'dependencies' in self.data:
                relationships = self.data.get('dependencies', [])
            
            print(f"🔗 Found {len(relationships)} relationships in SBOM")
            
            # Build package ID mapping for quick lookup
            pkg_id_map = {pkg['id']: pkg for pkg in self.parsed_data['packages']}
            
            # Process each relationship
            for rel in relationships:
                parsed_rel = self._parse_single_relationship(rel, pkg_id_map)
                if parsed_rel:
                    self.parsed_data['dependencies'].append(parsed_rel)
                    
                    # Build dependents tracking
                    parent_id = parsed_rel.get('parent_id')
                    child_id = parsed_rel.get('child_id')
                    if parent_id and child_id:
                        self.parsed_data['package_dependents'][parent_id].append(child_id)
            
            self.parsed_data['summary']['total_dependencies'] = len(self.parsed_data['dependencies'])
            
            # Calculate max dependency depth
            self._calculate_max_depth()
            
        except Exception as e:
            print(f"❌ Error parsing dependencies: {e}")
    
    def _parse_single_relationship(self, rel: Dict, pkg_id_map: Dict) -> Optional[Dict]:
        """Parse a single relationship"""
        try:
            # Different formats handle IDs differently
            parent_id = rel.get('parent', rel.get('parent_id', ''))
            child_id = rel.get('child', rel.get('child_id', ''))
            rel_type = rel.get('type', 'DEPENDS_ON').upper()
            
            # If IDs are not in package map, try to find by name/version
            if parent_id and parent_id not in pkg_id_map:
                # Try to find package by ID in map
                for pkg_id, pkg in pkg_id_map.items():
                    if pkg.get('id') == parent_id:
                        parent_id = pkg_id
                        break
            
            if child_id and child_id not in pkg_id_map:
                for pkg_id, pkg in pkg_id_map.items():
                    if pkg.get('id') == child_id:
                        child_id = pkg_id
                        break
            
            # Only add if both packages exist
            if parent_id in pkg_id_map and child_id in pkg_id_map:
                return {
                    'parent_id': parent_id,
                    'parent_name': pkg_id_map[parent_id].get('name', 'unknown'),
                    'parent_version': pkg_id_map[parent_id].get('version', 'unknown'),
                    'child_id': child_id,
                    'child_name': pkg_id_map[child_id].get('name', 'unknown'),
                    'child_version': pkg_id_map[child_id].get('version', 'unknown'),
                    'type': rel_type
                }
            else:
                # Try to use direct IDs if they exist
                if 'parent' in rel and 'child' in rel:
                    return {
                        'parent_id': rel.get('parent', ''),
                        'parent_name': 'unknown',
                        'parent_version': 'unknown',
                        'child_id': rel.get('child', ''),
                        'child_name': 'unknown',
                        'child_version': 'unknown',
                        'type': rel_type
                    }
            
            return None
            
        except Exception as e:
            print(f"⚠️ Error parsing relationship: {e}")
            return None
    
    def _calculate_max_depth(self):
        """Calculate maximum dependency depth"""
        try:
            if not self.parsed_data['dependencies']:
                return
            
            # Build dependency graph
            graph = defaultdict(list)
            for dep in self.parsed_data['dependencies']:
                parent = dep.get('parent_id')
                child = dep.get('child_id')
                if parent and child:
                    graph[parent].append(child)
            
            # Find root packages (those without parents)
            all_children = set()
            for deps in graph.values():
                all_children.update(deps)
            
            roots = set(graph.keys()) - all_children
            
            if not roots:
                roots = set(list(graph.keys())[:1])
            
            # DFS to find max depth
            max_depth = 0
            
            def dfs(node, depth, visited):
                nonlocal max_depth
                if depth > max_depth:
                    max_depth = depth
                
                for neighbor in graph.get(node, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        dfs(neighbor, depth + 1, visited)
                        visited.remove(neighbor)
            
            for root in roots:
                dfs(root, 0, {root})
            
            self.parsed_data['summary']['max_depth'] = max_depth
            
        except Exception as e:
            print(f"⚠️ Error calculating max depth: {e}")
    
    def get_packages_by_type(self) -> Dict:
        """Get package distribution by type"""
        return dict(self.parsed_data['summary']['by_type'])
    
    def get_top_packages(self, limit: int = 10) -> List[Dict]:
        """Get top packages by number of dependents"""
        packages = []
        for pkg_id, dependents in self.parsed_data['package_dependents'].items():
            # Find package name
            pkg_name = 'unknown'
            pkg_version = 'unknown'
            for pkg in self.parsed_data['packages']:
                if pkg.get('id') == pkg_id:
                    pkg_name = pkg.get('name', 'unknown')
                    pkg_version = pkg.get('version', 'unknown')
                    break
            
            packages.append({
                'id': pkg_id,
                'name': pkg_name,
                'version': pkg_version,
                'dependents': len(dependents),
                'dependent_ids': dependents
            })
        
        packages.sort(key=lambda x: x['dependents'], reverse=True)
        return packages[:limit]
    
    def get_dependency_chains(self, limit: int = 10) -> List[Dict]:
        """Get sample dependency chains"""
        chains = []
        
        # Build parent-child map
        parent_map = defaultdict(list)
        for dep in self.parsed_data['dependencies']:
            parent = dep.get('parent_id')
            child = dep.get('child_id')
            if parent and child:
                parent_map[parent].append(child)
        
        # Find root packages
        all_children = set()
        for deps in parent_map.values():
            all_children.update(deps)
        
        roots = set(parent_map.keys()) - all_children
        if not roots:
            roots = set(list(parent_map.keys())[:3])
        
        # Build chains from roots
        for root in roots:
            chain = self._build_chain(root, parent_map, 0)
            if chain:
                chains.append(chain)
                if len(chains) >= limit:
                    break
        
        return chains
    
    def _build_chain(self, node_id: str, graph: Dict, depth: int, visited: set = None) -> Optional[Dict]:
        """Build a dependency chain from a node"""
        if visited is None:
            visited = set()
        
        if node_id in visited:
            return None
        
        visited.add(node_id)
        
        # Find package name
        pkg_name = 'unknown'
        pkg_version = 'unknown'
        for pkg in self.parsed_data['packages']:
            if pkg.get('id') == node_id:
                pkg_name = pkg.get('name', 'unknown')
                pkg_version = pkg.get('version', 'unknown')
                break
        
        chain = {
            'id': node_id,
            'name': pkg_name,
            'version': pkg_version,
            'depth': depth,
            'children': []
        }
        
        # Add children
        for child_id in graph.get(node_id, []):
            child_chain = self._build_chain(child_id, graph, depth + 1, visited.copy())
            if child_chain:
                chain['children'].append(child_chain)
                if len(chain['children']) >= 3:  # Limit children for readability
                    break
        
        return chain
    
    def to_json(self) -> Dict:
        """Convert parsed data to JSON-serializable dict"""
        return {
            'image': self.parsed_data['image'],
            'summary': self.parsed_data['summary'],
            'packages': self.parsed_data['packages'],
            'dependencies': self.parsed_data['dependencies'],
            'top_packages': self.get_top_packages(),
            'packages_by_type': self.get_packages_by_type(),
            'dependency_chains': self.get_dependency_chains(5),
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
            lines.append("# 📦 Syft SBOM Analysis Report")
            lines.append("")
            lines.append(f"**Generated:** {self.parsed_data['scan_timestamp']}")
            lines.append(f"**Image:** {self.parsed_data['image'].get('name', 'unknown')}")
            lines.append(f"**Tag:** {self.parsed_data['image'].get('version', 'latest')}")
            lines.append("")
            
            # Summary
            lines.append("## 📊 Summary")
            lines.append("")
            lines.append(f"| **Total Packages** | {self.parsed_data['summary']['total_packages']} |")
            lines.append(f"| **Total Dependencies** | {self.parsed_data['summary']['total_dependencies']} |")
            lines.append(f"| **Max Dependency Depth** | {self.parsed_data['summary']['max_depth']} |")
            lines.append("")
            
            # Packages by type
            lines.append("## 📦 Packages by Type")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for pkg_type, count in sorted(self.get_packages_by_type().items(), 
                                          key=lambda x: x[1], reverse=True):
                lines.append(f"| {pkg_type} | {count} |")
            lines.append("")
            
            # Top packages
            lines.append("## 🔗 Top Packages by Dependents")
            lines.append("")
            lines.append("| Package | Version | Dependents |")
            lines.append("|---------|---------|------------|")
            for pkg in self.get_top_packages(10):
                lines.append(f"| {pkg['name']} | {pkg['version']} | {pkg['dependents']} |")
            lines.append("")
            
            # Sample dependency chains
            lines.append("## 🌳 Sample Dependency Chains")
            lines.append("")
            
            chains = self.get_dependency_chains(3)
            for chain in chains:
                lines.append(f"### Chain: {chain['name']}@{chain['version']}")
                lines.append("")
                lines.append("```")
                self._format_chain(chain, lines, 0)
                lines.append("```")
                lines.append("")
            
            # Package licenses
            lines.append("## 📋 Licenses Summary")
            lines.append("")
            
            license_counts = defaultdict(int)
            for pkg in self.parsed_data['packages']:
                for license_name in pkg.get('licenses', []):
                    if license_name:
                        license_counts[license_name] += 1
            
            if license_counts:
                lines.append("| License | Packages |")
                lines.append("|---------|----------|")
                for license_name, count in sorted(license_counts.items(), 
                                                  key=lambda x: x[1], reverse=True)[:10]:
                    lines.append(f"| {license_name} | {count} |")
                lines.append("")
            
            # Security insights
            lines.append("## 🔒 Security Insights")
            lines.append("")
            lines.append("### 📊 Attack Surface Analysis")
            lines.append("")
            lines.append(f"- **Total packages:** {self.parsed_data['summary']['total_packages']}")
            lines.append(f"- **Direct dependencies:** {len([d for d in self.parsed_data['dependencies'] if d.get('type') == 'DIRECT'])}")
            lines.append(f"- **Transitive dependencies:** {len([d for d in self.parsed_data['dependencies'] if d.get('type') == 'INDIRECT'])}")
            lines.append("")
            
            # Recommendations
            lines.append("## 📋 Recommendations")
            lines.append("")
            
            total = self.parsed_data['summary']['total_packages']
            if total > 100:
                lines.append("### ⚠️ Large Package Count")
                lines.append("")
                lines.append(f"Your image contains **{total} packages**, which is relatively large. Consider:")
                lines.append("")
                lines.append("1. **Use minimal base images** (Alpine, Distroless)")
                lines.append("2. **Remove unused packages**")
                lines.append("3. **Optimize dependency tree** by updating dependencies")
                lines.append("")
            
            if self.parsed_data['summary']['max_depth'] > 5:
                lines.append("### ⚠️ Deep Dependency Tree")
                lines.append("")
                lines.append(f"Maximum dependency depth is **{self.parsed_data['summary']['max_depth']}**, which may:")
                lines.append("")
                lines.append("1. **Increase build time**")
                lines.append("2. **Increase attack surface**")
                lines.append("3. **Make vulnerability tracking harder**")
                lines.append("")
            
            lines.append("### ✅ Best Practices")
            lines.append("")
            lines.append("1. **Regularly update dependencies** to latest versions")
            lines.append("2. **Use dependency management tools** (Dependabot, Renovate)")
            lines.append("3. **Monitor SBOM for new vulnerabilities**")
            lines.append("4. **Keep dependency tree shallow**")
            lines.append("5. **Review licenses** for compliance issues")
            lines.append("")
            
            # Write file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            print(f"✅ Markdown report generated: {output_path}")
            
        except Exception as e:
            print(f"❌ Error generating markdown: {e}")
    
    def _format_chain(self, chain: Dict, lines: List[str], indent: int):
        """Format a dependency chain as text"""
        prefix = "  " * indent
        if indent == 0:
            lines.append(f"{prefix}📦 {chain['name']}@{chain['version']}")
        else:
            lines.append(f"{prefix}└── 📦 {chain['name']}@{chain['version']}")
        
        for child in chain.get('children', []):
            self._format_chain(child, lines, indent + 1)

def main():
    parser = argparse.ArgumentParser(
        description='Parse Syft SBOM results and generate structured data'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Path to Syft SBOM JSON file'
    )
    parser.add_argument(
        '--output-json',
        default='syft-parsed.json',
        help='Output JSON file path'
    )
    parser.add_argument(
        '--output-markdown',
        default='syft-report.md',
        help='Output Markdown report file path'
    )
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for all files'
    )
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Build full paths
    json_path = os.path.join(args.output_dir, args.output_json)
    md_path = os.path.join(args.output_dir, args.output_markdown)
    
    # Parse
    parser_obj = SyftResultParser(args.input)
    
    if not parser_obj.load_sbom():
        sys.exit(1)
    
    parser_obj.extract_image_info()
    parser_obj.parse_packages()
    parser_obj.parse_dependencies()
    
    # Save outputs
    parser_obj.save_json(json_path)
    parser_obj.generate_markdown_report(md_path)
    
    # Also save simplified version for dashboards
    simplified = {
        'total_packages': parser_obj.parsed_data['summary']['total_packages'],
        'total_dependencies': parser_obj.parsed_data['summary']['total_dependencies'],
        'max_depth': parser_obj.parsed_data['summary']['max_depth'],
        'packages_by_type': parser_obj.get_packages_by_type(),
        'top_packages': parser_obj.get_top_packages(5),
        'image': parser_obj.parsed_data['image']
    }
    
    simple_path = os.path.join(args.output_dir, 'syft-simplified.json')
    with open(simple_path, 'w', encoding='utf-8') as f:
        json.dump(simplified, f, indent=2)
    
    print(f"✅ Simplified data saved to: {simple_path}")
    print("✅ Syft parsing complete!")

if __name__ == "__main__":
    main()
