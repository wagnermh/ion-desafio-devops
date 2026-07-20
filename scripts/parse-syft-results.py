#!/usr/bin/env python3
import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

class SyftResultParser:
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
        try:
            if not os.path.exists(self.syft_json_path):
                print(f"File not found: {self.syft_json_path}")
                return False
            with open(self.syft_json_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            print(f"Loaded Syft SBOM file: {self.syft_json_path}")
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False
    
    def extract_image_info(self):
        try:
            descriptor = self.data.get('descriptor', {})
            if descriptor:
                self.parsed_data['image']['name'] = os.environ.get('IMAGE_NAME', 'unknown-image')
                self.parsed_data['image']['version'] = os.environ.get('IMAGE_TAG', 'latest')
                self.parsed_data['image']['scanner'] = 'syft'
                self.parsed_data['image']['format'] = descriptor.get('name', 'unknown')
                self.parsed_data['image']['scanned_at'] = datetime.now().isoformat()
            else:
                self.parsed_data['image'] = {
                    'name': os.environ.get('IMAGE_NAME', 'unknown-image'),
                    'version': os.environ.get('IMAGE_TAG', 'latest'),
                    'scanner': 'syft',
                    'scanned_at': datetime.now().isoformat()
                }
        except Exception as e:
            print(f"Error extracting image info: {e}")
            self.parsed_data['image'] = {
                'name': os.environ.get('IMAGE_NAME', 'unknown-image'),
                'version': os.environ.get('IMAGE_TAG', 'latest'),
                'scanner': 'syft',
                'scanned_at': datetime.now().isoformat()
            }
    
    def parse_packages(self):
        try:
            packages = []
            if 'artifacts' in self.data:
                packages = self.data.get('artifacts', [])
            elif 'packages' in self.data:
                packages = self.data.get('packages', [])
            else:
                for key in ['sbom', 'bom', 'components']:
                    if key in self.data:
                        packages = self.data.get(key, [])
                        break
            print(f"Found {len(packages)} packages in SBOM")
            for idx, pkg in enumerate(packages):
                parsed_pkg = self._parse_single_package(pkg, idx)
                if parsed_pkg:
                    self.parsed_data['packages'].append(parsed_pkg)
                    pkg_type = parsed_pkg.get('type', 'unknown')
                    self.parsed_data['summary']['by_type'][pkg_type] = \
                        self.parsed_data['summary']['by_type'].get(pkg_type, 0) + 1
            self.parsed_data['summary']['total_packages'] = len(self.parsed_data['packages'])
        except Exception as e:
            print(f"Error parsing packages: {e}")
    
    def _parse_single_package(self, pkg: Dict, idx: int) -> Optional[Dict]:
        try:
            pkg_id = pkg.get('id', f"pkg_{idx}")
            name = pkg.get('name', 'unknown')
            version = pkg.get('version', 'unknown')
            pkg_type = pkg.get('type', 'unknown')
            licenses = pkg.get('licenses', [])
            if isinstance(licenses, list):
                licenses = [l.get('value', '') if isinstance(l, dict) else str(l) for l in licenses]
            upstreams = pkg.get('upstreams', [])
            if upstreams and isinstance(upstreams, list):
                upstream_names = [u.get('name', '') for u in upstreams if isinstance(u, dict)]
            else:
                upstream_names = []
            language = pkg.get('language', 'unknown')
            if not language or language == 'unknown':
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
            print(f"Error parsing package {idx}: {e}")
            return None
    
    def parse_dependencies(self):
        try:
            relationships = []
            if 'artifactRelationships' in self.data:
                relationships = self.data.get('artifactRelationships', [])
            elif 'relationships' in self.data:
                relationships = self.data.get('relationships', [])
            elif 'dependencies' in self.data:
                relationships = self.data.get('dependencies', [])
            print(f"Found {len(relationships)} relationships in SBOM")
            pkg_id_map = {pkg['id']: pkg for pkg in self.parsed_data['packages']}
            for rel in relationships:
                parsed_rel = self._parse_single_relationship(rel, pkg_id_map)
                if parsed_rel:
                    self.parsed_data['dependencies'].append(parsed_rel)
                    parent_id = parsed_rel.get('parent_id')
                    child_id = parsed_rel.get('child_id')
                    if parent_id and child_id:
                        self.parsed_data['package_dependents'][parent_id].append(child_id)
            self.parsed_data['summary']['total_dependencies'] = len(self.parsed_data['dependencies'])
            self._calculate_max_depth()
        except Exception as e:
            print(f"Error parsing dependencies: {e}")
    
    def _parse_single_relationship(self, rel: Dict, pkg_id_map: Dict) -> Optional[Dict]:
        try:
            parent_id = rel.get('parent', rel.get('parent_id', ''))
            child_id = rel.get('child', rel.get('child_id', ''))
            rel_type = rel.get('type', 'DEPENDS_ON').upper()
            if parent_id and parent_id not in pkg_id_map:
                for pkg_id, pkg in pkg_id_map.items():
                    if pkg.get('id') == parent_id:
                        parent_id = pkg_id
                        break
            if child_id and child_id not in pkg_id_map:
                for pkg_id, pkg in pkg_id_map.items():
                    if pkg.get('id') == child_id:
                        child_id = pkg_id
                        break
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
            elif 'parent' in rel and 'child' in rel:
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
            print(f"Error parsing relationship: {e}")
            return None
    
    def _calculate_max_depth(self):
        try:
            if not self.parsed_data['dependencies']:
                return
            graph = defaultdict(list)
            for dep in self.parsed_data['dependencies']:
                parent = dep.get('parent_id')
                child = dep.get('child_id')
                if parent and child:
                    graph[parent].append(child)
            all_children = set()
            for deps in graph.values():
                all_children.update(deps)
            roots = set(graph.keys()) - all_children
            if not roots:
                roots = set(list(graph.keys())[:1])
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
            print(f"Error calculating max depth: {e}")
    
    def get_packages_by_type(self) -> Dict:
        return dict(self.parsed_data['summary']['by_type'])
    
    def get_top_packages(self, limit: int = 10) -> List[Dict]:
        packages = []
        for pkg_id, dependents in self.parsed_data['package_dependents'].items():
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
        chains = []
        parent_map = defaultdict(list)
        for dep in self.parsed_data['dependencies']:
            parent = dep.get('parent_id')
            child = dep.get('child_id')
            if parent and child:
                parent_map[parent].append(child)
        all_children = set()
        for deps in parent_map.values():
            all_children.update(deps)
        roots = set(parent_map.keys()) - all_children
        if not roots:
            roots = set(list(parent_map.keys())[:3])
        for root in roots:
            chain = self._build_chain(root, parent_map, 0)
            if chain:
                chains.append(chain)
                if len(chains) >= limit:
                    break
        return chains
    
    def _build_chain(self, node_id: str, graph: Dict, depth: int, visited: set = None) -> Optional[Dict]:
        if visited is None:
            visited = set()
        if node_id in visited:
            return None
        visited.add(node_id)
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
        for child_id in graph.get(node_id, []):
            child_chain = self._build_chain(child_id, graph, depth + 1, visited.copy())
            if child_chain:
                chain['children'].append(child_chain)
                if len(chain['children']) >= 3:
                    break
        return chain
    
    def to_json(self) -> Dict:
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
        try:
            data = self.to_json()
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"Saved parsed data to: {output_path}")
        except Exception as e:
            print(f"Error saving JSON: {e}")
    
    def generate_markdown_report(self, output_path: str):
        try:
            lines = []
            lines.append("# Syft SBOM Analysis Report")
            lines.append("")
            lines.append(f"Generated: {self.parsed_data['scan_timestamp']}")
            lines.append(f"Image: {self.parsed_data['image'].get('name', 'unknown')}")
            lines.append(f"Tag: {self.parsed_data['image'].get('version', 'latest')}")
            lines.append("")
            lines.append("## Summary")
            lines.append("")
            lines.append(f"| Total Packages | {self.parsed_data['summary']['total_packages']} |")
            lines.append(f"| Total Dependencies | {self.parsed_data['summary']['total_dependencies']} |")
            lines.append(f"| Max Dependency Depth | {self.parsed_data['summary']['max_depth']} |")
            lines.append("")
            lines.append("## Packages by Type")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for pkg_type, count in sorted(self.get_packages_by_type().items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {pkg_type} | {count} |")
            lines.append("")
            lines.append("## Top Packages by Dependents")
            lines.append("")
            lines.append("| Package | Version | Dependents |")
            lines.append("|---------|---------|------------|")
            for pkg in self.get_top_packages(10):
                lines.append(f"| {pkg['name']} | {pkg['version']} | {pkg['dependents']} |")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f"Markdown report generated: {output_path}")
        except Exception as e:
            print(f"Error generating markdown: {e}")

def main():
    parser = argparse.ArgumentParser(description='Parse Syft SBOM results')
    parser.add_argument('--input', required=True, help='Path to Syft SBOM JSON file')
    parser.add_argument('--output-json', default='syft-parsed.json', help='Output JSON file path')
    parser.add_argument('--output-markdown', default='syft-report.md', help='Output Markdown report file path')
    parser.add_argument('--output-dir', default='.', help='Output directory for all files')
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, args.output_json)
    md_path = os.path.join(args.output_dir, args.output_markdown)
    parser_obj = SyftResultParser(args.input)
    if not parser_obj.load_sbom():
        sys.exit(1)
    parser_obj.extract_image_info()
    parser_obj.parse_packages()
    parser_obj.parse_dependencies()
    parser_obj.save_json(json_path)
    parser_obj.generate_markdown_report(md_path)
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
    print(f"Simplified data saved to: {simple_path}")
    print("Syft parsing complete!")

if __name__ == "__main__":
    main()
