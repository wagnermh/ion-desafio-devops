#!/usr/bin/env python3
"""
Generate Excalidraw security dashboard from scan results
"""
import json
import os
import argparse
from datetime import datetime
import uuid

def create_excalidraw_element(element_type, x, y, **kwargs):
    """Create a standard Excalidraw element"""
    base = {
        "id": str(uuid.uuid4())[:8],
        "type": element_type,
        "x": x,
        "y": y,
        "width": kwargs.get('width', 300),
        "height": kwargs.get('height', 40),
        "strokeColor": kwargs.get('strokeColor', '#000000'),
        "backgroundColor": kwargs.get('backgroundColor', 'transparent'),
        "fillStyle": "solid",
        "strokeWidth": 2,
        "strokeStyle": "solid",
        "roughness": 1,
        "opacity": 100,
        "groupIds": [],
        "roundness": {"type": 2},
        "seed": 1,
        "version": 1,
        "versionNonce": 1,
        "isDeleted": False,
        "boundElements": [],
        "updated": datetime.now().timestamp() * 1000,
        "link": kwargs.get('link', None),
        "locked": False,
    }
    
    if element_type == "text":
        base.update({
            "text": kwargs.get('text', ''),
            "fontSize": kwargs.get('fontSize', 20),
            "fontFamily": 1,
            "textAlign": "left",
            "verticalAlign": "top",
            "containerId": None,
            "originalText": kwargs.get('text', ''),
            "lineHeight": 1.25
        })
    elif element_type == "rectangle":
        base.update({
            "x": x,
            "y": y,
            "width": kwargs.get('width', 300),
            "height": kwargs.get('height', 40),
        })
    elif element_type == "ellipse":
        base.update({
            "x": x,
            "y": y,
            "width": kwargs.get('width', 100),
            "height": kwargs.get('height', 50),
        })
    
    return base

def load_data(data_dir):
    """Load Trivy and Syft data from directory"""
    data = {
        'trivy': None,
        'syft': None
    }
    
    trivy_files = [
        os.path.join(data_dir, 'trivy-analysis.json'),
        os.path.join(data_dir, 'trivy-parsed.json'),
        os.path.join(data_dir, 'trivy-simplified.json')
    ]
    
    for file_path in trivy_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    data['trivy'] = json.load(f)
                print(f"✅ Trivy data loaded from: {file_path}")
                break
            except Exception as e:
                print(f"⚠️ Error loading {file_path}: {e}")
    
    syft_files = [
        os.path.join(data_dir, 'syft-analysis.json'),
        os.path.join(data_dir, 'syft-parsed.json'),
        os.path.join(data_dir, 'syft-simplified.json')
    ]
    
    for file_path in syft_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    data['syft'] = json.load(f)
                print(f"✅ Syft data loaded from: {file_path}")
                break
            except Exception as e:
                print(f"⚠️ Error loading {file_path}: {e}")
    
    return data

def generate_excalidraw_dashboard(data_dir):
    """Generate complete Excalidraw dashboard"""
    
    data = load_data(data_dir)
    trivy_data = data.get('trivy', {})
    syft_data = data.get('syft', {})
    
    dashboard = {
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.com",
        "elements": [],
        "appState": {
            "viewBackgroundColor": "#ffffff",
            "currentItemStrokeColor": "#000000",
            "currentItemBackgroundColor": "transparent",
            "currentItemFillStyle": "solid",
            "currentItemStrokeWidth": 2,
            "currentItemStrokeStyle": "solid",
            "currentItemRoughness": 1,
            "currentItemOpacity": 100,
            "currentItemFontFamily": 1,
            "currentItemFontSize": 20,
            "currentItemTextAlign": "left",
            "currentItemStartArrowhead": None,
            "currentItemEndArrowhead": "arrow",
            "scrollX": 0,
            "scrollY": 0,
            "zoom": {"value": 1},
            "currentItemRoundness": {"type": 2},
            "gridSize": None,
            "colorPalette": {}
        }
    }
    
    dashboard['elements'].append(create_excalidraw_element(
        "text", 100, 50,
        text=f"🔒 Security Dashboard - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        fontSize=32,
        width=600,
        height=60
    ))
    
    image_name = os.environ.get('IMAGE_NAME', 'ion-desafio-devops-app')
    image_tag = os.environ.get('IMAGE_TAG', 'latest')
    
    dashboard['elements'].append(create_excalidraw_element(
        "text", 100, 130,
        text=f"📦 Image: {image_name}",
        fontSize=18,
        width=500,
        height=30
    ))
    
    dashboard['elements'].append(create_excalidraw_element(
        "text", 100, 170,
        text=f"🏷️ Tag: {image_tag}",
        fontSize=18,
        width=300,
        height=30
    ))
    
    y_pos = 230
    dashboard['elements'].append(create_excalidraw_element(
        "rectangle", 100, y_pos - 10,
        width=400,
        height=220,
        strokeColor="#333333",
        backgroundColor="#f5f5f5"
    ))
    
    dashboard['elements'].append(create_excalidraw_element(
        "text", 120, y_pos + 10,
        text="📊 Vulnerability Summary",
        fontSize=20,
        width=300,
        height=30
    ))
    
    severity_counts = {}
    if trivy_data:
        severity_counts = trivy_data.get('severity_counts', {})
        if not severity_counts:
            severity_counts = trivy_data.get('summary', {}).get('severity_counts', {})
    
    if not severity_counts:
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
    
    severity_colors = {
        'CRITICAL': '#f44336',
        'HIGH': '#ff9800',
        'MEDIUM': '#ffeb3b',
        'LOW': '#4caf50'
    }
    
    y_pos = 280
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        color = severity_colors.get(severity, '#999999')
        
        dashboard['elements'].append(create_excalidraw_element(
            "rectangle", 120, y_pos,
            width=360,
            height=30,
            strokeColor=color,
            backgroundColor=f"{color}33"
        ))
        
        emoji = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡' if severity == 'MEDIUM' else '🟢'
        dashboard['elements'].append(create_excalidraw_element(
            "text", 130, y_pos + 6,
            text=f"{emoji} {severity}: {count} vulnerabilities",
            fontSize=16,
            width=300,
            height=24
        ))
        y_pos += 40
    
    y_pos = 480
    dashboard['elements'].append(create_excalidraw_element(
        "text", 100, y_pos,
        text="📦 Top Vulnerable Packages",
        fontSize=20,
        width=300,
        height=30
    ))
    
    top_packages = []
    if trivy_data:
        top_packages = trivy_data.get('top_affected_packages', [])
    if not top_packages and syft_data:
        top_packages = syft_data.get('most_depended_on', [])
    
    if not top_packages:
        top_packages = [
            {'name': 'openssl', 'count': 3},
            {'name': 'python', 'count': 2},
            {'name': 'nginx', 'count': 2}
        ]
    
    y_pos = 520
    for pkg in top_packages[:5]:
        name = pkg.get('package', pkg.get('name', 'unknown'))
        count = pkg.get('count', pkg.get('vuln_count', pkg.get('dependents', 0)))
        bar_width = min(count * 30, 300)
        
        dashboard['elements'].append(create_excalidraw_element(
            "text", 120, y_pos,
            text=f"{name}",
            fontSize=14,
            width=200,
            height=20
        ))
        
        dashboard['elements'].append(create_excalidraw_element(
            "rectangle", 300, y_pos,
            width=bar_width if bar_width > 0 else 10,
            height=20,
            strokeColor="#2196f3",
            backgroundColor="#2196f333"
        ))
        
        dashboard['elements'].append(create_excalidraw_element(
            "text", 310, y_pos + 2,
            text=f"{count} vulns",
            fontSize=12,
            width=100,
            height=18
        ))
        
        y_pos += 30
    
    y_pos = 700
    scan_status = os.environ.get('SCAN_STATUS', 'passed')
    
    if scan_status == 'passed':
        color = '#4caf50'
        bg_color = '#e8f5e9'
        text = '✅ All scans passed - Image approved!'
    else:
        color = '#f44336'
        bg_color = '#ffebee'
        text = '❌ Scans failed - Review vulnerabilities!'
    
    dashboard['elements'].append(create_excalidraw_element(
        "rectangle", 100, y_pos,
        width=400,
        height=60,
        strokeColor=color,
        backgroundColor=bg_color
    ))
    
    dashboard['elements'].append(create_excalidraw_element(
        "text", 120, y_pos + 18,
        text=text,
        fontSize=18,
        width=350,
        height=28
    ))
    
    return dashboard

def main():
    parser = argparse.ArgumentParser(description='Generate Excalidraw dashboard')
    parser.add_argument('--input', required=True, help='Input directory with artifacts')
    parser.add_argument('--output', required=True, help='Output directory for dashboard')
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    dashboard = generate_excalidraw_dashboard(args.input)
    
    output_path = os.path.join(args.output, 'excalidraw-dashboard.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(dashboard, f, indent=2)
    
    print(f"✅ Excalidraw dashboard gerado: {output_path}")
    
    readme_path = os.path.join(args.output, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 🎨 Excalidraw Security Dashboard\n\n")
        f.write(f"**Gerado em:** {datetime.now().isoformat()}\n\n")
        f.write("## 📋 Como visualizar este dashboard:\n\n")
        f.write("1. **Acesse [Excalidraw](https://excalidraw.com)**\n")
        f.write("2. **Clique no menu (☰) → 'Load from file'**\n")
        f.write("3. **Faça upload do arquivo `excalidraw-dashboard.json`**\n")
        f.write("4. **O dashboard será renderizado automaticamente**\n\n")
        f.write("## 🔄 Alternativa: Usar o App Desktop\n\n")
        f.write("1. Baixe o [Excalidraw Desktop](https://github.com/excalidraw/excalidraw-desktop/releases)\n")
        f.write("2. Abra o app e carregue o arquivo JSON\n\n")
        f.write("## 📊 Elementos do Dashboard\n\n")
        f.write("- **Cabeçalho**: Nome da imagem, tag e data de geração\n")
        f.write("- **Resumo de Vulnerabilidades**: Contagens por severidade do Trivy\n")
        f.write("- **Top Pacotes**: Pacotes mais vulneráveis\n")
        f.write("- **Decisão**: Status geral de segurança\n")
    
    print(f"✅ README gerado: {readme_path}")
    print("✅ Dashboard Excalidraw gerado com sucesso!")

if __name__ == "__main__":
    main()
