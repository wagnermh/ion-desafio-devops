# 🎨 Guia de Uso do Excalidraw para Dashboards de Segurança

## Índice
1. [Introdução](#introdução)
2. [Dashboards Disponíveis](#dashboards-disponíveis)
3. [Como Visualizar](#como-visualizar)
4. [Edição e Personalização](#edição-e-personalização)
5. [Exemplos Avançados](#exemplos-avançados)
6. [Boas Práticas](#boas-práticas)
7. [Integração com Pipeline](#integração-com-pipeline)
8. [Solução de Problemas](#solução-de-problemas)

---

## Introdução

O **Excalidraw** é uma ferramenta de quadro branco virtual com estilo "desenhado à mão" que cria diagramas interativos e visualmente atraentes. Nossa pipeline gera automaticamente dashboards de segurança no formato Excalidraw, proporcionando uma visão clara e acessível do status de segurança.

### Vantagens

- ✅ **Visualização intuitiva**: Estilo "hand-drawn" mais amigável
- ✅ **Interativo**: Permite zoom, pan e navegação
- ✅ **Colaborativo**: Compartilhável e editável em tempo real
- ✅ **Exportável**: Múltiplos formatos (JSON, PNG, SVG)
- ✅ **Personalizável**: Fácil adaptação para diferentes necessidades

---

## Dashboards Disponíveis

### 1. 🔒 Dashboard de Segurança (`excalidraw-dashboard.json`)

Dashboard completo mostrando todas as métricas de segurança do container.
┌─────────────────────────────────────────────────────────────────┐
│ 🔒 Security Dashboard - 2026-07-20 14:30 │
├─────────────────────────────────────────────────────────────────┤
│ │
│ 📦 Image: ion-desafio-devops-app:1.42 │
│ 🏷️ Tag: 1.42 │
│ │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ 📊 Vulnerability Summary │ │
│ ├───────────────────────────────────────────────────────────┤ │
│ │ 🔴 CRITICAL: 3 vulnerabilities │ │
│ │ 🟠 HIGH: 12 vulnerabilities │ │
│ │ 🟡 MEDIUM: 45 vulnerabilities │ │
│ │ 🟢 LOW: 23 vulnerabilities │ │
│ └───────────────────────────────────────────────────────────┘ │
│ │
│ 📦 Top Vulnerable Packages: │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ openssl ████████████████░░░░ 3 vulns │ │
│ │ python ██████████████░░░░░░ 2 vulns │ │
│ │ nginx ████████████░░░░░░░░ 2 vulns │ │
│ └───────────────────────────────────────────────────────────┘ │
│ │
│ ✅ All scans passed - Image approved! │
└─────────────────────────────────────────────────────────────────┘

text

### 2. 📦 Dashboard de Dependências

Visualização detalhada das dependências e suas relações.
┌─────────────────────────────────────────────────────────────┐
│ 📦 Dependency Map │
├─────────────────────────────────────────────────────────────┤
│ │
│ [Application] │
│ │ │
│ ├── [fastapi v0.100.0] ── [starlette] │
│ │ │ │
│ │ └── [pydantic] │
│ │ │
│ ├── [sqlalchemy v2.0.19] ── [greenlet] │
│ │ │
│ └── [python v3.11.4] │
│ │
│ Legend: │
│ 🟢 Secure 🟡 Review 🔴 Needs Attention │
└─────────────────────────────────────────────────────────────┘

text

### 3. 📈 Dashboard de Tendências

Visualização da evolução das métricas de segurança.
┌─────────────────────────────────────────────────────────────┐
│ 📊 Security Trends │
├─────────────────────────────────────────────────────────────┤
│ │
│ Vulnerabilities over Time │
│ 50 ┤ ╭──╮ │
│ 40 ┤ ╭──╯ ╰──╮ │
│ 30 ┤ ╭──╯ ╰──╮ │
│ 20 ┤╭─╯ ╰─╮ │
│ 10 ┤╯ ╰─ │
│ 0 ┼─────────┬─────────┬─────────┬─────────┬───────── │
│ v1.0 v1.1 v1.2 v1.3 v1.4 │
│ │
│ 📈 Critical decreasing by 80% │
│ 📉 New vulnerabilities trend: ⬇️ 25% │
└─────────────────────────────────────────────────────────────┘

text

### 4. 🎯 Dashboard de Riscos

Matriz de riscos com posicionamento de vulnerabilidades.
┌─────────────────────────────────────────────────────────────┐
│ 🎯 Risk Matrix │
├─────────────────────────────────────────────────────────────┤
│ │
│ Impact │
│ High │ ⚠️ CVE-2023-1234 ⚠️ CVE-2023-5678 │
│ │ │
│ Med │ ⚠️ CVE-2023-9012 │
│ │ │
│ Low │ ⚠️ CVE-2023-3456 │
│ │ │
│ └────────┬────────┬────────┬────────┬────── │
│ Low Med High Critical │
│ Probability │
│ │
│ 🔴 Critical: 2 🟠 High: 1 🟡 Medium: 1 │
└─────────────────────────────────────────────────────────────┘

text

---

## Como Visualizar

### Online (Recomendado)

#### Opção 1: Excalidraw Web

1. Acesse [Excalidraw.com](https://excalidraw.com)
2. Clique no menu (☰) → **"Load from file"**
3. Selecione o arquivo `excalidraw-dashboard.json`
4. O dashboard será carregado automaticamente

#### Opção 2: Excalidraw + (Com armazenamento)

1. Acesse [Excalidraw.com](https://excalidraw.com)
2. Clique no menu (☰) → **"Save to..."** → **"Save to file"**
3. Faça download do arquivo JSON
4. Próxima vez, use **"Load from file"**

### Offline

#### Opção 1: Excalidraw Desktop

```bash
# Download desktop app
curl -L -o excalidraw.AppImage \
  https://github.com/excalidraw/excalidraw-desktop/releases/latest/download/Excalidraw.AppImage

# Tornar executável
chmod +x excalidraw.AppImage

# Executar
./excalidraw.AppImage

# Carregar o dashboard
# File → Open → selecionar excalidraw-dashboard.json
