# 📊 Guia de Uso do Mermaid para Visualizações de Segurança

## Índice
1. [Introdução](#introdução)
2. [Diagramas Disponíveis](#diagramas-disponíveis)
3. [Como Visualizar](#como-visualizar)
4. [Personalização](#personalização)
5. [Exemplos Avançados](#exemplos-avançados)
6. [Boas Práticas](#boas-práticas)
7. [Solução de Problemas](#solução-de-problemas)

---

## Introdução

O **Mermaid** é uma ferramenta de diagramação que permite criar gráficos e diagramas usando uma sintaxe baseada em texto (Markdown). Nossa pipeline gera automaticamente diagramas Mermaid para visualizar o fluxo de segurança, vulnerabilidades e dependências.

### Vantagens

- ✅ **Versionável**: Diagramas como código no Git
- ✅ **Integrado**: Renderização nativa no GitHub
- ✅ **Automático**: Gerados a cada build
- ✅ **Interativo**: Possibilidade de clicar e explorar
- ✅ **Documentação viva**: Sempre atualizada

---

## Diagramas Disponíveis

### 1. 🎯 Pipeline de Segurança (`pipeline.md`)

Mostra o fluxo completo da pipeline DevSecOps com todos os gates de segurança.

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
