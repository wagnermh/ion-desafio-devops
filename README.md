# 🚀 ION Sitemas Desafio DevOps - Ambiente KIND

Este projeto automatiza a criação de um cluster Kubernetes local usando KIND (Kubernetes IN Docker) e instala a aplicação do desafio DevOps.

## 📋 Pré-requisitos

### **Linux:**
- Docker instalado e rodando
- Git
- Bash

## 🛠️ Instalação Automática

### **Linux:**
```bash
# Clone o repositório
git clone https://github.com/wagnermh/ion-desafio-devops.git
cd ion-desafio-devops

# Execute o script de instalação
chmod +x scripts/install-kind-linux-complete.sh
./scripts/install-kind-linux-complete.sh

## 🛠️ Instalação Manual

### **Linux:**
```bash
# Clone o repositório
git clone https://github.com/wagnermh/ion-desafio-devops.git
cd ion-desafio-devops

## 🚀 Comandos Manuais (Opcional)
### Se preferir instalar manualmente:

# 1. Instalar KIND:
```bash
# Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# 2. Criar Cluster:
```bash
kind create cluster --config kind-config.yaml --name kind-cluster

# 3. Instalar Helm:
```bash
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
rm get_helm.sh

## 🎯 Instalar a Aplicação do Desafio

### Método 1: Usando Helm Chart Local
```bash
# Navegar para o diretório do chart
cd charts/app

# Instalar a aplicação
helm install ion-app /charts/app

## 🌐 Acessando a Aplicação
### 1. Configurar DNS Local:
```bash
# Linux/macOS
echo "127.0.0.1 ion-app.local" | sudo tee -a /etc/hosts

### 2. Acessar a Aplicação:
```text
URL: http://ion-app.local

## 3. Verificar Status:
```bash
# Verificar pods
kubectl get pods | grep ion-app

# Verificar serviços
kubectl get svc | grep ion-app

# Verificar ingress
kubectl get ingress

# Ver logs da aplicação
kubectl logs <pod-name>


## 🔄 Fluxo de Desenvolvimento

Desenvolver aplicação em src/

Testar localmente: go run src/main.go

Build da imagem: docker build -t seu-usuario/ion-desafio-devops-app .

Push da imagem: docker push seu-usuario/ion-desafio-devops-app

Deploy no KIND: helm upgrade ion-app charts/app/

Testar: curl http://ion-app.local
