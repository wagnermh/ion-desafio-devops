#!/bin/bash
# install-kind-linux.sh

set -e

echo "🐳 Instalando KIND no Linux..."
echo "================================"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para verificar se um comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Função para imprimir mensagens coloridas
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Verificar se é root
if [ "$EUID" -eq 0 ]; then
    print_warning "Não execute como root. O KIND não precisa de privilégios root."
    exit 1
fi

# Verificar se Docker está instalado
if ! command_exists docker; then
    print_error "Docker não encontrado. Instale o Docker primeiro:"
    echo "  https://docs.docker.com/engine/install/"
    exit 1
fi

print_status "Verificando versão do Docker..."
docker version

# Configurar DNS Local
print_status "Configurando DNS Local ..."
echo "127.0.0.1 ion-app.local" | sudo tee -a /etc/hosts

# Verificar arquivo de configuração
if [ ! -f "kind-config.yaml" ]; then
    print_error "Arquivo kind-config.yaml não encontrado!"
    echo "Criando arquivo de configuração padrão..."
    cat > kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: kind-cluster
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
EOF
    print_status "Arquivo kind-config.yaml criado"
fi

# Instalar KIND
print_status "Baixando e instalando KIND..."
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Verificar instalação
if command_exists kind; then
    print_status "KIND instalado com sucesso!"
    kind version
else
    print_error "Falha na instalação do KIND"
    exit 1
fi

# Criar cluster
print_status "Criando cluster KIND..."
kind create cluster --config kind-config.yaml --name kind-cluster 

# Verificar nodes
print_status "Nodes do cluster:"
kubectl get nodes

# Instalar NGINX Ingress
print_status "Instalando NGINX Ingress Controller..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

sleep 240

# Aguardar Ingress Controller ficar pronto
#print_status "Aguardando Ingress Controller ficar ready..."
#kubectl wait --namespace ingress-nginx \
#  --for=condition=ready pod \
#  --selector=app.kubernetes.io/component=controller \
#  --timeout=300s

print_status "Verificando Ingress:"
kubectl get pods -n ingress-nginx

# Instalar HELM
print_status "Instalando HELM..."
if ! command_exists helm; then
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 get_helm.sh
    ./get_helm.sh
    rm get_helm.sh
    print_status "HELM instalado com sucesso!"
else
    print_status "HELM já está instalado"
fi

helm version

# Configurar Helm
print_status "Configurando Helm..."
helm repo add stable https://charts.helm.sh/stable
helm repo update

# Testar Helm
print_status "Testando Helm..."
helm list --all-namespaces

print_status "Repositórios Helm disponíveis:"
helm repo list

sleep 10
echo ""
# Subir a aplicação
helm install ion-app ../charts/app
echo ""

echo ""
echo "🎉 INSTALAÇÃO CONCLUÍDA!"
echo "📊 Cluster: kind-cluster"
echo "🌐 Ingress disponível na porta 80"
echo "🔧 Contexto kubectl: kind-cluster"
echo ""
echo "📋 Comandos úteis:"
echo "   kind delete cluster --name kind-cluster"
echo "   kubectl get all --all-namespaces"
echo "   kubectl get ingress"

echo ""
echo "📋 Comandos úteis:"
echo "   kind delete cluster --name kind-cluster"
echo "   kubectl get all --all-namespaces"
echo "   helm list --all-namespaces"
echo "   helm install ion-app /charts/app"

echo ""
echo "🌐 Para testar a aplicação:"
echo "   Adicione ao /etc/hosts:"
echo "   127.0.0.1 ion-app.local"
echo "   Acesse: http://ion-app.local"

echo ""
echo "🔧 Para aplicar as configurações de auto-completion:"
echo "   source ~/.bashrc"
