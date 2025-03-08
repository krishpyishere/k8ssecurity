#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up secure Kubernetes environment...${NC}"

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install required tools
echo -e "${GREEN}Installing required tools...${NC}"
tools=("kind" "kubectl" "kubeseal" "kube-linter")
for tool in "${tools[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${YELLOW}Installing $tool...${NC}"
        brew install $tool
    else
        echo -e "${GREEN}$tool already installed${NC}"
    fi
done

# Create kind cluster if it doesn't exist
if ! kind get clusters | grep -q "security-test"; then
    echo -e "${GREEN}Creating Kubernetes cluster...${NC}"
    kind create cluster --name security-test --config kind-config.yaml
else
    echo -e "${YELLOW}Cluster 'security-test' already exists${NC}"
fi

# Wait for cluster to be ready
echo "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=60s

# Install NGINX Ingress Controller
echo -e "${GREEN}Installing NGINX Ingress Controller...${NC}"
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/cloud/deploy.yaml

# Install Sealed Secrets Controller
echo -e "${GREEN}Installing Sealed Secrets Controller...${NC}"
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.5/controller.yaml

# Wait for controllers to be ready
echo "Waiting for controllers to be ready..."
kubectl -n ingress-nginx wait --for=condition=Ready pod --selector=app.kubernetes.io/component=controller --timeout=90s
kubectl -n kube-system wait --for=condition=Ready pod --selector=name=sealed-secrets-controller --timeout=90s

# Apply security configurations
echo -e "${GREEN}Applying security configurations...${NC}"

# Create namespace and pod security policies
echo "Applying pod security configurations..."
kubectl apply -f security-configs/pod-security/secure-pod.yaml

# Apply RBAC configuration
echo "Applying RBAC configurations..."
kubectl apply -f security-configs/rbac/restricted-role.yaml

# Apply network policies to all namespaces
echo "Applying network policies..."
NAMESPACES=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')
for ns in $NAMESPACES; do
    echo "Applying network policies to namespace: $ns"
    # Replace namespace in network policies template and apply
    sed "s/test-security/$ns/g" security-configs/network-policies/default-policies.yaml | kubectl apply -f -
done

# Apply ingress configuration
echo "Applying ingress configurations..."
kubectl apply -f security-configs/ingress/secure-ingress.yaml

# Create and encrypt secrets
echo "Creating and encrypting secrets..."
# Get the public cert from the controller
kubeseal --fetch-cert > pub-cert.pem

# Create sealed secret from template
kubeseal --format=yaml --cert=pub-cert.pem \
    < security-configs/secrets/secret-template.yaml \
    > security-configs/secrets/sealed-secret.yaml

# Apply the sealed secret
kubectl apply -f security-configs/secrets/sealed-secret.yaml

# Run KubeLinter checks
echo -e "${GREEN}Running KubeLinter security checks...${NC}"
kube-linter lint --config .kube-linter.yaml security-configs/ 2>&1 | tee security-report.txt

# Clean up
rm pub-cert.pem

echo -e "${GREEN}Setup complete!${NC}"
echo -e "${YELLOW}To delete the cluster when done:${NC}"
echo "kind delete cluster --name security-test"

# Install Python dependencies for security checker
echo -e "${GREEN}Installing Python dependencies...${NC}"
python3 -m pip install -r requirements.txt
python3 -m pip install -e .

echo -e "${GREEN}You can now run the security checker with:${NC}"
echo "python3 k8s_security_check.py -n test-security" 