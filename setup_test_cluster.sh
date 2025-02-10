#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up local Kubernetes test cluster...${NC}"

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install kind if not present
if ! command -v kind &> /dev/null; then
    echo -e "${YELLOW}Installing kind...${NC}"
    brew install kind
fi

# Install kubectl if not present
if ! command -v kubectl &> /dev/null; then
    echo -e "${YELLOW}Installing kubectl...${NC}"
    brew install kubectl
fi

# Create kind cluster configuration
cat << EOF > kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

# Create the cluster
echo -e "${YELLOW}Creating Kubernetes cluster...${NC}"
kind create cluster --name security-test --config kind-config.yaml

# Wait for cluster to be ready
echo -e "${YELLOW}Waiting for cluster to be ready...${NC}"
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Create some test resources for security scanning
echo -e "${YELLOW}Creating test resources...${NC}"

# Create a test namespace
kubectl create namespace test-security

# Create a pod with security issues
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: security-test-pod
  namespace: test-security
spec:
  containers:
  - name: privileged-container
    image: nginx
    securityContext:
      privileged: true
  - name: root-container
    image: nginx
    securityContext:
      runAsNonRoot: false
  - name: no-limits
    image: nginx
EOF

# Create a service with NodePort
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: test-service
  namespace: test-security
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30080
  selector:
    app: test
EOF

# Create an overly permissive RBAC role
cat << EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: overly-permissive-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
EOF

# Create a pod with sensitive mounts
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: sensitive-mounts-pod
  namespace: test-security
spec:
  containers:
  - name: sensitive-container
    image: nginx
    volumeMounts:
    - name: docker-socket
      mountPath: /var/run/docker.sock
  volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock
EOF

# Create a pod with DinD
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: dind-pod
  namespace: test-security
spec:
  containers:
  - name: dind
    image: docker:dind
    securityContext:
      privileged: true
EOF

echo -e "${GREEN}Test cluster setup complete!${NC}"
echo -e "${GREEN}You can now run your security checker against the 'test-security' namespace${NC}"
echo -e "${YELLOW}To test the security checker, run:${NC}"
echo -e "k8s-security-check -n test-security"
echo
echo -e "${YELLOW}To delete the cluster when done:${NC}"
echo -e "kind delete cluster --name security-test" 