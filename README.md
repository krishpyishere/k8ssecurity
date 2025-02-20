# Kubernetes Security Scanner

A comprehensive security scanning tool for Kubernetes clusters that identifies security issues, misconfigurations, and potential vulnerabilities.

## Features

The script checks for:

### Container Security
- Containers running as root
- Containers running in privileged mode
- Missing resource limits
- Sensitive path mounts
- Docker-in-Docker (DinD) detection
- Crypto mining container detection
- Container escape risks
- Kubesec analysis:
  - Security context validation
  - Privilege escalation checks
  - Root user prevention
  - Read-only root filesystem
  - Resource limits enforcement
  - Security capabilities
- Trivy vulnerability scanning:
  - CVE detection and analysis
  - Package vulnerability assessment
  - Version-specific fixes
  - Severity-based categorization
  - Detailed vulnerability descriptions
  - Reference documentation
- gVisor security:
  - Runtime availability checks
  - Node configuration validation
  - RuntimeClass configuration
  - Workload isolation assessment
  - Security-sensitive workload detection
  - Privileged container isolation
  - Containerd integration verification

### Admission Controller Security
- Verification of enabled admission controllers
- Detection of missing critical controllers
- Identification of deprecated controllers
- Webhook configuration analysis:
  - TLS configuration validation
  - Security policy checks
  - Timeout settings review
  - Failure policy assessment
- Required controller checks:
  - PodSecurityPolicy
  - NodeRestriction
  - ValidatingAdmissionWebhook
  - MutatingAdmissionWebhook
  - AlwaysPullImages
  - ImagePolicyWebhook

### CIS Benchmark Analysis
- Comprehensive CIS Kubernetes Benchmark checks
- Severity-based categorization of findings
- Detailed remediation steps for each failed check
- Coverage of control plane and worker node security
- Audit steps for verification
- Sections include:
  - Control Plane Components
  - etcd
  - Control Plane Configuration
  - Worker Nodes
  - Policies
  - Managed Services

### Access and Authentication
- RBAC misconfigurations and least privilege violations
- Sensitive keys in secrets
- Overly permissive roles

### Network Security
- NodePort exposed services
- Network Policy configurations
- SSRF vulnerabilities
- Network boundary security

### Compliance and Best Practices
- Kubernetes CIS benchmarks analysis
- Docker CIS benchmarks analysis
- Resource limits and DoS prevention
- Namespace security

### Additional Security Checks
- Private registry security
- Helm security (including deprecated v2 tiller)
- Runtime security monitoring
- Hidden layer analysis
- Environment information gathering

### Software Bill of Materials (SBOM)
- Container image dependency analysis
- Vulnerability scanning using Grype
- Detection of outdated packages
- Identification of deprecated components
- CVE tracking and reporting
- Package version analysis

## Prerequisites

- Python 3.7+
- Docker Desktop for Mac
- Access to a Kubernetes cluster
- `kubectl` configured with proper cluster access
- `kube-bench` installed (optional, for CIS benchmark scanning)
- `syft` and `grype` installed (for SBOM analysis)
- `kubesec` installed (for Kubernetes security analysis)
- `trivy` installed (for container vulnerability scanning)
- `gvisor` installed (optional, for enhanced container isolation)

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/k8s-security-checker.git
cd k8s-security-checker
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the package in development mode:
```bash
pip install -e .
```

### Using pip (when published)

```bash
pip install k8s-security-checker
```

### Installing Optional Dependencies

For CIS benchmark scanning:

On macOS:
```bash
brew install kube-bench
```

On Linux:
```bash
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.2/kube-bench_0.6.2_linux_amd64.deb -o kube-bench.deb
sudo dpkg -i kube-bench.deb
```

### Installing SBOM Tools

For SBOM analysis, install Syft and Grype:

On macOS:
```bash
brew tap anchore/syft
brew install syft
brew tap anchore/grype
brew install grype
```

On Linux:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Installing Security Scanning Tools

For Kubesec:

On macOS:
```bash
brew install kubesec
```

On Linux:
```bash
curl -L https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec-linux-amd64 -o kubesec && \
chmod +x kubesec && \
sudo mv kubesec /usr/local/bin/
```

For Trivy:

On macOS:
```bash
brew install trivy
```

On Linux:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Installing gVisor

For macOS with Docker Desktop:
1. Open Docker Desktop preferences
2. Go to the "Features in development" section
3. Enable gVisor runtime

For Linux:
```bash
# Install gVisor
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# Configure containerd
sudo mkdir -p /etc/containerd
cat << EOF | sudo tee /etc/containerd/config.toml
version = 2
[plugins."io.containerd.runtime.v1.linux"]
  shim_debug = true
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF

# Restart containerd
sudo systemctl restart containerd
```

## Setting Up a Test Environment

The repository includes a script to set up a local Kubernetes cluster for testing. This creates a multi-node cluster using `kind` (Kubernetes in Docker) and deploys various resources with security issues for testing.

### Prerequisites for Test Environment

- Docker Desktop for Mac (must be running)
- Internet connection (to pull container images)

### Setting Up the Test Cluster

1. Make sure Docker Desktop is running

2. Run the setup script:
```bash
./setup_test_cluster.sh
```

The script will:
- Install necessary tools (kind, kubectl) if not present
- Create a 3-node Kubernetes cluster (1 control plane + 2 workers)
- Create a test namespace with various security issues:
  - Privileged containers
  - Root containers
  - Containers without resource limits
  - NodePort services
  - Overly permissive RBAC roles
  - Sensitive mount paths
  - Docker-in-Docker containers

### Testing the Security Checker

After the test cluster is ready, run the security checker:
```bash
k8s-security-check -n test-security
```

This will scan the test namespace and should find multiple security issues.

### Cleaning Up

To delete the test cluster:
```bash
kind delete cluster --name security-test
```

## Usage

### Basic Usage

Run the security checker on the default namespace:
```bash
k8s-security-check
```

Scan a specific namespace:
```bash
k8s-security-check -n your-namespace
```

### Exit Codes

The tool uses the following exit codes:
- 0: No issues found
- 1: HIGH severity issues found
- 2: CRITICAL severity issues found
- Other non-zero: Error running the checks

## Development

### Project Structure

```
k8s_security_checker/
├── __init__.py           # Package initialization
├── base_checker.py       # Base class for all checkers
├── main.py              # Main script and CLI
├── checks/              # Individual security checkers
│   ├── __init__.py
│   └── pod_security.py  # Pod security checks
└── tests/               # Test suite
    ├── __init__.py
    └── test_pod_security.py
```

### Adding New Checkers

1. Create a new file in `k8s_security_checker/checks/` (e.g., `network_policy.py`)
2. Create a checker class that inherits from `BaseChecker`
3. Implement the `run()` method
4. Create corresponding test file in `tests/`
5. Add the checker to the list in `main.py`

Example:
```python
from ..base_checker import BaseChecker

class MyNewChecker(BaseChecker):
    def run(self, namespace: str = "default"):
        issues = []
        # Implement your checks here
        return issues
```

### Running Tests

Run the entire test suite:
```bash
python -m unittest discover k8s_security_checker/tests
```

Run a specific test file:
```bash
python -m unittest k8s_security_checker/tests/test_pod_security.py
```

### Code Style

The project follows PEP 8 guidelines. Before committing, ensure your code is properly formatted:
```bash
# Install development dependencies
pip install black isort pylint

# Format code
black k8s_security_checker
isort k8s_security_checker

# Run linter
pylint k8s_security_checker
```

## Integration with Other Tools

The script can integrate with:
- Falco for runtime security monitoring
- Popeye for cluster sanitization
- Cilium Tetragon for eBPF-based security
- Kyverno for policy enforcement

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for your changes
5. Run the test suite
6. Submit a pull request

## Security Notes

- Make sure you have the proper permissions to access the Kubernetes cluster
- Some checks require additional tools to be installed (like kube-bench)
- Be cautious when running security scans in production environments
- Keep the tool and its dependencies updated
- Review the findings and false positives in your environment

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Kubernetes Security Best Practices
- CIS Kubernetes Benchmark
- OWASP Kubernetes Security Cheat Sheet 