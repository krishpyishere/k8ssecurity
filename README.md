# Kubernetes Security Scanner

A comprehensive security scanning tool for Kubernetes clusters that identifies security issues, misconfigurations, and potential vulnerabilities, aligned with the CKS (Certified Kubernetes Security Specialist) curriculum.

## Features

The scanner performs security checks across five major domains, each with specialized checkers:

### 1. Cluster Setup and Hardening

#### CIS Benchmark Checker (`CISBenchmarkChecker`)
- Validates compliance with CIS Kubernetes Benchmark standards
- Checks control plane configurations
- Validates worker node settings
- Verifies platform-specific security settings
- Provides remediation steps for non-compliant items

#### Admission Controller Checker (`AdmissionControllerChecker`)
- Validates admission controller configurations
- Checks PodSecurityPolicy setup
- Verifies ValidatingWebhookConfiguration
- Audits MutatingWebhookConfiguration
- Ensures critical admission controllers are enabled

#### RBAC Checker (`RBACChecker`)
- Audits role-based access control configurations
- Identifies overly permissive roles
- Checks service account configurations
- Validates role bindings
- Detects dangerous permissions

#### Network Policy Checker (`NetworkPolicyChecker`)
- Validates network segmentation
- Checks ingress/egress rules
- Identifies unprotected namespaces
- Verifies pod isolation
- Detects overly permissive network policies

### 2. System Hardening

#### Node Security Checker (`NodeSecurityChecker`)
- Validates node configurations
- Checks kernel parameters
- Verifies kubelet security settings
- Audits node labels and taints
- Monitors node conditions

#### Runtime Security Checker (`RuntimeSecurityChecker`)
- Validates container runtime configurations
- Checks containerd/Docker security settings
- Verifies seccomp profiles
- Validates AppArmor configurations
- Monitors runtime privileges

#### gVisor Checker (`GVisorChecker`)
- Verifies gVisor installation and configuration
- Checks runtime class definitions
- Validates pod runtime settings
- Monitors gVisor resource usage
- Ensures proper isolation

### 3. Minimize Microservice Vulnerabilities

#### Container Security Checker (`ContainerSecurityChecker`)
- Validates container security contexts
- Checks resource limits and requests
- Verifies image configurations
- Monitors privileged containers
- Detects dangerous capabilities

#### Pod Security Checker (`PodSecurityChecker`)
- Validates pod security contexts
- Checks host namespace usage
- Verifies volume mounts
- Monitors pod privileges
- Detects security risks

#### Secrets Checker (`SecretsChecker`)
- Audits secrets management
- Checks secret mounting methods
- Verifies secret encryption
- Monitors secret usage
- Detects exposed sensitive data

### 4. Supply Chain Security

#### Image Security Checker (`ImageSecurityChecker`)
- Validates image sources
- Checks image signatures
- Verifies image scanning results
- Monitors base images
- Detects vulnerable components

#### SBOM Checker (`SBOMChecker`)
- Analyzes software bill of materials
- Checks dependency versions
- Verifies package sources
- Monitors outdated components
- Detects vulnerable dependencies

### 5. Monitoring, Logging and Runtime Security

#### Audit Checker (`AuditChecker`)
- Validates audit logging configuration
- Checks audit policy rules
- Verifies log storage
- Monitors audit backends
- Ensures proper audit coverage

#### Falco Checker (`FalcoChecker`)
- Verifies Falco installation
- Checks rule configurations
- Validates alert settings
- Monitors Falco status
- Ensures runtime protection

## Prerequisites

- Python 3.7+
- Access to a Kubernetes cluster
- `kubectl` configured with proper cluster access

### Required Tools

The scanner integrates with several security tools. Here's how to install them:

#### For macOS:
```bash
# Install core tools
brew install kind kubectl

# Install SBOM tools
brew tap anchore/syft
brew install syft
brew tap anchore/grype
brew install grype

# Install security scanners
brew install kube-bench
brew install kubesec
brew install trivy

# Install Falco (optional)
brew tap falcosecurity/tap
brew install falco
```

#### For Linux:
```bash
# Install SBOM tools
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install security scanners
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.2/kube-bench_0.6.2_linux_amd64.deb -o kube-bench.deb
sudo dpkg -i kube-bench.deb

curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Falco (optional)
curl -fsSL https://falco.org/repo/falcosecurity-3672BA8F.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
sudo apt-get install -y falco
```

### Installing the Scanner

```bash
# From PyPI
pip install k8s-security-checker

# From source
git clone https://github.com/yourusername/k8s-security-checker.git
cd k8s-security-checker
pip install -e .
```

## Usage

### Basic Usage

```bash
# Scan default namespace
k8s-security-check

# Scan specific namespace
k8s-security-check -n your-namespace

# Scan with increased verbosity
k8s-security-check -v

# Export results to JSON
k8s-security-check --output json > results.json
```

### Configuration

The scanner can be configured using environment variables or a configuration file:

```yaml
# config.yaml
checkers:
  cis_benchmark:
    enabled: true
    skip_tests: ["1.2.3", "1.3.4"]
  
  network_policy:
    enabled: true
    ignore_namespaces: ["kube-system"]
  
  image_security:
    enabled: true
    allowed_registries:
      - "registry.company.com"
      - "gcr.io/company-project"

  runtime_security:
    enabled: true
    required_seccomp_profiles:
      - "runtime/default"
      - "localhost/custom-profile"
    required_apparmor_profiles:
      - "runtime/default"
      - "localhost/custom-profile"

  pod_security:
    enabled: true
    forbidden_capabilities:
      - "SYS_ADMIN"
      - "NET_ADMIN"
    required_drop_capabilities:
      - "ALL"

  secrets:
    enabled: true
    forbidden_mount_paths:
      - "/etc"
      - "/root"
    required_annotations:
      - "vault.hashicorp.com/agent-inject"

  audit:
    enabled: true
    min_log_size: "10Gi"
    required_audit_levels:
      - "Metadata"
      - "Request"
      - "RequestResponse"

  falco:
    enabled: true
    required_rules:
      - "Terminal shell in container"
      - "File open by system procs"
```

### Environment Variables

```bash
# Enable/disable specific checkers
export K8S_SECURITY_CHECKER_DISABLE="cis_benchmark,network_policy"

# Configure severity thresholds
export K8S_SECURITY_CHECKER_MIN_SEVERITY="HIGH"

# Set output format
export K8S_SECURITY_CHECKER_OUTPUT="json"

# Configure tool paths
export K8S_SECURITY_CHECKER_KUBE_BENCH_PATH="/usr/local/bin/kube-bench"
export K8S_SECURITY_CHECKER_TRIVY_PATH="/usr/local/bin/trivy"
```

### Exit Codes

- 0: No issues found
- 1: Low/Medium severity issues found
- 2: High severity issues found
- 3: Critical severity issues found
- Other: Error running checks

## Development

### Project Structure

```
k8s_security_checker/
├── __init__.py
├── base_checker.py
├── main.py
├── checks/
│   ├── cluster_hardening/
│   │   ├── cis_benchmark.py
│   │   ├── admission_controller.py
│   │   ├── rbac.py
│   │   └── network_policy.py
│   ├── system_hardening/
│   │   ├── node_security.py
│   │   ├── runtime_security.py
│   │   └── gvisor.py
│   ├── microservice/
│   │   ├── container_security.py
│   │   ├── pod_security.py
│   │   └── secrets.py
│   ├── supply_chain/
│   │   ├── image_security.py
│   │   └── sbom.py
│   └── monitoring/
│       ├── audit.py
│       └── falco.py
└── tests/
    └── checks/
        ├── test_cis_benchmark.py
        ├── test_network_policy.py
        └── ...
```

### Adding New Checkers

1. Create a new checker class in the appropriate domain directory
2. Inherit from `BaseChecker`
3. Implement the `run()` method
4. Add tests in the `tests/` directory
5. Register the checker in `main.py`

Example:
```python
from typing import List, Dict
from ...base_checker import BaseChecker

class MyNewChecker(BaseChecker):
    """My new security checker."""
    
    def run(self, namespace: str = "default") -> List[Dict]:
        issues = []
        # Implement security checks
        return issues
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/checks/test_network_policy.py

# Run with coverage
python -m pytest --cov=k8s_security_checker
```

### Code Style

The project follows PEP 8 guidelines. Before committing:

```bash
# Install development tools
pip install black isort pylint

# Format code
black k8s_security_checker
isort k8s_security_checker

# Check style
pylint k8s_security_checker
```

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
          
      - name: Install k8s-security-checker
        run: pip install k8s-security-checker
        
      - name: Run security scan
        run: k8s-security-check --output json > scan-results.json
        
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: scan-results.json
```

### ArgoCD Pre-Sync Hook

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: security-scan
  annotations:
    argocd.argoproj.io/hook: PreSync
spec:
  template:
    spec:
      containers:
      - name: security-scanner
        image: k8s-security-checker
        command: ["k8s-security-check"]
        args: ["-n", "$(NAMESPACE)"]
      restartPolicy: Never
```

### Prometheus Integration

The scanner can expose metrics for Prometheus:

```yaml
# prometheus-config.yaml
scrape_configs:
  - job_name: 'k8s-security-checker'
    static_configs:
      - targets: ['localhost:9090']
```

Metrics exposed:
- `k8s_security_issues_total{severity="CRITICAL|HIGH|MEDIUM|LOW"}`
- `k8s_security_check_duration_seconds{checker="checker_name"}`
- `k8s_security_check_errors_total{checker="checker_name"}`

## Security Notes

- The scanner requires read access to cluster resources
- Some checks may require elevated privileges
- Review findings before applying automated fixes
- Keep the scanner and its dependencies updated
- Monitor scanner resource usage in production

## Troubleshooting

Common issues and solutions:

1. **Permission Errors**
   ```bash
   # Create necessary RBAC roles
   kubectl apply -f k8s_security_checker/deploy/rbac.yaml
   ```

2. **Tool Not Found**
   ```bash
   # Check tool installation
   which kube-bench syft grype trivy
   
   # Verify PATH
   echo $PATH
   ```

3. **High Resource Usage**
   ```bash
   # Configure resource limits
   export K8S_SECURITY_CHECKER_MAX_WORKERS=4
   export K8S_SECURITY_CHECKER_TIMEOUT=300
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Kubernetes Security Best Practices
- CIS Kubernetes Benchmark
- OWASP Kubernetes Security Cheat Sheet
- CKS Curriculum and Guidelines 