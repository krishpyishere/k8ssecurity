from typing import List, Dict
import subprocess
import json
import tempfile
import yaml
from pathlib import Path
from ..base_checker import BaseChecker

class ContainerSecurityScanner(BaseChecker):
    """Check container security using Kubesec and Trivy."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run container security checks."""
        issues = []
        
        # Check for required tools
        if not self._check_tool_installed("kubesec"):
            issues.append({
                "pod": "N/A",
                "container": "System",
                "issue": ("Kubesec not installed. Install with:\n"
                         "# For macOS:\n"
                         "brew install kubesec\n"
                         "# For Linux:\n"
                         "curl -L https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec-linux-amd64 -o kubesec && \\\n"
                         "chmod +x kubesec && \\\n"
                         "sudo mv kubesec /usr/local/bin/"),
                "severity": "INFO"
            })
        
        if not self._check_tool_installed("trivy"):
            issues.append({
                "pod": "N/A",
                "container": "System",
                "issue": ("Trivy not installed. Install with:\n"
                         "# For macOS:\n"
                         "brew install trivy\n"
                         "# For Linux:\n"
                         "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"),
                "severity": "INFO"
            })
            return issues

        try:
            # Get all pods in the namespace
            pods = self.v1.list_namespaced_pod(namespace)
            
            # Create a temporary directory for YAML files
            with tempfile.TemporaryDirectory() as temp_dir:
                for pod in pods.items:
                    # Export pod definition to YAML
                    pod_yaml = yaml.dump(self._convert_pod_to_dict(pod))
                    pod_file = Path(temp_dir) / f"{pod.metadata.name}.yaml"
                    pod_file.write_text(pod_yaml)
                    
                    # Run Kubesec scan
                    issues.extend(self._run_kubesec_scan(str(pod_file), pod.metadata.name))
                    
                    # Run Trivy scan for each container
                    for container in pod.spec.containers:
                        issues.extend(self._run_trivy_scan(container.image, pod.metadata.name, container.name))
                        
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "Container Scanner",
                "issue": f"Error during container security scan: {str(e)}",
                "severity": "INFO"
            })
            
        return issues

    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a required tool is installed."""
        try:
            subprocess.run(["which", tool_name], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _convert_pod_to_dict(self, pod) -> Dict:
        """Convert pod object to dictionary format."""
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace
            },
            "spec": pod.spec.to_dict()
        }

    def _run_kubesec_scan(self, yaml_file: str, pod_name: str) -> List[Dict]:
        """Run Kubesec scan on a pod YAML file."""
        issues = []
        try:
            result = subprocess.run(
                ["kubesec", "scan", yaml_file],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                scan_results = json.loads(result.stdout)
                
                for scan in scan_results:
                    # Process critical vulnerabilities
                    for critical in scan.get("critical", []):
                        issues.append({
                            "pod": pod_name,
                            "container": "Kubesec",
                            "issue": (f"Critical security issue: {critical.get('id')}\n"
                                    f"Description: {critical.get('message')}\n"
                                    f"Remediation: {critical.get('fix', 'No fix provided')}"),
                            "severity": "CRITICAL"
                        })
                    
                    # Process high vulnerabilities
                    for high in scan.get("high", []):
                        issues.append({
                            "pod": pod_name,
                            "container": "Kubesec",
                            "issue": (f"High security issue: {high.get('id')}\n"
                                    f"Description: {high.get('message')}\n"
                                    f"Remediation: {high.get('fix', 'No fix provided')}"),
                            "severity": "HIGH"
                        })
                    
                    # Process medium vulnerabilities
                    for medium in scan.get("medium", []):
                        issues.append({
                            "pod": pod_name,
                            "container": "Kubesec",
                            "issue": (f"Medium security issue: {medium.get('id')}\n"
                                    f"Description: {medium.get('message')}\n"
                                    f"Remediation: {medium.get('fix', 'No fix provided')}"),
                            "severity": "MEDIUM"
                        })
                        
        except Exception as e:
            issues.append({
                "pod": pod_name,
                "container": "Kubesec",
                "issue": f"Error running Kubesec scan: {str(e)}",
                "severity": "INFO"
            })
            
        return issues

    def _run_trivy_scan(self, image: str, pod_name: str, container_name: str) -> List[Dict]:
        """Run Trivy scan on a container image."""
        issues = []
        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", image],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                scan_results = json.loads(result.stdout)
                
                for result in scan_results.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN").upper()
                        if severity == "UNKNOWN":
                            severity = "INFO"
                            
                        fixed_version = vuln.get("FixedVersion", "Not available")
                        fix_info = f" (Fixed in version: {fixed_version})" if fixed_version != "Not available" else ""
                        
                        issues.append({
                            "pod": pod_name,
                            "container": f"{container_name} (Trivy)",
                            "issue": (f"Vulnerability {vuln.get('VulnerabilityID')}: {vuln.get('Title')}\n"
                                    f"Package: {vuln.get('PkgName')} (version: {vuln.get('InstalledVersion')}){fix_info}\n"
                                    f"Description: {vuln.get('Description')}\n"
                                    f"References: {', '.join(vuln.get('References', []))}"),
                            "severity": severity
                        })
                        
        except Exception as e:
            issues.append({
                "pod": pod_name,
                "container": f"{container_name} (Trivy)",
                "issue": f"Error running Trivy scan: {str(e)}",
                "severity": "INFO"
            })
            
        return issues 