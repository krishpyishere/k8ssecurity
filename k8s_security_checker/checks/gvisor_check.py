from typing import List, Dict
import subprocess
import json
from ..base_checker import BaseChecker

class GVisorChecker(BaseChecker):
    """Check for gVisor runtime security configuration."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run gVisor security checks."""
        issues = []
        
        try:
            # Check if gVisor is installed
            if not self._check_gvisor_installed():
                issues.append({
                    "pod": "N/A",
                    "container": "System",
                    "issue": ("gVisor not detected. Consider installing for enhanced container isolation:\n"
                             "# For macOS with Docker Desktop:\n"
                             "1. Enable gVisor in Docker Desktop settings\n"
                             "# For Linux:\n"
                             "1. Install gVisor: https://gvisor.dev/docs/user_guide/install/\n"
                             "2. Configure containerd to use gVisor runtime"),
                    "severity": "MEDIUM"
                })
                return issues

            # Get node information
            nodes = self.v1.list_node()
            
            # Check runtime class configuration
            runtime_classes = self._get_runtime_classes()
            if not any(rc.get('handler') == 'runsc' for rc in runtime_classes):
                issues.append({
                    "pod": "N/A",
                    "container": "RuntimeClass",
                    "issue": ("No gVisor runtime class (runsc) configured.\n"
                             "Remediation: Create a RuntimeClass for gVisor:\n"
                             "apiVersion: node.k8s.io/v1\n"
                             "kind: RuntimeClass\n"
                             "metadata:\n"
                             "  name: gvisor\n"
                             "handler: runsc"),
                    "severity": "HIGH"
                })

            # Check pods in namespace for gVisor usage
            pods = self.v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                self._check_pod_gvisor_config(pod, issues)

            # Check node configuration
            for node in nodes.items:
                self._check_node_gvisor_config(node, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "gVisor Checker",
                "issue": f"Error checking gVisor configuration: {str(e)}",
                "severity": "INFO"
            })

        return issues

    def _check_gvisor_installed(self) -> bool:
        """Check if gVisor is installed and available."""
        try:
            # Check for runsc binary
            result = subprocess.run(["which", "runsc"], capture_output=True, text=True)
            if result.returncode == 0:
                return True

            # Check containerd configuration for gVisor runtime
            result = subprocess.run(
                ["crictl", "info"],
                capture_output=True,
                text=True
            )
            return 'runsc' in result.stdout
        except subprocess.CalledProcessError:
            return False

    def _get_runtime_classes(self) -> List[Dict]:
        """Get RuntimeClass resources from the cluster."""
        try:
            runtime_classes = self.k8s_client.request(
                '/apis/node.k8s.io/v1/runtimeclasses',
                'GET'
            )
            return runtime_classes.get('items', [])
        except Exception:
            return []

    def _check_pod_gvisor_config(self, pod, issues: List[Dict]):
        """Check pod configuration for gVisor usage."""
        pod_name = pod.metadata.name
        runtime_class = pod.spec.runtime_class_name

        # Check security-sensitive workloads that should use gVisor
        sensitive_indicators = [
            ('network-proxy', 'Proxy pods handling untrusted traffic'),
            ('untrusted', 'Pods marked as untrusted'),
            ('sandbox', 'Sandbox environments'),
            ('user-workload', 'User-submitted workloads')
        ]

        for indicator, description in sensitive_indicators:
            if indicator in pod_name.lower() and not runtime_class == 'gvisor':
                issues.append({
                    "pod": pod_name,
                    "container": "Pod Configuration",
                    "issue": (f"Security-sensitive pod ({description}) not using gVisor runtime.\n"
                             "Remediation: Add runtimeClassName: gvisor to pod spec"),
                    "severity": "HIGH"
                })

        # Check for workloads with elevated privileges
        if pod.spec.security_context:
            if pod.spec.security_context.privileged or \
               pod.spec.security_context.run_as_root:
                issues.append({
                    "pod": pod_name,
                    "container": "Pod Security",
                    "issue": ("Privileged/root pod without gVisor isolation.\n"
                             "Consider using gVisor for additional security layer"),
                    "severity": "MEDIUM"
                })

    def _check_node_gvisor_config(self, node, issues: List[Dict]):
        """Check node configuration for gVisor support."""
        node_name = node.metadata.name
        
        try:
            # Check if node has gVisor runtime available
            result = subprocess.run(
                ["kubectl", "get", "node", node_name, "-o", "json"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                node_info = json.loads(result.stdout)
                runtime_handler = node_info.get('status', {}).get('nodeInfo', {}).get('containerRuntimeVersion', '')
                
                if 'containerd' in runtime_handler.lower():
                    # Check containerd configuration on node
                    if not self._check_node_containerd_config(node_name):
                        issues.append({
                            "pod": "N/A",
                            "container": f"Node: {node_name}",
                            "issue": ("Node missing gVisor runtime configuration in containerd.\n"
                                     "Remediation: Configure containerd with runsc runtime handler"),
                            "severity": "HIGH"
                        })

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": f"Node: {node_name}",
                "issue": f"Error checking node gVisor configuration: {str(e)}",
                "severity": "INFO"
            })

    def _check_node_containerd_config(self, node_name: str) -> bool:
        """Check if node's containerd is configured with gVisor runtime."""
        try:
            # This is a simplified check - in production, you'd need to check the actual
            # containerd configuration on the node
            result = subprocess.run(
                ["kubectl", "exec", "-n", "kube-system", 
                 f"node/{node_name}", "--", "crictl", "info"],
                capture_output=True,
                text=True
            )
            return 'runsc' in result.stdout
        except subprocess.CalledProcessError:
            return False 