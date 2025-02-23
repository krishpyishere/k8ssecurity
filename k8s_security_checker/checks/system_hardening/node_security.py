"""Node security checker for Kubernetes clusters."""

from typing import List, Dict
import subprocess
from kubernetes import client
from ...base_checker import BaseChecker

class NodeSecurityChecker(BaseChecker):
    """Checks for node-level security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run node security checks."""
        issues = []
        v1 = client.CoreV1Api()

        try:
            # Get all nodes
            nodes = v1.list_node()
            
            for node in nodes.items:
                self._check_node_security(node, issues)
                self._check_kubelet_security(node, issues)
                self._check_kernel_parameters(node, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking node security: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_node_security(self, node, issues: List[Dict]):
        """Check node-level security settings."""
        node_name = node.metadata.name
        
        # Check node labels for sensitive information
        labels = node.metadata.labels or {}
        sensitive_keys = ["password", "secret", "key", "token", "credential"]
        for key in labels:
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}",
                    "issue": f"Node label contains sensitive information: {key}",
                    "severity": "HIGH"
                })
        
        # Check node conditions
        for condition in node.status.conditions:
            if condition.type == "Ready" and condition.status != "True":
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}",
                    "issue": "Node is not in Ready state",
                    "severity": "HIGH"
                })

    def _check_kubelet_security(self, node, issues: List[Dict]):
        """Check kubelet security configuration."""
        node_name = node.metadata.name
        
        # Check kubelet configuration
        try:
            # This would typically require SSH access to the node
            # For demonstration, we'll check common misconfigurations
            kubelet_config = self._get_kubelet_config(node_name)
            
            if kubelet_config.get("authentication", {}).get("anonymous", {}).get("enabled", False):
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/kubelet",
                    "issue": "Anonymous authentication is enabled on kubelet",
                    "severity": "CRITICAL"
                })
            
            if not kubelet_config.get("authorization", {}).get("mode") == "Webhook":
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/kubelet",
                    "issue": "Kubelet authorization mode is not set to Webhook",
                    "severity": "HIGH"
                })
            
        except Exception:
            # If we can't access kubelet config, report it
            issues.append({
                "pod": "N/A",
                "container": f"Node/{node_name}/kubelet",
                "issue": "Unable to check kubelet configuration",
                "severity": "MEDIUM"
            })

    def _check_kernel_parameters(self, node, issues: List[Dict]):
        """Check Linux kernel security parameters."""
        node_name = node.metadata.name
        
        # These checks would typically require SSH access to the node
        # For demonstration, we'll check common parameters
        kernel_params = {
            "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.accept_source_route": "0"
        }
        
        try:
            for param, expected_value in kernel_params.items():
                actual_value = self._get_kernel_param(node_name, param)
                if actual_value != expected_value:
                    issues.append({
                        "pod": "N/A",
                        "container": f"Node/{node_name}/kernel",
                        "issue": f"Kernel parameter {param} is set to {actual_value} (should be {expected_value})",
                        "severity": "HIGH"
                    })
        except Exception:
            issues.append({
                "pod": "N/A",
                "container": f"Node/{node_name}/kernel",
                "issue": "Unable to check kernel parameters",
                "severity": "MEDIUM"
            })

    def _get_kubelet_config(self, node_name: str) -> Dict:
        """Get kubelet configuration from node."""
        # This is a placeholder - in a real implementation,
        # you would need to SSH to the node or use a node agent
        return {
            "authentication": {"anonymous": {"enabled": False}},
            "authorization": {"mode": "Webhook"}
        }

    def _get_kernel_param(self, node_name: str, param: str) -> str:
        """Get kernel parameter value from node."""
        # This is a placeholder - in a real implementation,
        # you would need to SSH to the node or use a node agent
        return "0" 