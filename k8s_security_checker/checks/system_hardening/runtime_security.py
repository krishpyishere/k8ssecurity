"""Container runtime security checker for Kubernetes clusters."""

from typing import List, Dict
import json
import subprocess
from kubernetes import client
from ...base_checker import BaseChecker

class RuntimeSecurityChecker(BaseChecker):
    """Checks for container runtime security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run container runtime security checks."""
        issues = []
        v1 = client.CoreV1Api()

        try:
            # Get all nodes to check their container runtime
            nodes = v1.list_node()
            for node in nodes.items:
                self._check_runtime_security(node, issues)

            # Get all pods to check their security context
            pods = v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                self._check_pod_security_context(pod, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking runtime security: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_runtime_security(self, node, issues: List[Dict]):
        """Check container runtime security settings."""
        node_name = node.metadata.name
        
        try:
            # Get container runtime info from node status
            runtime = node.status.node_info.container_runtime_version
            
            # Check containerd configuration
            if "containerd" in runtime.lower():
                self._check_containerd_config(node_name, issues)
            # Check Docker configuration
            elif "docker" in runtime.lower():
                self._check_docker_config(node_name, issues)
            else:
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/runtime",
                    "issue": f"Unknown container runtime: {runtime}",
                    "severity": "MEDIUM"
                })
        
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": f"Node/{node_name}/runtime",
                "issue": f"Unable to check runtime configuration: {str(e)}",
                "severity": "MEDIUM"
            })

    def _check_containerd_config(self, node_name: str, issues: List[Dict]):
        """Check containerd security configuration."""
        try:
            # This would typically require SSH access to the node
            # For demonstration, we'll check common misconfigurations
            config = self._get_containerd_config(node_name)
            
            # Check for privileged containers
            if config.get("privileged_without_host_devices", True):
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/containerd",
                    "issue": "Privileged containers allowed without host devices restriction",
                    "severity": "HIGH"
                })
            
            # Check for insecure registries
            registries = config.get("registry", {}).get("mirrors", {})
            for registry in registries:
                if not registries[registry].get("tls", {}).get("verify", True):
                    issues.append({
                        "pod": "N/A",
                        "container": f"Node/{node_name}/containerd",
                        "issue": f"Insecure registry configured: {registry}",
                        "severity": "HIGH"
                    })
            
        except Exception:
            issues.append({
                "pod": "N/A",
                "container": f"Node/{node_name}/containerd",
                "issue": "Unable to check containerd configuration",
                "severity": "MEDIUM"
            })

    def _check_docker_config(self, node_name: str, issues: List[Dict]):
        """Check Docker daemon security configuration."""
        try:
            # This would typically require SSH access to the node
            # For demonstration, we'll check common misconfigurations
            config = self._get_docker_config(node_name)
            
            # Check for insecure configurations
            if config.get("live-restore", False):
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/docker",
                    "issue": "Docker live-restore is enabled",
                    "severity": "MEDIUM"
                })
            
            if not config.get("selinux-enabled", False):
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/docker",
                    "issue": "SELinux is not enabled for Docker",
                    "severity": "HIGH"
                })
            
            if not config.get("userns-remap", ""):
                issues.append({
                    "pod": "N/A",
                    "container": f"Node/{node_name}/docker",
                    "issue": "User namespace remapping is not configured",
                    "severity": "MEDIUM"
                })
            
        except Exception:
            issues.append({
                "pod": "N/A",
                "container": f"Node/{node_name}/docker",
                "issue": "Unable to check Docker configuration",
                "severity": "MEDIUM"
            })

    def _check_pod_security_context(self, pod, issues: List[Dict]):
        """Check pod and container security contexts."""
        pod_name = pod.metadata.name
        
        # Check pod security context
        security_context = pod.spec.security_context or {}
        
        if not security_context.get("run_as_non_root", False):
            issues.append({
                "pod": pod_name,
                "container": "Pod",
                "issue": "Pod does not enforce running as non-root",
                "severity": "HIGH"
            })
        
        # Check each container's security context
        for container in pod.spec.containers:
            container_name = container.name
            container_context = container.security_context or {}
            
            if container_context.get("privileged", False):
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": "Container runs in privileged mode",
                    "severity": "CRITICAL"
                })
            
            if not container_context.get("read_only_root_filesystem", False):
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": "Container root filesystem is not read-only",
                    "severity": "MEDIUM"
                })
            
            if container_context.get("allow_privilege_escalation", True):
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": "Container allows privilege escalation",
                    "severity": "HIGH"
                })

    def _get_containerd_config(self, node_name: str) -> Dict:
        """Get containerd configuration from node."""
        # This is a placeholder - in a real implementation,
        # you would need to SSH to the node or use a node agent
        return {
            "privileged_without_host_devices": False,
            "registry": {
                "mirrors": {
                    "docker.io": {
                        "tls": {"verify": True}
                    }
                }
            }
        }

    def _get_docker_config(self, node_name: str) -> Dict:
        """Get Docker daemon configuration from node."""
        # This is a placeholder - in a real implementation,
        # you would need to SSH to the node or use a node agent
        return {
            "live-restore": False,
            "selinux-enabled": True,
            "userns-remap": "default"
        } 