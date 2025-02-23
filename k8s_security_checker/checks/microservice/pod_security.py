from typing import List, Dict
from ..base_checker import BaseChecker

class PodSecurityChecker(BaseChecker):
    """Check for pod-related security issues."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run pod security checks."""
        issues = []
        try:
            pods = self.v1.list_namespaced_pod(namespace)
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                
                # Check containers in the pod
                for container in pod.spec.containers:
                    issues.extend(self._check_container(pod_name, container))
                    
        except Exception as e:
            raise RuntimeError(f"Error checking pod security: {e}")
            
        return issues

    def _check_container(self, pod_name: str, container) -> List[Dict]:
        """Check a single container for security issues."""
        issues = []
        
        # Check if running as root
        if not container.security_context or \
           (container.security_context.run_as_non_root is None or \
            not container.security_context.run_as_non_root):
            issues.append({
                "pod": pod_name,
                "container": container.name,
                "issue": "Container might be running as root",
                "severity": "HIGH"
            })

        # Check for privileged mode
        if container.security_context and \
           container.security_context.privileged:
            issues.append({
                "pod": pod_name,
                "container": container.name,
                "issue": "Container running in privileged mode",
                "severity": "CRITICAL"
            })

        # Check for resource limits
        if not container.resources or \
           not container.resources.limits:
            issues.append({
                "pod": pod_name,
                "container": container.name,
                "issue": "No resource limits defined",
                "severity": "MEDIUM"
            })

        # Check for sensitive mounts
        if container.volume_mounts:
            sensitive_paths = ["/etc", "/var/run/docker.sock", "/root"]
            for mount in container.volume_mounts:
                if any(path in mount.mount_path for path in sensitive_paths):
                    issues.append({
                        "pod": pod_name,
                        "container": container.name,
                        "issue": f"Sensitive path mounted: {mount.mount_path}",
                        "severity": "HIGH"
                    })

        # Check for DinD (Docker-in-Docker)
        if container.image and ("docker" in container.image.lower() or "dind" in container.image.lower()):
            issues.append({
                "pod": pod_name,
                "container": container.name,
                "issue": "Docker-in-Docker detected - potential security risk",
                "severity": "CRITICAL"
            })

        # Check for crypto mining indicators
        mining_keywords = ["cryptominer", "monero", "bitcoin", "xmrig"]
        if container.image and any(keyword in container.image.lower() for keyword in mining_keywords):
            issues.append({
                "pod": pod_name,
                "container": container.name,
                "issue": "Potential crypto mining container detected",
                "severity": "CRITICAL"
            })

        return issues 