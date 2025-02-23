"""Container image security checker for Kubernetes clusters."""

from typing import List, Dict
import subprocess
from kubernetes import client
from ...base_checker import BaseChecker

class ImageSecurityChecker(BaseChecker):
    """Checks for container image security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run container image security checks."""
        issues = []
        v1 = client.CoreV1Api()

        try:
            # Get all pods to check their images
            pods = v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                self._check_pod_images(pod, issues)

            # Check image pull secrets
            secrets = v1.list_namespaced_secret(namespace)
            self._check_registry_secrets(secrets.items, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking image security: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_pod_images(self, pod, issues: List[Dict]):
        """Check security of container images used in a pod."""
        pod_name = pod.metadata.name
        
        # Check each container's image
        for container in pod.spec.containers:
            container_name = container.name
            image = container.image
            
            # Check for latest tag usage
            if ":latest" in image or ":" not in image:
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": f"Container uses 'latest' or untagged image: {image}",
                    "severity": "HIGH"
                })
            
            # Check for public images
            if self._is_public_registry(image):
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": f"Container uses public registry image: {image}",
                    "severity": "MEDIUM"
                })
            
            # Check image signature verification
            if not self._verify_image_signature(image):
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": f"Image signature verification failed: {image}",
                    "severity": "HIGH"
                })
            
            # Check image scan results
            scan_issues = self._scan_image(image)
            for issue in scan_issues:
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": f"Image security issue: {issue}",
                    "severity": "HIGH"
                })

    def _check_registry_secrets(self, secrets: List, issues: List[Dict]):
        """Check registry authentication secrets."""
        registry_secrets = [s for s in secrets if s.type == "kubernetes.io/dockerconfigjson"]
        
        if not registry_secrets:
            issues.append({
                "pod": "N/A",
                "container": "Namespace",
                "issue": "No private registry credentials configured",
                "severity": "MEDIUM"
            })
            return
        
        for secret in registry_secrets:
            secret_name = secret.metadata.name
            
            # Check for default docker config location
            if secret_name == ".dockerconfigjson":
                issues.append({
                    "pod": "N/A",
                    "container": f"Secret/{secret_name}",
                    "issue": "Using default docker config location",
                    "severity": "LOW"
                })
            
            # Check registry configurations
            try:
                docker_config = secret.data[".dockerconfigjson"]
                if "index.docker.io" in docker_config:
                    issues.append({
                        "pod": "N/A",
                        "container": f"Secret/{secret_name}",
                        "issue": "Using public Docker Hub registry",
                        "severity": "LOW"
                    })
            except:
                issues.append({
                    "pod": "N/A",
                    "container": f"Secret/{secret_name}",
                    "issue": "Invalid registry credentials format",
                    "severity": "MEDIUM"
                })

    def _is_public_registry(self, image: str) -> bool:
        """Check if image is from a public registry."""
        public_registries = [
            "docker.io",
            "index.docker.io",
            "registry.hub.docker.com",
            "gcr.io",
            "quay.io",
            "ghcr.io"
        ]
        return any(reg in image.lower() for reg in public_registries)

    def _verify_image_signature(self, image: str) -> bool:
        """Verify container image signature."""
        try:
            # This would typically use cosign or similar tool
            # For demonstration, we'll assume unsigned images
            return False
        except:
            return False

    def _scan_image(self, image: str) -> List[str]:
        """Scan container image for security issues."""
        issues = []
        try:
            # Try using Trivy if available
            result = subprocess.run(
                ["trivy", "image", "--quiet", "--severity", "HIGH,CRITICAL", image],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                issues.append(f"Trivy scan failed: {result.stderr}")
            elif result.stdout:
                issues.append("Critical vulnerabilities found in image")
        except FileNotFoundError:
            issues.append("Image scanning tool (Trivy) not available")
        except Exception as e:
            issues.append(f"Error scanning image: {str(e)}")
        
        return issues 