"""Secrets management security checker for Kubernetes clusters."""

from typing import List, Dict
import base64
from kubernetes import client
from ...base_checker import BaseChecker

class SecretsChecker(BaseChecker):
    """Checks for secrets management security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run secrets management security checks."""
        issues = []
        v1 = client.CoreV1Api()

        try:
            # Check secrets in the namespace
            secrets = v1.list_namespaced_secret(namespace)
            for secret in secrets.items:
                self._check_secret(secret, issues)

            # Check pods for secret usage
            pods = v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                self._check_pod_secrets(pod, issues)

            # Check service accounts for token automounting
            service_accounts = v1.list_namespaced_service_account(namespace)
            for sa in service_accounts.items:
                self._check_service_account_tokens(sa, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking secrets: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_secret(self, secret, issues: List[Dict]):
        """Check individual secret for security issues."""
        secret_name = secret.metadata.name
        
        # Check for default token secrets
        if secret_name.startswith("default-token-"):
            return  # Skip default token secrets
        
        # Check secret type
        if secret.type == "Opaque":
            issues.append({
                "pod": "N/A",
                "container": f"Secret/{secret_name}",
                "issue": "Secret uses Opaque type instead of specific type",
                "severity": "LOW"
            })
        
        # Check for common sensitive patterns in secret names
        sensitive_patterns = ["password", "key", "token", "secret", "credential"]
        if any(pattern in secret_name.lower() for pattern in sensitive_patterns):
            issues.append({
                "pod": "N/A",
                "container": f"Secret/{secret_name}",
                "issue": "Secret name contains sensitive information",
                "severity": "MEDIUM"
            })
        
        # Check for base64 encoded secrets that are easily decodable
        if secret.data:
            for key, value in secret.data.items():
                try:
                    decoded = base64.b64decode(value).decode('utf-8')
                    if self._is_plaintext_sensitive(decoded):
                        issues.append({
                            "pod": "N/A",
                            "container": f"Secret/{secret_name}",
                            "issue": f"Secret data '{key}' appears to be plaintext sensitive data",
                            "severity": "HIGH"
                        })
                except:
                    pass  # Not UTF-8 decodable, likely not plaintext

    def _check_pod_secrets(self, pod, issues: List[Dict]):
        """Check how secrets are used in pods."""
        pod_name = pod.metadata.name
        
        # Check for secrets mounted as environment variables
        for container in pod.spec.containers:
            container_name = container.name
            
            if container.env:
                for env in container.env:
                    if env.value_from and env.value_from.secret_key_ref:
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": f"Secret '{env.value_from.secret_key_ref.name}' exposed as environment variable",
                            "severity": "MEDIUM"
                        })
        
        # Check for secret volume mounts
        if pod.spec.volumes:
            for volume in pod.spec.volumes:
                if volume.secret:
                    # Check mount permissions
                    for container in pod.spec.containers:
                        for mount in container.volume_mounts:
                            if mount.name == volume.name and not mount.read_only:
                                issues.append({
                                    "pod": pod_name,
                                    "container": container.name,
                                    "issue": f"Secret volume '{volume.name}' mounted with write permissions",
                                    "severity": "HIGH"
                                })

    def _check_service_account_tokens(self, sa, issues: List[Dict]):
        """Check service account token settings."""
        sa_name = sa.metadata.name
        
        # Check if tokens are automatically mounted
        if sa.automount_service_account_token:
            issues.append({
                "pod": "N/A",
                "container": f"ServiceAccount/{sa_name}",
                "issue": "Service account automatically mounts API tokens",
                "severity": "MEDIUM"
            })
        
        # Check for multiple tokens
        if sa.secrets and len(sa.secrets) > 1:
            issues.append({
                "pod": "N/A",
                "container": f"ServiceAccount/{sa_name}",
                "issue": "Service account has multiple tokens",
                "severity": "LOW"
            })

    def _is_plaintext_sensitive(self, text: str) -> bool:
        """Check if text appears to be sensitive plaintext data."""
        # Check for common patterns that suggest sensitive data
        sensitive_patterns = [
            "password=", "apikey=", "secret=", "token=",
            "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
            "aws_access_key_id", "aws_secret_access_key"
        ]
        return any(pattern.lower() in text.lower() for pattern in sensitive_patterns) 