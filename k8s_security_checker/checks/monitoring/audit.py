"""Kubernetes audit logging checker."""

from typing import List, Dict
import json
import subprocess
from kubernetes import client
from ...base_checker import BaseChecker

class AuditChecker(BaseChecker):
    """Checks for audit logging configuration and issues."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run audit logging checks."""
        issues = []

        try:
            # Check API server audit configuration
            self._check_api_server_audit(issues)
            
            # Check audit policy
            self._check_audit_policy(issues)
            
            # Check audit log storage
            self._check_audit_log_storage(issues)
            
            # Check audit webhook configuration
            self._check_audit_webhook(issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking audit configuration: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_api_server_audit(self, issues: List[Dict]):
        """Check API server audit configuration."""
        try:
            # Get API server pod
            v1 = client.CoreV1Api()
            api_pods = v1.list_namespaced_pod(
                "kube-system",
                label_selector="component=kube-apiserver"
            )
            
            if not api_pods.items:
                issues.append({
                    "pod": "N/A",
                    "container": "kube-apiserver",
                    "issue": "Unable to find API server pod",
                    "severity": "HIGH"
                })
                return
            
            # Check audit flags
            for pod in api_pods.items:
                for container in pod.spec.containers:
                    if container.name == "kube-apiserver":
                        self._check_audit_flags(container.command, issues)
        
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "kube-apiserver",
                "issue": f"Error checking API server audit config: {str(e)}",
                "severity": "HIGH"
            })

    def _check_audit_flags(self, command: List[str], issues: List[Dict]):
        """Check API server audit-related flags."""
        flags = " ".join(command or [])
        
        # Check if audit logging is enabled
        if "--audit-log-path=" not in flags:
            issues.append({
                "pod": "N/A",
                "container": "kube-apiserver",
                "issue": "Audit logging is not enabled (--audit-log-path not set)",
                "severity": "HIGH"
            })
        
        # Check audit log max age
        if "--audit-log-maxage=" not in flags:
            issues.append({
                "pod": "N/A",
                "container": "kube-apiserver",
                "issue": "Audit log retention age not set (--audit-log-maxage)",
                "severity": "MEDIUM"
            })
        
        # Check audit log max backup
        if "--audit-log-maxbackup=" not in flags:
            issues.append({
                "pod": "N/A",
                "container": "kube-apiserver",
                "issue": "Audit log backup limit not set (--audit-log-maxbackup)",
                "severity": "MEDIUM"
            })
        
        # Check audit log max size
        if "--audit-log-maxsize=" not in flags:
            issues.append({
                "pod": "N/A",
                "container": "kube-apiserver",
                "issue": "Audit log size limit not set (--audit-log-maxsize)",
                "severity": "MEDIUM"
            })
        
        # Check audit policy file
        if "--audit-policy-file=" not in flags:
            issues.append({
                "pod": "N/A",
                "container": "kube-apiserver",
                "issue": "Audit policy file not configured (--audit-policy-file)",
                "severity": "HIGH"
            })

    def _check_audit_policy(self, issues: List[Dict]):
        """Check audit policy configuration."""
        try:
            # This would typically read from the audit policy file
            # For demonstration, we'll check common configurations
            policy = self._get_audit_policy()
            
            if not policy:
                issues.append({
                    "pod": "N/A",
                    "container": "audit-policy",
                    "issue": "Unable to read audit policy configuration",
                    "severity": "HIGH"
                })
                return
            
            # Check policy rules
            rules = policy.get("rules", [])
            if not rules:
                issues.append({
                    "pod": "N/A",
                    "container": "audit-policy",
                    "issue": "No audit policy rules defined",
                    "severity": "HIGH"
                })
                return
            
            # Check for catch-all rule
            has_catch_all = False
            for rule in rules:
                if not rule.get("resources") and not rule.get("namespaces"):
                    has_catch_all = True
                    break
            
            if not has_catch_all:
                issues.append({
                    "pod": "N/A",
                    "container": "audit-policy",
                    "issue": "No catch-all rule in audit policy",
                    "severity": "MEDIUM"
                })
            
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "audit-policy",
                "issue": f"Error checking audit policy: {str(e)}",
                "severity": "HIGH"
            })

    def _check_audit_log_storage(self, issues: List[Dict]):
        """Check audit log storage configuration."""
        try:
            # Check persistent volume for audit logs
            v1 = client.CoreV1Api()
            pvcs = v1.list_namespaced_persistent_volume_claim("kube-system")
            
            audit_pvc = None
            for pvc in pvcs.items:
                if "audit" in pvc.metadata.name.lower():
                    audit_pvc = pvc
                    break
            
            if not audit_pvc:
                issues.append({
                    "pod": "N/A",
                    "container": "audit-storage",
                    "issue": "No dedicated storage found for audit logs",
                    "severity": "HIGH"
                })
            else:
                # Check storage capacity
                capacity = audit_pvc.spec.resources.requests.get("storage", "0Gi")
                if capacity.endswith("Gi"):
                    size_gb = int(capacity[:-2])
                    if size_gb < 10:
                        issues.append({
                            "pod": "N/A",
                            "container": "audit-storage",
                            "issue": f"Audit log storage capacity might be insufficient: {capacity}",
                            "severity": "MEDIUM"
                        })
        
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "audit-storage",
                "issue": f"Error checking audit log storage: {str(e)}",
                "severity": "HIGH"
            })

    def _check_audit_webhook(self, issues: List[Dict]):
        """Check audit webhook configuration."""
        try:
            # This would typically check the webhook configuration
            # For demonstration, we'll check common settings
            webhook_config = self._get_webhook_config()
            
            if not webhook_config:
                issues.append({
                    "pod": "N/A",
                    "container": "audit-webhook",
                    "issue": "No audit webhook configuration found",
                    "severity": "MEDIUM"
                })
                return
            
            # Check webhook endpoint
            if not webhook_config.get("endpoint"):
                issues.append({
                    "pod": "N/A",
                    "container": "audit-webhook",
                    "issue": "Audit webhook endpoint not configured",
                    "severity": "HIGH"
                })
            
            # Check TLS configuration
            if not webhook_config.get("tls", {}).get("enabled"):
                issues.append({
                    "pod": "N/A",
                    "container": "audit-webhook",
                    "issue": "Audit webhook TLS not enabled",
                    "severity": "HIGH"
                })
            
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "audit-webhook",
                "issue": f"Error checking audit webhook: {str(e)}",
                "severity": "HIGH"
            })

    def _get_audit_policy(self) -> Dict:
        """Get audit policy configuration."""
        # This is a placeholder - in a real implementation,
        # you would read from the actual audit policy file
        return {
            "rules": [
                {
                    "level": "Metadata",
                    "resources": ["pods"]
                },
                {
                    "level": "Request",
                    "resources": ["secrets"]
                }
            ]
        }

    def _get_webhook_config(self) -> Dict:
        """Get audit webhook configuration."""
        # This is a placeholder - in a real implementation,
        # you would read from the actual webhook config
        return {
            "endpoint": "https://audit.example.com",
            "tls": {
                "enabled": True,
                "verify": True
            }
        } 