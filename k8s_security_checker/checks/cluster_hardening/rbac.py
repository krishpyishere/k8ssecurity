"""RBAC security checker for Kubernetes clusters."""

from typing import List, Dict
from kubernetes import client
from ...base_checker import BaseChecker

class RBACChecker(BaseChecker):
    """Checks for RBAC security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run RBAC security checks."""
        issues = []
        v1 = client.RbacAuthorizationV1Api()

        try:
            # Check cluster roles
            cluster_roles = v1.list_cluster_role()
            for role in cluster_roles.items:
                self._check_cluster_role(role, issues)

            # Check roles in namespace
            roles = v1.list_namespaced_role(namespace)
            for role in roles.items:
                self._check_role(role, issues)

            # Check service accounts
            core_v1 = client.CoreV1Api()
            service_accounts = core_v1.list_namespaced_service_account(namespace)
            for sa in service_accounts.items:
                self._check_service_account(sa, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking RBAC configuration: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_cluster_role(self, role, issues: List[Dict]):
        """Check a cluster role for security issues."""
        # Check for overly permissive rules
        for rule in role.rules:
            if "*" in rule.verbs and "*" in rule.resources:
                issues.append({
                    "pod": "N/A",
                    "container": "ClusterRole",
                    "issue": f"Cluster role '{role.metadata.name}' has wildcard permissions",
                    "severity": "HIGH"
                })
                break

    def _check_role(self, role, issues: List[Dict]):
        """Check a namespaced role for security issues."""
        # Check for dangerous permissions
        dangerous_resources = ["secrets", "pods/exec", "pods/attach"]
        for rule in role.rules:
            for resource in rule.resources:
                if resource in dangerous_resources and "*" in rule.verbs:
                    issues.append({
                        "pod": "N/A",
                        "container": f"Role/{role.metadata.name}",
                        "issue": f"Role has dangerous permissions on {resource}",
                        "severity": "HIGH"
                    })

    def _check_service_account(self, sa, issues: List[Dict]):
        """Check a service account for security issues."""
        # Check for default service account usage
        if sa.metadata.name == "default":
            issues.append({
                "pod": "N/A",
                "container": "ServiceAccount/default",
                "issue": "Default service account is in use",
                "severity": "MEDIUM"
            })

        # Check for automounted service account tokens
        if sa.automount_service_account_token:
            issues.append({
                "pod": "N/A",
                "container": f"ServiceAccount/{sa.metadata.name}",
                "issue": "Service account token is automatically mounted",
                "severity": "LOW"
            }) 