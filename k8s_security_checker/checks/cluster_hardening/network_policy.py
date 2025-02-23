"""Network policy security checker for Kubernetes clusters."""

from typing import List, Dict
from kubernetes import client
from ...base_checker import BaseChecker

class NetworkPolicyChecker(BaseChecker):
    """Checks for network policy security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run network policy security checks."""
        issues = []
        v1 = client.NetworkingV1Api()

        try:
            # Get all pods in the namespace
            core_v1 = client.CoreV1Api()
            pods = core_v1.list_namespaced_pod(namespace)

            # Get network policies in the namespace
            net_pols = v1.list_namespaced_network_policy(namespace)
            
            # Check if namespace has any network policies
            if not net_pols.items:
                issues.append({
                    "pod": "N/A",
                    "container": "Namespace",
                    "issue": f"No network policies found in namespace '{namespace}'",
                    "severity": "HIGH"
                })
            
            # Check each pod's network policies
            for pod in pods.items:
                self._check_pod_network_policies(pod, net_pols.items, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking network policies: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_pod_network_policies(self, pod, policies, issues: List[Dict]):
        """Check network policies for a specific pod."""
        pod_name = pod.metadata.name
        pod_labels = pod.metadata.labels or {}
        
        # Check if pod is covered by any network policy
        covered_by_policy = False
        for policy in policies:
            selector = policy.spec.pod_selector
            if self._selector_matches_pod(selector, pod_labels):
                covered_by_policy = True
                self._check_policy_rules(policy, pod_name, issues)
                break
        
        if not covered_by_policy:
            issues.append({
                "pod": pod_name,
                "container": "NetworkPolicy",
                "issue": "Pod is not covered by any network policy",
                "severity": "HIGH"
            })

    def _selector_matches_pod(self, selector, pod_labels: Dict) -> bool:
        """Check if a selector matches pod labels."""
        if not selector.match_labels and not selector.match_expressions:
            return True  # Empty selector matches everything
        
        if selector.match_labels:
            for key, value in selector.match_labels.items():
                if pod_labels.get(key) != value:
                    return False
        
        # TODO: Add support for match_expressions
        return True

    def _check_policy_rules(self, policy, pod_name: str, issues: List[Dict]):
        """Check network policy rules for security issues."""
        policy_name = policy.metadata.name
        
        # Check ingress rules
        if not policy.spec.ingress:
            issues.append({
                "pod": pod_name,
                "container": f"NetworkPolicy/{policy_name}",
                "issue": "Network policy has no ingress rules",
                "severity": "MEDIUM"
            })
        else:
            for rule in policy.spec.ingress:
                if not rule.from_:
                    issues.append({
                        "pod": pod_name,
                        "container": f"NetworkPolicy/{policy_name}",
                        "issue": "Network policy has empty ingress rule (allows all)",
                        "severity": "HIGH"
                    })
        
        # Check egress rules
        if not policy.spec.egress:
            issues.append({
                "pod": pod_name,
                "container": f"NetworkPolicy/{policy_name}",
                "issue": "Network policy has no egress rules",
                "severity": "MEDIUM"
            })
        else:
            for rule in policy.spec.egress:
                if not rule.to:
                    issues.append({
                        "pod": pod_name,
                        "container": f"NetworkPolicy/{policy_name}",
                        "issue": "Network policy has empty egress rule (allows all)",
                        "severity": "HIGH"
                    }) 