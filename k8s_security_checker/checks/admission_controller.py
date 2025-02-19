from typing import List, Dict
import subprocess
import json
from ..base_checker import BaseChecker

class AdmissionControllerChecker(BaseChecker):
    """Check for admission controller configuration and security."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run admission controller checks."""
        issues = []
        try:
            # Get API server pod in kube-system namespace
            api_server_pods = self.v1.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )

            if not api_server_pods.items:
                # Try to get API server info from kubectl
                result = subprocess.run(
                    ["kubectl", "get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "json"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    api_server_pods = json.loads(result.stdout)
                else:
                    issues.append({
                        "pod": "N/A",
                        "container": "System",
                        "issue": "Unable to find kube-apiserver pod for admission controller checks",
                        "severity": "INFO"
                    })
                    return issues

            # Check enabled admission controllers
            required_controllers = {
                "NodeRestriction": {
                    "severity": "HIGH",
                    "description": "Limits node access to specific APIs",
                },
                "PodSecurityPolicy": {
                    "severity": "CRITICAL",
                    "description": "Enforces pod security standards",
                },
                "ValidatingAdmissionWebhook": {
                    "severity": "HIGH",
                    "description": "Enables validation of resources",
                },
                "MutatingAdmissionWebhook": {
                    "severity": "HIGH",
                    "description": "Enables mutation of resources",
                },
                "AlwaysPullImages": {
                    "severity": "MEDIUM",
                    "description": "Enforces image pull policy",
                },
                "ImagePolicyWebhook": {
                    "severity": "HIGH",
                    "description": "Controls allowed container images",
                },
            }

            # Get enabled admission controllers
            enabled_controllers = set()
            for pod in api_server_pods.items:
                for container in pod.spec.containers:
                    if container.name == "kube-apiserver":
                        for arg in container.command:
                            if "--enable-admission-plugins=" in arg:
                                enabled = arg.split("=")[1].split(",")
                                enabled_controllers.update(enabled)

            # Check for missing required controllers
            for controller, info in required_controllers.items():
                if controller not in enabled_controllers:
                    issues.append({
                        "pod": "N/A",
                        "container": "Admission Controllers",
                        "issue": (f"Missing recommended admission controller: {controller}\n"
                                f"Description: {info['description']}\n"
                                f"Remediation: Enable {controller} in the API server configuration"),
                        "severity": info["severity"]
                    })

            # Check for deprecated controllers
            deprecated_controllers = {
                "ServiceAccount": "Use ServiceAccountToken instead",
                "SecurityContextDeny": "Use PodSecurityPolicy instead",
                "ResourceQuota": "Use ResourceQuota admission controller instead",
            }

            for controller in enabled_controllers:
                if controller in deprecated_controllers:
                    issues.append({
                        "pod": "N/A",
                        "container": "Admission Controllers",
                        "issue": (f"Deprecated admission controller in use: {controller}\n"
                                f"Remediation: {deprecated_controllers[controller]}"),
                        "severity": "MEDIUM"
                    })

            # Check webhook configurations
            try:
                # Check validating webhooks
                validating_webhooks = self.k8s_client.request(
                    '/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations',
                    'GET'
                )
                
                for webhook in validating_webhooks.get('items', []):
                    self._check_webhook_config(webhook, "Validating", issues)

                # Check mutating webhooks
                mutating_webhooks = self.k8s_client.request(
                    '/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations',
                    'GET'
                )
                
                for webhook in mutating_webhooks.get('items', []):
                    self._check_webhook_config(webhook, "Mutating", issues)

            except Exception as e:
                issues.append({
                    "pod": "N/A",
                    "container": "Admission Controllers",
                    "issue": f"Error checking webhook configurations: {str(e)}",
                    "severity": "INFO"
                })

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "Admission Controllers",
                "issue": f"Error checking admission controllers: {str(e)}",
                "severity": "INFO"
            })

        return issues

    def _check_webhook_config(self, webhook: Dict, webhook_type: str, issues: List[Dict]):
        """Check webhook configuration for security issues."""
        name = webhook.get('metadata', {}).get('name', 'Unknown')
        
        # Check TLS configuration
        for webhook_config in webhook.get('webhooks', []):
            client_config = webhook_config.get('clientConfig', {})
            
            # Check if TLS is properly configured
            if not client_config.get('caBundle'):
                issues.append({
                    "pod": "N/A",
                    "container": f"{webhook_type} Webhook",
                    "issue": (f"Missing CA bundle in webhook configuration: {name}\n"
                             "Remediation: Configure proper TLS with a valid CA bundle"),
                    "severity": "HIGH"
                })

            # Check for insecure URL
            if client_config.get('url', '').startswith('http://'):
                issues.append({
                    "pod": "N/A",
                    "container": f"{webhook_type} Webhook",
                    "issue": (f"Insecure webhook URL (using http://) in: {name}\n"
                             "Remediation: Use https:// for webhook endpoints"),
                    "severity": "CRITICAL"
                })

            # Check failure policy
            if webhook_config.get('failurePolicy') == 'Ignore':
                issues.append({
                    "pod": "N/A",
                    "container": f"{webhook_type} Webhook",
                    "issue": (f"Webhook using 'Ignore' failure policy: {name}\n"
                             "This could allow security controls to be bypassed when the webhook is unavailable\n"
                             "Remediation: Consider using 'Fail' policy for security-critical webhooks"),
                    "severity": "MEDIUM"
                })

            # Check timeout
            if int(webhook_config.get('timeoutSeconds', 30)) > 30:
                issues.append({
                    "pod": "N/A",
                    "container": f"{webhook_type} Webhook",
                    "issue": (f"Long webhook timeout configured: {name}\n"
                             "Long timeouts could impact API server performance\n"
                             "Remediation: Consider reducing timeout to 30 seconds or less"),
                    "severity": "LOW"
                }) 