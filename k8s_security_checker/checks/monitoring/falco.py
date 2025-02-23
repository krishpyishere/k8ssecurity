"""Falco runtime security checker for Kubernetes clusters."""

from typing import List, Dict
import subprocess
import json
from kubernetes import client
from ...base_checker import BaseChecker

class FalcoChecker(BaseChecker):
    """Checks for Falco runtime security configuration and issues."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run Falco security checks."""
        issues = []

        try:
            # Check Falco installation and configuration
            self._check_falco_installation(issues)
            
            # Check Falco rules
            self._check_falco_rules(issues)
            
            # Check Falco alerts
            self._check_falco_alerts(issues)
            
            # Check Falco integrations
            self._check_falco_integrations(issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking Falco configuration: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_falco_installation(self, issues: List[Dict]):
        """Check Falco installation status and configuration."""
        try:
            # Check for Falco pods
            v1 = client.CoreV1Api()
            falco_pods = v1.list_pod_for_all_namespaces(
                label_selector="app=falco"
            )
            
            if not falco_pods.items:
                issues.append({
                    "pod": "N/A",
                    "container": "falco",
                    "issue": "Falco is not installed in the cluster",
                    "severity": "CRITICAL"
                })
                return
            
            # Check Falco pod status
            for pod in falco_pods.items:
                if pod.status.phase != "Running":
                    issues.append({
                        "pod": pod.metadata.name,
                        "container": "falco",
                        "issue": f"Falco pod is not running (status: {pod.status.phase})",
                        "severity": "HIGH"
                    })
                
                # Check container status
                for container in pod.status.container_statuses:
                    if not container.ready:
                        issues.append({
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "issue": "Falco container is not ready",
                            "severity": "HIGH"
                        })
        
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "falco",
                "issue": f"Error checking Falco installation: {str(e)}",
                "severity": "HIGH"
            })

    def _check_falco_rules(self, issues: List[Dict]):
        """Check Falco rules configuration."""
        try:
            # Get Falco ConfigMap
            v1 = client.CoreV1Api()
            try:
                config_map = v1.read_namespaced_config_map(
                    "falco-rules",
                    "default"
                )
            except:
                issues.append({
                    "pod": "N/A",
                    "container": "falco-rules",
                    "issue": "Falco rules ConfigMap not found",
                    "severity": "HIGH"
                })
                return
            
            # Check rules content
            rules = config_map.data.get("falco_rules.yaml")
            if not rules:
                issues.append({
                    "pod": "N/A",
                    "container": "falco-rules",
                    "issue": "No Falco rules defined",
                    "severity": "HIGH"
                })
                return
            
            # Check for essential rules
            essential_rules = [
                "Terminal shell in container",
                "File open by system procs",
                "Create Privileged Pod",
                "Modify Binary Dirs",
                "Launch Package Management Process"
            ]
            
            for rule in essential_rules:
                if rule not in rules:
                    issues.append({
                        "pod": "N/A",
                        "container": "falco-rules",
                        "issue": f"Essential Falco rule missing: {rule}",
                        "severity": "MEDIUM"
                    })
        
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "falco-rules",
                "issue": f"Error checking Falco rules: {str(e)}",
                "severity": "HIGH"
            })

    def _check_falco_alerts(self, issues: List[Dict]):
        """Check Falco alerting configuration."""
        try:
            # Get Falco configuration
            config = self._get_falco_config()
            
            if not config:
                issues.append({
                    "pod": "N/A",
                    "container": "falco-config",
                    "issue": "Unable to read Falco configuration",
                    "severity": "HIGH"
                })
                return
            
            # Check alert outputs
            outputs = config.get("outputs", [])
            if not outputs:
                issues.append({
                    "pod": "N/A",
                    "container": "falco-config",
                    "issue": "No alert outputs configured",
                    "severity": "HIGH"
                })
            
            # Check for essential outputs
            essential_outputs = ["stdout", "file"]
            configured_outputs = [out.get("name") for out in outputs]
            
            for output in essential_outputs:
                if output not in configured_outputs:
                    issues.append({
                        "pod": "N/A",
                        "container": "falco-config",
                        "issue": f"Essential output not configured: {output}",
                        "severity": "MEDIUM"
                    })
            
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "falco-config",
                "issue": f"Error checking Falco alerts: {str(e)}",
                "severity": "HIGH"
            })

    def _check_falco_integrations(self, issues: List[Dict]):
        """Check Falco integrations configuration."""
        try:
            # Check for common integrations
            integrations = self._get_falco_integrations()
            
            if not integrations:
                issues.append({
                    "pod": "N/A",
                    "container": "falco-integrations",
                    "issue": "No Falco integrations configured",
                    "severity": "MEDIUM"
                })
                return
            
            # Check essential integrations
            essential_integrations = ["kubernetes", "webhook"]
            for integration in essential_integrations:
                if not integrations.get(integration, {}).get("enabled", False):
                    issues.append({
                        "pod": "N/A",
                        "container": "falco-integrations",
                        "issue": f"Essential integration not enabled: {integration}",
                        "severity": "MEDIUM"
                    })
            
            # Check webhook configuration
            webhook = integrations.get("webhook", {})
            if webhook.get("enabled") and not webhook.get("url"):
                issues.append({
                    "pod": "N/A",
                    "container": "falco-integrations",
                    "issue": "Webhook integration enabled but no URL configured",
                    "severity": "HIGH"
                })
            
        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "falco-integrations",
                "issue": f"Error checking Falco integrations: {str(e)}",
                "severity": "HIGH"
            })

    def _get_falco_config(self) -> Dict:
        """Get Falco configuration."""
        # This is a placeholder - in a real implementation,
        # you would read from the actual Falco configuration
        return {
            "outputs": [
                {"name": "stdout"},
                {"name": "file", "path": "/var/log/falco.log"}
            ]
        }

    def _get_falco_integrations(self) -> Dict:
        """Get Falco integrations configuration."""
        # This is a placeholder - in a real implementation,
        # you would read from the actual integrations configuration
        return {
            "kubernetes": {
                "enabled": True,
                "audit": True
            },
            "webhook": {
                "enabled": True,
                "url": "https://alerts.example.com/falco"
            }
        } 