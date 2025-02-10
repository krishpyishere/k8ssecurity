#!/usr/bin/env python3

from kubernetes import client, config
from typing import List, Dict, Optional
import sys
import subprocess
import json
import re
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import yaml
import requests
from pathlib import Path

class K8sSecurityChecker:
    def __init__(self):
        try:
            # Load kube config
            config.load_kube_config()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.console = Console()
        except Exception as e:
            print(f"Error initializing Kubernetes client: {e}")
            sys.exit(1)

    def check_pod_security(self, namespace: str = "default") -> List[Dict]:
        issues = []
        try:
            pods = self.v1.list_namespaced_pod(namespace)
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                
                # Check containers in the pod
                for container in pod.spec.containers:
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

                    # Check resource limits for DoS prevention
                    if container.resources and container.resources.limits:
                        cpu_limit = container.resources.limits.get('cpu')
                        memory_limit = container.resources.limits.get('memory')
                        if not cpu_limit or not memory_limit:
                            issues.append({
                                "pod": pod_name,
                                "container": container.name,
                                "issue": "Missing CPU or memory limits - DoS risk",
                                "severity": "HIGH"
                            })

        except Exception as e:
            print(f"Error checking pod security: {e}")
        return issues

    def check_nodeport_exposure(self) -> List[Dict]:
        issues = []
        try:
            services = self.v1.list_service_for_all_namespaces()
            for svc in services.items:
                if svc.spec.type == "NodePort":
                    issues.append({
                        "pod": "N/A",
                        "container": f"Service: {svc.metadata.name}",
                        "issue": f"NodePort service exposed on port {svc.spec.ports[0].node_port}",
                        "severity": "MEDIUM"
                    })
        except Exception as e:
            print(f"Error checking NodePort exposure: {e}")
        return issues

    def check_rbac_configuration(self) -> List[Dict]:
        issues = []
        try:
            cluster_roles = self.rbac_v1.list_cluster_role()
            for role in cluster_roles.items:
                # Check for overly permissive roles
                for rule in role.rules:
                    if "*" in rule.resources and "*" in rule.verbs:
                        issues.append({
                            "pod": "N/A",
                            "container": f"ClusterRole: {role.metadata.name}",
                            "issue": "Overly permissive RBAC role with wildcard permissions",
                            "severity": "HIGH"
                        })
        except Exception as e:
            print(f"Error checking RBAC configuration: {e}")
        return issues

    def check_network_policies(self) -> List[Dict]:
        issues = []
        try:
            namespaces = self.v1.list_namespace()
            networking_v1 = client.NetworkingV1Api()
            
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                policies = networking_v1.list_namespaced_network_policy(ns_name)
                
                if not policies.items:
                    issues.append({
                        "pod": "N/A",
                        "container": f"Namespace: {ns_name}",
                        "issue": "No NetworkPolicies defined - network access not restricted",
                        "severity": "HIGH"
                    })
        except Exception as e:
            print(f"Error checking network policies: {e}")
        return issues

    def run_cis_benchmark(self) -> List[Dict]:
        issues = []
        try:
            # Check for kube-bench installation
            result = subprocess.run(["which", "kube-bench"], capture_output=True, text=True)
            if result.returncode != 0:
                issues.append({
                    "pod": "N/A",
                    "container": "System",
                    "issue": "kube-bench not installed - cannot perform CIS benchmark checks",
                    "severity": "INFO"
                })
                return issues

            # Run kube-bench
            result = subprocess.run(["kube-bench", "--json"], capture_output=True, text=True)
            if result.returncode == 0:
                benchmark_results = json.loads(result.stdout)
                for test in benchmark_results.get("tests", []):
                    for result in test.get("results", []):
                        if result.get("status") == "FAIL":
                            issues.append({
                                "pod": "N/A",
                                "container": "CIS Benchmark",
                                "issue": f"Failed check: {result.get('desc')}",
                                "severity": "HIGH"
                            })
        except Exception as e:
            print(f"Error running CIS benchmark: {e}")
        return issues

    def check_sensitive_keys(self) -> List[Dict]:
        issues = []
        try:
            secrets = self.v1.list_secret_for_all_namespaces()
            for secret in secrets.items:
                # Check for common sensitive key patterns
                for key in secret.data.keys():
                    if any(pattern in key.lower() for pattern in ["key", "token", "password", "secret"]):
                        issues.append({
                            "pod": "N/A",
                            "container": f"Secret: {secret.metadata.name}",
                            "issue": f"Potentially sensitive key found: {key}",
                            "severity": "MEDIUM"
                        })
        except Exception as e:
            print(f"Error checking sensitive keys: {e}")
        return issues

    def display_results(self, issues: List[Dict]):
        if not issues:
            self.console.print("\n[green]No security issues found![/green]")
            return

        table = Table(title="Kubernetes Security Issues")
        table.add_column("Pod/Resource", style="cyan")
        table.add_column("Container/Component", style="blue")
        table.add_column("Issue", style="yellow")
        table.add_column("Severity", style="red")

        for issue in issues:
            table.add_row(
                issue["pod"],
                issue["container"],
                issue["issue"],
                issue["severity"]
            )

        self.console.print(table)

def main():
    checker = K8sSecurityChecker()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning Kubernetes cluster for security issues...", total=7)
        
        all_issues = []
        
        # Run all security checks
        progress.update(task, advance=1, description="Checking pod security...")
        all_issues.extend(checker.check_pod_security())
        
        progress.update(task, advance=1, description="Checking NodePort exposure...")
        all_issues.extend(checker.check_nodeport_exposure())
        
        progress.update(task, advance=1, description="Checking RBAC configuration...")
        all_issues.extend(checker.check_rbac_configuration())
        
        progress.update(task, advance=1, description="Checking network policies...")
        all_issues.extend(checker.check_network_policies())
        
        progress.update(task, advance=1, description="Running CIS benchmark...")
        all_issues.extend(checker.run_cis_benchmark())
        
        progress.update(task, advance=1, description="Checking sensitive keys...")
        all_issues.extend(checker.check_sensitive_keys())
        
        progress.update(task, advance=1, description="Generating report...")
    
    # Display results
    checker.display_results(all_issues)

if __name__ == "__main__":
    main() 