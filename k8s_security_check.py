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
import tempfile

class K8sSecurityChecker:
    def __init__(self):
        try:
            # Load kube config
            config.load_kube_config()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.console = Console()
            
            # Check for SBOM tools
            self.has_syft = self._check_tool_installed("syft")
            self.has_grype = self._check_tool_installed("grype")
        except Exception as e:
            print(f"Error initializing Kubernetes client: {e}")
            sys.exit(1)

    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        try:
            subprocess.run(["which", tool_name], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

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

    def check_sbom(self, namespace: str = "default") -> List[Dict]:
        """Check Software Bill of Materials (SBOM) for container images."""
        issues = []
        
        if not self.has_syft or not self.has_grype:
            issues.append({
                "pod": "N/A",
                "container": "System",
                "issue": "SBOM tools (syft/grype) not installed - cannot perform deep dependency analysis",
                "severity": "INFO"
            })
            return issues

        try:
            pods = self.v1.list_namespaced_pod(namespace)
            
            for pod in pods.items:
                pod_name = pod.metadata.name
                
                for container in pod.spec.containers:
                    image = container.image
                    sbom_issues = self._analyze_container_sbom(pod_name, container.name, image)
                    issues.extend(sbom_issues)
                    
        except Exception as e:
            print(f"Error checking SBOM: {e}")
        
        return issues

    def _analyze_container_sbom(self, pod_name: str, container_name: str, image: str) -> List[Dict]:
        """Analyze a container's SBOM using syft and grype."""
        issues = []
        
        try:
            # Generate SBOM using syft
            syft_cmd = ["syft", image, "-o", "json"]
            syft_result = subprocess.run(syft_cmd, capture_output=True, text=True)
            
            if syft_result.returncode == 0:
                sbom_data = json.loads(syft_result.stdout)
                
                # Check for known vulnerable dependencies
                grype_cmd = ["grype", image, "--output", "json"]
                grype_result = subprocess.run(grype_cmd, capture_output=True, text=True)
                
                if grype_result.returncode == 0:
                    vuln_data = json.loads(grype_result.stdout)
                    
                    # Process vulnerability findings
                    for match in vuln_data.get("matches", []):
                        vulnerability = match.get("vulnerability", {})
                        severity = vulnerability.get("severity", "UNKNOWN").upper()
                        
                        # Map severity to our scale
                        severity_map = {
                            "CRITICAL": "CRITICAL",
                            "HIGH": "HIGH",
                            "MEDIUM": "MEDIUM",
                            "LOW": "LOW",
                            "NEGLIGIBLE": "INFO",
                            "UNKNOWN": "INFO"
                        }
                        
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": (f"Vulnerable package found: {match.get('artifact', {}).get('name')} "
                                    f"(version: {match.get('artifact', {}).get('version')}) - "
                                    f"CVE: {vulnerability.get('id')}"),
                            "severity": severity_map.get(severity, "INFO")
                        })

                # Check for outdated dependencies
                for package in sbom_data.get("artifacts", []):
                    if package.get("metadata", {}).get("outdated"):
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": f"Outdated package: {package.get('name')} (version: {package.get('version')})",
                            "severity": "MEDIUM"
                        })

                # Check for deprecated packages
                for package in sbom_data.get("artifacts", []):
                    if package.get("metadata", {}).get("deprecated"):
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": f"Deprecated package: {package.get('name')} (version: {package.get('version')})",
                            "severity": "HIGH"
                        })

        except Exception as e:
            issues.append({
                "pod": pod_name,
                "container": container_name,
                "issue": f"Error analyzing SBOM: {str(e)}",
                "severity": "INFO"
            })
            
        return issues

    def display_results(self, issues: List[Dict]):
        if not issues:
            self.console.print("\n[bright_green]No security issues found![/bright_green]")
            return

        # Sort issues by severity
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4
        }
        sorted_issues = sorted(
            issues,
            key=lambda x: severity_order.get(x["severity"], 999)
        )

        # Separate SBOM issues from general security issues
        sbom_issues = []
        general_issues = []
        
        for issue in sorted_issues:
            if any(sbom_keyword in issue["issue"].lower() 
                  for sbom_keyword in ["vulnerable package", "outdated package", 
                                     "deprecated package", "cve:", "dependency"]):
                sbom_issues.append(issue)
            else:
                general_issues.append(issue)

        # Display general security issues with suggestions
        self.console.print("\n[bold bright_white]Security Analysis & Recommendations:[/]")
        analysis_table = Table(title="Security Issues & Fixes")
        analysis_table.add_column("Resource", style="bright_yellow")
        analysis_table.add_column("Component", style="orange1")
        analysis_table.add_column("Issue", style="bright_magenta")
        analysis_table.add_column("Severity", style="bright_cyan")
        analysis_table.add_column("Recommended Fix", style="bright_green")

        # Add suggestions based on issue type
        for issue in general_issues:
            suggestion = self._get_suggestion(issue["issue"])
            analysis_table.add_row(
                issue["pod"],
                issue["container"],
                issue["issue"],
                issue["severity"],
                suggestion
            )

        self.console.print(analysis_table)

        # Display SBOM Analysis with suggestions
        if sbom_issues:
            self.console.print("\n[bold bright_white]SBOM Analysis & Recommendations:[/]")
            
            sbom_table = Table(title="Dependencies & Vulnerabilities")
            sbom_table.add_column("Resource", style="bright_yellow")
            sbom_table.add_column("Component", style="orange1")
            sbom_table.add_column("Issue", style="bright_magenta")
            sbom_table.add_column("Severity", style="bright_cyan")
            sbom_table.add_column("Recommended Fix", style="bright_green")

            for issue in sbom_issues:
                suggestion = self._get_sbom_suggestion(issue["issue"])
                sbom_table.add_row(
                    issue["pod"],
                    issue["container"],
                    issue["issue"],
                    issue["severity"],
                    suggestion
                )

            self.console.print(sbom_table)

            # SBOM Statistics in table format
            stats_table = Table(title="SBOM Analysis Summary")
            stats_table.add_column("Metric", style="bright_yellow")
            stats_table.add_column("Count", justify="right", style="bright_white")
            stats_table.add_column("Risk Level", style="bright_red")
            stats_table.add_column("Action Required", style="bright_green")
            
            # Calculate statistics
            affected_containers = set()
            issue_types = {"vulnerabilities": 0, "outdated": 0, "deprecated": 0}
            vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            
            for issue in sbom_issues:
                vuln_counts[issue["severity"]] += 1
                affected_containers.add(f"{issue['pod']}/{issue['container']}")
                
                if "vulnerable package" in issue["issue"].lower():
                    issue_types["vulnerabilities"] += 1
                elif "outdated package" in issue["issue"].lower():
                    issue_types["outdated"] += 1
                elif "deprecated package" in issue["issue"].lower():
                    issue_types["deprecated"] += 1

            # Add statistics rows with risk assessment
            stats_table.add_row(
                "Affected Containers",
                str(len(affected_containers)),
                "HIGH" if len(affected_containers) > 3 else "MEDIUM",
                "Review and update affected containers"
            )
            stats_table.add_row(
                "Critical Vulnerabilities",
                str(vuln_counts["CRITICAL"]),
                "CRITICAL",
                "Immediate patching required"
            )
            stats_table.add_row(
                "High Vulnerabilities",
                str(vuln_counts["HIGH"]),
                "HIGH",
                "Schedule urgent updates"
            )
            stats_table.add_row(
                "Outdated Packages",
                str(issue_types["outdated"]),
                "MEDIUM",
                "Plan version upgrades"
            )
            stats_table.add_row(
                "Deprecated Components",
                str(issue_types["deprecated"]),
                "HIGH",
                "Replace deprecated components"
            )
            
            self.console.print(stats_table)

        # Overall Risk Assessment
        risk_table = Table(title="Overall Risk Assessment")
        risk_table.add_column("Category", style="bright_yellow")
        risk_table.add_column("Risk Level", style="bright_red")
        risk_table.add_column("Priority", style="bright_cyan")
        risk_table.add_column("Recommended Actions", style="bright_green")

        total_critical = sum(1 for i in issues if i["severity"] == "CRITICAL")
        total_high = sum(1 for i in issues if i["severity"] == "HIGH")
        
        # Add risk assessment rows
        if total_critical > 0:
            risk_table.add_row(
                "Critical Security Issues",
                "CRITICAL",
                "Immediate",
                "Urgent remediation required - Critical vulnerabilities found"
            )
        if total_high > 0:
            risk_table.add_row(
                "High Security Issues",
                "HIGH",
                "Urgent",
                "Schedule fixes within 1-2 weeks"
            )
        if issue_types.get("deprecated", 0) > 0:
            risk_table.add_row(
                "Deprecated Components",
                "HIGH",
                "High",
                "Plan replacement of deprecated components"
            )
        if issue_types.get("outdated", 0) > 0:
            risk_table.add_row(
                "Outdated Dependencies",
                "MEDIUM",
                "Medium",
                "Update dependencies in next sprint"
            )

        self.console.print("\n")
        self.console.print(risk_table)

    def _get_suggestion(self, issue: str) -> str:
        """Get suggestion based on issue type."""
        suggestions = {
            "running as root": "Add 'runAsNonRoot: true' to container's securityContext",
            "privileged mode": "Remove privileged mode or use more specific capabilities",
            "resource limits": "Add CPU and memory limits to container spec",
            "sensitive path mounted": "Remove sensitive mount or use more restrictive paths",
            "docker.sock": "Avoid mounting docker socket, use more secure alternatives",
            "nodeport": "Consider using ClusterIP or Ingress instead",
            "network policies": "Implement NetworkPolicy resources to restrict traffic",
            "rbac": "Review and restrict RBAC permissions to least privilege",
            "overly permissive": "Define specific permissions instead of using wildcards"
        }
        
        for key, suggestion in suggestions.items():
            if key in issue.lower():
                return suggestion
        return "Review and apply security best practices"

    def _get_sbom_suggestion(self, issue: str) -> str:
        """Get suggestion for SBOM-related issues."""
        if "vulnerable package" in issue.lower():
            return "Update package to latest secure version"
        elif "outdated package" in issue.lower():
            return "Upgrade to latest stable version"
        elif "deprecated package" in issue.lower():
            return "Replace with supported alternative package"
        elif "cve:" in issue.lower():
            return "Apply security patch or update package"
        return "Review and update dependencies"

def main():
    checker = K8sSecurityChecker()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning Kubernetes cluster for security issues...", total=8)
        
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
        
        progress.update(task, advance=1, description="Analyzing Software Bill of Materials...")
        all_issues.extend(checker.check_sbom())
        
        progress.update(task, advance=1, description="Generating report...")
    
    # Display results
    checker.display_results(all_issues)

if __name__ == "__main__":
    main() 