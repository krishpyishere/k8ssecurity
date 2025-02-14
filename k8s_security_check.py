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
from rich import box
import os

class K8sSecurityChecker:
    def __init__(self):
        try:
            # Load kube config
            config.load_kube_config()
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.console = Console()
            
            # Check for security tools
            self.has_syft = self._check_tool_installed("syft")
            self.has_grype = self._check_tool_installed("grype")
            self.has_kube_linter = self._check_tool_installed("kube-linter")
        except Exception as e:
            print(f"Error initializing Kubernetes client: {e}")
            sys.exit(1)

    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and try to install if missing."""
        try:
            # First check if tool exists
            subprocess.run(["which", tool_name], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            print(f"\n[yellow]Warning: {tool_name} not found.[/yellow]")
            
            # Get current user
            try:
                current_user = subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()
            except subprocess.CalledProcessError:
                current_user = None

            if sys.platform == "darwin":  # macOS
                if current_user == "root":
                    print(f"[red]Error: Cannot install {tool_name} as root user.[/red]")
                    print("[yellow]Please run the script as a regular user. Homebrew should not be run as root.[/yellow]")
                    print("\nTo fix this:")
                    print("1. Exit the root session")
                    print("2. Run the script as your regular user")
                    print(f"3. Install {tool_name} manually with:")
                    if tool_name == "kube-linter":
                        print("   brew install kube-linter")
                    else:
                        print(f"   brew tap anchore/{tool_name}")
                        print(f"   brew install {tool_name}")
                else:
                    try:
                        if tool_name == "kube-linter":
                            subprocess.run(["brew", "install", "kube-linter"], check=True)
                        else:
                            subprocess.run(["brew", "tap", f"anchore/{tool_name}"], check=True)
                            subprocess.run(["brew", "install", tool_name], check=True)
                        print(f"[green]{tool_name} successfully installed![/green]")
                        return True
                    except subprocess.CalledProcessError as e:
                        print(f"[red]Error installing {tool_name}: {e}[/red]")
                        print(f"\n[yellow]Please install {tool_name} manually:[/yellow]")
                        if tool_name == "kube-linter":
                            print("brew install kube-linter")
                        else:
                            print(f"brew tap anchore/{tool_name}")
                            print(f"brew install {tool_name}")
            else:  # Linux
                try:
                    if tool_name == "kube-linter":
                        # For Linux, we'll install to user's local bin directory
                        user_bin_dir = str(Path.home() / ".local" / "bin")
                        Path(user_bin_dir).mkdir(parents=True, exist_ok=True)
                        
                        subprocess.run([
                            "curl", "-L",
                            "https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz",
                            "-o", f"{user_bin_dir}/kube-linter.tar.gz"
                        ], check=True)
                        subprocess.run(["tar", "xzf", f"{user_bin_dir}/kube-linter.tar.gz", "-C", user_bin_dir], check=True)
                        subprocess.run(["chmod", "+x", f"{user_bin_dir}/kube-linter"], check=True)
                        # Clean up
                        Path(f"{user_bin_dir}/kube-linter.tar.gz").unlink()
                    else:
                        # For Syft and Grype, install to user's local bin
                        install_script = f"https://raw.githubusercontent.com/anchore/{tool_name}/main/install.sh"
                        subprocess.run([
                            "curl", "-sSfL", install_script,
                            "-o", f"/tmp/{tool_name}-install.sh"
                        ], check=True)
                        subprocess.run([
                            "sh", f"/tmp/{tool_name}-install.sh",
                            "-b", str(Path.home() / ".local" / "bin")
                        ], check=True)
                        # Clean up
                        Path(f"/tmp/{tool_name}-install.sh").unlink()
                    
                    print(f"[green]{tool_name} successfully installed![/green]")
                    # Add the local bin to PATH if not already there
                    local_bin = str(Path.home() / ".local" / "bin")
                    if local_bin not in os.environ["PATH"]:
                        os.environ["PATH"] = f"{local_bin}:{os.environ['PATH']}"
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"[red]Error installing {tool_name}: {e}[/red]")
                    print(f"\n[yellow]Please install {tool_name} manually:[/yellow]")
                    if tool_name == "kube-linter":
                        print(f"mkdir -p ~/.local/bin")
                        print(f"curl -L https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz | tar xzf - -C ~/.local/bin")
                        print(f"chmod +x ~/.local/bin/kube-linter")
                    else:
                        print(f"curl -sSfL https://raw.githubusercontent.com/anchore/{tool_name}/main/install.sh | sh -s -- -b ~/.local/bin")
            
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
        
        # Check for required tools
        missing_tools = []
        if not self.has_syft:
            missing_tools.append("syft")
        if not self.has_grype:
            missing_tools.append("grype")
            
        if missing_tools:
            tool_names = " and ".join(missing_tools)
            issues.append({
                "pod": "N/A",
                "container": "System",
                "issue": (f"SBOM analysis skipped: Missing required tools ({tool_names}). "
                         f"SBOM analysis provides important security insights but requires admin privileges to install tools. "
                         f"Please have your system administrator install the required tools."),
                "severity": "INFO"
            })
            print(f"\n[yellow]Warning: Skipping SBOM analysis due to missing tools ({tool_names}).[/yellow]")
            print("[yellow]Other security checks will still be performed.[/yellow]")
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
            print(f"\nAnalyzing dependencies for {image}...")
            syft_cmd = ["syft", image, "-o", "json"]
            syft_result = subprocess.run(syft_cmd, capture_output=True, text=True)
            
            if syft_result.returncode == 0:
                sbom_data = json.loads(syft_result.stdout)
                
                # Check for known vulnerable dependencies
                print(f"Scanning for vulnerabilities in {image}...")
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
                        
                        # Get fix version if available
                        fix_version = vulnerability.get("fix", {}).get("versions", ["unknown"])[0]
                        fix_info = f" (Fix available in version {fix_version})" if fix_version != "unknown" else ""
                        
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": (f"Vulnerable package found: {match.get('artifact', {}).get('name')} "
                                    f"(version: {match.get('artifact', {}).get('version')}) - "
                                    f"CVE: {vulnerability.get('id')}{fix_info}"),
                            "severity": severity_map.get(severity, "INFO")
                        })

                # Check for outdated dependencies
                for package in sbom_data.get("artifacts", []):
                    if package.get("metadata", {}).get("outdated"):
                        latest_version = package.get("metadata", {}).get("latest_version", "unknown")
                        version_info = f" (Latest: {latest_version})" if latest_version != "unknown" else ""
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": f"Outdated package: {package.get('name')} (current: {package.get('version')}){version_info}",
                            "severity": "MEDIUM"
                        })

                # Check for deprecated packages
                for package in sbom_data.get("artifacts", []):
                    if package.get("metadata", {}).get("deprecated"):
                        alternative = package.get("metadata", {}).get("alternative", "")
                        alt_info = f" (Alternative: {alternative})" if alternative else ""
                        issues.append({
                            "pod": pod_name,
                            "container": container_name,
                            "issue": f"Deprecated package: {package.get('name')} (version: {package.get('version')}){alt_info}",
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

    def check_kube_linter(self, namespace: str = "default") -> List[Dict]:
        """Run KubeLinter checks on the namespace."""
        issues = []

        if not self.has_kube_linter:
            issues.append({
                "pod": "N/A",
                "container": "System",
                "issue": ("KubeLinter not installed. Install with:\n"
                         "# For macOS:\nbrew install kube-linter\n"
                         "# For Linux:\n"
                         "curl -L https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz | tar xvzf - -C /usr/local/bin\n"
                         "chmod +x /usr/local/bin/kube-linter"),
                "severity": "HIGH"
            })
            return issues

        try:
            # Create a temporary file to store namespace resources
            with tempfile.NamedTemporaryFile(suffix='.yaml') as temp_file:
                # Export namespace resources to the temp file
                export_cmd = f"kubectl get all -n {namespace} -o yaml > {temp_file.name}"
                subprocess.run(export_cmd, shell=True, check=True)

                # Run kube-linter with all checks enabled
                print(f"\nRunning KubeLinter analysis on namespace {namespace}...")
                linter_cmd = ["kube-linter", "lint", 
                            "--format", "json",
                            "--include-all",
                            temp_file.name]
                
                result = subprocess.run(linter_cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    lint_data = json.loads(result.stdout)
                    
                    # Process KubeLinter findings
                    for report in lint_data.get("Reports", []):
                        # Map KubeLinter severity to our scale
                        severity_map = {
                            "error": "HIGH",
                            "warning": "MEDIUM",
                            "info": "LOW"
                        }
                        
                        # Extract object details
                        object_info = report.get("Object", {})
                        object_name = object_info.get("Name", "N/A")
                        object_kind = object_info.get("K8sObject", {}).get("Kind", "Resource")
                        
                        # Get remediation
                        remediation = report.get("Remediation", "No specific remediation provided")
                        
                        issues.append({
                            "pod": f"{object_kind}/{object_name}",
                            "container": report.get("Check", "N/A"),
                            "issue": f"{report.get('Description', 'No description')}\nRemediation: {remediation}",
                            "severity": severity_map.get(report.get("Severity", "warning"), "MEDIUM")
                        })
                else:
                    issues.append({
                        "pod": "N/A",
                        "container": "KubeLinter",
                        "issue": f"Error running KubeLinter: {result.stderr}",
                        "severity": "INFO"
                    })

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "KubeLinter",
                "issue": f"Error during KubeLinter analysis: {str(e)}",
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

        # Categorize issues
        categories = {
            "Container Security": [],
            "RBAC & Access Control": [],
            "Network Security": [],
            "Resource Management": [],
            "Dependencies & SBOM": [],
            "Configuration": [],
            "Best Practices": []
        }

        for issue in sorted_issues:
            issue_text = issue["issue"].lower()
            if any(keyword in issue_text for keyword in ["container", "privileged", "root", "dind", "docker"]):
                categories["Container Security"].append(issue)
            elif any(keyword in issue_text for keyword in ["rbac", "role", "permission", "access"]):
                categories["RBAC & Access Control"].append(issue)
            elif any(keyword in issue_text for keyword in ["network", "nodeport", "port", "expose"]):
                categories["Network Security"].append(issue)
            elif any(keyword in issue_text for keyword in ["limit", "quota", "resource", "memory", "cpu"]):
                categories["Resource Management"].append(issue)
            elif any(keyword in issue_text for keyword in ["package", "dependency", "cve", "vulnerability"]):
                categories["Dependencies & SBOM"].append(issue)
            elif any(keyword in issue_text for keyword in ["config", "setting", "parameter"]):
                categories["Configuration"].append(issue)
            else:
                categories["Best Practices"].append(issue)

        # Display Analysis Summary
        self.console.print("\n[bold bright_white]Security Analysis Summary[/]")
        
        summary_table = Table(title="Security Analysis by Category")
        summary_table.add_column("Category", style="bright_yellow")
        summary_table.add_column("Critical", style="bright_red", justify="right")
        summary_table.add_column("High", style="red", justify="right")
        summary_table.add_column("Medium", style="bright_yellow", justify="right")
        summary_table.add_column("Low", style="bright_green", justify="right")
        summary_table.add_column("Info", style="bright_white", justify="right")
        summary_table.add_column("Total", style="bright_white", justify="right")
        summary_table.add_column("Risk Level", style="orange1")

        for category, category_issues in categories.items():
            if category_issues:
                severity_counts = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0
                }
                
                for issue in category_issues:
                    severity = issue.get("severity", "INFO")  # Default to INFO if severity is missing
                    severity_counts[severity] += 1
                
                total = sum(severity_counts.values())
                
                # Calculate risk level (excluding INFO from risk calculation)
                risk_score = (severity_counts["CRITICAL"] * 4 + 
                            severity_counts["HIGH"] * 3 + 
                            severity_counts["MEDIUM"] * 2 + 
                            severity_counts["LOW"])
                risk_level = "CRITICAL" if risk_score >= 8 else \
                           "HIGH" if risk_score >= 5 else \
                           "MEDIUM" if risk_score >= 3 else "LOW"
                
                summary_table.add_row(
                    category,
                    str(severity_counts["CRITICAL"]),
                    str(severity_counts["HIGH"]),
                    str(severity_counts["MEDIUM"]),
                    str(severity_counts["LOW"]),
                    str(severity_counts["INFO"]),
                    str(total),
                    risk_level
                )

        self.console.print(summary_table)

        # Display Detailed Analysis
        self.console.print("\n[bold bright_white]Detailed Analysis by Category[/]")
        
        for category, category_issues in categories.items():
            if category_issues:
                self.console.print(f"\n[bold bright_yellow]{category}[/]")
                
                category_table = Table(show_header=True, box=box.MINIMAL)
                category_table.add_column("Resource", style="bright_white")
                category_table.add_column("Component", style="orange1")
                category_table.add_column("Issue", style="bright_magenta")
                category_table.add_column("Severity", style="bright_cyan")
                category_table.add_column("Recommended Fix", style="bright_green")

                for issue in sorted(category_issues, key=lambda x: severity_order.get(x["severity"], 999)):
                    suggestion = self._get_suggestion(issue["issue"])
                    category_table.add_row(
                        issue["pod"],
                        issue["container"],
                        issue["issue"],
                        issue["severity"],
                        suggestion
                    )

                self.console.print(category_table)

        # Display Risk Assessment
        self.console.print("\n[bold bright_white]Risk Assessment & Priorities[/]")
        
        risk_table = Table(title="Risk Assessment")
        risk_table.add_column("Risk Level", style="bright_red")
        risk_table.add_column("Category", style="bright_yellow")
        risk_table.add_column("Impact", style="bright_magenta")
        risk_table.add_column("Recommended Actions", style="bright_green")
        risk_table.add_column("Timeline", style="orange1")

        # Add critical risks
        critical_categories = [cat for cat, issues in categories.items() 
                             if any(i["severity"] == "CRITICAL" for i in issues)]
        if critical_categories:
            for category in critical_categories:
                risk_table.add_row(
                    "CRITICAL",
                    category,
                    "Immediate security threat",
                    "Urgent remediation required",
                    "24-48 hours"
                )

        # Add high risks
        high_categories = [cat for cat, issues in categories.items() 
                          if any(i["severity"] == "HIGH" for i in issues)]
        if high_categories:
            for category in high_categories:
                risk_table.add_row(
                    "HIGH",
                    category,
                    "Significant vulnerability",
                    "Prioritize fixes",
                    "1 week"
                )

        self.console.print(risk_table)

        # Display original detailed tables
        self.console.print("\n[bold bright_white]Detailed Findings[/]")
        
        # Display general security issues with suggestions
        analysis_table = Table(title="Security Issues & Fixes")
        analysis_table.add_column("Resource", style="bright_yellow")
        analysis_table.add_column("Component", style="orange1")
        analysis_table.add_column("Issue", style="bright_magenta")
        analysis_table.add_column("Severity", style="bright_cyan")
        analysis_table.add_column("Recommended Fix", style="bright_green")

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
            self.console.print("\n[bold bright_white]SBOM Analysis & Recommendations[/]")
            
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
        task = progress.add_task("[cyan]Scanning Kubernetes cluster for security issues...", total=9)  # Updated total
        
        all_issues = []
        
        # Run all security checks
        progress.update(task, advance=1, description="Checking pod security...")
        all_issues.extend(checker.check_pod_security())
        
        progress.update(task, advance=1, description="Running KubeLinter checks...")
        all_issues.extend(checker.check_kube_linter())
        
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