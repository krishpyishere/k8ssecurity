"""Software Bill of Materials (SBOM) checker for Kubernetes clusters."""

from typing import List, Dict
import subprocess
import json
from kubernetes import client
from ...base_checker import BaseChecker

class SBOMChecker(BaseChecker):
    """Checks for SBOM-related security issues in the cluster."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run SBOM security checks."""
        issues = []
        v1 = client.CoreV1Api()

        try:
            # Get all pods to check their images
            pods = v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                self._check_pod_sbom(pod, issues)

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "N/A",
                "issue": f"Error checking SBOM: {str(e)}",
                "severity": "HIGH"
            })

        return issues

    def _check_pod_sbom(self, pod, issues: List[Dict]):
        """Check SBOM for all containers in a pod."""
        pod_name = pod.metadata.name
        
        for container in pod.spec.containers:
            container_name = container.name
            image = container.image
            
            # Generate SBOM using syft
            sbom_issues = self._generate_sbom(image)
            for issue in sbom_issues:
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": issue,
                    "severity": "MEDIUM"
                })
            
            # Check for vulnerabilities using grype
            vuln_issues = self._check_vulnerabilities(image)
            for issue in vuln_issues:
                issues.append({
                    "pod": pod_name,
                    "container": container_name,
                    "issue": issue["issue"],
                    "severity": issue["severity"]
                })

    def _generate_sbom(self, image: str) -> List[str]:
        """Generate and analyze SBOM for an image."""
        issues = []
        try:
            # Run syft to generate SBOM
            result = subprocess.run(
                ["syft", image, "-o", "json"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                issues.append(f"Failed to generate SBOM: {result.stderr}")
                return issues
            
            # Parse and analyze SBOM
            sbom = json.loads(result.stdout)
            issues.extend(self._analyze_sbom(sbom))
            
        except FileNotFoundError:
            issues.append("SBOM tool (syft) not available")
        except json.JSONDecodeError:
            issues.append("Failed to parse SBOM output")
        except Exception as e:
            issues.append(f"Error generating SBOM: {str(e)}")
        
        return issues

    def _check_vulnerabilities(self, image: str) -> List[Dict]:
        """Check for vulnerabilities using grype."""
        issues = []
        try:
            # Run grype for vulnerability scanning
            result = subprocess.run(
                ["grype", image, "--output", "json"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                issues.append({
                    "issue": f"Vulnerability scan failed: {result.stderr}",
                    "severity": "HIGH"
                })
                return issues
            
            # Parse and analyze vulnerabilities
            vulns = json.loads(result.stdout)
            issues.extend(self._analyze_vulnerabilities(vulns))
            
        except FileNotFoundError:
            issues.append({
                "issue": "Vulnerability scanner (grype) not available",
                "severity": "MEDIUM"
            })
        except json.JSONDecodeError:
            issues.append({
                "issue": "Failed to parse vulnerability scan output",
                "severity": "HIGH"
            })
        except Exception as e:
            issues.append({
                "issue": f"Error scanning for vulnerabilities: {str(e)}",
                "severity": "HIGH"
            })
        
        return issues

    def _analyze_sbom(self, sbom: Dict) -> List[str]:
        """Analyze SBOM data for security issues."""
        issues = []
        
        # Check for outdated packages
        if "artifacts" in sbom:
            for artifact in sbom["artifacts"]:
                name = artifact.get("name", "unknown")
                version = artifact.get("version", "unknown")
                
                # Check for packages without versions
                if version == "unknown" or not version:
                    issues.append(f"Package {name} has no version specified")
                
                # Check for development dependencies in production
                if any(scope in artifact.get("metadata", {}).get("scope", "").lower() 
                      for scope in ["dev", "test", "development"]):
                    issues.append(f"Development dependency {name} found in production image")
        
        return issues

    def _analyze_vulnerabilities(self, vulns: Dict) -> List[Dict]:
        """Analyze vulnerability scan results."""
        issues = []
        
        # Process vulnerability matches
        if "matches" in vulns:
            for match in vulns["matches"]:
                vulnerability = match.get("vulnerability", {})
                severity = vulnerability.get("severity", "UNKNOWN").upper()
                
                if severity in ["CRITICAL", "HIGH"]:
                    issues.append({
                        "issue": (f"Critical vulnerability {vulnerability.get('id', 'unknown')} "
                                f"found in {match.get('artifact', {}).get('name', 'unknown')}"),
                        "severity": severity
                    })
        
        return issues 