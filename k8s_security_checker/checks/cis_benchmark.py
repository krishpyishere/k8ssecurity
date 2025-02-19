from typing import List, Dict
import subprocess
import json
from ..base_checker import BaseChecker

class CISBenchmarkChecker(BaseChecker):
    """Check for CIS benchmark compliance."""

    def run(self, namespace: str = "default") -> List[Dict]:
        """Run CIS benchmark checks."""
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
                
                # Process each test section
                for test in benchmark_results.get("tests", []):
                    section = test.get("desc", "Unknown Section")
                    for result in test.get("results", []):
                        if result.get("status") == "FAIL":
                            # Map severity based on test type
                            severity = self._map_severity(result.get("test_number", ""))
                            
                            remediation = result.get("remediation", "No remediation provided")
                            audit = result.get("audit", "No audit steps provided")
                            
                            issues.append({
                                "pod": "N/A",
                                "container": f"CIS Benchmark - {section}",
                                "issue": (f"Failed check {result.get('test_number')}: {result.get('desc')}\n"
                                         f"Remediation: {remediation}\n"
                                         f"Audit: {audit}"),
                                "severity": severity
                            })
            else:
                issues.append({
                    "pod": "N/A",
                    "container": "CIS Benchmark",
                    "issue": f"Error running kube-bench: {result.stderr}",
                    "severity": "HIGH"
                })

        except Exception as e:
            issues.append({
                "pod": "N/A",
                "container": "CIS Benchmark",
                "issue": f"Error during CIS benchmark analysis: {str(e)}",
                "severity": "INFO"
            })
            
        return issues

    def _map_severity(self, test_number: str) -> str:
        """Map CIS benchmark test numbers to severity levels."""
        # Map specific test sections to severity levels
        # Based on CIS Kubernetes Benchmark v1.6.1
        critical_sections = ["1.1", "1.2", "4.2"]  # Master node security configuration, etc.
        high_sections = ["2.", "3."]  # Worker node security, etc.
        medium_sections = ["4.1", "4.3", "4.4"]  # Worker node configuration, etc.
        
        for section in critical_sections:
            if test_number.startswith(section):
                return "CRITICAL"
                
        for section in high_sections:
            if test_number.startswith(section):
                return "HIGH"
                
        for section in medium_sections:
            if test_number.startswith(section):
                return "MEDIUM"
                
        return "LOW" 