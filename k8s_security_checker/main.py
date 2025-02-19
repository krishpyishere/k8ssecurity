#!/usr/bin/env python3

import sys
import argparse
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from .checks.pod_security import PodSecurityChecker
from .checks.cis_benchmark import CISBenchmarkChecker
from .checks.admission_controller import AdmissionControllerChecker
# Import other checkers as they are created

class SecurityScanner:
    """Main security scanner that coordinates all checks."""
    
    def __init__(self):
        self.console = Console()
        self.checkers = [
            PodSecurityChecker(),
            CISBenchmarkChecker(),
            AdmissionControllerChecker(),
            # Add other checkers as they are created
        ]

    def run_all_checks(self, namespace: str = "default") -> List[Dict]:
        """Run all security checks."""
        all_issues = []
        
        with Progress() as progress:
            total_checks = len(self.checkers)
            task = progress.add_task(
                "[cyan]Running security checks...",
                total=total_checks
            )
            
            for checker in self.checkers:
                checker_name = checker.__class__.__name__
                progress.update(
                    task,
                    advance=1,
                    description=f"Running {checker_name}..."
                )
                
                try:
                    issues = checker.run(namespace)
                    all_issues.extend(issues)
                except Exception as e:
                    self.console.print(f"[red]Error in {checker_name}: {e}[/red]")
        
        return all_issues

    def display_results(self, issues: List[Dict]):
        """Display the results in a formatted table."""
        if not issues:
            self.console.print("\n[green]No security issues found![/green]")
            return

        table = Table(
            title="Kubernetes Security Issues",
            style="white",
            header_style="bold bright_white",
            border_style="white"
        )
        table.add_column("Pod/Resource", style="bright_white")
        table.add_column("Container/Component", style="orange1")
        table.add_column("Issue", style="bright_white")
        table.add_column("Severity", style="bright_white")

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

        # Add severity-based styling
        for issue in sorted_issues:
            severity = issue["severity"]
            severity_style = {
                "CRITICAL": "[bold bright_red]" + severity + "[/]",
                "HIGH": "[bright_red]" + severity + "[/]",
                "MEDIUM": "[bright_yellow]" + severity + "[/]",
                "LOW": "[bright_green]" + severity + "[/]",
                "INFO": "[bright_white]" + severity + "[/]"
            }.get(severity, severity)
            
            table.add_row(
                issue["pod"],
                issue["container"],
                issue["issue"],
                severity_style
            )

        self.console.print(table)
        
        # Print summary with enhanced visibility
        severity_counts = {}
        for issue in issues:
            severity = issue["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        self.console.print("\n[bold bright_white]Summary:[/]")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            style = {
                "CRITICAL": "bold bright_red",
                "HIGH": "bright_red",
                "MEDIUM": "bright_yellow",
                "LOW": "bright_green",
                "INFO": "bright_white"
            }.get(severity, "bright_white")
            self.console.print(
                f"[{style}]{severity}: {count} issue(s)[/]"
            )

def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes Security Checker"
    )
    parser.add_argument(
        "-n", "--namespace",
        default="default",
        help="Kubernetes namespace to scan (default: default)"
    )
    args = parser.parse_args()

    scanner = SecurityScanner()
    
    try:
        issues = scanner.run_all_checks(args.namespace)
        scanner.display_results(issues)
        
        # Exit with status code based on severity of findings
        if any(i["severity"] == "CRITICAL" for i in issues):
            sys.exit(2)
        elif any(i["severity"] == "HIGH" for i in issues):
            sys.exit(1)
        sys.exit(0)
        
    except Exception as e:
        console = Console()
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 