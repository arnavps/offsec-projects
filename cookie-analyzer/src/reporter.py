"""
Cookie Sentinel reporter module.
Formats and outputs analysis results in multiple formats: Console (rich), JSON, and Markdown.
"""

import json
import datetime
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

from .analyzer import Finding

# Severity color scheme for console reporting
SEVERITY_COLORS = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "blue",
    "Info": "cyan"
}

def mask_cookie_value(value: str) -> str:
    """Masks sensitive cookie values to prevent credential leakage in reports."""
    if not value:
        return ""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}...{value[-3:]} (len={len(value)})"

class Reporter:
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_cli_summary(self, cookies: List[Dict[str, Any]], findings_by_cookie: Dict[str, List[Finding]]):
        """Prints a summary dashboard of cookies and issues to the console."""
        total_cookies = len(cookies)
        total_findings = sum(len(f) for f in findings_by_cookie.values())
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for findings in findings_by_cookie.values():
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        self.console.print("\n[bold]Cookie Sentinel Audit Summary[/bold]")
        self.console.print("=" * 40)
        self.console.print(f"Total Cookies Scanned: {total_cookies}")
        self.console.print(f"Total Security Issues: {total_findings}")
        
        # Colorized badges for severities
        badges = []
        for sev, count in severity_counts.items():
            color = SEVERITY_COLORS.get(sev, "white")
            badges.append(f"[{color}]{sev}: {count}[/{color}]")
        self.console.print(" | ".join(badges))
        self.console.print()

    def print_cli_cookie_table(self, cookies: List[Dict[str, Any]]):
        """Prints a table of all analyzed cookies and their configured security flags."""
        table = Table(title="Scanned Cookies Overview", show_header=True, header_style="bold magenta")
        table.add_column("Cookie Name", style="bold cyan")
        table.add_column("Value (Masked)")
        table.add_column("HttpOnly", justify="center")
        table.add_column("Secure", justify="center")
        table.add_column("SameSite", justify="center")
        table.add_column("Domain")
        table.add_column("Path")
        
        for cookie in cookies:
            attrs = cookie.get("attributes", {})
            httponly = "[green]Yes[/green]" if attrs.get("httponly") else "[red]No[/red]"
            secure = "[green]Yes[/green]" if attrs.get("secure") else "[red]No[/red]"
            
            samesite = attrs.get("samesite")
            if samesite == "None":
                samesite_str = "[red]None[/red]"
            elif samesite in ["Lax", "Strict"]:
                samesite_str = f"[green]{samesite}[/green]"
            else:
                samesite_str = "[yellow]Missing[/yellow]"
                
            domain = attrs.get("domain") or "[dim]Default[/dim]"
            path = attrs.get("path") or "[dim]Default[/dim]"
            
            table.add_row(
                cookie.get("name", ""),
                mask_cookie_value(cookie.get("value", "")),
                httponly,
                secure,
                samesite_str,
                domain,
                path
            )
            
        self.console.print(table)
        self.console.print()

    def print_cli_findings(self, findings_by_cookie: Dict[str, List[Finding]]):
        """Prints details of each security issue with actionable remediation advice."""
        if not findings_by_cookie:
            self.console.print("[bold green][+] No security issues identified on the analyzed cookies.[/bold green]\n")
            return

        self.console.print("[bold red]Detailed Security Findings[/bold red]")
        self.console.print("=" * 40)

        for cookie_name, findings in findings_by_cookie.items():
            self.console.print(f"\n[bold yellow]Cookie: {cookie_name}[/bold yellow]")
            for f in findings:
                color = SEVERITY_COLORS.get(f.severity, "white")
                
                # Panel for each finding to look premium
                title = f"[{color}]{f.severity}[/{color}] - Rule: {f.rule_id}"
                
                content = Text()
                content.append("Description: ", style="bold")
                content.append(f"{f.description}\n\n")
                content.append("Remediation: ", style="bold green")
                content.append(f"{f.remediation}")
                
                if f.details:
                    content.append(f"\n\nDetails: {f.details}")

                self.console.print(Panel(content, title=title, border_style=color, expand=False))

    def generate_json_report(self, cookies: List[Dict[str, Any]], findings_by_cookie: Dict[str, List[Finding]], filepath: str):
        """Generates a structured JSON report for defensive pipelines."""
        serialized_findings = {}
        for c_name, findings in findings_by_cookie.items():
            serialized_findings[c_name] = [f.to_dict() for f in findings]
            
        # Clean cookie structure for report, masking values
        clean_cookies = []
        for c in cookies:
            clean_cookies.append({
                "name": c.get("name"),
                "value": mask_cookie_value(c.get("value", "")),
                "attributes": c.get("attributes"),
                "raw_header": c.get("raw_header"),
                "url": c.get("url")
            })

        report_data = {
            "meta": {
                "tool": "Cookie Sentinel",
                "timestamp": datetime.datetime.now().isoformat(),
                "total_cookies": len(cookies),
                "total_issues": sum(len(f) for f in findings_by_cookie.values())
            },
            "cookies": clean_cookies,
            "findings": serialized_findings
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        self.console.print(f"[green][+] JSON report saved to {filepath}[/green]")

    def generate_markdown_report(self, cookies: List[Dict[str, Any]], findings_by_cookie: Dict[str, List[Finding]], filepath: str):
        """Generates a formal Markdown report suitable for sharing with developers or clients."""
        total_cookies = len(cookies)
        total_findings = sum(len(f) for f in findings_by_cookie.values())
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for findings in findings_by_cookie.values():
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        md = []
        md.append("# Cookie Sentinel - Security Audit Report")
        md.append(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append("")
        md.append("## Executive Summary")
        md.append(f"- **Total Cookies Audited:** {total_cookies}")
        md.append(f"- **Total Vulnerabilities / Misconfigurations:** {total_findings}")
        md.append("")
        md.append("### Severity Breakdown")
        for sev, count in severity_counts.items():
            md.append(f"- **{sev}:** {count}")
        md.append("")
        
        md.append("## Audited Cookies Table")
        md.append("| Cookie Name | Value (Masked) | HttpOnly | Secure | SameSite | Domain | Path |")
        md.append("| --- | --- | --- | --- | --- | --- | --- |")
        for c in cookies:
            attrs = c.get("attributes", {})
            h_on = "✅ Yes" if attrs.get("httponly") else "❌ No"
            s_on = "✅ Yes" if attrs.get("secure") else "❌ No"
            ss = attrs.get("samesite") or "⚠️ Missing"
            dom = attrs.get("domain") or "*Default*"
            path = attrs.get("path") or "*Default*"
            md.append(f"| {c.get('name')} | `{mask_cookie_value(c.get('value', ''))}` | {h_on} | {s_on} | {ss} | {dom} | {path} |")
        md.append("")
        
        md.append("## Detailed Security Findings")
        if not findings_by_cookie:
            md.append("No security issues were identified.")
        else:
            for cookie_name, findings in findings_by_cookie.items():
                md.append(f"### Cookie: `{cookie_name}`")
                for f in findings:
                    md.append(f"#### [{f.severity}] {f.rule_id}")
                    md.append(f"- **Description:** {f.description}")
                    md.append(f"- **Remediation:** {f.remediation}")
                    if f.details:
                        md.append(f"- **Details:** {f.details}")
                    md.append("")
                    
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(md))
        self.console.print(f"[green][+] Markdown report saved to {filepath}[/green]")
