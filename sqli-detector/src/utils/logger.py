from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict

class Logger:
    """
    Handles terminal output formatting using the 'rich' library.
    Provides clear, color-coded feedback during the scan and a summarized table at the end.
    """

    def __init__(self):
        self.console = Console()
        self.findings: List[Dict] = []

    def info(self, message: str):
        """Print general information."""
        self.console.print(f"[cyan][*][/cyan] {message}")

    def success(self, message: str):
        """Print a success message."""
        self.console.print(f"[green][+][/green] {message}")

    def warning(self, message: str):
        """Print a warning message."""
        self.console.print(f"[yellow][!][/yellow] {message}")

    def error(self, message: str):
        """Print an error message."""
        self.console.print(f"[red][-][/red] {message}")

    def log_finding(self, parameter: str, payload: str, dbms: str, url: str):
        """
        Records a detected vulnerability and prints an immediate alert.
        """
        finding = {
            "parameter": parameter,
            "payload": payload,
            "dbms": dbms,
            "url": url
        }
        self.findings.append(finding)
        self.console.print(f"\n[bold red][!] VULNERABILITY FOUND[/bold red]")
        self.console.print(f"[red] > Parameter:[/red] {parameter}")
        self.console.print(f"[red] > Payload:[/red] {payload}")
        self.console.print(f"[red] > DB Type:[/red] {dbms}\n")

    def print_summary(self):
        """
        Prints a final summary table of all findings.
        """
        if not self.findings:
            self.console.print("\n[bold green]Scan Complete: No vulnerabilities found.[/bold green]")
            return

        self.console.print("\n[bold red]Scan Complete: Vulnerabilities Detected![/bold red]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Parameter", style="cyan", width=15)
        table.add_column("DBMS", style="yellow", width=15)
        table.add_column("Payload", style="red")

        # Use a set to track unique parameter/dbms combos to reduce noise in the summary table
        seen = set()
        for f in self.findings:
            unique_key = f"{f['parameter']}_{f['dbms']}"
            if unique_key not in seen:
                table.add_row(f["parameter"], f["dbms"], f["payload"])
                seen.add(unique_key)

        self.console.print(table)
