from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn, SpinnerColumn

class ConsoleFormatter:
    """Handles rich terminal layout formatting and real-time color-coded feedback."""

    def __init__(self):
        self.console = Console()

    def format_status(self, status: int, error: str) -> Text:
        """Returns colored status codes or error messages."""
        if error:
            return Text(f"ERR: {error}", style="bold red")
        
        status_str = str(status)
        if status_str.startswith("2"):
            return Text(status_str, style="bold green")
        elif status_str.startswith("3"):
            return Text(status_str, style="bold yellow")
        elif status_str.startswith("4"):
            return Text(status_str, style="bold magenta")
        elif status_str.startswith("5"):
            return Text(status_str, style="bold red")
        return Text(status_str, style="white")

    def print_result(self, result: Dict[str, Any]):
        """Prints a single line summary of a target result to stdout in real-time."""
        url = result["url"]
        status = result["status_code"]
        error = result["error"]
        time_ms = result["response_time_ms"]
        server = result.get("server", "Unknown")
        takeover = result.get("takeover")

        status_text = self.format_status(status, error)
        time_str = f"{time_ms}ms" if time_ms is not None else "-"
        
        # Format redirect visualizer if history exists
        target_display = url
        if result["redirect_chain"]:
            arrow = " ➜ "
            # Create a simple representation of chain: http://abc.com -> https://abc.com
            target_display = f"{url}{arrow}{result['resolved_url']}"

        # If subdomain takeover detected, print a high-priority alert!
        if takeover and takeover.get("detected"):
            service = takeover["service"]
            alert = Text(
                f"[!] TAKEOVER DETECTED: {url} -> {service} (Matched: '{takeover['matched_fingerprint']}')",
                style="bold blink red on black"
            )
            self.console.print(alert)

        # Standard log output line
        log_line = Text()
        log_line.append("[", style="grey50")
        log_line.append(status_text)
        log_line.append("] ", style="grey50")
        log_line.append(f"{target_display:<60} ", style="sky_blue3")
        log_line.append(f"({time_str})", style="grey37")
        
        if server and server != "Unknown":
            log_line.append(f" [Server: {server}]", style="dark_orange3")
            
        self.console.print(log_line)

    def print_summary(self, results: List[Dict[str, Any]], duration_seconds: float):
        """Prints a beautiful summary statistics table at the end of the run."""
        total = len(results)
        success_count = sum(1 for r in results if r["status_code"] is not None)
        fail_count = total - success_count
        
        takeovers = [r for r in results if r.get("takeover") and r["takeover"].get("detected")]
        
        # Calculate response time stats for successful connections
        resp_times = [r["response_time_ms"] for r in results if r["response_time_ms"] is not None]
        avg_resp = round(sum(resp_times) / len(resp_times), 2) if resp_times else 0

        self.console.print("\n" + "=" * 80)
        self.console.print("🚀 PROBING COMPLETE SUMMARY", style="bold cyan")
        self.console.print("=" * 80)

        # Print general stats
        self.console.print(f"[*] Total Endpoints Scanned  : [bold]{total}[/]")
        self.console.print(f"[*] Successful HTTP Responses: [bold green]{success_count}[/]")
        self.console.print(f"[*] Connection Failures     : [bold red]{fail_count}[/]")
        self.console.print(f"[*] Average Response Time   : [bold yellow]{avg_resp} ms[/]")
        self.console.print(f"[*] Elapsed Execution Time  : [bold]{round(duration_seconds, 2)} s[/]")
        
        if takeovers:
            self.console.print(
                f"[!] SUBDOMAIN TAKEOVERS FOUND: [bold blink red]{len(takeovers)}[/]", 
                style="bold red"
            )
        else:
            self.console.print("[*] Subdomain Takeovers      : [green]0 detected[/]")

        # Print Top resolved endpoints
        table = Table(title="Top Probed Endpoints Details", title_style="bold underline magenta", show_lines=True)
        table.add_column("Target URL", style="cyan", no_wrap=True)
        table.add_column("Resolved URL", style="blue")
        table.add_column("Status", justify="center")
        table.add_column("Resp Time", justify="right", style="yellow")
        table.add_column("Technologies / Server", style="green")

        # Add top 15 results or all if small
        display_results = results[:15]
        for r in display_results:
            techs = ", ".join(r.get("technologies", [])) or r.get("server", "Unknown")
            status_cell = self.format_status(r["status_code"], r["error"])
            time_cell = f"{r['response_time_ms']} ms" if r["response_time_ms"] else "-"
            table.add_row(
                r["url"],
                r["resolved_url"] if r["redirect_chain"] else "-",
                status_cell,
                time_cell,
                techs
            )

        self.console.print(table)
        
        if len(results) > 15:
            self.console.print(f"... and {len(results) - 15} more records output to file.", style="italic grey50")

    @staticmethod
    def get_progress_bar() -> Progress:
        """Returns a formatted rich progress bar custom configured for async tasks."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="green", finished_style="bold blue"),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            transient=True
        )
