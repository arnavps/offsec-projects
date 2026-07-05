from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

class ReportFormatter:
    """
    Formats the output for the terminal using Rich.
    
    Security Relevance:
    In offensive security tooling, clear, actionable output is critical. 
    A messy output stream can cause an analyst to miss key data points during an engagement.
    """
    def __init__(self):
        self.console = Console()

    def _get_color_for_category(self, category: str) -> str:
        colors = {
            "Very Weak": "bold red",
            "Weak": "red",
            "Reasonable": "yellow",
            "Strong": "green",
            "Very Strong": "bold green"
        }
        return colors.get(category, "white")

    def print_report(self, length: int, pool_size: int, entropy: float, category: str):
        color = self._get_color_for_category(category)
        
        table = Table(title="Password Analysis Report", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        
        table.add_row("Length (L)", str(length))
        table.add_row("Pool Size (R)", str(pool_size))
        table.add_row("Entropy (bits)", f"{entropy:.2f}")
        
        cat_text = Text(category, style=color)
        table.add_row("Strength Classification", cat_text)
        
        self.console.print(Panel(table, title="[bold blue]Results", expand=False))
