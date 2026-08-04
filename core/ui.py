"""
UI module for WebCTF Suite using Rich for high-impact terminal visuals.
Safe across Windows CP1256/UTF-8 terminal encodings.
"""

import sys

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

console = Console(force_terminal=True, legacy_windows=False)

BANNER = r"""
 [bold cyan]██╗    ██╗███████╗██████╗      ██████╗████████╗███████╗[/bold cyan]
 [bold cyan]██║    ██║██╔════╝██╔══██╗    ██╔════╝╚══██╔══╝██╔════╝[/bold cyan]
 [bold blue]██║ █╗ ██║█████╗  ██████╔╝    ██║        ██║   █████╗  [/bold blue]
 [bold blue]██║███╗██║██╔══╝  ██╔══██╗    ██║        ██║   ██╔══╝  [/bold blue]
 [bold magenta]╚███╔███╔╝███████╗██████╔╝    ╚██████╗   ██║   ██║     [/bold magenta]
  [bold magenta]╚══╝╚══╝ ╚══════╝╚═════╝      ╚═════╝   ╚═╝   ╚═╝     [/bold magenta]
 [bold yellow]───► Ultimate Web CTF Toolkit & Exploit Assistant ◄───[/bold yellow]
"""

def print_banner():
    """Display the main WebCTF banner."""
    console.print(BANNER)
    console.print("[dim]Type [bold green]'help'[/bold green] or [bold green]'?'[/bold green] to list commands. Type [bold red]'exit'[/bold red] to quit.[/dim]\n")

def print_header(title: str, subtitle: str = ""):
    """Display a styled section header."""
    text = Text()
    text.append(f" {title.upper()} ", style="bold white on blue")
    if subtitle:
        text.append(f"  {subtitle}", style="dim italic")
    console.print(Panel(text, border_style="blue", expand=False))

def print_success(msg: str):
    """Print success message."""
    console.print(f"[bold green][+][/bold green] [green]{msg}[/green]")

def print_error(msg: str):
    """Print error message."""
    console.print(f"[bold red][-][/bold red] [red]{msg}[/red]")

def print_info(msg: str):
    """Print info message."""
    console.print(f"[bold cyan][*][/bold cyan] [cyan]{msg}[/cyan]")

def print_warning(msg: str):
    """Print warning message."""
    console.print(f"[bold yellow][!][/bold yellow] [yellow]{msg}[/yellow]")

def print_flag(flag: str):
    """Highlight a captured CTF flag."""
    console.print(Panel(
        f"[bold yellow blink][FLAG FOUND]:[/bold yellow blink]\n[bold green]{flag}[/bold green]",
        title="[bold red]CTF VICTORY[/bold red]",
        border_style="yellow",
        expand=False
    ))

def print_table(headers: list, rows: list, title: str = ""):
    """Print a clean styled table."""
    table = Table(title=title, border_style="cyan", header_style="bold magenta")
    for header in headers:
        table.add_column(header)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    console.print(table)

def print_payload(name: str, payload: str, desc: str = "", lang: str = "text"):
    """Display a single exploit payload with copy-friendly formatting."""
    content = f"[bold cyan]Description:[/bold cyan] {desc}\n\n" if desc else ""
    content += f"[bold yellow]Payload:[/bold yellow]\n{payload}"
    console.print(Panel(
        content,
        title=f"[bold green]{name}[/bold green]",
        border_style="green",
        expand=False
    ))

def print_code(code: str, language: str = "python", title: str = ""):
    """Print syntax highlighted code snippet."""
    syntax = Syntax(code, language, theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=title or f"Code ({language})", border_style="bright_blue"))
