import asyncio
import json
import sys
import os
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.port_scanner import run_scan
from models.scan_result import ScanResult, Severity


# --- Setup ---

# Typer app - this is the CLI application
app = typer.Typer(
    name="lynxmap",
    help="LynxMap — Network vulnerability scanner",
    add_completion=False  # disable shell completion for simplicity
)

# Rich console - handles all our pretty terminal output
console = Console()


# --- Severity colours ---

SEVERITY_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "NONE":     "dim white",
}


# --- Helper functions ---

def _severity_label(severity: str) -> Text:
    """Return a coloured Rich Text object for a severity string."""
    colour = SEVERITY_COLOURS.get(severity.upper(), "white")
    return Text(severity.upper(), style=colour)


def _worst_severity(cves: list) -> str:
    """
    Given a list of CVE objects, return the worst severity string.
    Used to colour the whole row by its most serious vulnerability.
    """
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    severities = [c.severity.value if hasattr(c.severity, 'value')
                  else str(c.severity) for c in cves]

    for level in order:
        if level in severities:
            return level
    return "NONE"


def _print_results_table(result: ScanResult, show_filtered: bool) -> None:
    """
    Print scan results as a formatted Rich table to the terminal.
    This is the human-readable output mode.
    """

    # --- Header panel ---
    header_text = (
        f"[bold]Target:[/bold] {result.target}\n"
        f"[bold]Scan ID:[/bold] {result.scan_id}\n"
        f"[bold]Ports scanned:[/bold] {result.ports_scanned}\n"
        f"[bold]Open ports:[/bold] {result.open_ports}\n"
        f"[bold]Duration:[/bold] "
        f"{(result.end_time - result.start_time).seconds}s"
    )

    console.print(Panel(
        header_text,
        title="[bold cyan]LynxMap Scan Results[/bold cyan]",
        border_style="cyan"
    ))

    # --- Filter results ---
    ports_to_show = [
        r for r in result.results
        if r.state.value == "open" or (show_filtered and r.state.value == "filtered")
    ]

    if not ports_to_show:
        console.print("\n[yellow]No open ports found.[/yellow]")
        return

    # --- Build ports table ---
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True
    )

    table.add_column("Port", style="bold white", width=8)
    table.add_column("State", width=10)
    table.add_column("Service", width=16)
    table.add_column("Version", width=16)
    table.add_column("CVEs", width=6)
    table.add_column("Top Severity", width=14)

    for port_result in sorted(ports_to_show, key=lambda p: p.port):
        state_colour = "green" if port_result.state.value == "open" else "yellow"
        state_text = Text(port_result.state.value.upper(), style=state_colour)

        service_name = "-"
        version = "-"
        cve_count = "-"
        severity_text = Text("-", style="dim")

        if port_result.service:
            service_name = port_result.service.name or "-"
            version = port_result.service.version or "-"

            cves = port_result.service.cves
            if cves:
                cve_count = str(len(cves))
                worst = _worst_severity(cves)
                severity_text = _severity_label(worst)

        table.add_row(
            f"{port_result.port}/tcp",
            state_text,
            service_name,
            version,
            cve_count,
            severity_text
        )

    console.print(table)

    # --- CVE detail section ---
    # For each port with CVEs, print a breakdown
    ports_with_cves = [
        p for p in ports_to_show
        if p.service and p.service.cves
    ]

    if ports_with_cves:
        console.print(
            "\n[bold cyan]CVE Details[/bold cyan]"
        )

        for port_result in ports_with_cves:
            cves = port_result.service.cves

            console.print(
                f"\n[bold]Port {port_result.port} — "
                f"{port_result.service.name} "
                f"{port_result.service.version or ''}[/bold]"
            )

            cve_table = Table(
                box=box.SIMPLE,
                header_style="bold white",
                show_lines=False
            )

            cve_table.add_column("CVE ID", width=18)
            cve_table.add_column("Severity", width=10)
            cve_table.add_column("Score", width=7)
            cve_table.add_column("Description", width=70)

            # Show top 5 CVEs
            for cve in cves[:5]:
                score_str = str(cve.cvss_score) if cve.cvss_score else "N/A"
                severity_val = (cve.severity.value
                               if hasattr(cve.severity, 'value')
                               else str(cve.severity))

                cve_table.add_row(
                    cve.cve_id,
                    _severity_label(severity_val),
                    score_str,
                    cve.description[:120] + "..."
                    if len(cve.description) > 120
                    else cve.description
                )

            console.print(cve_table)

            if len(cves) > 5:
                console.print(
                    f"  [dim]...and {len(cves) - 5} more CVEs. "
                    f"Use --output json for full results.[/dim]"
                )


# --- Commands ---

@app.command()
def scan(
    target: str = typer.Argument(
        ...,  # ... means required
        help="IP address or hostname to scan"
    ),
    ports: str = typer.Option(
        "1-1024",
        "--ports", "-p",
        help="Port range to scan e.g. 1-1024 or 80-443"
    ),
    timeout: float = typer.Option(
        1.0,
        "--timeout", "-t",
        help="Seconds to wait per port before marking filtered"
    ),
    output: str = typer.Option(
        "table",
        "--output", "-o",
        help="Output format: table or json"
    ),
    show_filtered: bool = typer.Option(
        False,
        "--show-filtered",
        help="Include filtered ports in output"
    )
):
    """
    Scan a target host for open ports and known vulnerabilities.

    Examples:\n
        python cli.py scan 192.168.1.1\n
        python cli.py scan scanme.nmap.org --ports 1-500\n
        python cli.py scan 10.0.0.1 --output json\n
        python cli.py scan 10.0.0.1 --ports 1-65535 --show-filtered
    """

    # --- Parse port range ---
    try:
        parts = ports.split("-")
        if len(parts) != 2:
            raise ValueError()
        port_start = int(parts[0])
        port_end = int(parts[1])

        if port_start < 1 or port_end > 65535 or port_start > port_end:
            raise ValueError()

    except ValueError:
        console.print(
            "[red]Invalid port range. Use format: 1-1024[/red]"
        )
        raise typer.Exit(code=1)

    # --- Disclaimer ---
    # Always show this
    console.print(Panel(
        "[yellow]Only scan hosts you own or have explicit permission to scan.\n"
        "Unauthorised scanning may be illegal in your jurisdiction.[/yellow]",
        title="[bold yellow]Legal Notice[/bold yellow]",
        border_style="yellow"
    ))

    console.print(
        f"\n[cyan]Scanning[/cyan] [bold]{target}[/bold] "
        f"[cyan]ports[/cyan] [bold]{port_start}-{port_end}[/bold]\n"
    )

    # --- Run scan ---
    # asyncio.run() is the synchronous entry point into async code
    # The CLI is sync (Typer runs normally), so we bridge into async here
    try:
        result = asyncio.run(run_scan(
            target=target,
            port_start=port_start,
            port_end=port_end,
            timeout=timeout
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(code=0)
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        raise typer.Exit(code=1)

    # --- Output ---
    if output == "json":
        # Raw JSON - useful for piping into other tools
        print(result.model_dump_json(indent=2, exclude_none=True))

    else:
        # Pretty table output
        _print_results_table(result, show_filtered)

        # Always print the dashboard URL hint at the end
        console.print(
            f"\n[dim]View in dashboard: "
            f"http://localhost:3000 "
            f"(start the frontend first)[/dim]\n"
        )

@app.command()
def version():
    """Show LynxMap version information."""
    console.print(Panel(
        "[bold cyan]LynxMap[/bold cyan] v0.1.0\n"
        "Network vulnerability scanner\n"
        "[dim]FastAPI + Python asyncio + NVD API[/dim]",
        border_style="cyan"
    ))


# --- Entry point ---

if __name__ == "__main__":
    app()
