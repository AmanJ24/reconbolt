"""ReconBolt CLI — Beautiful terminal interface with Rich.

Usage:
    reconbolt scan example.com
    reconbolt scan example.com --intensity aggressive --bruteforce
    reconbolt scan example.com --skip-ports --skip-osint -o ./results
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from reconbolt.engine.events import EventLevel, ScanEvent, ScanPhase

app = typer.Typer(
    name="reconbolt",
    help="⚡ ReconBolt — AI-Powered Cybersecurity Reconnaissance Platform",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def _make_banner() -> Panel:
    """Create the startup banner."""
    banner_text = Text.from_markup(
        "[bold cyan]"
        "  ____                      ____        _ _   \n"
        " |  _ \\ ___  ___ ___  _ __ | __ )  ___ | | |_ \n"
        " | |_) / _ \\/ __/ _ \\| '_ \\|  _ \\ / _ \\| | __|\n"
        " |  _ \\  __/ (_| (_) | | | | |_) | (_) | | |_ \n"
        " |_| \\_\\___|\\___\\___/|_| |_|____/ \\___/|_|\\__|\n"
        "[/bold cyan]\n"
        "[dim]AI-Powered Cybersecurity Reconnaissance Platform v1.0.0[/dim]"
    )
    return Panel(banner_text, border_style="cyan", padding=(1, 2))


def _event_to_rich(event: ScanEvent) -> Text:
    """Convert a ScanEvent to Rich formatted text."""
    color_map = {
        EventLevel.INFO: "blue",
        EventLevel.SUCCESS: "green",
        EventLevel.WARNING: "yellow",
        EventLevel.ERROR: "red",
        EventLevel.COMMAND: "dim",
    }
    prefix_map = {
        EventLevel.INFO: "[+]",
        EventLevel.SUCCESS: "[✓]",
        EventLevel.WARNING: "[!]",
        EventLevel.ERROR: "[✗]",
        EventLevel.COMMAND: " $ ",
    }
    color = color_map.get(event.level, "white")
    prefix = prefix_map.get(event.level, "[·]")
    return Text.from_markup(f"[{color}]{prefix}[/{color}] {event.message}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or IP address to scan"),
    intensity: str = typer.Option("normal", "--intensity", "-i", help="Scan intensity: low, normal, aggressive"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    bruteforce: bool = typer.Option(False, "--bruteforce", "-b", help="Enable DNS brute-force"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Custom wordlist for brute-force"),
    skip_subdomains: bool = typer.Option(False, "--skip-subdomains", help="Skip subdomain enumeration"),
    skip_ports: bool = typer.Option(False, "--skip-ports", help="Skip port scanning"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln", help="Skip vulnerability scanning"),
    skip_osint: bool = typer.Option(False, "--skip-osint", help="Skip OSINT gathering"),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI analysis"),
    json_only: bool = typer.Option(False, "--json", help="Output JSON only (no Rich formatting)"),
) -> None:
    """⚡ Run a full reconnaissance scan against a target."""
    asyncio.run(
        _run_scan(
            target=target,
            intensity=intensity,
            output_dir=output,
            bruteforce=bruteforce,
            wordlist=wordlist,
            skip_subdomains=skip_subdomains,
            skip_ports=skip_ports,
            skip_vuln=skip_vuln,
            skip_osint=skip_osint,
            skip_ai=skip_ai,
            json_only=json_only,
        )
    )


async def _run_scan(
    target: str,
    intensity: str,
    output_dir: str | None,
    bruteforce: bool,
    wordlist: str | None,
    skip_subdomains: bool,
    skip_ports: bool,
    skip_vuln: bool,
    skip_osint: bool,
    skip_ai: bool,
    json_only: bool,
) -> None:
    """Execute the scan with Rich progress display."""
    from reconbolt.engine.events import EventEmitter
    from reconbolt.engine.orchestrator import ScanOrchestrator
    from reconbolt.models.scan import ScanConfig
    from reconbolt.reporting.generator import ReportGenerator

    # Show banner
    if not json_only:
        console.print(_make_banner())
        console.print()

    # Build config
    config = ScanConfig(
        target=target,
        intensity=intensity,
        enable_subdomain_enum=not skip_subdomains,
        enable_port_scan=not skip_ports,
        enable_vuln_scan=not skip_vuln,
        enable_osint=not skip_osint,
        enable_takeover_check=not skip_subdomains,
        enable_ai_analysis=not skip_ai,
        enable_bruteforce=bruteforce,
        wordlist_path=wordlist,
    )

    # Setup event emitter with Rich progress
    emitter = EventEmitter()
    log_lines: list[Text] = []

    progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="cyan"),
        TextColumn("[dim]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )
    task_id = progress.add_task("Initializing scan...", total=100)

    def handle_event(event: ScanEvent) -> None:
        """Handle scan events for Rich display."""
        progress.update(task_id, description=event.message[:60], completed=event.progress)
        if event.level != EventLevel.DEBUG:
            log_lines.append(_event_to_rich(event))

    emitter.on_event(handle_event)

    # Run scan with progress display
    if not json_only:
        console.print(f"[bold]Target:[/bold] [cyan]{target}[/cyan]")
        console.print(f"[bold]Intensity:[/bold] {intensity}")
        console.print()

    with progress:
        orchestrator = ScanOrchestrator(config, emitter)
        result = await orchestrator.run()

    # Print event log
    if not json_only:
        console.print()
        log_panel = Panel(
            Text("\n").join(log_lines[-30:]) if log_lines else Text("No events"),
            title="[bold]Scan Log[/bold]",
            border_style="dim",
        )
        console.print(log_panel)

    # Print summary table
    if not json_only:
        console.print()
        _print_summary(result)

    # Generate reports
    out_path = Path(output_dir) if output_dir else None
    generator = ReportGenerator(result, out_path)
    report_paths = generator.generate_all()

    if json_only:
        import json
        print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        console.print()
        console.print("[bold green]📄 Reports generated:[/bold green]")
        for fmt, path in report_paths.items():
            console.print(f"  [dim]•[/dim] {fmt.upper()}: [link=file://{path}]{path}[/link]")
        console.print()


def _print_summary(result) -> None:
    """Print a Rich summary table of scan results."""
    s = result.summary
    risk_colors = {"info": "blue", "low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
    risk_color = risk_colors.get(s.risk_level, "white")

    # Summary stats table
    table = Table(title="Scan Summary", border_style="cyan", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Target", result.target)
    table.add_row("Duration", f"{result.duration_seconds}s")
    table.add_row("Subdomains", str(s.total_subdomains))
    table.add_row("Open Ports", str(s.total_open_ports))
    table.add_row("Vulnerabilities", str(s.total_vulnerabilities))
    table.add_row("Takeover Risks", str(s.total_takeovers))
    table.add_row("Risk Score", f"[{risk_color}]{s.risk_score}/10[/{risk_color}]")
    table.add_row("Risk Level", f"[{risk_color}]{s.risk_level.upper()}[/{risk_color}]")

    console.print(table)

    # Open ports table (if any)
    if result.ports:
        console.print()
        port_table = Table(title="Open Ports", border_style="dim")
        port_table.add_column("Host")
        port_table.add_column("Port")
        port_table.add_column("Service")
        port_table.add_column("Version")
        for p in result.ports[:20]:
            port_table.add_row(
                p.host,
                f"{p.port}/{p.protocol}",
                p.service_name,
                f"{p.product} {p.version}".strip() or "—",
            )
        console.print(port_table)

    # Vulnerabilities (if any)
    if result.vulnerabilities:
        console.print()
        vuln_table = Table(title="Vulnerabilities", border_style="red")
        vuln_table.add_column("Host")
        vuln_table.add_column("Type")
        vuln_table.add_column("Severity")
        vuln_table.add_column("Title")
        for v in result.vulnerabilities:
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(v.severity, "")
            vuln_table.add_row(v.host, v.vuln_type, f"[{sev_style}]{v.severity.upper()}[/{sev_style}]", v.title)
        console.print(vuln_table)


@app.command()
def version() -> None:
    """Show ReconBolt version."""
    from reconbolt import __version__
    console.print(f"[bold cyan]ReconBolt[/bold cyan] v{__version__}")


if __name__ == "__main__":
    app()
