"""wifi-passview CLI."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from .platforms import get_profiles
from .reporters import csv_report, json_report
from .reporters import terminal as term_reporter

console = Console()


@click.group()
@click.version_option(version="1.1.0", prog_name="wifi-passview")
def main():
    """
    \b
    wifi-passview — saved WiFi credential dumper
    Works on Linux, Windows, and macOS.

    \b
    Examples:
      wifi-passview dump
      wifi-passview dump --format json
      wifi-passview dump --format csv --output networks.csv
      wifi-passview dump --redact
      wifi-passview dump --no-password
      wifi-passview search "HomeNetwork"
    """
    pass


@main.command()
@click.option("--format", "fmt", default="terminal",
              type=click.Choice(["terminal", "json", "csv"]),
              help="Output format.")
@click.option("--output", "-o", type=click.Path(path_type=Path),
              default=None, help="Write output to file.")
@click.option("--redact", is_flag=True, default=False,
              help="Partially mask passwords in output.")
@click.option("--no-password", "no_password", is_flag=True, default=False,
              help="Hide passwords entirely.")
@click.option("--ssid", default=None, metavar="NAME",
              help="Filter results to a specific SSID (partial match).")
def dump(fmt, output, redact, no_password, ssid):
    """Dump all saved WiFi profiles and passwords."""

    if fmt == "terminal":
        term_reporter.print_banner()

    with console.status("[dim]Reading WiFi profiles...[/dim]"):
        result = get_profiles()

    # Apply SSID filter
    if ssid:
        result.profiles = [
            p for p in result.profiles
            if ssid.lower() in p.ssid.lower()
        ]

    if fmt == "terminal":
        term_reporter.print_results(
            result, show_passwords=not no_password, redact=redact
        )

    elif fmt == "json":
        if output:
            json_report.write(result, output, redact=redact)
            console.print(f"[green]✓ JSON written to {output}[/green]")
        else:
            json_report.print_json(result, redact=redact)

    elif fmt == "csv":
        if not output:
            output = Path("wifi_profiles.csv")
        csv_report.write(result, output, redact=redact)
        console.print(f"[green]✓ CSV written to {output}[/green]")


@main.command()
@click.argument("query")
def search(query):
    """Search saved profiles by SSID name."""
    term_reporter.print_banner()

    with console.status("[dim]Searching WiFi profiles...[/dim]"):
        result = get_profiles()

    result.profiles = [
        p for p in result.profiles
        if query.lower() in p.ssid.lower()
    ]

    if not result.profiles:
        console.print(f"[yellow]No profiles matching '{query}'[/yellow]")
        return

    console.print(
        f"\n[dim]Found {len(result.profiles)} match(es) "
        f"for '[cyan]{query}[/cyan]':[/dim]"
    )
    term_reporter.print_results(result)
