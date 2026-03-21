"""Rich terminal reporter for wifi-passview."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import ScanResult

console = Console(highlight=False)


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]wifi-passview[/bold cyan] "
        "[dim]— saved WiFi credential dumper[/dim]",
        border_style="cyan",
    ))


def print_results(
    result: ScanResult, show_passwords: bool = True, redact: bool = False
):
    if not result.profiles:
        console.print("\n[yellow]No WiFi profiles found.[/yellow]")
        if result.errors:
            _print_errors(result)
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="bold dim",
        show_lines=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column("SSID", style="bold white", min_width=20)
    table.add_column("PASSWORD", min_width=20)
    table.add_column("AUTH", style="dim", width=14)
    table.add_column("BAND", style="dim", width=8)
    table.add_column("AUTO", style="dim", width=6)

    for profile in sorted(result.profiles, key=lambda p: p.ssid.lower()):
        p = profile.redact() if redact else profile

        if not show_passwords:
            pw_text = Text("hidden", style="dim")
        elif p.password:
            pw_text = Text(p.password, style="green")
        else:
            pw_text = Text("(none / open)", style="dim")

        auth = p.auth_type or "—"
        band = p.band or "—"
        auto = (
            ("yes" if p.auto_connect else "no")
            if p.auto_connect is not None else "—"
        )

        table.add_row(p.ssid, pw_text, auth, band, auto)

    console.print()
    console.print(table)

    _print_errors(result)
    _print_summary(result)


def _print_errors(result: ScanResult):
    if result.errors:
        console.print()
        for err in result.errors:
            console.print(f"  [yellow]⚠ {err}[/yellow]")


def _print_summary(result: ScanResult):
    table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column(justify="right")

    table.add_row("Platform", result.platform)
    table.add_row("Total profiles", str(result.total))
    table.add_row(
        "[green]With password[/green]",
        f"[green]{result.with_password}[/green]",
    )
    table.add_row("[dim]Without password[/dim]", str(result.without_password))

    console.print(Panel(table, title="[bold]Summary[/bold]", border_style="dim"))
