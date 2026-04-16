"""
Rich-powered console reporter.

Produces beautiful, color-coded terminal output with severity
badges, file-grouped findings, and a summary table.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from keychase.scanner.base import ScanResult

# Severity → color mapping
SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold white on red",
    "high": "bold white on dark_orange",
    "medium": "bold black on yellow",
    "low": "bold white on blue",
}

SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


def render_console_report(result: ScanResult, console: Console | None = None) -> None:
    """
    Render a scan result to the terminal using Rich.
    """
    if console is None:
        console = Console()

    # ── Header ────────────────────────────────────────────────────
    console.print()
    header = Text()
    header.append("🔑 Keychase ", style="bold cyan")
    header.append("Scan Report", style="bold white")
    console.print(Panel(header, border_style="cyan", padding=(0, 2)))

    # ── Scan metadata ─────────────────────────────────────────────
    meta_table = Table(show_header=False, box=None, padding=(0, 2))
    meta_table.add_column("Key", style="dim")
    meta_table.add_column("Value")
    meta_table.add_row("Target", result.target or "N/A")
    meta_table.add_row("Scan Type", result.scan_type or "N/A")
    meta_table.add_row("Files Scanned", str(result.files_scanned))
    meta_table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    meta_table.add_row("Findings", str(result.finding_count))
    console.print(meta_table)
    console.print()

    # ── No findings ───────────────────────────────────────────────
    if not result.has_findings:
        console.print(
            Panel(
                "✅ [bold green]No secrets detected![/bold green]\n"
                "Your code looks clean.",
                border_style="green",
                padding=(1, 2),
            )
        )
        _render_errors(result, console)
        return

    # ── Findings by file ──────────────────────────────────────────
    by_file = result.findings_by_file()
    for file_path, findings in sorted(by_file.items()):
        console.print(f"\n📄 [bold]{file_path}[/bold]")
        for finding in sorted(findings, key=lambda f: f.line_number):
            sev = finding.severity
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            style = SEVERITY_STYLES.get(sev, "")

            # Location line
            loc = f"  Line {finding.line_number}" if finding.line_number else "  (diff)"
            if finding.commit_sha:
                loc += f"  [dim]commit {finding.commit_sha[:8]}[/dim]"
                if finding.commit_author:
                    loc += f" [dim]by {finding.commit_author}[/dim]"

            severity_badge = Text(f" {sev.upper()} ", style=style)

            console.print(f"  {emoji} ", end="")
            console.print(severity_badge, end=" ")
            console.print(f"[bold]{finding.detector_name}[/bold]")
            console.print(f"  {loc}")
            # Show the snippet with the matched text highlighted
            snippet = finding.snippet
            if finding.matched_text and finding.matched_text in snippet:
                # Redact the middle of the matched text for safety
                redacted = _redact(finding.matched_text)
                display_snippet = snippet.replace(finding.matched_text, redacted, 1)
            else:
                display_snippet = snippet
            console.print(f"    [dim]{display_snippet}[/dim]")
            if finding.description:
                console.print(f"    [italic dim]{finding.description}[/italic dim]")
            console.print()

    # ── Summary table ─────────────────────────────────────────────
    console.print()
    summary = Table(title="Summary", border_style="cyan", show_lines=False)
    summary.add_column("Severity", justify="center")
    summary.add_column("Count", justify="center")

    by_severity = result.findings_by_severity()
    for sev in ("critical", "high", "medium", "low"):
        count = len(by_severity.get(sev, []))
        if count > 0:
            style = SEVERITY_STYLES.get(sev, "")
            emoji = SEVERITY_EMOJI.get(sev, "")
            summary.add_row(f"{emoji} {sev.upper()}", f"[bold]{count}[/bold]", style=style)

    console.print(summary)
    console.print()

    # ── Security advisory ─────────────────────────────────────────
    console.print(
        Panel(
            "⚠️  [bold yellow]Security Advisory[/bold yellow]\n"
            "Rotate any leaked credentials immediately.\n"
            "Do [bold]not[/bold] share this report without redacting secrets.",
            border_style="yellow",
            padding=(0, 2),
        )
    )

    _render_errors(result, console)


def _redact(text: str, visible_chars: int = 6) -> str:
    """Partially redact a secret, showing only the first few characters."""
    if len(text) <= visible_chars:
        return text[:2] + "*" * (len(text) - 2)
    return text[:visible_chars] + "*" * min(len(text) - visible_chars, 20) + "…"


def _render_errors(result: ScanResult, console: Console) -> None:
    """Render any scan errors."""
    if result.errors:
        console.print()
        console.print("[bold red]Errors encountered during scan:[/bold red]")
        for error in result.errors:
            console.print(f"  ⚠️  {error}", style="dim red")
