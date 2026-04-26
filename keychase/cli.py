"""
Keychase CLI — built with Typer.

Usage:
    keychase scan .                          # Scan current directory
    keychase scan /path/to/project           # Scan a local path
    keychase scan owner/repo --token xxx     # Scan a GitHub repo
    keychase scan . --history                # Include git history
    keychase scan . --format json            # JSON output
    keychase scan . --format sarif           # SARIF output for GitHub Code Scanning
    keychase version                         # Show version
    keychase detectors                       # List all loaded detectors
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from keychase import __version__
from keychase.config import ScanConfig, is_github_target
from keychase.detectors import DetectorRegistry

app = typer.Typer(
    name="keychase",
    help="🔑 Keychase — A fast, flexible secret scanner for Git repos and filesystems.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    targets: list[str] = typer.Argument(
        None,
        help="Paths to scan (directories, files, or 'owner/repo' for GitHub).",
    ),
    history: bool = typer.Option(
        False, "--history", "-H",
        help="Also scan git commit history for secrets.",
    ),
    history_depth: Optional[int] = typer.Option(
        None, "--depth", "-d",
        help="Max number of git commits to scan (default: all).",
    ),
    branch: Optional[str] = typer.Option(
        None, "--branch", "-b",
        help="Branch to scan (GitHub scanner or git history).",
    ),
    format: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, json, sarif.",
    ),
    token: Optional[str] = typer.Option(
        None, "--token", "-t",
        help="GitHub token (or set KEYCHASE_GITHUB_TOKEN env var).",
        envvar="KEYCHASE_GITHUB_TOKEN",
    ),
    patterns: Optional[str] = typer.Option(
        None, "--patterns", "-p",
        help="Path to a file with custom regex patterns (one per line).",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Write report to file instead of stdout.",
    ),
    no_progress: bool = typer.Option(
        False, "--no-progress",
        help="Disable progress bars (useful in CI).",
    ),
) -> None:
    """Scan a local directory or GitHub repository for hardcoded secrets."""
    from keychase.scanner.base import ScanResult

    # ── Setup ─────────────────────────────────────────────────────
    config = ScanConfig(
        custom_patterns_path=patterns,
        history_depth=history_depth,
        output_format=format,
        github_token=token,
        show_progress=not no_progress,
    )

    registry = DetectorRegistry()
    registry.load_builtin_detectors()

    # Load custom patterns if provided
    if config.custom_patterns_path:
        custom = config.load_custom_patterns()
        if custom:
            registry.load_custom_patterns(custom)
            if not no_progress:
                console.print(f"  📋 Loaded {len(custom)} custom patterns.")

    if not targets:
        targets = ["."]

    if not no_progress:
        _print_banner()
        console.print(f"  🎯 Targets: [bold]{', '.join(targets)}[/bold]")
        console.print(f"  🔍 Detectors loaded: [bold]{registry.count}[/bold]")
        console.print()

    # ── Determine scan mode ───────────────────────────────────────
    result = ScanResult(target=", ".join(targets))

    for target in targets:
        if is_github_target(target):
            # GitHub API scan
            gh_token = config.github_token
            if not gh_token:
                console.print("[bold red]Error:[/bold red] GitHub token is required for remote scans.")
                console.print("  Set KEYCHASE_GITHUB_TOKEN or use --token.")
                raise typer.Exit(code=2)

            from keychase.scanner.github_scanner import GitHubScanner
            scanner = GitHubScanner(
                repo=target,
                token=gh_token,
                registry=registry,
                branch=branch,
                show_progress=config.show_progress,
            )
            sub_result = scanner.scan()
            result.merge(sub_result)

        else:
            # Local filesystem scan
            target_path = Path(target).resolve()
            if not target_path.exists():
                # For pre-commit, some files might be passed that are already deleted but staged.
                # We can just skip them rather than throwing a fatal error.
                result.errors.append(f"Path not found: {target_path}")
                continue

            from keychase.scanner.local_scanner import LocalScanner
            local_scanner = LocalScanner(
                target_path=target_path,
                registry=registry,
                config=config,
                show_progress=config.show_progress,
            )
            sub_result = local_scanner.scan()
            result.merge(sub_result)

            # If --history, also scan git history and merge
            if history:
                from keychase.scanner.git_history_scanner import GitHistoryScanner
                history_scanner = GitHistoryScanner(
                    repo_path=target_path,
                    registry=registry,
                    max_depth=config.history_depth,
                    branch=branch,
                    show_progress=config.show_progress,
                )
                try:
                    hist_result = history_scanner.scan()
                    result.merge(hist_result)
                except ValueError as e:
                    console.print(f"[bold yellow]Warning:[/bold yellow] {e}")

    # ── Output ────────────────────────────────────────────────────
    if format == "json":
        from keychase.reporters.json_reporter import render_json_report
        render_json_report(result, output_path=output)
    elif format == "sarif":
        from keychase.reporters.sarif import render_sarif_report
        render_sarif_report(result, output_path=output)
    else:
        from keychase.reporters.console import render_console_report
        render_console_report(result, console=console)

    # ── Exit code ─────────────────────────────────────────────────
    # Exit 1 if secrets were found (CI-friendly)
    if result.has_findings:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show the keychase version."""
    console.print(f"🔑 keychase [bold cyan]v{__version__}[/bold cyan]")


@app.command()
def detectors() -> None:
    """List all loaded secret detectors."""
    registry = DetectorRegistry()
    registry.load_builtin_detectors()

    table = Table(
        title=f"🔍 Loaded Detectors ({registry.count})",
        border_style="cyan",
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Severity", justify="center")
    table.add_column("Description", max_width=50)

    severity_styles = {
        "critical": "bold red",
        "high": "dark_orange",
        "medium": "yellow",
        "low": "blue",
    }

    for i, det in enumerate(registry.detectors, start=1):
        sev = det.severity.value
        style = severity_styles.get(sev, "")
        table.add_row(
            str(i),
            det.id,
            det.name,
            Text(sev.upper(), style=style),
            det.description[:50] + "…" if len(det.description) > 50 else det.description,
        )

    console.print(table)
    console.print()

    # Print summary
    summary = registry.summary()
    parts = [f"[bold red]{summary.get('critical', 0)} CRITICAL[/bold red]"]
    parts.append(f"[dark_orange]{summary.get('high', 0)} HIGH[/dark_orange]")
    parts.append(f"[yellow]{summary.get('medium', 0)} MEDIUM[/yellow]")
    parts.append(f"[blue]{summary.get('low', 0)} LOW[/blue]")
    console.print("  " + " · ".join(parts))


def _print_banner() -> None:
    """Print the keychase banner."""
    console.print()
    console.print("[bold cyan]  Keychase[/bold cyan] [dim]v" + __version__ + "[/dim]")
    console.print("[dim]  Fast, flexible secret scanner for Git repos & filesystems[/dim]")
    console.print()


if __name__ == "__main__":
    app()
