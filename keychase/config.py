"""
Keychase configuration management.

Centralises scan settings, loads ignore files, and reads
environment variables so the CLI and scanners have a single
source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Default file extensions — can be overridden in config
DEFAULT_FILE_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".php", ".rb", ".java", ".go", ".rs",
    ".swift", ".kt", ".kts", ".cs", ".c", ".cpp", ".h", ".hpp",
    ".sql", ".xml", ".html", ".css", ".tf", ".hcl", ".properties",
    ".gradle", ".md", ".txt", ".r", ".R", ".dart", ".scala",
}

DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "env", ".eggs", "dist", "build", ".tox", ".nox", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", "htmlcov", ".idea", ".vscode",
    "target",
}


@dataclass
class ScanConfig:
    """
    Configuration for a scan operation.

    Attributes:
        file_extensions: File extensions to include in the scan.
        excluded_dirs: Directory names to skip entirely.
        custom_patterns_path: Optional path to a file with additional regex patterns.
        history_depth: Maximum number of git commits to scan (None = all).
        output_format: Output format for CLI ("table", "json", "sarif").
        github_token: GitHub PAT for API-based scans.
        show_progress: Whether to display Rich progress bars.
    """
    file_extensions: set[str] = field(default_factory=lambda: DEFAULT_FILE_EXTENSIONS.copy())
    excluded_dirs: set[str] = field(default_factory=lambda: DEFAULT_EXCLUDED_DIRS.copy())
    custom_patterns_path: Optional[str] = None
    history_depth: Optional[int] = None
    output_format: str = "table"
    github_token: Optional[str] = None
    show_progress: bool = True

    def __post_init__(self) -> None:
        # Read GitHub token from env if not explicitly provided
        if self.github_token is None:
            self.github_token = os.environ.get("KEYCHASE_GITHUB_TOKEN") or os.environ.get(
                "GITHUB_TOKEN"
            )

    def load_custom_patterns(self) -> dict[str, str]:
        """
        Read custom regex patterns from the configured file.
        Returns a dict mapping pattern_name -> regex_string.
        File format: one regex per line, lines starting with # are comments.
        """
        patterns: dict[str, str] = {}
        if not self.custom_patterns_path:
            return patterns

        path = Path(self.custom_patterns_path)
        if not path.is_file():
            return patterns

        try:
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    patterns[f"Custom Pattern #{i}"] = stripped
        except OSError:
            pass

        return patterns


def is_github_target(target: str) -> bool:
    """
    Determine if a scan target looks like a GitHub repo (owner/repo)
    versus a local path.
    """
    # If it contains path separators or exists on disk, it's local
    if os.path.sep in target or os.path.exists(target) or target == ".":
        return False
    # If it matches owner/repo pattern (no deep slashes), it's GitHub
    parts = target.split("/")
    if len(parts) == 2 and all(p and not p.startswith(".") for p in parts):
        return True
    return False
