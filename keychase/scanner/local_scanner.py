"""
Local filesystem scanner.

Walks a directory tree, respects .gitignore and .keychaseignore,
filters by file extension, skips binary files, then runs every
line through the detector registry.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from keychase.config import ScanConfig
from keychase.detectors import DetectorRegistry
from keychase.scanner.base import BaseScanner, Finding, ScanResult

# File extensions considered scannable by default
DEFAULT_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".php", ".rb", ".java", ".go", ".rs",
    ".swift", ".kt", ".kts", ".cs", ".c", ".cpp", ".h", ".hpp",
    ".sql", ".xml", ".html", ".css", ".tf", ".hcl", ".properties",
    ".gradle", ".md", ".txt", ".r", ".R", ".dart", ".scala",
    ".Dockerfile", ".dockerignore", ".env.example", ".env.local",
}

# Directories always skipped
DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "env", ".eggs", "dist", "build", ".tox", ".nox", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", "htmlcov", ".idea", ".vscode",
    "target",  # Java/Rust
}

# Filename keywords that guarantee scanning regardless of extension
SENSITIVE_KEYWORDS: tuple[str, ...] = (
    ".env", "credential", "secret", "password", "token",
    "auth", "config", "keyfile", "key.pem", "id_rsa",
)

# Maximum file size to scan (2 MB) — skip enormous files
MAX_FILE_SIZE: int = 2 * 1024 * 1024


def _is_binary(file_path: Path, sample_size: int = 8192) -> bool:
    """Quick binary detection: check for null bytes in the first chunk."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


def _load_ignore_patterns(path: Path) -> list[str]:
    """Load a gitignore/keychaseignore file and return non-comment lines."""
    patterns: list[str] = []
    if path.is_file():
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    patterns.append(stripped)
        except OSError:
            pass
    return patterns


def _is_ignored_by_patterns(
    rel_path: str, patterns: list[str]
) -> bool:
    """
    Simplified gitignore-style matching.
    Uses pathspec if available, otherwise falls back to basic matching.
    """
    try:
        import pathspec
        spec = pathspec.PathSpec.from_lines("gitignore", patterns)
        return spec.match_file(rel_path)
    except ImportError:
        # Fallback: exact prefix/suffix matching
        for pattern in patterns:
            clean = pattern.strip("/")
            if clean in rel_path or rel_path.endswith(clean):
                return True
        return False


def _should_scan_file(
    file_path: Path,
    rel_path: str,
    extensions: set[str],
) -> bool:
    """Decide whether a file should be scanned."""
    name_lower = file_path.name.lower()

    # Always scan files matching sensitive keywords
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in name_lower:
            return True

    # Check file extension
    suffix = file_path.suffix.lower()
    if suffix in extensions:
        return True

    # Files named exactly like "Dockerfile", "Makefile", etc.
    if name_lower in {"dockerfile", "makefile", "vagrantfile", "gemfile", "rakefile"}:
        return True

    return False


class LocalScanner(BaseScanner):
    """
    Scans a local directory for secrets.

    Usage:
        registry = DetectorRegistry()
        registry.load_builtin_detectors()
        scanner = LocalScanner("/path/to/project", registry)
        result = scanner.scan()
    """

    def __init__(
        self,
        target_path: str | Path,
        registry: DetectorRegistry,
        config: Optional[ScanConfig] = None,
        show_progress: bool = True,
    ) -> None:
        super().__init__(scan_type="local")
        self.target_path = Path(target_path).resolve()
        self.registry = registry
        self.config = config or ScanConfig()
        self.show_progress = show_progress

    def _collect_files(self) -> list[Path]:
        """Walk the directory tree and collect scannable files."""
        # Load ignore patterns
        ignore_patterns: list[str] = []
        gitignore = self.target_path / ".gitignore"
        ignore_patterns.extend(_load_ignore_patterns(gitignore))
        keychase_ignore = self.target_path / ".keychaseignore"
        ignore_patterns.extend(_load_ignore_patterns(keychase_ignore))

        extensions = self.config.file_extensions or DEFAULT_EXTENSIONS
        excluded_dirs = self.config.excluded_dirs or DEFAULT_EXCLUDED_DIRS

        files: list[Path] = []
        for root, dirs, filenames in os.walk(self.target_path):
            # Prune excluded directories in-place
            dirs[:] = [
                d for d in dirs
                if d not in excluded_dirs
            ]

            root_path = Path(root)
            for filename in filenames:
                file_path = root_path / filename
                rel_path = str(file_path.relative_to(self.target_path)).replace("\\", "/")

                # Check ignore patterns
                if ignore_patterns and _is_ignored_by_patterns(rel_path, ignore_patterns):
                    continue

                # Check file size
                try:
                    if file_path.stat().st_size > MAX_FILE_SIZE:
                        continue
                    if file_path.stat().st_size == 0:
                        continue
                except OSError:
                    continue

                # Check if we should scan this type of file
                if not _should_scan_file(file_path, rel_path, extensions):
                    continue

                # Skip binary files
                if _is_binary(file_path):
                    continue

                files.append(file_path)

        return files

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file and return findings."""
        findings: list[Finding] = []
        rel_path = str(file_path.relative_to(self.target_path)).replace("\\", "/")

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return findings

        for line_num, line in enumerate(content.splitlines(), start=1):
            # Skip empty lines and very short lines
            if len(line.strip()) < 8:
                continue

            matches = self.registry.scan_line(line)
            for match in matches:
                findings.append(
                    Finding(
                        file_path=rel_path,
                        line_number=line_num,
                        detector_id=match.detector_id,
                        detector_name=match.detector_name,
                        severity=match.severity.value,
                        snippet=line.strip(),
                        matched_text=match.matched_text,
                        description=match.description,
                    )
                )

        return findings

    def _execute_scan(self) -> ScanResult:
        """Run the local filesystem scan."""
        result = ScanResult(target=str(self.target_path))
        files = self._collect_files()

        if self.show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("Scanning files...", total=len(files))
                for file_path in files:
                    try:
                        findings = self._scan_file(file_path)
                        result.findings.extend(findings)
                    except Exception as exc:
                        result.errors.append(f"Error scanning {file_path}: {exc}")
                    result.files_scanned += 1
                    progress.update(task, advance=1)
        else:
            for file_path in files:
                try:
                    findings = self._scan_file(file_path)
                    result.findings.extend(findings)
                except Exception as exc:
                    result.errors.append(f"Error scanning {file_path}: {exc}")
                result.files_scanned += 1

        return result
