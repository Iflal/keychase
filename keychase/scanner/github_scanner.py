"""
GitHub API-based scanner.

Scans a remote GitHub repository via the REST API. This is a
refactored version of the original prototype with proper rate-limit
handling (reads X-RateLimit headers, exponential backoff) and
clean architecture that returns ScanResult.
"""

from __future__ import annotations

import base64
import time
from typing import Optional

import requests
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from keychase.detectors import DetectorRegistry
from keychase.scanner.base import BaseScanner, Finding, ScanResult

# Extensions and directories to filter
FILE_EXTENSIONS: tuple[str, ...] = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash",
    ".php", ".rb", ".java", ".go", ".rs", ".swift", ".kt",
    ".cs", ".c", ".cpp", ".h", ".sql", ".xml", ".html", ".tf",
    ".properties", ".gradle", ".md", ".txt",
)
SENSITIVE_KEYWORDS: tuple[str, ...] = (
    ".env", "config", "credential", "secret", "key", "auth", "token",
)
EXCLUDED_DIRS: set[str] = {"node_modules", "vendor", ".git", "__pycache__", "dist", "build"}

API_URL = "https://api.github.com"


class GitHubScanner(BaseScanner):
    """
    Scans a GitHub repository via the REST API.

    Usage:
        registry = DetectorRegistry()
        registry.load_builtin_detectors()
        scanner = GitHubScanner("owner/repo", "ghp_xxx...", registry)
        result = scanner.scan()
    """

    def __init__(
        self,
        repo: str,
        token: str,
        registry: DetectorRegistry,
        branch: Optional[str] = None,
        show_progress: bool = True,
    ) -> None:
        super().__init__(scan_type="github")
        if "/" not in repo:
            raise ValueError(f"Repository must be in 'owner/repo' format, got: {repo!r}")
        self.owner, self.repo_name = repo.split("/", 1)
        self.token = token
        self.registry = registry
        self.branch = branch
        self.target_branch: Optional[str] = None
        self.show_progress = show_progress
        self._headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

    # ── HTTP layer ────────────────────────────────────────────────

    def _make_request(
        self, url: str, params: Optional[dict] = None, max_retries: int = 5
    ) -> Optional[requests.Response]:
        """
        Make a GitHub API request with smart rate-limit handling.
        Reads X-RateLimit-Remaining and sleeps until X-RateLimit-Reset.
        Falls back to exponential backoff on 429/403 rate-limit responses.
        """
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=self._headers, params=params, timeout=30)

                # Check rate-limit headers proactively
                remaining = response.headers.get("X-RateLimit-Remaining")
                if remaining is not None and int(remaining) <= 1:
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    wait = max(reset_time - int(time.time()), 1)
                    time.sleep(min(wait, 60))  # Cap at 60 seconds

                if response.status_code == 200:
                    return response

                if response.status_code == 404:
                    return None

                if response.status_code in (429, 403):
                    # Rate limited — exponential backoff
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    if reset_time:
                        wait = max(reset_time - int(time.time()), 1)
                    else:
                        wait = 2 ** attempt
                    time.sleep(min(wait, 120))
                    continue

                if response.status_code == 401:
                    raise ConnectionError("Authentication failed. Check your GitHub token.")

                response.raise_for_status()

            except requests.exceptions.RequestException as exc:
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise ConnectionError(f"Network error after {max_retries} retries: {exc}")

        return None

    # ── Branch detection ──────────────────────────────────────────

    def _determine_branch(self) -> str:
        """Determine the branch to scan."""
        if self.branch:
            return self.branch
        url = f"{API_URL}/repos/{self.owner}/{self.repo_name}"
        response = self._make_request(url)
        if response:
            return response.json().get("default_branch", "main")
        return "main"

    # ── File discovery ────────────────────────────────────────────

    def _should_scan(self, filename: str) -> bool:
        """Decide whether a file should be scanned."""
        lower = filename.lower()
        if lower.endswith(FILE_EXTENSIONS):
            return True
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in lower:
                return True
        return False

    def _get_files(self, path: str = "") -> list[dict]:
        """Recursively list files in the repo."""
        url = f"{API_URL}/repos/{self.owner}/{self.repo_name}/contents/{path}"
        response = self._make_request(url, params={"ref": self.target_branch})
        if not response:
            return []

        items = response.json()
        if not isinstance(items, list):
            return []

        files: list[dict] = []
        for item in items:
            if item["type"] == "file" and self._should_scan(item["name"]):
                files.append(item)
            elif item["type"] == "dir" and item["name"] not in EXCLUDED_DIRS:
                files.extend(self._get_files(item["path"]))
        return files

    # ── File scanning ─────────────────────────────────────────────

    def _scan_file(self, file_item: dict) -> list[Finding]:
        """Fetch and scan a single file."""
        findings: list[Finding] = []
        response = self._make_request(file_item["url"])
        if not response:
            return findings

        data = response.json()
        content_b64 = data.get("content")
        if not content_b64:
            return findings

        try:
            content = base64.b64decode(content_b64).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return findings

        for line_num, line in enumerate(content.splitlines(), start=1):
            if len(line.strip()) < 8:
                continue
            matches = self.registry.scan_line(line)
            for match in matches:
                findings.append(
                    Finding(
                        file_path=file_item["path"],
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

    # ── Main ──────────────────────────────────────────────────────

    def _execute_scan(self) -> ScanResult:
        """Run the GitHub API scan."""
        full_repo = f"{self.owner}/{self.repo_name}"
        result = ScanResult(target=full_repo)

        self.target_branch = self._determine_branch()
        files = self._get_files()

        if self.show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task(
                    f"Scanning {full_repo} ({len(files)} files)...", total=len(files)
                )
                for file_item in files:
                    try:
                        findings = self._scan_file(file_item)
                        result.findings.extend(findings)
                    except Exception as exc:
                        result.errors.append(f"Error scanning {file_item['path']}: {exc}")
                    result.files_scanned += 1
                    progress.update(task, advance=1)
        else:
            for file_item in files:
                try:
                    findings = self._scan_file(file_item)
                    result.findings.extend(findings)
                except Exception as exc:
                    result.errors.append(f"Error scanning {file_item['path']}: {exc}")
                result.files_scanned += 1

        return result
