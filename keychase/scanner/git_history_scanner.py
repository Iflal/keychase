"""
Git history scanner.

Uses GitPython to walk commit diffs and detect secrets that
were introduced (and possibly later removed) in the repository
history. This catches secrets that were committed and then
deleted — the most common real-world leak scenario.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from keychase.detectors import DetectorRegistry
from keychase.scanner.base import BaseScanner, Finding, ScanResult


class GitHistoryScanner(BaseScanner):
    """
    Scans the git history of a local repository for secrets.

    Walks commit diffs and applies detectors to added lines.
    Only looks at lines that were *added* (not removed), because
    we care about secrets that entered the codebase.

    Usage:
        registry = DetectorRegistry()
        registry.load_builtin_detectors()
        scanner = GitHistoryScanner("/path/to/repo", registry, max_depth=100)
        result = scanner.scan()
    """

    def __init__(
        self,
        repo_path: str | Path,
        registry: DetectorRegistry,
        max_depth: Optional[int] = None,
        branch: Optional[str] = None,
        show_progress: bool = True,
    ) -> None:
        super().__init__(scan_type="git-history")
        self.repo_path = Path(repo_path).resolve()
        self.registry = registry
        self.max_depth = max_depth
        self.branch = branch
        self.show_progress = show_progress

    def _execute_scan(self) -> ScanResult:
        """Walk git log diffs and scan added lines."""
        result = ScanResult(target=str(self.repo_path))

        # Import lazily — gitpython is only needed for history scans
        try:
            from git import Repo, InvalidGitRepositoryError, GitCommandNotFound
        except ImportError:
            result.errors.append(
                "GitPython is required for history scanning. "
                "Install it with: pip install gitpython"
            )
            return result

        try:
            repo = Repo(self.repo_path)
        except InvalidGitRepositoryError:
            result.errors.append(
                f"'{self.repo_path}' is not a valid Git repository. "
                "Use 'keychase scan <path>' without --history for non-git directories."
            )
            return result
        except GitCommandNotFound:
            result.errors.append(
                "Git is not installed or not found on PATH. "
                "Install Git to use history scanning."
            )
            return result

        # Determine the branch/ref to scan
        try:
            if self.branch:
                commits = list(repo.iter_commits(self.branch, max_count=self.max_depth))
            else:
                commits = list(repo.iter_commits(max_count=self.max_depth))
        except Exception as exc:
            result.errors.append(f"Error reading git history: {exc}")
            return result

        if not commits:
            return result

        seen_findings: set[tuple[str, int, str, str]] = set()

        if self.show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task(
                    f"Scanning {len(commits)} commits...", total=len(commits)
                )
                for commit in commits:
                    self._scan_commit(commit, result, seen_findings)
                    result.files_scanned += 1
                    progress.update(task, advance=1)
        else:
            for commit in commits:
                self._scan_commit(commit, result, seen_findings)
                result.files_scanned += 1

        return result

    def _scan_commit(
        self,
        commit,
        result: ScanResult,
        seen: set[tuple[str, int, str, str]],
    ) -> None:
        """Scan the diff introduced by a single commit."""
        try:
            # For the initial commit, diff against an empty tree
            if not commit.parents:
                diffs = commit.diff(
                    None,  # diff against empty tree
                    create_patch=True,
                    R=True,
                )
            else:
                diffs = commit.parents[0].diff(commit, create_patch=True)
        except Exception as exc:
            result.errors.append(f"Error diffing commit {commit.hexsha[:8]}: {exc}")
            return

        commit_sha = commit.hexsha
        commit_author = str(commit.author) if commit.author else "unknown"
        commit_date = commit.committed_datetime.isoformat() if commit.committed_datetime else ""

        for diff in diffs:
            if not diff.b_path:
                continue

            file_path = diff.b_path
            try:
                diff_text = diff.diff
                if isinstance(diff_text, bytes):
                    diff_text = diff_text.decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Only scan added lines (lines starting with '+')
            for raw_line in diff_text.splitlines():
                if not raw_line.startswith("+") or raw_line.startswith("+++"):
                    continue

                line = raw_line[1:]  # Remove the leading '+'
                if len(line.strip()) < 8:
                    continue

                matches = self.registry.scan_line(line)
                for match in matches:
                    # Deduplicate — same file, same matched text, same detector
                    dedup_key = (file_path, match.detector_id, match.matched_text, commit_sha)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    result.findings.append(
                        Finding(
                            file_path=file_path,
                            line_number=0,  # Line numbers aren't reliable in diffs
                            detector_id=match.detector_id,
                            detector_name=match.detector_name,
                            severity=match.severity.value,
                            snippet=line.strip(),
                            matched_text=match.matched_text,
                            commit_sha=commit_sha,
                            commit_author=commit_author,
                            commit_date=commit_date,
                            description=match.description,
                        )
                    )
