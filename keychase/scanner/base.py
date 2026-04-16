"""
Base scanner interface and shared data models.

All scanner implementations (local, git-history, github) inherit
from BaseScanner and return ScanResult instances.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """
    A single secret finding in a scanned file.

    Attributes:
        file_path: Relative path to the file containing the secret.
        line_number: 1-indexed line number within the file.
        detector_id: ID of the detector that matched (e.g. "aws-access-key-id").
        detector_name: Human-readable detector name.
        severity: Severity level string (critical, high, medium, low).
        snippet: The full line of code where the match was found.
        matched_text: The specific text that matched the pattern.
        commit_sha: Git commit SHA (only set for git-history scans).
        commit_author: Git commit author (only set for git-history scans).
        commit_date: Git commit date string (only set for git-history scans).
        description: Description from the detector about this type of leak.
    """
    file_path: str
    line_number: int
    detector_id: str
    detector_name: str
    severity: str
    snippet: str
    matched_text: str = ""
    commit_sha: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    description: str = ""

    @property
    def severity_rank(self) -> int:
        """Numeric rank for sorting (higher = more severe)."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(self.severity, 0)

    @property
    def location(self) -> str:
        """Human-readable location string."""
        loc = f"{self.file_path}:{self.line_number}"
        if self.commit_sha:
            loc = f"{self.commit_sha[:8]} → {loc}"
        return loc


@dataclass
class ScanResult:
    """
    Aggregated result of a scan operation.

    Attributes:
        findings: All detected secrets.
        files_scanned: Number of files processed.
        duration_seconds: Wall-clock time of the scan.
        scan_type: Type of scan ("local", "git-history", "github").
        target: What was scanned (path or repo name).
        errors: Non-fatal errors encountered during the scan.
    """
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    scan_type: str = ""
    target: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity level."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def findings_by_file(self) -> dict[str, list[Finding]]:
        """Group findings by file path."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.file_path, []).append(finding)
        return grouped

    def merge(self, other: "ScanResult") -> "ScanResult":
        """Merge another ScanResult into this one (mutates self)."""
        self.findings.extend(other.findings)
        self.files_scanned += other.files_scanned
        self.duration_seconds += other.duration_seconds
        self.errors.extend(other.errors)
        return self


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.

    Subclasses must implement `_execute_scan()` which populates
    and returns a ScanResult. The `scan()` method wraps it with
    timing and error handling.
    """

    def __init__(self, scan_type: str = "") -> None:
        self._scan_type = scan_type

    def scan(self) -> ScanResult:
        """
        Run the scan with timing.
        Catches unexpected exceptions and records them as errors.
        """
        start = time.perf_counter()
        try:
            result = self._execute_scan()
        except Exception as exc:
            result = ScanResult(
                scan_type=self._scan_type,
                errors=[f"Fatal scan error: {exc}"],
            )
        result.duration_seconds = time.perf_counter() - start
        result.scan_type = self._scan_type
        return result

    @abstractmethod
    def _execute_scan(self) -> ScanResult:
        """Perform the actual scan. Must be implemented by subclasses."""
        ...
