"""
Keychase Detector Registry.

Auto-discovers detector modules and provides a unified interface
to scan lines of text against all registered patterns.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity level for a detected secret."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


@dataclass(frozen=True)
class Detector:
    """
    A single secret detection rule.

    Attributes:
        id: Unique identifier, e.g. "aws-access-key-id".
        name: Human-readable name, e.g. "AWS Access Key ID".
        pattern: Compiled regex pattern.
        severity: How critical a leak of this type is.
        description: Short explanation shown in reports.
        keywords: Optional fast-reject keywords. If provided, the line must
                  contain at least one keyword (case-insensitive) before the
                  expensive regex is evaluated. This is a performance optimization.
    """
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str = ""
    keywords: tuple[str, ...] = ()


@dataclass
class Match:
    """A single match found by a detector on a line."""
    detector_id: str
    detector_name: str
    severity: Severity
    matched_text: str
    description: str = ""


def _compile(pattern_str: str, flags: int = 0) -> re.Pattern:
    """Compile a regex string, raising a clear error on invalid patterns."""
    try:
        return re.compile(pattern_str, flags)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern: {pattern_str!r}") from exc


class DetectorRegistry:
    """
    Central registry that loads all detector modules and exposes
    a single `scan_line()` method.

    Usage:
        registry = DetectorRegistry()
        registry.load_builtin_detectors()
        matches = registry.scan_line("AKIAIOSFODNN7EXAMPLE")
    """

    def __init__(self) -> None:
        self._detectors: list[Detector] = []

    # ── Registration ──────────────────────────────────────────────

    def register(self, detector: Detector) -> None:
        """Register a single detector."""
        self._detectors.append(detector)

    def register_many(self, detectors: list[Detector]) -> None:
        """Register a list of detectors."""
        self._detectors.extend(detectors)

    # ── Discovery ─────────────────────────────────────────────────

    def load_builtin_detectors(self) -> None:
        """
        Auto-discover and import every module in this package
        (except __init__). Each module must expose a `DETECTORS`
        list of Detector instances.
        """
        package = importlib.import_module(__package__)
        for _importer, modname, _ispkg in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{__package__}.{modname}")
            detectors = getattr(module, "DETECTORS", None)
            if detectors and isinstance(detectors, list):
                self.register_many(detectors)

    def load_custom_patterns(self, patterns: dict[str, str]) -> None:
        """
        Load user-supplied regex patterns as detectors.

        Args:
            patterns: Mapping of pattern_name -> regex_string.
        """
        for name, regex in patterns.items():
            detector = Detector(
                id=f"custom-{name.lower().replace(' ', '-')}",
                name=name,
                pattern=_compile(regex),
                severity=Severity.MEDIUM,
                description="User-defined custom pattern.",
            )
            self.register(detector)

    # ── Scanning ──────────────────────────────────────────────────

    def scan_line(self, line: str) -> list[Match]:
        """
        Run all registered detectors against a single line.
        Returns a list of Match objects for every pattern that hits.
        """
        matches: list[Match] = []
        line_lower: Optional[str] = None  # lazy lowercase

        for det in self._detectors:
            # Fast-reject: if the detector has keywords, the line must
            # contain at least one before we bother with the regex.
            if det.keywords:
                if line_lower is None:
                    line_lower = line.lower()
                if not any(kw in line_lower for kw in det.keywords):
                    continue

            m = det.pattern.search(line)
            if m:
                matches.append(
                    Match(
                        detector_id=det.id,
                        detector_name=det.name,
                        severity=det.severity,
                        matched_text=m.group(0),
                        description=det.description,
                    )
                )

        return matches

    # ── Introspection ─────────────────────────────────────────────

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors)

    @property
    def count(self) -> int:
        return len(self._detectors)

    def summary(self) -> dict[str, int]:
        """Count detectors by severity."""
        counts: dict[str, int] = {}
        for det in self._detectors:
            key = det.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts
