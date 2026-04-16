"""
JSON reporter.

Outputs scan results as structured JSON, suitable for piping into
other tools, CI/CD artifact storage, or API responses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from keychase.scanner.base import ScanResult


def render_json_report(
    result: ScanResult,
    output_path: Optional[str] = None,
    indent: int = 2,
) -> str:
    """
    Render a scan result as JSON.

    Args:
        result: The scan result to serialize.
        output_path: If provided, write JSON to this file. Otherwise, print to stdout.
        indent: JSON indentation level.

    Returns:
        The JSON string.
    """
    report = {
        "keychase_version": _get_version(),
        "scan": {
            "target": result.target,
            "type": result.scan_type,
            "files_scanned": result.files_scanned,
            "duration_seconds": round(result.duration_seconds, 3),
        },
        "summary": {
            "total_findings": result.finding_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "by_severity": {
                sev: len(findings)
                for sev, findings in result.findings_by_severity().items()
            },
        },
        "findings": [
            {
                "file_path": f.file_path,
                "line_number": f.line_number,
                "detector_id": f.detector_id,
                "detector_name": f.detector_name,
                "severity": f.severity,
                "snippet": f.snippet,
                "matched_text": _redact(f.matched_text),
                "commit_sha": f.commit_sha,
                "commit_author": f.commit_author,
                "commit_date": f.commit_date,
                "description": f.description,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }

    json_str = json.dumps(report, indent=indent, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
    else:
        sys.stdout.write(json_str + "\n")

    return json_str


def _redact(text: str, visible_chars: int = 6) -> str:
    """Partially redact a secret."""
    if not text:
        return text
    if len(text) <= visible_chars:
        return text[:2] + "*" * (len(text) - 2)
    return text[:visible_chars] + "*" * min(len(text) - visible_chars, 20)


def _get_version() -> str:
    try:
        from keychase import __version__
        return __version__
    except ImportError:
        return "unknown"
