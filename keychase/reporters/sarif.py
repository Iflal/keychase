"""
SARIF reporter.

Produces SARIF v2.1.0 output for integration with GitHub
Code Scanning, VS Code SARIF Viewer, and other analysis tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from keychase.scanner.base import ScanResult

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif_report(
    result: ScanResult,
    output_path: Optional[str] = None,
) -> str:
    """
    Render a scan result as SARIF v2.1.0.

    Args:
        result: The scan result to serialize.
        output_path: If provided, write SARIF to this file.

    Returns:
        The SARIF JSON string.
    """
    # Build the set of unique rules from findings
    rules_seen: dict[str, dict] = {}
    results_list: list[dict] = []

    for finding in result.findings:
        # Register rule if not seen
        if finding.detector_id not in rules_seen:
            rules_seen[finding.detector_id] = {
                "id": finding.detector_id,
                "name": finding.detector_name,
                "shortDescription": {"text": finding.detector_name},
                "fullDescription": {"text": finding.description or finding.detector_name},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
                },
                "properties": {
                    "security-severity": _severity_score(finding.severity),
                },
            }

        # Build location
        physical_location: dict = {
            "artifactLocation": {
                "uri": finding.file_path,
            }
        }
        if finding.line_number > 0:
            physical_location["region"] = {
                "startLine": finding.line_number,
                "snippet": {"text": finding.snippet},
            }

        sarif_result: dict = {
            "ruleId": finding.detector_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": (
                    f"Potential secret detected: {finding.detector_name}. "
                    f"{finding.description}"
                ),
            },
            "locations": [{"physicalLocation": physical_location}],
        }

        # Add git commit info as properties if available
        if finding.commit_sha:
            sarif_result["properties"] = {
                "commit_sha": finding.commit_sha,
                "commit_author": finding.commit_author or "",
                "commit_date": finding.commit_date or "",
            }

        results_list.append(sarif_result)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "keychase",
                        "version": _get_version(),
                        "informationUri": "https://github.com/keychase/keychase",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results_list,
                "invocations": [
                    {
                        "executionSuccessful": len(result.errors) == 0,
                        "toolExecutionNotifications": [
                            {"message": {"text": e}, "level": "error"}
                            for e in result.errors
                        ],
                    }
                ],
            }
        ],
    }

    json_str = json.dumps(sarif_doc, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
    else:
        sys.stdout.write(json_str + "\n")

    return json_str


def _severity_score(severity: str) -> str:
    """Map severity to a numeric score for GitHub Code Scanning."""
    return {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.5",
    }.get(severity, "5.0")


def _get_version() -> str:
    try:
        from keychase import __version__
        return __version__
    except ImportError:
        return "unknown"
