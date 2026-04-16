"""
Tests for the local filesystem scanner.

Creates temporary directories with fixture files, runs the scanner,
and verifies findings + .keychaseignore support.
"""

import os
import tempfile
from pathlib import Path

import pytest

from keychase.config import ScanConfig
from keychase.detectors import DetectorRegistry
from keychase.scanner.local_scanner import LocalScanner


@pytest.fixture
def registry():
    r = DetectorRegistry()
    r.load_builtin_detectors()
    return r


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project with known secrets and clean files."""
    # File with secrets
    secrets_file = tmp_path / "config.py"
    secrets_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'password = "super_secret_password_123"\n'
        'safe_var = "hello world"\n',
        encoding="utf-8",
    )

    # Clean file
    clean_file = tmp_path / "main.py"
    clean_file.write_text(
        "import os\n\ndef main():\n    print('Hello')\n",
        encoding="utf-8",
    )

    # File that should be ignored
    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "package.json").write_text(
        '{"password": "should_not_be_scanned_because_excluded_dir"}',
        encoding="utf-8",
    )

    # Binary file (should be skipped)
    binary_file = tmp_path / "image.py"
    binary_file.write_bytes(b"\x00\x01\x02\x03AKIAIOSFODNN7EXAMPLE\x00")

    return tmp_path


@pytest.fixture
def temp_project_with_ignore(tmp_path):
    """Project with a .keychaseignore file."""
    secrets_file = tmp_path / "config.py"
    secrets_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        encoding="utf-8",
    )

    ignored_file = tmp_path / "test_credentials.py"
    ignored_file.write_text(
        'TEST_KEY = "AKIAIOSFODNN7TESTONLY"\n',
        encoding="utf-8",
    )

    ignore_file = tmp_path / ".keychaseignore"
    ignore_file.write_text("test_credentials.py\n", encoding="utf-8")

    return tmp_path


class TestLocalScanner:
    def test_finds_secrets(self, registry, temp_project):
        scanner = LocalScanner(temp_project, registry, show_progress=False)
        result = scanner.scan()

        assert result.has_findings
        assert result.files_scanned >= 2

        # Should find AWS key and password
        detector_ids = {f.detector_id for f in result.findings}
        assert "aws-access-key-id" in detector_ids
        assert "generic-password-assignment" in detector_ids

    def test_skips_excluded_dirs(self, registry, temp_project):
        scanner = LocalScanner(temp_project, registry, show_progress=False)
        result = scanner.scan()

        # No findings should come from node_modules
        for finding in result.findings:
            assert "node_modules" not in finding.file_path

    def test_skips_binary_files(self, registry, temp_project):
        scanner = LocalScanner(temp_project, registry, show_progress=False)
        result = scanner.scan()

        # No findings from file that has null bytes
        for finding in result.findings:
            assert finding.file_path != "image.py"

    def test_clean_directory(self, registry, tmp_path):
        clean = tmp_path / "app.py"
        clean.write_text("import os\nprint('hello')\n", encoding="utf-8")

        scanner = LocalScanner(tmp_path, registry, show_progress=False)
        result = scanner.scan()

        assert not result.has_findings
        assert result.files_scanned >= 1

    def test_keychaseignore(self, registry, temp_project_with_ignore):
        scanner = LocalScanner(
            temp_project_with_ignore, registry, show_progress=False
        )
        result = scanner.scan()

        # Only config.py should produce findings, not test_credentials.py
        files_with_findings = {f.file_path for f in result.findings}
        assert "config.py" in files_with_findings
        assert "test_credentials.py" not in files_with_findings

    def test_scan_result_properties(self, registry, temp_project):
        scanner = LocalScanner(temp_project, registry, show_progress=False)
        result = scanner.scan()

        assert result.scan_type == "local"
        assert result.duration_seconds > 0
        assert result.finding_count > 0

    def test_findings_by_file(self, registry, temp_project):
        scanner = LocalScanner(temp_project, registry, show_progress=False)
        result = scanner.scan()

        by_file = result.findings_by_file()
        assert "config.py" in by_file

    def test_findings_by_severity(self, registry, temp_project):
        scanner = LocalScanner(temp_project, registry, show_progress=False)
        result = scanner.scan()

        by_sev = result.findings_by_severity()
        assert any(sev in by_sev for sev in ("critical", "high", "medium"))
