"""
Tests for the keychase CLI.

Uses typer.testing.CliRunner to test CLI commands
without spawning subprocesses.
"""

import json

import pytest
from typer.testing import CliRunner

from keychase.cli import app

runner = CliRunner()


class TestVersion:
    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestDetectors:
    def test_detectors_command(self):
        result = runner.invoke(app, ["detectors"])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output
        assert "HIGH" in result.output


class TestScan:
    def test_scan_fixtures_finds_secrets(self, tmp_path):
        """Scan a temp dir with fake secrets — exit code should be 1."""
        secret_file = tmp_path / "leaky.py"
        secret_file.write_text(
            'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
            encoding="utf-8",
        )
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-progress"])
        assert result.exit_code == 1

    def test_scan_clean_dir(self, tmp_path):
        """Scan a clean dir — exit code should be 0."""
        clean_file = tmp_path / "app.py"
        clean_file.write_text(
            "import os\nprint('hello')\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-progress"])
        assert result.exit_code == 0

    def test_scan_json_output(self, tmp_path):
        """JSON output should be valid JSON with expected structure."""
        secret_file = tmp_path / "config.py"
        secret_file.write_text(
            'password = "my_secret_password_value"\n',
            encoding="utf-8",
        )
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--no-progress", "-f", "json"]
        )
        assert result.exit_code == 1

        data = json.loads(result.output)
        assert "findings" in data
        assert "summary" in data
        assert data["summary"]["total_findings"] > 0

    def test_scan_sarif_output(self, tmp_path):
        """SARIF output should be valid JSON with SARIF structure."""
        secret_file = tmp_path / "config.py"
        secret_file.write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
            encoding="utf-8",
        )
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--no-progress", "-f", "sarif"]
        )
        assert result.exit_code == 1

        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"][0]["results"]) > 0

    def test_scan_nonexistent_path(self):
        """Scanning a non-existent path should exit with code 2."""
        result = runner.invoke(app, ["scan", "/nonexistent/path", "--no-progress"])
        assert result.exit_code == 2

    def test_scan_github_without_token(self):
        """GitHub scan without token should exit with code 2."""
        result = runner.invoke(app, ["scan", "owner/repo", "--no-progress"])
        assert result.exit_code == 2
        assert "token" in result.output.lower()
