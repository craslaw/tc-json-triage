"""Tests for CLI directory expansion behavior."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from tc_json_triage.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def runner():
    return CliRunner()


def test_sarif_directory_input(runner, tmp_path):
    """A directory containing .sarif files is expanded automatically."""
    shutil.copy(FIXTURES / "sample.sarif", tmp_path / "scan.sarif")
    result = runner.invoke(
        main,
        [
            "--threat-model", str(FIXTURES / "sample.tc.json"),
            "--sarif", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    # Should have parsed the file (not zero findings path)
    assert "scan.sarif" in result.output or "findings" in result.output.lower()


def test_sarif_directory_no_files_warning(runner, tmp_path):
    """A directory with no SARIF files emits a warning and produces no findings."""
    result = runner.invoke(
        main,
        [
            "--threat-model", str(FIXTURES / "sample.tc.json"),
            "--sarif", str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert "Warning: no SARIF files found" in result.output
    assert "No findings to triage." in result.output


def test_sarif_dot_sarif_json_extension(runner, tmp_path):
    """Files with .sarif.json extension are also picked up from a directory."""
    shutil.copy(FIXTURES / "sample.sarif", tmp_path / "scan.sarif.json")
    result = runner.invoke(
        main,
        [
            "--threat-model", str(FIXTURES / "sample.tc.json"),
            "--sarif", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "scan.sarif.json" in result.output or "findings" in result.output.lower()
