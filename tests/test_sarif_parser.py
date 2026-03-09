"""Tests for SARIF parser."""

from pathlib import Path

from tc_json_triage.models import FindingSource, Severity
from tc_json_triage.parsers.sarif import parse_sarif

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_sample_sarif():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    assert len(findings) == 5


def test_finding_sources():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    by_id = {f.id: f for f in findings}

    # CodeQL findings should be SAST
    assert by_id["finding-001"].source == FindingSource.SAST
    assert by_id["finding-002"].source == FindingSource.SAST

    # Trivy finding should be SCA
    assert by_id["finding-004"].source == FindingSource.SCA

    # Gitleaks finding should be SECRETS
    assert by_id["finding-005"].source == FindingSource.SECRETS


def test_cwes_extracted():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    by_id = {f.id: f for f in findings}

    assert "CWE-89" in by_id["finding-001"].cwes
    assert "CWE-79" in by_id["finding-002"].cwes
    assert "CWE-502" in by_id["finding-004"].cwes


def test_severity_from_security_severity():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    by_id = {f.id: f for f in findings}

    # security-severity 9.8 → critical
    assert by_id["finding-001"].severity == Severity.CRITICAL
    # security-severity 6.1 → medium
    assert by_id["finding-002"].severity == Severity.MEDIUM
    # security-severity 10.0 → critical
    assert by_id["finding-004"].severity == Severity.CRITICAL


def test_locations_extracted():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    by_id = {f.id: f for f in findings}

    assert by_id["finding-001"].file == "src/api/search.go"
    assert by_id["finding-001"].start_line == 42


def test_sca_package_info():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    by_id = {f.id: f for f in findings}

    assert by_id["finding-004"].cve_id == "CVE-2021-44228"
    assert by_id["finding-004"].package_name == "log4j-core"


def test_secrets_type():
    findings = parse_sarif(FIXTURES / "sample.sarif")
    by_id = {f.id: f for f in findings}

    assert by_id["finding-005"].secret_type == "AWS Access Key"
