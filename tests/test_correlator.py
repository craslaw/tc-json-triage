"""Tests for the correlation engine."""

from pathlib import Path

from tc_json_triage.mapping.correlator import correlate_all, correlate_finding
from tc_json_triage.models import Confidence, FindingSource, Severity
from tc_json_triage.parsers.sarif import parse_sarif
from tc_json_triage.parsers.threat_model import parse_threat_model

FIXTURES = Path(__file__).parent / "fixtures"


def _load():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    findings = parse_sarif(FIXTURES / "sample.sarif")
    return findings, model


def test_sql_injection_matches_threat_1():
    """SQL injection finding should match threat-001 (SQL injection threat)."""
    findings, model = _load()
    sqli = next(f for f in findings if f.id == "finding-001")
    result = correlate_finding(sqli, model)

    assert result.matched_threat is not None
    assert result.matched_threat.id == "threat-001"
    assert result.confidence != Confidence.NONE


def test_mitigated_threat_reduces_severity():
    """SQL injection finding matches mitigated threat-001, severity should be reduced."""
    findings, model = _load()
    sqli = next(f for f in findings if f.id == "finding-001")
    result = correlate_finding(sqli, model)

    # Threat-001 is mitigated (linked to resolved mit-001)
    assert result.matched_threat.is_mitigated is True
    # Original was critical, should be reduced
    assert result.adjusted_severity.rank < result.original_severity.rank


def test_secrets_never_reduced():
    """Secrets findings should never have severity reduced."""
    findings, model = _load()
    secret = next(f for f in findings if f.id == "finding-005")
    result = correlate_finding(secret, model)

    assert result.adjusted_severity == result.original_severity
    assert secret.source == FindingSource.SECRETS


def test_unmitigated_threat_keeps_severity():
    """XSS finding matches unmitigated threat-005, severity should stay."""
    findings, model = _load()
    xss = next(f for f in findings if f.id == "finding-002")
    result = correlate_finding(xss, model)

    # If it matches threat-005 (unmitigated), severity stays the same
    if result.matched_threat and not result.matched_threat.is_mitigated:
        assert result.adjusted_severity == result.original_severity


def test_correlate_all_returns_all():
    """correlate_all should return one result per finding."""
    findings, model = _load()
    results = correlate_all(findings, model)
    assert len(results) == len(findings)


def test_gap_detection():
    """Findings with no matching threat should be flagged as gaps."""
    findings, model = _load()
    results = correlate_all(findings, model)
    for r in results:
        if r.is_gap:
            assert r.matched_threat is None
            assert r.confidence == Confidence.NONE


def test_severity_model():
    """Test the Severity reduction helper."""
    assert Severity.CRITICAL.reduced(3) == Severity.LOW
    assert Severity.HIGH.reduced(1) == Severity.MEDIUM
    assert Severity.LOW.reduced(5) == Severity.INFO
    assert Severity.INFO.reduced(1) == Severity.INFO
