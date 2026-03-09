"""Tests for threat model (.tc.json) parser."""

from pathlib import Path

from tc_json_triage.parsers.threat_model import parse_threat_model

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_threats():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    assert len(model.threats) == 5


def test_parse_mitigations():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    assert len(model.mitigations) == 4


def test_stride_extraction():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    # Threat 1 has STRIDE metadata entries with value "T" and "I"
    assert set(by_id["threat-001"].stride) == {"T", "I"}
    # Threat 2 uses single-letter key style
    assert "I" in by_id["threat-002"].stride


def test_priority_extraction():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    assert by_id["threat-001"].priority == "High"
    assert by_id["threat-002"].priority == "Medium"


def test_mitigation_resolved_threat():
    """Threat 003 has status=threatResolved, should be mitigated."""
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    assert by_id["threat-003"].is_mitigated is True


def test_mitigation_via_links():
    """Threat 001 is linked to mit-001 (resolved), so it should be mitigated."""
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    assert by_id["threat-001"].is_mitigated is True
    assert len(by_id["threat-001"].linked_mitigations) == 1
    assert by_id["threat-001"].linked_mitigations[0].content == "Use parameterized queries for all database access"


def test_unmitigated_threat():
    """Threat 002 is linked to mit-002 (inProgress), so it should NOT be mitigated."""
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    assert by_id["threat-002"].is_mitigated is False


def test_impacted_assets():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    assert by_id["threat-001"].impacted_assets == ["search-api", "database"]


def test_unlinked_threat_not_mitigated():
    """Threat 005 has no mitigation links and is 'identified', so not mitigated."""
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    by_id = {t.id: t for t in model.threats}

    assert by_id["threat-005"].is_mitigated is False
    assert by_id["threat-005"].linked_mitigations == []
