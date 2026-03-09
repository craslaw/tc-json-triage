"""Tests for output generators."""

import json
from pathlib import Path

from tc_json_triage.mapping.correlator import correlate_all
from tc_json_triage.output.sarif_annotator import annotate_sarif
from tc_json_triage.output.summary import format_summary_json, format_summary_markdown, generate_summary
from tc_json_triage.parsers.sarif import parse_sarif
from tc_json_triage.parsers.threat_model import parse_threat_model

FIXTURES = Path(__file__).parent / "fixtures"


def _get_results():
    model = parse_threat_model(FIXTURES / "sample.tc.json")
    findings = parse_sarif(FIXTURES / "sample.sarif")
    return correlate_all(findings, model)


def test_summary_structure():
    results = _get_results()
    summary = generate_summary(results)

    assert summary["total_findings"] == 5
    assert "matched" in summary
    assert "unmatched_gaps" in summary
    assert "threat_model_coverage" in summary
    assert "findings" in summary
    assert "action_required" in summary["findings"]
    assert "reduced_severity" in summary["findings"]
    assert "gaps" in summary["findings"]


def test_summary_markdown():
    results = _get_results()
    md = format_summary_markdown(results)

    assert "# Scan Triage Report" in md
    assert "Total findings" in md


def test_summary_json():
    results = _get_results()
    text = format_summary_json(results)
    data = json.loads(text)

    assert data["total_findings"] == 5


def test_annotated_sarif():
    results = _get_results()
    annotated = annotate_sarif(FIXTURES / "sample.sarif", results)

    # Should still be valid SARIF structure
    assert annotated["version"] == "2.1.0"
    assert "runs" in annotated

    # Check that at least one result has correlation properties
    has_correlation = False
    for run in annotated["runs"]:
        for result in run.get("results", []):
            props = result.get("properties", {})
            if "threatModelCorrelation" in props:
                has_correlation = True
                tc = props["threatModelCorrelation"]
                assert "confidence" in tc
                assert "reason" in tc
    assert has_correlation
