"""Produce annotated SARIF output with severity adjustments and correlation metadata."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from tc_json_triage.models import CorrelationResult, Severity

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _build_correlation_property(result: CorrelationResult) -> dict[str, Any]:
    prop: dict[str, Any] = {
        "confidence": result.confidence.value,
        "originalSeverity": result.original_severity.value,
        "adjustedSeverity": result.adjusted_severity.value,
        "reason": result.reason,
        "isGap": result.is_gap,
    }
    if result.matched_threat:
        prop["matchedThreat"] = {
            "id": result.matched_threat.id,
            "numericId": result.matched_threat.numeric_id,
            "statement": result.matched_threat.statement,
            "isMitigated": result.matched_threat.is_mitigated,
            "stride": result.matched_threat.stride,
        }
    if result.matched_mitigations:
        prop["matchedMitigations"] = [
            {"id": m.id, "numericId": m.numeric_id, "content": m.content, "status": m.status}
            for m in result.matched_mitigations
        ]
    return prop


def annotate_sarif(
    original_sarif_path: str | Path,
    results: list[CorrelationResult],
) -> dict[str, Any]:
    """Read original SARIF and return a copy with correlation annotations.

    Matches correlation results to SARIF results by finding ID (result GUID or
    the raw dict reference).
    """
    with open(original_sarif_path) as f:
        sarif = json.load(f)

    annotated = copy.deepcopy(sarif)

    # Build lookup: finding id → correlation result
    by_id: dict[str, CorrelationResult] = {r.finding.id: r for r in results}

    for run in annotated.get("runs", []):
        for result in run.get("results", []):
            guid = result.get("guid", "")
            cr = by_id.get(guid)
            if cr is None:
                continue

            # Adjust level
            result["level"] = _SEVERITY_TO_LEVEL.get(cr.adjusted_severity, result.get("level", "warning"))

            # Add correlation properties
            props = result.setdefault("properties", {})
            props["originalSeverity"] = cr.original_severity.value
            props["threatModelCorrelation"] = _build_correlation_property(cr)

    return annotated


def write_annotated_sarif(
    original_sarif_path: str | Path,
    results: list[CorrelationResult],
    output_path: str | Path,
) -> None:
    """Write annotated SARIF to a file."""
    annotated = annotate_sarif(original_sarif_path, results)
    with open(output_path, "w") as f:
        json.dump(annotated, f, indent=2)
