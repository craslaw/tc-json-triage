"""Generate summary reports from correlation results."""

from __future__ import annotations

import json
from typing import Any

from tc_json_triage.models import Confidence, CorrelationResult


def generate_summary(results: list[CorrelationResult]) -> dict[str, Any]:
    """Generate a structured summary of correlation results."""
    total = len(results)
    gaps = [r for r in results if r.is_gap]
    mitigated = [r for r in results if r.matched_threat and r.matched_threat.is_mitigated]
    unmitigated = [
        r for r in results
        if r.matched_threat and not r.matched_threat.is_mitigated
    ]
    reduced = [r for r in results if r.adjusted_severity != r.original_severity]

    return {
        "total_findings": total,
        "matched": total - len(gaps),
        "unmatched_gaps": len(gaps),
        "mitigated_matches": len(mitigated),
        "unmitigated_matches": len(unmitigated),
        "severity_reductions": len(reduced),
        "threat_model_coverage": f"{((total - len(gaps)) / total * 100):.0f}%" if total else "N/A",
        "findings": {
            "action_required": [_finding_summary(r) for r in unmitigated],
            "reduced_severity": [_finding_summary(r) for r in reduced],
            "gaps": [_finding_summary(r) for r in gaps],
        },
    }


def _finding_summary(r: CorrelationResult) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "finding_id": r.finding.id,
        "tool": r.finding.tool,
        "rule_id": r.finding.rule_id,
        "original_severity": r.original_severity.value,
        "adjusted_severity": r.adjusted_severity.value,
        "confidence": r.confidence.value,
        "reason": r.reason,
    }
    if r.finding.file:
        entry["location"] = r.finding.file
        if r.finding.start_line:
            entry["location"] += f":{r.finding.start_line}"
    if r.matched_threat:
        entry["matched_threat"] = f"T-{r.matched_threat.numeric_id}"
    return entry


def format_summary_markdown(results: list[CorrelationResult]) -> str:
    """Format correlation results as a Markdown report."""
    summary = generate_summary(results)
    lines: list[str] = []

    lines.append("# Scan Triage Report")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"- **Total findings**: {summary['total_findings']}")
    lines.append(f"- **Matched to threats**: {summary['matched']}")
    lines.append(f"- **Unmatched (gaps)**: {summary['unmatched_gaps']}")
    lines.append(f"- **Mitigated matches**: {summary['mitigated_matches']}")
    lines.append(f"- **Unmitigated matches**: {summary['unmitigated_matches']}")
    lines.append(f"- **Severity reductions**: {summary['severity_reductions']}")
    lines.append(f"- **Threat model coverage**: {summary['threat_model_coverage']}")
    lines.append("")

    # Action required
    action = summary["findings"]["action_required"]
    if action:
        lines.append("## Action Required (Unmitigated Threats)")
        lines.append("")
        for item in action:
            loc = item.get("location", "N/A")
            lines.append(
                f"- **{item['rule_id']}** ({item['original_severity']}) - "
                f"{item.get('matched_threat', 'N/A')} - {loc}"
            )
            lines.append(f"  {item['reason']}")
        lines.append("")

    # Reduced
    reduced = summary["findings"]["reduced_severity"]
    if reduced:
        lines.append("## Reduced Severity (Mitigated)")
        lines.append("")
        for item in reduced:
            loc = item.get("location", "N/A")
            lines.append(
                f"- **{item['rule_id']}** ({item['original_severity']} -> {item['adjusted_severity']}) -- "
                f"{item.get('matched_threat', 'N/A')} - {loc}"
            )
            lines.append(f"  {item['reason']}")
        lines.append("")

    # Gaps
    gaps = summary["findings"]["gaps"]
    if gaps:
        lines.append("## Coverage Gaps (No Matching Threat)")
        lines.append("")
        for item in gaps:
            loc = item.get("location", "N/A")
            lines.append(
                f"- **{item['rule_id']}** ({item['original_severity']}) - {loc}"
            )
            lines.append(f"  {item['reason']}")
        lines.append("")

    return "\n".join(lines)


def format_summary_json(results: list[CorrelationResult]) -> str:
    """Format correlation results as JSON."""
    return json.dumps(generate_summary(results), indent=2)
