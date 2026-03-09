"""Core correlation engine — matches scan findings to threat model entries."""

from __future__ import annotations

import re

from tc_json_triage.mapping.cwe_stride import cwes_to_stride
from tc_json_triage.models import (
    Confidence,
    CorrelationResult,
    FindingSource,
    ParsedThreat,
    ScanFinding,
    Severity,
    ThreatModel,
)

# Minimum score to consider a threat a candidate match
_MATCH_THRESHOLD = 3

# Score thresholds for confidence levels
_HIGH_CONFIDENCE = 5
_MEDIUM_CONFIDENCE = 3


def _keyword_overlap(text_a: str, text_b: str, min_word_len: int = 4) -> int:
    """Count overlapping meaningful words between two texts."""
    words_a = {w.lower() for w in re.findall(r"\w+", text_a) if len(w) >= min_word_len}
    words_b = {w.lower() for w in re.findall(r"\w+", text_b) if len(w) >= min_word_len}
    return len(words_a & words_b)


def _score_candidate(finding: ScanFinding, threat: ParsedThreat, finding_stride: set[str]) -> int:
    """Score how well a threat matches a finding. Higher is better."""
    score = 0

    # STRIDE category overlap (+3 per overlapping category, capped)
    threat_stride = set(threat.stride)
    overlap = finding_stride & threat_stride
    if overlap:
        score += 3

    # Asset matching: check if finding's package or file appears in impacted assets (+2)
    assets_text = " ".join(threat.impacted_assets).lower()
    if finding.package_name and finding.package_name.lower() in assets_text:
        score += 2
    if finding.file:
        file_base = finding.file.rsplit("/", 1)[-1].lower()
        if file_base in assets_text:
            score += 2

    # Keyword matching between finding description and threat statement (+2 if good overlap)
    kw_count = _keyword_overlap(finding.description, threat.statement)
    if kw_count >= 3:
        score += 2
    elif kw_count >= 1:
        score += 1

    # Priority alignment (+1)
    priority_sev = {
        "High": {"critical", "high"},
        "Medium": {"medium"},
        "Low": {"low", "info"},
    }
    expected = priority_sev.get(threat.priority, set())
    if finding.severity.value in expected:
        score += 1

    return score


def _score_to_confidence(score: int) -> Confidence:
    if score >= _HIGH_CONFIDENCE:
        return Confidence.HIGH
    if score >= _MEDIUM_CONFIDENCE:
        return Confidence.MEDIUM
    return Confidence.LOW


def _adjust_severity(
    original: Severity,
    source: FindingSource,
    is_mitigated: bool,
    confidence: Confidence,
) -> Severity:
    """Apply severity reduction rules."""
    # Never reduce secrets findings
    if source == FindingSource.SECRETS:
        return original

    if not is_mitigated:
        return original

    if confidence == Confidence.HIGH:
        return original.reduced(3)
    if confidence == Confidence.MEDIUM:
        return original.reduced(1)
    # Low confidence — don't reduce
    return original


def correlate_finding(finding: ScanFinding, model: ThreatModel) -> CorrelationResult:
    """Correlate a single finding against the threat model."""
    # Map finding CWEs to STRIDE
    if finding.cwes:
        finding_stride = cwes_to_stride(finding.cwes)
    else:
        # Default: Information Disclosure for findings without CWEs
        finding_stride = {"I"}

    # Score all threats
    scored: list[tuple[int, ParsedThreat]] = []
    for threat in model.threats:
        score = _score_candidate(finding, threat, finding_stride)
        if score >= _MATCH_THRESHOLD:
            scored.append((score, threat))

    scored.sort(key=lambda x: x[0], reverse=True)

    if not scored:
        # No match — this is a gap in the threat model
        return CorrelationResult(
            finding=finding,
            adjusted_severity=finding.severity,
            original_severity=finding.severity,
            confidence=Confidence.NONE,
            reason="No matching threat found in threat model (potential coverage gap)",
            is_gap=True,
        )

    best_score, best_threat = scored[0]
    confidence = _score_to_confidence(best_score)
    adjusted = _adjust_severity(finding.severity, finding.source, best_threat.is_mitigated, confidence)

    if best_threat.is_mitigated:
        mit_names = ", ".join(
            f"M-{m.numeric_id}" for m in best_threat.linked_mitigations
        ) or "threat marked resolved"
        reason = (
            f"Matched threat T-{best_threat.numeric_id} (mitigated by {mit_names}). "
            f"Severity {'reduced' if adjusted != finding.severity else 'unchanged'} "
            f"(confidence: {confidence.value})."
        )
    else:
        reason = (
            f"Matched unmitigated threat T-{best_threat.numeric_id}: "
            f"\"{best_threat.statement[:120]}\" "
            f"(confidence: {confidence.value})."
        )

    return CorrelationResult(
        finding=finding,
        matched_threat=best_threat,
        matched_mitigations=best_threat.linked_mitigations,
        confidence=confidence,
        adjusted_severity=adjusted,
        original_severity=finding.severity,
        reason=reason,
        is_gap=False,
    )


def correlate_all(findings: list[ScanFinding], model: ThreatModel) -> list[CorrelationResult]:
    """Correlate all findings against the threat model."""
    return [correlate_finding(f, model) for f in findings]
