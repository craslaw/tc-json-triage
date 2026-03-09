"""Optional LLM-assisted correlation for ambiguous matches."""

from __future__ import annotations

import json
from typing import Any

from tc_json_triage.models import Confidence, ParsedThreat, ScanFinding

_PROMPT_TEMPLATE = """Given this security scan finding:
  Tool: {tool}
  Rule: {rule_id}
  CWEs: {cwes}
  Severity: {severity}
  Description: {description}
  Location: {location}

And these candidate threats from the threat model:

{candidates}

Which threat (if any) does this finding most closely relate to?
Consider the threat metadata for additional context — it may contain comments,
custom annotations, or source references that clarify the threat's scope.

Return your answer as JSON with this schema:
{{"threat_id": "<threat id or null>", "confidence": "high|medium|low", "reasoning": "<brief explanation>"}}
"""

_CANDIDATE_TEMPLATE = """Threat T-{numeric_id}:
  Statement: {statement}
  STRIDE: {stride}
  Priority: {priority}
  Impacted Assets: {assets}
  Mitigation Status: {mit_status}
  Linked Mitigations: {mitigations}
"""


def build_prompt(finding: ScanFinding, candidates: list[ParsedThreat]) -> str:
    """Build the LLM prompt for disambiguation."""
    candidate_texts = []
    for c in candidates:
        mit_contents = ", ".join(m.content for m in c.linked_mitigations) or "none"
        candidate_texts.append(
            _CANDIDATE_TEMPLATE.format(
                numeric_id=c.numeric_id,
                statement=c.statement,
                stride=", ".join(c.stride),
                priority=c.priority,
                assets=", ".join(c.impacted_assets) or "none",
                mit_status="mitigated" if c.is_mitigated else "unmitigated",
                mitigations=mit_contents,
            )
        )

    location = finding.file or "N/A"
    if finding.start_line:
        location += f":{finding.start_line}"

    return _PROMPT_TEMPLATE.format(
        tool=finding.tool,
        rule_id=finding.rule_id,
        cwes=", ".join(finding.cwes) or "none",
        severity=finding.severity.value,
        description=finding.description,
        location=location,
        candidates="\n".join(candidate_texts),
    )


def parse_llm_response(response_text: str) -> tuple[str | None, Confidence]:
    """Parse the LLM's JSON response into a threat ID and confidence."""
    try:
        # Find JSON in response (may be wrapped in markdown code blocks)
        text = response_text.strip()
        if "```" in text:
            start = text.index("{")
            end = text.rindex("}") + 1
            text = text[start:end]
        data = json.loads(text)
        threat_id = data.get("threat_id")
        confidence_str = data.get("confidence", "low")
        confidence_map = {
            "high": Confidence.HIGH,
            "medium": Confidence.MEDIUM,
            "low": Confidence.LOW,
        }
        return threat_id, confidence_map.get(confidence_str, Confidence.LOW)
    except (json.JSONDecodeError, ValueError):
        return None, Confidence.LOW
