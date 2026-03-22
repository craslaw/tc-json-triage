"""Parser for .tc.json threat-composer threat model files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tc_json_triage.models import ParsedMitigation, ParsedThreat, ThreatModel

_STRIDE_KEYS = {"S", "T", "R", "I", "D", "E"}

# Mitigation statuses that count as "resolved"
_RESOLVED_STATUSES = {"mitigationResolved", "mitigationResolvedWillNotAction"}


def _extract_stride(metadata: list[dict[str, Any]]) -> list[str]:
    """Extract STRIDE tags from threat metadata entries."""
    stride: list[str] = []
    for entry in metadata:
        key = entry.get("key", "")
        # Metadata keys like "STRIDE" with values "S", "T", etc.
        if key == "STRIDE":
            val = entry.get("value", "")
            # Handle list values like ["S", "T"] or string values like "ST"
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.upper() in _STRIDE_KEYS:
                        stride.append(item.upper())
            else:
                for ch in val:
                    if ch.upper() in _STRIDE_KEYS:
                        stride.append(ch.upper())
        # Also handle individual STRIDE keys (e.g. key="S", value="Spoofing")
        if key.upper() in _STRIDE_KEYS:
            stride.append(key.upper())
    return list(dict.fromkeys(stride))  # deduplicate preserving order


def _extract_priority(metadata: list[dict[str, Any]]) -> str:
    for entry in metadata:
        if entry.get("key", "").lower() == "priority":
            return entry.get("value", "")
    return ""


def _extract_metadata_dict(metadata: list[dict[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for e in metadata:
        key = e.get("key", "")
        if not key:
            continue
        val = e.get("value", "")
        # Convert list values to comma-separated strings
        if isinstance(val, list):
            result[key] = ",".join(str(v) for v in val)
        else:
            result[key] = str(val) if val is not None else ""
    return result


def _extract_impacted_assets(statement_parts: dict[str, Any]) -> list[str]:
    assets = statement_parts.get("impactedAssets", [])
    if isinstance(assets, list):
        return assets
    if isinstance(assets, str) and assets:
        return [assets]
    return []


def _extract_impacted_goal(statement_parts: dict[str, Any]) -> list[str]:
    goals = statement_parts.get("impactedGoal", [])
    if isinstance(goals, list):
        return goals
    if isinstance(goals, str) and goals:
        return [goals]
    return []


def _build_statement(threat: dict[str, Any]) -> str:
    """Build the full threat statement string."""
    stmt = threat.get("statement", "")
    if stmt:
        return stmt
    # Reconstruct from parts if no pre-built statement
    parts = []
    for field in ["threatSource", "prerequisites", "threatAction", "threatImpact"]:
        val = threat.get(field, "")
        if val:
            parts.append(val)
    return " ".join(parts)


def parse_threat_model(path: str | Path) -> ThreatModel:
    """Parse a .tc.json file and return a structured ThreatModel."""
    with open(path) as f:
        data = json.load(f)

    # Build mitigation lookup
    raw_mitigations = data.get("mitigations", [])
    mitigations: list[ParsedMitigation] = []
    mit_by_id: dict[str, ParsedMitigation] = {}
    for m in raw_mitigations:
        pm = ParsedMitigation(
            id=m.get("id", ""),
            numeric_id=m.get("numericId", 0),
            content=m.get("content", ""),
            status=m.get("status", ""),
        )
        mitigations.append(pm)
        mit_by_id[pm.id] = pm

    # Build mitigation links lookup: threat_id → [mitigation_ids]
    raw_links = data.get("mitigationLinks", [])
    threat_to_mits: dict[str, list[str]] = {}
    for link in raw_links:
        linked_id = link.get("linkedId", "")
        mit_id = link.get("mitigationId", "")
        if linked_id and mit_id:
            threat_to_mits.setdefault(linked_id, []).append(mit_id)

    # Parse threats
    raw_threats = data.get("threats", [])
    threats: list[ParsedThreat] = []
    for t in raw_threats:
        tid = t.get("id", "")
        metadata_raw = t.get("metadata", [])
        if isinstance(metadata_raw, list):
            metadata_list = metadata_raw
        else:
            metadata_list = []

        stride = _extract_stride(metadata_list)
        priority = _extract_priority(metadata_list)
        metadata_dict = _extract_metadata_dict(metadata_list)

        # Resolve linked mitigations
        linked_mit_ids = threat_to_mits.get(tid, [])
        linked_mits = [mit_by_id[mid] for mid in linked_mit_ids if mid in mit_by_id]

        # Determine if mitigated
        status = t.get("status", "")
        is_mitigated = status == "threatResolved"
        if not is_mitigated and linked_mits:
            is_mitigated = all(m.status in _RESOLVED_STATUSES for m in linked_mits)

        threats.append(
            ParsedThreat(
                id=tid,
                numeric_id=t.get("numericId", 0),
                statement=_build_statement(t),
                status=status,
                stride=stride,
                priority=priority,
                impacted_assets=_extract_impacted_assets(t),
                impacted_goal=_extract_impacted_goal(t),
                threat_source=t.get("threatSource", ""),
                threat_action=t.get("threatAction", ""),
                threat_impact=t.get("threatImpact", ""),
                is_mitigated=is_mitigated,
                linked_mitigations=linked_mits,
                metadata=metadata_dict,
            )
        )

    # Normalise links for output
    norm_links = [
        {"linkedId": l.get("linkedId", ""), "mitigationId": l.get("mitigationId", "")}
        for l in raw_links
    ]
    assumption_links = data.get("assumptionLinks", [])

    return ThreatModel(
        threats=threats,
        mitigations=mitigations,
        mitigation_links=norm_links,
        assumption_links=assumption_links,
    )
