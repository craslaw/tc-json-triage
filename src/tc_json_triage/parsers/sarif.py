"""SARIF v2.1.0 parser — extracts normalized ScanFinding objects."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from tc_json_triage.models import FindingSource, ScanFinding, Severity

# Tool-name patterns used to infer finding source
_SCA_TOOLS = re.compile(r"trivy|grype|snyk|dependabot|dependency.check|oss.index", re.I)
_SECRETS_TOOLS = re.compile(r"gitleaks|trufflehog|detect.secrets|secret", re.I)

# SARIF level → Severity
_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _infer_source(tool_name: str, rule_id: str) -> FindingSource:
    if _SECRETS_TOOLS.search(tool_name) or _SECRETS_TOOLS.search(rule_id):
        return FindingSource.SECRETS
    if _SCA_TOOLS.search(tool_name) or _SCA_TOOLS.search(rule_id):
        return FindingSource.SCA
    return FindingSource.SAST


def _extract_cwes(rule: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from a SARIF rule's tags or properties."""
    cwes: list[str] = []
    tags: list[str] = rule.get("properties", {}).get("tags", [])
    for tag in tags:
        # CodeQL style: "external/cwe/cwe-89"
        m = re.search(r"cwe[/-](\d+)", tag, re.I)
        if m:
            cwes.append(f"CWE-{m.group(1)}")
    # Also check rule.properties.cwe directly
    cwe_prop = rule.get("properties", {}).get("cwe", [])
    if isinstance(cwe_prop, str):
        cwe_prop = [cwe_prop]
    for c in cwe_prop:
        normalised = c.upper().strip()
        if not normalised.startswith("CWE-"):
            normalised = f"CWE-{normalised}"
        if normalised not in cwes:
            cwes.append(normalised)
    return cwes


def _extract_severity(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
    """Determine severity from SARIF result level and rule properties."""
    # Check rule properties for security-severity (GitHub/CodeQL convention)
    sec_sev = rule.get("properties", {}).get("security-severity")
    if sec_sev is not None:
        try:
            score = float(sec_sev)
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            if score >= 0.1:
                return Severity.LOW
            return Severity.INFO
        except (ValueError, TypeError):
            pass
    level = result.get("level", "warning")
    return _LEVEL_MAP.get(level, Severity.MEDIUM)


def _build_rules_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build a rule-id → rule-descriptor lookup from the SARIF run."""
    index: dict[str, dict[str, Any]] = {}
    driver = run.get("tool", {}).get("driver", {})
    for rule in driver.get("rules", []):
        rid = rule.get("id", "")
        if rid:
            index[rid] = rule
    for ext in run.get("tool", {}).get("extensions", []):
        for rule in ext.get("rules", []):
            rid = rule.get("id", "")
            if rid:
                index[rid] = rule
    return index


def parse_sarif(path: str | Path) -> list[ScanFinding]:
    """Parse a SARIF file and return normalized findings."""
    with open(path) as f:
        data = json.load(f)

    findings: list[ScanFinding] = []

    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules_index = _build_rules_index(run)

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules_index.get(rule_id, {})
            cwes = _extract_cwes(rule)
            source = _infer_source(tool_name, rule_id)
            severity = _extract_severity(result, rule)

            # Extract message
            message = result.get("message", {})
            description = message.get("text", message.get("markdown", ""))

            # Extract location
            file_path: str | None = None
            start_line: int | None = None
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                file_path = artifact.get("uri")
                region = phys.get("region", {})
                start_line = region.get("startLine")

            # Extract CVE / package for SCA
            cve_id: str | None = None
            package_name: str | None = None
            if source == FindingSource.SCA:
                props = result.get("properties", {})
                cve_id = props.get("cve") or rule.get("properties", {}).get("cve")
                package_name = props.get("package") or rule.get("properties", {}).get("package")

            # Extract secret type
            secret_type: str | None = None
            if source == FindingSource.SECRETS:
                secret_type = rule.get("shortDescription", {}).get("text", rule_id)

            finding_id = result.get("guid") or str(uuid.uuid4())

            findings.append(
                ScanFinding(
                    id=finding_id,
                    source=source,
                    tool=tool_name,
                    rule_id=rule_id,
                    severity=severity,
                    cwes=cwes,
                    description=description,
                    file=file_path,
                    start_line=start_line,
                    cve_id=cve_id,
                    package_name=package_name,
                    secret_type=secret_type,
                    raw=result,
                )
            )

    return findings
