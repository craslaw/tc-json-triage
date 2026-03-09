# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

tc-json-triage correlates SARIF security scan findings against threat-composer (`.tc.json`) threat models. Findings matched to mitigated threats get severity reduced; unmatched findings are flagged as threat model coverage gaps.

## Commands

```bash
# Install for development
pip install -e ".[dev]"

# Install with LLM support
pip install -e ".[dev,llm]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_correlator.py

# Run a specific test
pytest tests/test_correlator.py::test_name -v

# Run tests with coverage
pytest --cov=tc_json_triage

# Run the CLI
tc-json-triage --threat-model app.tc.json --sarif scan.sarif
```

## Architecture

**Data flow:** CLI (`cli.py`) → parsers → correlator → output formatters

- **`models.py`** — All Pydantic models shared across the codebase: `ScanFinding`, `ParsedThreat`, `ThreatModel`, `CorrelationResult`, `Severity` (with rank-based reduction), `Confidence`, `FindingSource`
- **`parsers/`** — `sarif.py` parses SARIF v2.1.0 into `ScanFinding` objects (infers source type from tool name); `threat_model.py` parses `.tc.json` into `ThreatModel` (resolves mitigation links and `is_mitigated` status)
- **`mapping/correlator.py`** — Core engine. Scores each finding against all threats using STRIDE overlap (+3), asset matching (+2), keyword overlap (+1-2), and priority alignment (+1). Thresholds: ≥3 match, ≥5 high confidence, ≥3 medium. Applies severity reduction per confidence level
- **`mapping/cwe_stride.py`** — Maps CWE IDs to STRIDE categories using `data/cwe_stride_map.json`
- **`output/`** — `summary.py` produces markdown or JSON reports; `sarif_annotator.py` produces annotated SARIF output
- **`llm/correlator.py`** — Optional Anthropic API-based disambiguation (requires `[llm]` extra)

## Development approach

Use Test-Driven Development: write a failing test first, then implement the minimum code to make it pass, then refactor.

## Key domain rules

- Secrets findings (`FindingSource.SECRETS`) are **never** severity-reduced regardless of threat model status
- A threat is mitigated when: status is `threatResolved`, OR all linked mitigations are resolved
- Severity reduction: high confidence = -3 levels, medium = -1, low = none
- Findings with no CWEs default to STRIDE category "I" (Information Disclosure)
- Match threshold is score ≥ 3; below that, finding is flagged as a coverage gap
