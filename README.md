# tc-json-triage

Correlate security scan findings against a [threat-composer](https://github.com/awslabs/threat-composer) threat model (`.tc.json`). Findings related to **mitigated** threats have their severity reduced; findings related to **unmitigated** threats retain original severity. The result surfaces what truly warrants human review.

## How it works

1. Parses your `.tc.json` threat model to determine which threats are mitigated
2. Parses one or more SARIF scan result files (from SAST, SCA, or secrets scanners)
3. Correlates each finding to threats via CWE→STRIDE mapping and keyword scoring
4. Adjusts severity based on mitigation status and match confidence
5. Reports findings grouped by: action required, reduced severity, and coverage gaps

### Severity reduction rules

| Match result | Confidence | Reduction |
|---|---|---|
| Mitigated threat | High | -3 levels (Critical→Low, High→Info, …) |
| Mitigated threat | Medium | -1 level |
| Mitigated threat | Low | None (ambiguous) |
| Unmitigated threat | Any | None (keep original) |
| No match (gap) | None | None (keep original, flagged as gap) |
| Secrets finding | Any | **Never reduced** |

Coverage gaps (findings with no matching threat) are flagged separately — they often indicate incomplete threat modeling.

## Installation

Requires Python 3.10+.

```bash
pip install tc-json-triage
```

Or install from source:

```bash
git clone https://github.com/craslaw/tc-json-triage
cd tc-json-triage
pip install -e .
```

To enable optional LLM-assisted matching:

```bash
pip install "tc-json-triage[llm]"
```

## Usage

### Basic

```bash
tc-json-triage --threat-model app.tc.json --sarif scan-results.sarif
```

### Multiple scan files

```bash
tc-json-triage \
  --threat-model app.tc.json \
  --sarif sca-results.sarif \
  --sarif sast-results.sarif \
  --sarif secrets-results.sarif
```

### Output formats

**Markdown summary** (default) — human-readable report:

```bash
tc-json-triage --threat-model app.tc.json --sarif scan.sarif
# or explicitly:
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --output-format summary
# save to file:
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --output report.md
```

**JSON summary** — structured data for further processing:

```bash
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --output-format json
tc-json-triage --threat-model app.tc.json --sarif scan.sarif --output-format json --output report.json
```

**Annotated SARIF** — modified SARIF compatible with GitHub Code Scanning upload:

```bash
tc-json-triage \
  --threat-model app.tc.json \
  --sarif scan.sarif \
  --output-format sarif \
  --output triaged.sarif
```

> Note: SARIF output requires exactly one `--sarif` input file.

### CLI reference

```
Usage: tc-json-triage [OPTIONS]

  Correlate security scan findings against a threat-composer threat model.

Options:
  --threat-model PATH              Path to .tc.json threat model file.  [required]
  --sarif PATH                     Path to SARIF scan result file (can be
                                   repeated).  [required]
  --output-format [summary|json|sarif]
                                   Output format (default: summary).
  --output PATH                    Output file path (default: stdout).
  --help                           Show this message and exit.
```

## GitHub Actions integration

```yaml
steps:
  - name: Run security scans
    # ... your scan steps that produce SARIF output ...

  - name: Triage findings against threat model
    run: |
      pip install tc-json-triage
      tc-json-triage \
        --threat-model threat-model.tc.json \
        --sarif codeql-results.sarif \
        --sarif trivy-results.sarif \
        --output-format sarif \
        --output triaged.sarif

  - name: Upload triaged results to GitHub Code Scanning
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: triaged.sarif
```

## Supported scan tools

Any tool that outputs SARIF v2.1.0 is supported. Tested with:

| Category | Tools |
|---|---|
| SAST | CodeQL, Semgrep |
| SCA | Trivy, Grype |
| Secrets | Gitleaks, TruffleHog |

Source type (SCA / SAST / secrets) is inferred from the tool name in the SARIF. Secrets findings are never severity-reduced regardless of threat model status.

## Threat model requirements

The tool works with `.tc.json` files produced by [threat-composer](https://github.com/awslabs/threat-composer).

For best matching results, ensure your threats have:

- **STRIDE tags** in the threat metadata — used as the primary matching signal
- **Impacted assets** — matched against finding file paths and package names
- **Linked mitigations** with resolved status (`mitigationResolved` or `mitigationResolvedWillNotAction`)

A threat is considered **mitigated** when:
- Its status is `threatResolved`, OR
- It has at least one linked mitigation AND all linked mitigations are resolved

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=tc_json_triage
```

### Project structure

```
src/tc_json_triage/
  models.py            Shared Pydantic data models
  cli.py               CLI entry point (Click)
  parsers/
    sarif.py           SARIF v2.1.0 parser
    threat_model.py    .tc.json parser
  mapping/
    cwe_stride.py      CWE to STRIDE category mapping
    correlator.py      Core correlation and scoring engine
  output/
    sarif_annotator.py Annotated SARIF output
    summary.py         Markdown and JSON summary reports
  llm/
    correlator.py      Optional LLM-assisted disambiguation
data/
  cwe_stride_map.json  Static CWE->STRIDE mapping table (90+ CWEs)
tests/
  fixtures/            Sample .tc.json and SARIF files for testing
```
